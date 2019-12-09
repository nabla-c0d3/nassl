from datetime import datetime
from enum import IntEnum
from pathlib import Path
from typing import Optional, List
from typing import Any

from dataclasses import dataclass

from nassl import _nassl
from typing import Dict


class OcspResponseNotTrustedError(Exception):
    def __init__(self, trust_store_path: Path) -> None:
        self.trust_store_path = trust_store_path


class OcspResponseStatusEnum(IntEnum):
    SUCCESSFUL = 0
    MALFORMED_REQUEST = 1
    INTERNAL_ERROR = 2
    TRY_LATER = 3
    SIG_REQUIRED = 5
    UNAUTHORIZED = 6


@dataclass(frozen=True)
class SignedCertificateTimestamp:
    version: str
    log_id: str
    timestamp: datetime


@dataclass(frozen=True)
class SignedCertificateTimestampsExtension:
    signed_certificate_timestamps: List[SignedCertificateTimestamp]

    @classmethod
    def from_openssl(cls, openssl_ocsp_response: _nassl.OCSP_RESPONSE) -> "SignedCertificateTimestampsExtension":
        response_text = _openssl_response_to_text(openssl_ocsp_response)
        scts_text_list = response_text.split("Signed Certificate Timestamp")
        if len(scts_text_list) < 2:
            raise ValueError("No SCTs in the OCSP response")

        scts_text_list = scts_text_list[1::]
        parsed_scts = []
        for sct_text in scts_text_list:
            sct_as_dict = _parse_single_sct(sct_text)
            parsed_scts.append(SignedCertificateTimestamp(**sct_as_dict))

        return cls(signed_certificate_timestamps=parsed_scts)


@dataclass(frozen=True)
class OcspResponse:
    status: OcspResponseStatusEnum
    type: str
    version: int
    responder_id: str
    produced_at: datetime

    certificate_status: str
    this_update: datetime
    next_update: datetime

    hash_algorithm: str
    issuer_name_hash: str
    issuer_key_hash: str
    serial_number: str

    extensions: Optional[List[SignedCertificateTimestampsExtension]]  # Only SCT is supported at the moment

    _openssl_ocsp_response: _nassl.OCSP_RESPONSE  # The OpenSSL object, needed to implement verify()

    def verify(self, verify_locations: Path) -> None:
        """Verify that the OCSP response is trusted.

        Args:
            verify_locations: The file path to a trust store containing pem-formatted certificates, to be used for
            validating the OCSP response.

        Raises OcspResponseNotTrustedError if the validation failed ie. the OCSP response is not trusted.
        """
        # Ensure the file exists
        with verify_locations.open():
            pass

        try:
            self._openssl_ocsp_response.basic_verify(str(verify_locations))
        except _nassl.OpenSSLError as e:
            if "certificate verify error" in str(e):
                raise OcspResponseNotTrustedError(verify_locations)
            raise

    @classmethod
    def from_openssl(cls, openssl_ocsp_response: _nassl.OCSP_RESPONSE) -> "OcspResponse":
        response_status = OcspResponseStatusEnum(openssl_ocsp_response.get_status())
        response_text = _openssl_response_to_text(openssl_ocsp_response)

        response_dict = dict(
            status=response_status,
            version=int(_get_value_from_text_output_no_p("Version:", response_text)),
            type=_get_value_from_text_output("Response Type:", response_text),
            responder_id=_get_value_from_text_output("Responder Id:", response_text),
            produced_at=_get_datetime_from_text_output("Produced At:", response_text),
            _openssl_ocsp_response=openssl_ocsp_response,
        )

        if response_status == OcspResponseStatusEnum.SUCCESSFUL:
            # A successful OCSP response will contain more data - let's parse it
            response_dict.update(
                dict(
                    hash_algorithm=_get_value_from_text_output("Hash Algorithm:", response_text),
                    issuer_name_hash=_get_value_from_text_output("Issuer Name Hash:", response_text),
                    issuer_key_hash=_get_value_from_text_output("Issuer Key Hash:", response_text),
                    serial_number=_get_value_from_text_output("Serial Number:", response_text),
                    certificate_status=_get_value_from_text_output("Cert Status:", response_text),
                    this_update=_get_datetime_from_text_output("This Update:", response_text),
                    next_update=_get_datetime_from_text_output("Next Update:", response_text),
                )
            )

            # Then try to parse the SCT extension
            if "Signed Certificate Timestamp" in response_text:
                sct_ext = SignedCertificateTimestampsExtension.from_openssl(openssl_ocsp_response)
                response_dict["extensions"] = [sct_ext]
            else:
                response_dict["extensions"] = None

        return cls(**response_dict)


# Text parsing
def _get_value_from_text_output(key: str, text_output: str) -> str:
    value = text_output.split(key)
    return value[1].split("\n")[0].strip()


def _get_value_from_text_output_no_p(key: str, text_output: str) -> str:
    value = _get_value_from_text_output(key, text_output)
    return value.split("(")[0].strip()


def _parse_sct_text_line(text_output: str) -> str:
    text_output_split = text_output.split(":", 1)
    value = text_output_split[1].strip()
    return value


def _parse_single_sct(sct_text_output: str) -> Dict[str, Any]:
    parsed_sct: Dict[str, Any] = {}
    # We ignore the Extensions: line
    for line in sct_text_output.split("\n"):
        if "Version" in line:
            parsed_sct["version"] = _parse_sct_text_line(line)
        elif "Timestamp" in line:
            value_as_str = _parse_sct_text_line(line)
            # The SCT timestamp has an extra microseconds field that we remove so we can parse the datetime like any
            # other OpenSSL datetime field
            value_split = value_as_str.split(".")
            date_and_time = value_split[0]
            year_and_tz = value_split[1][3::]
            sanitized_value = f"{date_and_time.strip()} {year_and_tz.strip()}"
            parsed_sct["timestamp"] = _parse_openssl_time(sanitized_value)
        elif "Log ID" in line:
            log_id_text = sct_text_output.split("Log ID    :")[1].split("Timestamp")[0]
            final_log_id = ""
            for line in log_id_text:
                final_log_id += line.strip(" ").replace("\n", "")
            parsed_sct["log_id"] = final_log_id

    return parsed_sct


def _openssl_response_to_text(openssl_ocsp_response: _nassl.OCSP_RESPONSE) -> str:
    # Parse OpenSSL's text output
    ocsp_resp_bytes = openssl_ocsp_response.as_text()
    # The response may contain certificates, which then may contain non-utf8 characters - get rid of them
    # TODO(AD): However this means we only parse the very first response
    ocsp_first_resp = ocsp_resp_bytes.split(b"Certificate:")[0]
    response_text = ocsp_first_resp.decode("utf-8")
    return response_text


def _parse_openssl_time(openssl_time: str) -> datetime:
    openssl_datetime_format = "%b %d %H:%M:%S %Y %Z"
    return datetime.strptime(openssl_time, openssl_datetime_format)


def _get_datetime_from_text_output(key: str, text_output: str) -> datetime:
    value_as_str = _get_value_from_text_output(key, text_output)
    return _parse_openssl_time(value_as_str)
