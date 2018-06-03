from enum import IntEnum
from typing import Tuple, Optional, List
from typing import Any
from nassl import _nassl
from typing import Dict


class OcspResponseNotTrustedError(IOError):

    def __init__(self, trust_store_path: str) -> None:
        self.trust_store_path = trust_store_path


class OcspResponseStatusEnum(IntEnum):
    SUCCESSFUL = 0
    MALFORMED_REQUEST = 1
    INTERNAL_ERROR = 2
    TRY_LATER = 3
    SIG_REQUIRED = 5
    UNAUTHORIZED = 6


class OcspResponse:
    """High level API for parsing an OCSP response.
    """

    def __init__(self, ocsp_response: _nassl.OCSP_RESPONSE) -> None:
        self._ocsp_response = ocsp_response
        self._ocsp_response_dict = self._parse_ocsp_response_from_openssl_text(self.as_text(), self.status)

    @property
    def status(self) -> OcspResponseStatusEnum:
        return OcspResponseStatusEnum(self._ocsp_response.get_status())

    def as_text(self) -> str:
        ocsp_resp_bytes = self._ocsp_response.as_text()
        # The response may contain certificates, which then may contain non-utf8 characters - get rid of them
        ocsp_first_resp = ocsp_resp_bytes.split(b'Certificate:')[0]
        return ocsp_first_resp.decode('utf-8')

    def verify(self, verify_locations: str) -> None:
        """Verify that the OCSP response is trusted.

        Args:
            verify_locations: The file path to a trust store containing pem-formatted certificates, to be used for
            validating the OCSP response.

        Raises OcspResponseNotTrustedError if the validation failed ie. the OCSP response is not trusted.
        """
        # Ensure the file exists
        with open(verify_locations):
            pass

        try:
            self._ocsp_response.basic_verify(verify_locations)
        except _nassl.OpenSSLError as e:
            if 'certificate verify error' in str(e):
                raise OcspResponseNotTrustedError(verify_locations)
            raise

    def as_dict(self) -> Dict[str, Any]:
        return self._ocsp_response_dict

    @classmethod
    def _parse_ocsp_response_from_openssl_text(
            cls,
            response_text: str,
            response_status: OcspResponseStatusEnum
    ) -> Dict[str, Any]:
        """Parse OpenSSL's text output and make a lot of assumptions.
        """
        response_dict = {
            'responseStatus': cls._get_value_from_text_output_no_p('OCSP Response Status:', response_text),
            'version': cls._get_value_from_text_output_no_p('Version:', response_text),
            'responseType': cls._get_value_from_text_output('Response Type:', response_text),
            'responderID': cls._get_value_from_text_output('Responder Id:', response_text),
            'producedAt': cls._get_value_from_text_output('Produced At:', response_text),
            }  # type: Dict[str, Any]

        if response_status != OcspResponseStatusEnum.SUCCESSFUL:
            return response_dict

        # A successful OCSP response will contain more data - let's parse it
        # TODO(ad): This will not work correctly if there are multiple responses as it assumes just one
        response_dict['responses'] = [
            {
                'certID': {
                    'hashAlgorithm': cls._get_value_from_text_output('Hash Algorithm:', response_text),
                    'issuerNameHash': cls._get_value_from_text_output('Issuer Name Hash:', response_text),
                    'issuerKeyHash': cls._get_value_from_text_output('Issuer Key Hash:', response_text),
                    'serialNumber': cls._get_value_from_text_output('Serial Number:', response_text)
                },
                'certStatus': cls._get_value_from_text_output('Cert Status:', response_text),
                'thisUpdate': cls._get_value_from_text_output('This Update:', response_text),
                'nextUpdate': cls._get_value_from_text_output('Next Update:', response_text),
            }
        ]
        if cls._get_scts_from_text_output(response_text):
            # SCT extension present
            response_dict['responses'][0]['singleExtensions'] = {
                'ctCertificateScts': cls._get_scts_from_text_output(response_text)
            }
        return response_dict

# Text parsing
    @staticmethod
    def _get_value_from_text_output(key: str, text_output: str) -> Optional[str]:
        value = text_output.split(key)
        return None if len(value) < 2 else value[1].split('\n')[0].strip()

    @classmethod
    def _get_value_from_text_output_no_p(cls, key: str, text_output: str) -> Optional[str]:
        value = cls._get_value_from_text_output(key, text_output)
        return None if value is None else value.split('(')[0].strip()

    @staticmethod
    def _parse_sct_text_line(text_output: str) -> Tuple[str, Optional[str]]:
        text_output_split = text_output.split(':', 1)
        key = text_output_split[0].strip()
        value = text_output_split[1].strip()
        if value == 'none':
            final_value = None
        else:
            final_value = value
        return key, final_value

    @classmethod
    def _parse_single_sct(cls, sct_text_output: str) -> Dict[str, Any]:
        parsed_sct = {}
        for line in sct_text_output.split('\n'):
            # One-line fields
            if any(key in line for key in ['Version', 'Extensions', 'Timestamp']):
                key, value = cls._parse_sct_text_line(line)
                parsed_sct[key] = value

            elif 'Log ID' in line:
                log_id_text = sct_text_output.split('Log ID    :')[1].split('Timestamp')[0]
                final_log_id = ''
                for line in log_id_text:
                    final_log_id += line.strip(' ').replace('\n', '')
                parsed_sct['logId'] = final_log_id

        return parsed_sct

    @classmethod
    def _get_scts_from_text_output(cls, response_text: str) -> Optional[List[Dict[str, Any]]]:
        scts_text_list = response_text.split('Signed Certificate Timestamp')
        if len(scts_text_list) < 1:
            return None

        scts_text_list = scts_text_list[1::]
        parsed_scts = []
        for sct_text in scts_text_list:
            parsed_scts.append(cls._parse_single_sct(sct_text))
        return parsed_scts
