from pathlib import Path
from typing import Protocol

from nassl.errors import OpenSSLError


class OcspResponseProtocol(Protocol):
    """The OCSP_RESPONSE object returned by get_tlsext_status_ocsp_resp(); same API for every OpenSSL version."""

    def as_text(self) -> bytes: ...  # Bytes because the text may contain non-UTF-8 characters

    def as_der_bytes(self) -> bytes: ...

    def basic_verify(self, trust_store_path: str) -> None: ...


class OcspResponseNotTrustedError(Exception):
    def __init__(self, message: str, trust_store_path: Path) -> None:
        super().__init__(message)
        self.trust_store_path = trust_store_path


def verify_ocsp_response(ocsp_response: OcspResponseProtocol, trust_store_path: Path) -> None:
    """Verify that the OCSP response is trusted.

    Args:
        ocsp_response: The OCSP response to verify.
        trust_store_path: The file path to a trust store containing pem-formatted certificates, to be used for
        validating the OCSP response.

    Raises OcspResponseNotTrustedError if the validation failed ie. the OCSP response is not trusted.
    """
    # Ensure that the trust store file exists
    with trust_store_path.open():
        pass

    try:
        ocsp_response.basic_verify(str(trust_store_path))
    except OpenSSLError as e:
        if "certificate verify error" in str(e):
            raise OcspResponseNotTrustedError(
                "OCSP Response verification failed: the response is not trusted",
                trust_store_path,
            )
        raise
