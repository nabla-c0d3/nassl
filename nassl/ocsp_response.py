from pathlib import Path

from nassl import _nassl


class OcspResponseNotTrustedError(Exception):
    def __init__(self, message: str, trust_store_path: Path) -> None:
        super().__init__(message)
        self.trust_store_path = trust_store_path


def verify_ocsp_response(ocsp_response: _nassl.OCSP_RESPONSE, trust_store_path: Path) -> None:
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
    except _nassl.OpenSSLError as e:
        if "certificate verify error" in str(e):
            raise OcspResponseNotTrustedError(
                "OCSP Response verification failed: the response is not trusted", trust_store_path
            )
        raise
