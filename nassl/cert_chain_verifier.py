from pathlib import Path
from typing import List
from nassl._nassl import X509, X509_STORE_CTX


class CertificateChainVerificationFailed(Exception):
    def __init__(self, openssl_error_code: int) -> None:
        self.openssl_error_code = openssl_error_code
        self.openssl_error_string = X509.verify_cert_error_string(self.openssl_error_code)
        super().__init__(
            f'Verification failed with OpenSSL error code {self.openssl_error_code}: "{self.openssl_error_string}"'
        )


class CertificateChainVerifier:
    def __init__(self, trusted_certificates: List[X509]) -> None:
        if not trusted_certificates:
            raise ValueError("Supplied an empty list of trusted certificates")
        self._trusted_certificates = trusted_certificates

    @classmethod
    def from_pem(cls, trusted_certificates_as_pem: List[str]) -> "CertificateChainVerifier":
        if not trusted_certificates_as_pem:
            raise ValueError("Supplied an empty list of trusted certificates")

        return cls([X509(cert_pem) for cert_pem in trusted_certificates_as_pem])

    @classmethod
    def from_file(cls, trusted_certificates_path: Path) -> "CertificateChainVerifier":
        parsed_certificates: List[str] = []
        with trusted_certificates_path.open() as file_content:
            for pem_segment in file_content.read().split("-----BEGIN CERTIFICATE-----")[1::]:
                pem_content = pem_segment.split("-----END CERTIFICATE-----")[0]
                pem_cert = f"-----BEGIN CERTIFICATE-----{pem_content}-----END CERTIFICATE-----"
                parsed_certificates.append(pem_cert)

        return cls.from_pem(parsed_certificates)

    def verify(self, certificate_chain: List[X509]) -> List[X509]:
        """Validate a certificate chain and if successful, return the verified chain.

        The leaf certificate must be at index 0 of the certificate chain.

        WARNING: the validation logic does not perform hostname validation.
        """
        if not certificate_chain:
            raise ValueError("Supplied an empty certificate chain")

        # Setup the context object for cert verification
        store_ctx = X509_STORE_CTX()
        store_ctx.set0_trusted_stack(self._trusted_certificates)
        store_ctx.set0_untrusted(certificate_chain)

        leaf_cert = certificate_chain[0]
        store_ctx.set_cert(leaf_cert)

        # Run the verification
        result: int = X509.verify_cert(store_ctx)
        if result == 1:
            # Validation succeeded
            verified_chain = store_ctx.get1_chain()
            return verified_chain
        elif result == 0:
            # Validation failed
            verify_result = store_ctx.get_error()
            raise CertificateChainVerificationFailed(verify_result)
        elif result < 0:
            raise RuntimeError("X509_verify_cert() was invoked incorrectly")
        else:
            raise RuntimeError(f"Result {result}; should never happen according to the OpenSSL documentation")
