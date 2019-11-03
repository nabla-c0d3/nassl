from pathlib import Path
from typing import List
from nassl._nassl import X509, X509_STORE_CTX


class CertificateChainIsUntrusted(Exception):
    pass


# TODO(AD): Better name? X509PathValidator?
class CertificatePathValidator:
    def __init__(self, trusted_certificates: List[X509]) -> None:
        if not trusted_certificates:
            raise ValueError("Supplied an empty list of trusted certificates")
        self._trusted_certificates = trusted_certificates

    @classmethod
    def from_pem(cls, trusted_certificates_as_pem: List[str]) -> "CertificatePathValidator":
        if not trusted_certificates_as_pem:
            raise ValueError("Supplied an empty list of trusted certificates")

        return cls([X509(cert_pem) for cert_pem in trusted_certificates_as_pem])

    @classmethod
    def from_file(cls, trusted_certificates_path: Path) -> "CertificatePathValidator":
        parsed_certificates: List[str] = []
        with trusted_certificates_path.open() as file_content:
            for pem_segment in file_content.read().split("-----BEGIN CERTIFICATE-----")[1::]:
                pem_content = pem_segment.split("-----END CERTIFICATE-----")[0]
                pem_cert = f"-----BEGIN CERTIFICATE-----{pem_content}-----END CERTIFICATE-----"
                parsed_certificates.append(pem_cert)

        return cls.from_pem(parsed_certificates)

    # TODO(AD): verify()?
    def validate(self, certificate_chain: List[X509]) -> List[X509]:
        """Leaf must be at index 0.

        Returns the verified chain.
        """
        if not certificate_chain:
            raise ValueError("Supplied an empty certificate chain")

        # Setup the context object for cert verification
        store_ctx = X509_STORE_CTX()
        store_ctx.set0_trusted_stack(self._trusted_certificates)
        store_ctx.set0_untrusted(certificate_chain)
        store_ctx.set_cert(certificate_chain[0])

        # Run the verification
        result: int = X509.verify_cert(store_ctx)
        if result > 0:
            return []  # TODO(AD) Get the list
        elif result == 0:
            # TODO(AD) Get the details with X509_STORE_CTX_get_error
            raise CertificateChainIsUntrusted()
        elif result < 0:
            # Get the details with X509_STORE_CTX_get_error
            raise RuntimeError()
