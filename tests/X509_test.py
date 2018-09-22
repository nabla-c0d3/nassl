import socket

import pytest

from nassl.legacy_ssl_client import LegacySslClient
from nassl.ssl_client import SslClient, OpenSslVerifyEnum
from nassl import _nassl
from nassl import _nassl_legacy


@pytest.fixture()
def pem_certificate():
    """Return a sample PEM-formatted certificate.
    """
    return """
-----BEGIN CERTIFICATE-----
MIIDdTCCAl2gAwIBAgILBAAAAAABFUtaw5QwDQYJKoZIhvcNAQEFBQAwVzELMAkGA1UEBhMCQkUx
GTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNVBAsTB1Jvb3QgQ0ExGzAZBgNVBAMTEkds
b2JhbFNpZ24gUm9vdCBDQTAeFw05ODA5MDExMjAwMDBaFw0yODAxMjgxMjAwMDBaMFcxCzAJBgNV
BAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMRAwDgYDVQQLEwdSb290IENBMRswGQYD
VQQDExJHbG9iYWxTaWduIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDa
DuaZjc6j40+Kfvvxi4Mla+pIH/EqsLmVEQS98GPR4mdmzxzdzxtIK+6NiY6arymAZavpxy0Sy6sc
THAHoT0KMM0VjU/43dSMUBUc71DuxC73/OlS8pF94G3VNTCOXkNz8kHp1Wrjsok6Vjk4bwY8iGlb
Kk3Fp1S4bInMm/k8yuX9ifUSPJJ4ltbcdG6TRGHRjcdGsnUOhugZitVtbNV4FpWi6cgKOOvyJBNP
c1STE4U6G7weNLWLBYy5d4ux2x8gkasJU26Qzns3dLlwR5EiUWMWea6xrkEmCMgZK9FGqkjWZCrX
gzT/LCrBbBlDSgeF59N89iFo7+ryUp9/k5DPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBRge2YaRQ2XyolQL30EzTSo//z9SzANBgkqhkiG9w0BAQUF
AAOCAQEA1nPnfE920I2/7LqivjTFKDK1fPxsnCwrvQmeU79rXqoRSLblCKOzyj1hTdNGCbM+w6Dj
Y1Ub8rrvrTnhQ7k4o+YviiY776BQVvnGCv04zcQLcFGUl5gE38NflNUVyRRBnMRddWQVDf9VMOyG
j/8N7yy5Y0b2qvzfvGn9LhJIZJrglfCm7ymPAbEVtQwdpf5pLGkkeB6zpxxxYu7KyJesF12KwvhH
hm4qxFYxldBniYUr+WymXUadDKqC5JlR3XC321Y9YeRq4VzW9v493kHMB65jUr9TU/Qr6cf9tveC
X4XSQRjbgbMEHMUfpIBvFSDJ3gyICh3WZlXi/EjJKSZp4A==
-----END CERTIFICATE-----"""


@pytest.mark.parametrize("nassl_module", [_nassl, _nassl_legacy])
class TestX509:

    def test_from_pem(self, nassl_module, pem_certificate):
        certificate = nassl_module.X509(pem_certificate)

        assert certificate
        assert certificate.get_version()
        assert certificate.get_notBefore()
        assert certificate.get_notAfter()
        assert certificate.digest()
        assert certificate.as_pem()
        assert certificate.get_extensions()
        assert certificate.get_issuer_name_entries()
        assert certificate.get_subject_name_entries()
        assert certificate.get_spki_bytes()

    def test_from_pem_bad(self, nassl_module):
        pem_cert = '123123'
        with pytest.raises(ValueError):
            nassl_module.X509(pem_cert)

    def test_verify_cert_error_string(self, nassl_module):
        assert nassl_module.X509.verify_cert_error_string(1)


@pytest.mark.parametrize("ssl_client_cls", [SslClient, LegacySslClient])
class TestOnlineX509:

    def test(self, ssl_client_cls):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(('www.google.com', 443))

        ssl_client = ssl_client_cls(underlying_socket=sock, ssl_verify=OpenSslVerifyEnum.NONE)
        ssl_client.do_handshake()
        cert = ssl_client.get_peer_certificate()
        ssl_client.shutdown()

        assert cert.as_text()
