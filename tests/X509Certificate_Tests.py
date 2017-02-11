#!/usr/bin/python2.7
import unittest
import socket

from nassl import OpenSslVerifyEnum, OpenSslVersionEnum
from nassl.ssl_client import SslClient
from nassl.x509_certificate import X509Certificate, HostnameValidationResultEnum


class X509Certificate_Tests_Hostname_Validation(unittest.TestCase):

    def test_hostname_validation(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((u'www.google.fr', 443))

        ssl_client = SslClient(ssl_version=OpenSslVersionEnum.SSLV23, sock=sock, ssl_verify=OpenSslVerifyEnum.NONE)
        ssl_client.do_handshake()
        self.ssl_client = ssl_client
        self.cert = ssl_client.get_peer_certificate()

        self.assertEqual(HostnameValidationResultEnum.NAME_MATCHES_SAN, self.cert.matches_hostname(u'www.google.fr'))
        self.assertEqual(HostnameValidationResultEnum.NAME_DOES_NOT_MATCH, self.cert.matches_hostname(u'www.tests.com'))


class X509Certificate_Tests(unittest.TestCase):

    def setUp(self):
        self.pem_cert = u"""-----BEGIN CERTIFICATE-----
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
        self.cert = X509Certificate.from_pem(self.pem_cert)

    def test_get_hpkp_pin(self):
        self.assertEquals(self.cert.get_hpkp_pin(), u'K87oWBWM9UZfyddvDfoxL+8lpNyoUB2ptGtn0fv6G2Q=')

    def test_as_text(self):
        self.assertTrue(self.cert.as_text())

    def test_as_pem(self):
        self.assertEquals(self.cert.as_pem().replace('\n','').strip(), self.pem_cert.replace('\n','').strip())

    def test_as_dict(self):
        self.assertTrue(self.cert.as_dict())

    def test_get_SHA1_fingerprint(self):
        self.assertEquals(self.cert.get_SHA1_fingerprint(), u'b1bc968bd4f49d622aa89a81f2150152a41d829c')


def main():
    unittest.main()

if __name__ == u'__main__':
    main()