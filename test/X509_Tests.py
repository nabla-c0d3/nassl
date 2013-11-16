import unittest
import socket
from nassl.SslClient import SslClient
from nassl import _nassl, SSL_VERIFY_NONE


class X509_Tests(unittest.TestCase):

    def test_new_bad(self):
        self.assertRaises(NotImplementedError, _nassl.X509, (None))


class X509_Tests_Online(unittest.TestCase):

    def setUp(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(("www.google.com", 443))

        sslClient = SslClient(sock=sock, sslVerify=SSL_VERIFY_NONE)
        sslClient.do_handshake()
        self.cert = sslClient.get_peer_certificate()._x509


    def test_as_text(self):
        self.assertIsNotNone(self.cert.as_text())


    def test_get_version(self):
        self.assertIsNotNone(self.cert.get_version())


    def test_get_notBefore(self):
        self.assertIsNotNone(self.cert.get_notBefore())


    def test_get_notAfter(self):
        self.assertIsNotNone(self.cert.get_notAfter())


    def test_digest(self):
        self.assertIsNotNone(self.cert.digest())


    def test_as_pem(self):
        self.assertIsNotNone(self.cert.as_pem())


    def test_get_extensions(self):
        self.assertIsNotNone(self.cert.get_extensions())


    def test_get_issuer_name_entries(self):
        self.assertIsNotNone(self.cert.get_issuer_name_entries())


    def test_get_subject_name_entries(self):
        self.assertIsNotNone(self.cert.get_subject_name_entries())


    def test_verify_cert_error_string(self):
        self.assertEqual('error number 1', _nassl.X509.verify_cert_error_string(1))



def main():
    unittest.main()

if __name__ == '__main__':
    main()