import unittest
import nassl
import socket
from SslClient import SslClient


class X509_Tests_Tests(unittest.TestCase):

    def test_new_bad(self):
        self.assertRaises(NotImplementedError, nassl.X509, (None))


class X509_Tests_Online(unittest.TestCase):

    def setUp(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(("www.google.com", 443))

        sslClient = SslClient(sslVersion=nassl.SSLV23, sock=sock)
        sslClient.do_handshake()
        self.cert = sslClient.get_peer_certificate()


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


    def test_get_ext_count(self):
        self.assertIsNotNone(self.cert.get_ext_count())



def main():
    unittest.main()

if __name__ == '__main__':
    main()