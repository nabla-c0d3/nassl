import unittest
import nassl
import socket
from SslClient import SslClient


class X509_EXTENSION_Tests(unittest.TestCase):

    def test_new_bad(self):
        self.assertRaises(NotImplementedError, nassl.X509_EXTENSION, (None))


class X509_EXTENSION_Tests_Online(unittest.TestCase):

    def setUp(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(("www.google.com", 443))

        sslClient = SslClient(sslVersion=nassl.SSLV23, sock=sock)
        sslClient.do_handshake()
        self.x509ext = sslClient.get_peer_certificate()._x509.get_ext(1)


    def test_get_data(self):
        self.assertIsNotNone(self.x509ext.get_data())


    def test_get_object(self):
        self.assertIsNotNone(self.x509ext.get_object())
        

    def test_get_critical(self):
        self.assertIsNotNone(self.x509ext.get_critical())
        

def main():
    unittest.main()

if __name__ == '__main__':
    main()