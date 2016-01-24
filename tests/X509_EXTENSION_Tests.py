#!/usr/bin/python2.7
import unittest
from nassl import _nassl, SSL_VERIFY_NONE
from nassl.ssl_client import SslClient
import socket


class X509_EXTENSION_Tests(unittest.TestCase):

    def test_new_bad(self):
        self.assertRaises(NotImplementedError, _nassl.X509_EXTENSION, (None))


class X509_EXTENSION_Tests_Online(unittest.TestCase):

    def setUp(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(("www.google.com", 443))

        sslClient = SslClient(sock=sock, ssl_verify=SSL_VERIFY_NONE)
        sslClient.do_handshake()
        self.x509ext = sslClient.get_peer_certificate()._x509.get_extensions()[0];


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