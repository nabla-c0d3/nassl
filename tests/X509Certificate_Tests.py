#!/usr/bin/python2.7
import unittest
import socket
from nassl import SSLV23, SSL_VERIFY_NONE, X509_NAME_MISMATCH, X509_NAME_MATCHES_SAN
from nassl.ssl_client import SslClient


class X509Certificate_Tests_Hostname_Validation(unittest.TestCase):

    def setUp(self):
        # Requires being online :(
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(("www.google.fr", 443))

        ssl_client = SslClient(ssl_version=SSLV23, sock=sock, ssl_verify=SSL_VERIFY_NONE)
        ssl_client.do_handshake()
        self.ssl_client = ssl_client
        self.cert = ssl_client.get_peer_certificate()

    def test_matches_hostname_good(self):
        self.assertEqual(X509_NAME_MATCHES_SAN, self.cert.matches_hostname('www.google.fr'))

    def test_matches_hostname_bad(self):
        self.assertEqual(X509_NAME_MISMATCH, self.cert.matches_hostname('www.tests.com'))



def main():
    unittest.main()

if __name__ == '__main__':
    main()