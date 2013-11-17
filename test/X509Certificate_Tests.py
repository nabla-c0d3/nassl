import unittest
import socket
import tempfile
from nassl import SSLV23, SSL_VERIFY_NONE, X509_NAME_MISMATCH, X509_NAME_MATCHES_SAN
from nassl.SslClient import SslClient
from nassl.X509Certificate import X509Certificate


class X509Certificate_Tests_Hostname_Validation(unittest.TestCase):

    def setUp(self):
        # Requires being online :(
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(("www.google.fr", 443))

        sslClient = SslClient(sslVersion=SSLV23, sock=sock, sslVerify=SSL_VERIFY_NONE)
        sslClient.do_handshake()
        self.sslClient = sslClient
        self.cert = sslClient.get_peer_certificate()

    def test_matches_hostname_good(self):
        self.assertEqual(X509_NAME_MATCHES_SAN, self.cert.matches_hostname('www.google.fr'))

    def test_matches_hostname_bad(self):
        self.assertEqual(X509_NAME_MISMATCH, self.cert.matches_hostname('www.test.com'))



def main():
    unittest.main()

if __name__ == '__main__':
    main()