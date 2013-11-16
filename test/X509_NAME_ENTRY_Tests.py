import unittest
from nassl import _nassl, SSL_VERIFY_NONE
import socket
from nassl.SslClient import SslClient


class X509_NAME_ENTRY_Tests(unittest.TestCase):

    def test_new_bad(self):
        self.assertRaises(NotImplementedError, _nassl.X509_NAME_ENTRY, (None))


class X509_NAME_ENTRY_Tests_Online(unittest.TestCase):

    def setUp(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(("www.google.com", 443))

        sslClient = SslClient(sock=sock, sslVerify=SSL_VERIFY_NONE)
        sslClient.do_handshake()
        self.nameEntry = sslClient.get_peer_certificate()._x509.get_subject_name_entries()[0];


    def test_get_data(self):
        self.assertIsNotNone(self.nameEntry.get_data())


    def test_get_object(self):
        self.assertIsNotNone(self.nameEntry.get_object())


def main():
    unittest.main()

if __name__ == '__main__':
    main()