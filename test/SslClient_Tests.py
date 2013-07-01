import unittest
import nassl
import socket
from SslClient import SslClient



class SslClient_Tests_Handshake(unittest.TestCase):

    def setUp(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(("www.google.com", 443))

        sslClient = SslClient(sslVersion=nassl.SSLV23, sock=sock)
        self.sslClient = sslClient

    def test_do_handshake(self):
        self.assertTrue(self.sslClient.do_handshake())


class SslClient_Tests_Online(unittest.TestCase):

    def setUp(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(("www.google.com", 443))

        sslClient = SslClient(sslVersion=nassl.SSLV23, sock=sock)
        sslClient.do_handshake()
        self.sslClient = sslClient


    def test_write(self):
        self.assertGreater(self.sslClient.write('GET / HTTP/1.0\r\n\r\n'), 1)


    def test_read(self):
        self.sslClient.write('GET / HTTP/1.0\r\n\r\n')
        self.assertRegexpMatches(self.sslClient.read(1024), 'google')

    def test_get_peer_certificate(self):
        self.assertIsNotNone(self.sslClient.get_peer_certificate())
        


def main():
    unittest.main()

if __name__ == '__main__':
    main()