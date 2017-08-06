#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals
import unittest
from nassl import _nassl
from nassl.ssl_client import SslClient, OpenSslVerifyEnum
import socket


class X509_EXTENSION_Tests(unittest.TestCase):

    def test_new_bad(self):
        self.assertRaises(NotImplementedError, _nassl.X509_EXTENSION, (None))


class X509_EXTENSION_Tests_Online(unittest.TestCase):

    def test(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(('www.google.com', 443))

        sslClient = SslClient(underlying_socket=sock, ssl_verify=OpenSslVerifyEnum.NONE)
        sslClient.do_handshake()
        x509ext = sslClient.get_peer_certificate().get_extensions()[0]

        self.assertIsNotNone(x509ext.get_data())
        self.assertIsNotNone(x509ext.get_object())
        self.assertIsNotNone(x509ext.get_critical())


def main():
    unittest.main()

if __name__ == '__main__':
    main()