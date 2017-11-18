#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals
import unittest
from nassl import _nassl_legacy
from nassl import _nassl
from nassl.legacy_ssl_client import LegacySslClient
from nassl.ssl_client import SslClient, OpenSslVerifyEnum
import socket


class Common_X509_EXTENSION_Tests(unittest.TestCase):

    # To be set in subclasses
    _NASSL_MODULE = None

    @classmethod
    def setUpClass(cls):
        if cls is Common_X509_EXTENSION_Tests:
            raise unittest.SkipTest("Skip tests, it's a base class")
        super(Common_X509_EXTENSION_Tests, cls).setUpClass()

    def test_new_bad(self):
        self.assertRaises(NotImplementedError, self._NASSL_MODULE.X509_EXTENSION, (None))


class Modern_X509_EXTENSION_Tests(Common_X509_EXTENSION_Tests):
    _NASSL_MODULE = _nassl_legacy


class Legacy_X509_EXTENSION_Tests(Common_X509_EXTENSION_Tests):
    _NASSL_MODULE = _nassl


class Common_X509_EXTENSION_Tests_Online(unittest.TestCase):

    # To be set in subclasses
    _SSL_CLIENT_CLS = None

    @classmethod
    def setUpClass(cls):
        if cls is Common_X509_EXTENSION_Tests_Online:
            raise unittest.SkipTest("Skip tests, it's a base class")
        super(Common_X509_EXTENSION_Tests_Online, cls).setUpClass()

    def test(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(('www.google.com', 443))

        sslClient = self._SSL_CLIENT_CLS(underlying_socket=sock, ssl_verify=OpenSslVerifyEnum.NONE)
        sslClient.do_handshake()
        x509ext = sslClient.get_peer_certificate().get_extensions()[0]

        self.assertIsNotNone(x509ext.get_data())
        self.assertIsNotNone(x509ext.get_object())
        self.assertIsNotNone(x509ext.get_critical())


class Legacy_X509_EXTENSION_Tests_Online(Common_X509_EXTENSION_Tests_Online):
    _SSL_CLIENT_CLS = LegacySslClient


class Modern_X509_EXTENSION_Tests_Online(Common_X509_EXTENSION_Tests_Online):
    _SSL_CLIENT_CLS = SslClient


def main():
    unittest.main()

if __name__ == '__main__':
    main()