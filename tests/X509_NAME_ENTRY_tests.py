#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

import unittest
from nassl import _nassl_legacy
from nassl import _nassl
import socket

from nassl.legacy_ssl_client import LegacySslClient
from nassl.ssl_client import SslClient, OpenSslVerifyEnum


class Common_X509_NAME_ENTRY_Tests(unittest.TestCase):

    # To be set in subclasses
    _NASSL_MODULE = None

    @classmethod
    def setUpClass(cls):
        if cls is Common_X509_NAME_ENTRY_Tests:
            raise unittest.SkipTest("Skip tests, it's a base class")
        super(Common_X509_NAME_ENTRY_Tests, cls).setUpClass()

    def test_new_bad(self):
        self.assertRaises(NotImplementedError, self._NASSL_MODULE.X509_NAME_ENTRY, (None))


class Legacy_X509_NAME_ENTRY_Tests(Common_X509_NAME_ENTRY_Tests):
    _NASSL_MODULE = _nassl_legacy


class Modern_X509_NAME_ENTRY_Tests(Common_X509_NAME_ENTRY_Tests):
    _NASSL_MODULE = _nassl


class Common_X509_NAME_ENTRY_Tests_Online(unittest.TestCase):

    # To be set in subclasses
    _SSL_CLIENT_CLS = None

    @classmethod
    def setUpClass(cls):
        if cls is Common_X509_NAME_ENTRY_Tests_Online:
            raise unittest.SkipTest("Skip tests, it's a base class")
        super(Common_X509_NAME_ENTRY_Tests_Online, cls).setUpClass()

    def test(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(('www.google.com', 443))

        ssl_client = self._SSL_CLIENT_CLS(underlying_socket=sock, ssl_verify=OpenSslVerifyEnum.NONE)
        ssl_client.do_handshake()
        name_entry = ssl_client.get_peer_certificate().get_subject_name_entries()[0]
        ssl_client.shutdown()
        sock.close()

        self.assertIsNotNone(name_entry.get_data())
        self.assertIsNotNone(name_entry.get_object())


class Legacy_X509_NAME_ENTRY_Tests_Online(Common_X509_NAME_ENTRY_Tests_Online):
    _SSL_CLIENT_CLS = LegacySslClient


class Modern_X509_NAME_ENTRY_Tests_Online(Common_X509_NAME_ENTRY_Tests_Online):
    _SSL_CLIENT_CLS = SslClient


def main():
    unittest.main()

if __name__ == '__main__':
    main()
