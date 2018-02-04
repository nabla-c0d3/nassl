#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals
import unittest
import socket
import tempfile

from nassl._nassl import OpenSSLError
from nassl.legacy_ssl_client import LegacySslClient
from nassl.ssl_client import ClientCertificateRequested, OpenSslVersionEnum, OpenSslVerifyEnum, OpenSslFileTypeEnum, \
    SslClient


class CommonSslClientPrivateKeyTests(unittest.TestCase):

    # To be defined in subclasses
    _SSL_CLIENT_CLS = None

    @classmethod
    def setUpClass(cls):
        if cls is CommonSslClientPrivateKeyTests:
            raise unittest.SkipTest("Skip tests, it's a base class")
        super(CommonSslClientPrivateKeyTests, cls).setUpClass()

    def setUp(self):
        self.ssl_client = LegacySslClient(ssl_version=OpenSslVersionEnum.SSLV23, ssl_verify=OpenSslVerifyEnum.NONE)

        test_file = tempfile.NamedTemporaryFile(delete=False, mode='wt')
        test_file.write("""-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,7D15D836EE9E1B77

fzTe/7+BUBBpW7rFqfffSMeNTNwjVT8uT6+aQFkv1sazU295heEWcvnqYPQ2suDS
dqud4pxLizkSRZpAIoKZV/E0z3iM1zsrGiyNXZ3mouRjSZdESEBnPEbtIdsyHLkL
9arhA/kvuMqXMjgun+tPD0+ETlaFf5GCKgfFQzbF2W4WpeEXii43ZLZ9UmObUUql
5Y65K/07+ga/dj3E+l1dLtA7VhVV5CK+8TTmVdqOr85pEZ/BC3U09vnwovDWJ+l0
sV7GhzsDFSpwxeArZy7wSMkSOTe71O1gvjOxWlupznFcZvirhRtI+5k1/btcn7hx
8b7dp36pTb/GfwaeUVsAvJBqwdSun3NOWX7zJxIDGU6LxA80eiV4z3SxAykS52gl
rlb2e+F6dV+tRuREfaDaeS1DSlDMp1mQjPSD2ix6nSypv19FHdh01OoCd0OFxM6D
xs5RQnUeu4J9g45Wdp6lmXM62EhUqYLKRbjXnZbFMlVMq81UwpMazwAruTEOCxl4
iQk3rNzfREONa9HeshiMlkeRAQpyB1qLZwhoTwTl6xKaMkt6nFEE6qX1KrrACHkH
CFJVbuWVJCyoRFv+0Gypi7zn1ZZGkE4inDHxqIzUa0sSmbShEWooTxCyGUSoosaY
u2ozh8ESQCy03JFR9DY6mo3YekbIcCEjgdmE35nK4lJQFbo3A8YlHunEdVK0tb8Z
Wxf7cJ6J55bG5/Kft65kJnXAHrV9LnM1tPiRkB8umZkj/ou5NpDKiuLjR+WBfwi0
tqXk90NdSqJtMMGgrtVM84TYFPXP58QCBnE9oAI7XYM1rusuVBOXZw==
-----END RSA PRIVATE KEY-----""")
        test_file.close()
        self.test_file = test_file
        test_file2 = tempfile.NamedTemporaryFile(delete=False, mode='wt')
        test_file2.write("""-----BEGIN CERTIFICATE-----
MIIDCjCCAnOgAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBgDELMAkGA1UEBhMCRlIx
DjAMBgNVBAgMBVBhcmlzMQ4wDAYDVQQHDAVQYXJpczEWMBQGA1UECgwNRGFzdGFy
ZGx5IEluYzEMMAoGA1UECwwDMTIzMQ8wDQYDVQQDDAZBbCBCYW4xGjAYBgkqhkiG
9w0BCQEWC2xvbEBsb2wuY29tMB4XDTEzMDEyNzAwMDM1OFoXDTE0MDEyNzAwMDM1
OFowgZcxCzAJBgNVBAYTAkZSMQwwCgYDVQQIDAMxMjMxDTALBgNVBAcMBFRlc3Qx
IjAgBgNVBAoMGUludHJvc3B5IFRlc3QgQ2xpZW50IENlcnQxCzAJBgNVBAsMAjEy
MRUwEwYDVQQDDAxBbGJhbiBEaXF1ZXQxIzAhBgkqhkiG9w0BCQEWFG5hYmxhLWMw
ZDNAZ21haWwuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDlnvP1ltVO
8JDNT3AA99QqtiqCi/7BeEcFDm2al46mv7looz6CmB84osrusNVFsS5ICLbrCmeo
w5sxW7VVveGueBQyWynngl2PmmufA5Mhwq0ZY8CvwV+O7m0hEXxzwbyGa23ai16O
zIiaNlBAb0mC2vwJbsc3MTMovE6dHUgmzQIDAQABo3sweTAJBgNVHRMEAjAAMCwG
CWCGSAGG+EIBDQQfFh1PcGVuU1NMIEdlbmVyYXRlZCBDZXJ0aWZpY2F0ZTAdBgNV
HQ4EFgQUYR45okpFsqTYB1wlQQblLH9cRdgwHwYDVR0jBBgwFoAUP0X2HQlaca7D
NBzVbsjsdhzOqUQwDQYJKoZIhvcNAQEFBQADgYEAWEOxpRjvKvTurDXK/sEUw2KY
gmbbGP3tF+fQ/6JS1VdCdtLxxJAHHTW62ugVTlmJZtpsEGlg49BXAEMblLY/K7nm
dWN8oZL+754GaBlJ+wK6/Nz4YcuByJAnN8OeTY4Acxjhks8PrAbZgcf0FdpJaAlk
Pd2eQ9+DkopOz3UGU7c=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDCjCCAnOgAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBgDELMAkGA1UEBhMCRlIx
DjAMBgNVBAgMBVBhcmlzMQ4wDAYDVQQHDAVQYXJpczEWMBQGA1UECgwNRGFzdGFy
ZGx5IEluYzEMMAoGA1UECwwDMTIzMQ8wDQYDVQQDDAZBbCBCYW4xGjAYBgkqhkiG
9w0BCQEWC2xvbEBsb2wuY29tMB4XDTEzMDEyNzAwMDM1OFoXDTE0MDEyNzAwMDM1
OFowgZcxCzAJBgNVBAYTAkZSMQwwCgYDVQQIDAMxMjMxDTALBgNVBAcMBFRlc3Qx
IjAgBgNVBAoMGUludHJvc3B5IFRlc3QgQ2xpZW50IENlcnQxCzAJBgNVBAsMAjEy
MRUwEwYDVQQDDAxBbGJhbiBEaXF1ZXQxIzAhBgkqhkiG9w0BCQEWFG5hYmxhLWMw
ZDNAZ21haWwuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDlnvP1ltVO
8JDNT3AA99QqtiqCi/7BeEcFDm2al46mv7looz6CmB84osrusNVFsS5ICLbrCmeo
w5sxW7VVveGueBQyWynngl2PmmufA5Mhwq0ZY8CvwV+O7m0hEXxzwbyGa23ai16O
zIiaNlBAb0mC2vwJbsc3MTMovE6dHUgmzQIDAQABo3sweTAJBgNVHRMEAjAAMCwG
CWCGSAGG+EIBDQQfFh1PcGVuU1NMIEdlbmVyYXRlZCBDZXJ0aWZpY2F0ZTAdBgNV
HQ4EFgQUYR45okpFsqTYB1wlQQblLH9cRdgwHwYDVR0jBBgwFoAUP0X2HQlaca7D
NBzVbsjsdhzOqUQwDQYJKoZIhvcNAQEFBQADgYEAWEOxpRjvKvTurDXK/sEUw2KY
gmbbGP3tF+fQ/6JS1VdCdtLxxJAHHTW62ugVTlmJZtpsEGlg49BXAEMblLY/K7nm
dWN8oZL+754GaBlJ+wK6/Nz4YcuByJAnN8OeTY4Acxjhks8PrAbZgcf0FdpJaAlk
Pd2eQ9+DkopOz3UGU7c=
-----END CERTIFICATE-----""")
        test_file2.close()
        self.testFile2 = test_file2

    def test_use_private_key(self):
        self.assertIsNone(self.ssl_client._use_private_key(self.testFile2.name, self.test_file.name,
                                                           OpenSslFileTypeEnum.PEM, 'testPW'))

    def test_use_private_key_bad(self):
        with self.assertRaises(ValueError):
            self.ssl_client._use_private_key(self.testFile2.name, self.test_file.name, OpenSslFileTypeEnum.PEM, 'bad')


class ModernSslClientPrivateKeyTests(CommonSslClientPrivateKeyTests):
    _SSL_CLIENT_CLS = SslClient


class LegacySslClientPrivateKeyTests(CommonSslClientPrivateKeyTests):
    _SSL_CLIENT_CLS = LegacySslClient


class CommonSslClientOnlineTests(unittest.TestCase):

    # To be defined in subclasses
    _SSL_CLIENT_CLS = None

    @classmethod
    def setUpClass(cls):
        if cls is CommonSslClientPrivateKeyTests:
            raise unittest.SkipTest("Skip tests, it's a base class")
        super(CommonSslClientOnlineTests, cls).setUpClass()

    def setUp(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(('www.google.com', 443))

        ssl_client = LegacySslClient(ssl_version=OpenSslVersionEnum.SSLV23, underlying_socket=sock,
                                     ssl_verify=OpenSslVerifyEnum.NONE)
        ssl_client.set_cipher_list('ECDH')  # Needed for test_get_ecdh_param()
        ssl_client.do_handshake()
        self.ssl_client = ssl_client

    def tearDown(self):
        self.ssl_client.shutdown()
        self.ssl_client.get_underlying_socket().close()

    def test_write(self):
        self.assertGreater(self.ssl_client.write(b'GET / HTTP/1.0\r\n\r\n'), 1)

    def test_read(self):
        self.ssl_client.write(b'GET / HTTP/1.0\r\n\r\n')
        self.assertRegexpMatches(self.ssl_client.read(1024), b'google')

    def test_get_peer_certificate(self):
        self.assertIsNotNone(self.ssl_client.get_peer_certificate())

    def test_get_peer_cert_chain(self):
        self.assertIsNotNone(self.ssl_client.get_peer_cert_chain())

    def test_get_ecdh_param(self):
        self.assertIsNotNone(self.ssl_client.get_ecdh_param())

    def test_get_certificate_chain_verify_result(self):
        self.assertEqual(20, self.ssl_client.get_certificate_chain_verify_result()[0])


class ModernSslClientOnlineTests(CommonSslClientOnlineTests):

    _SSL_CLIENT_CLS = SslClient


class LegacySslClientOnlineTests(CommonSslClientOnlineTests):

    _SSL_CLIENT_CLS = LegacySslClient

    def test_do_ssl2_iis_handshake(self):
        self.ssl_client.do_ssl2_iis_handshake()


class CommonSslClientOnlineClientAuthenticationTests(unittest.TestCase):

    # To be defined in subclasses
    _SSL_CLIENT_CLS = None

    @classmethod
    def setUpClass(cls):
        if cls is CommonSslClientPrivateKeyTests:
            raise unittest.SkipTest("Skip tests, it's a base class")
        super(CommonSslClientOnlineClientAuthenticationTests, cls).setUpClass()

    def test_client_certificate_requested(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(('auth.startssl.com', 443))

        ssl_client = LegacySslClient(ssl_version=OpenSslVersionEnum.SSLV23, underlying_socket=sock,
                                     ssl_verify=OpenSslVerifyEnum.NONE)

        self.assertRaisesRegexp(ClientCertificateRequested, 'Server requested a client certificate',
                                ssl_client.do_handshake)

    def test_ignore_client_authentication_requests(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(('auth.startssl.com', 443))

        ssl_client = LegacySslClient(ssl_version=OpenSslVersionEnum.SSLV23, underlying_socket=sock,
                                     ssl_verify=OpenSslVerifyEnum.NONE, ignore_client_authentication_requests=True)

        ssl_client.do_handshake()
        self.assertGreater(len(ssl_client.get_client_CA_list()), 2)


class ModernSslClientOnlineClientAuthenticationTests(CommonSslClientOnlineClientAuthenticationTests):

    _SSL_CLIENT_CLS = SslClient


class LegacySslClientOnlineClientAuthenticationTests(CommonSslClientOnlineClientAuthenticationTests):

    _SSL_CLIENT_CLS = LegacySslClient


class ModernSslClientOnlineTls13Tests(unittest.TestCase):
    def test_tls_1_3(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(('tls13.crypto.mozilla.org', 443))
        ssl_client = SslClient(ssl_version=OpenSslVersionEnum.TLSV1_3, underlying_socket=sock,
                               ssl_verify=OpenSslVerifyEnum.NONE)
        self.assertTrue(ssl_client)

class ModernSslClientOnlineEarlyDataTests(unittest.TestCase):

    _DATA_TO_SEND = 'GET / HTTP/1.1\r\nHost: tls13.crypto.mozilla.org\r\n\r\n'

    def setUp(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        #sock.connect(('tls13.crypto.mozilla.org', 443))
        sock.connect(('tls13.baishancloud.com', 44344))
        ssl_client = SslClient(ssl_version=OpenSslVersionEnum.TLSV1_3, underlying_socket=sock,
                               ssl_verify=OpenSslVerifyEnum.NONE)
        self.ssl_client = ssl_client

    def tearDown(self):
        self.ssl_client.shutdown()
        self.ssl_client.get_underlying_socket().close()

    def test_write_early_data_doesnot_finish_handshake(self):
        self.ssl_client.do_handshake()
        self.ssl_client.write(self._DATA_TO_SEND);
        self.ssl_client.read(2048) 
        sess = self.ssl_client.get_session()
        self.assertIsNotNone(sess)
        self.tearDown()
        self.setUp()
        self.ssl_client.set_session(sess)
        self.ssl_client.write_early_data(self._DATA_TO_SEND);
        self.assertFalse(self.ssl_client.is_handshake_completed())

    def test_write_early_data_fail_when_used_on_non_reused_session(self):
        self.assertRaisesRegexp(OpenSSLError, 
                                'function you should not call',
                                self.ssl_client.write_early_data,
                                self._DATA_TO_SEND)

    def test_write_early_data_fail_when_trying_to_send_more_than_max_ealry_data(self):
        self.ssl_client.do_handshake()
        self.ssl_client.write(self._DATA_TO_SEND);
        self.ssl_client.read(2048) 
        sess = self.ssl_client.get_session()
        max_early = sess.get_max_early_data()
        str_to_send = 'GET / HTTP/1.1\r\nData: {}\r\n\r\n'
        self.assertIsNotNone(sess)
        self.tearDown()
        self.setUp()
        self.ssl_client.set_session(sess)
        self.assertRaisesRegexp(OpenSSLError, 
                                'too much early data',
                                self.ssl_client.write_early_data,
                                str_to_send.format('*' * max_early))


def main():
    unittest.main()

if __name__ == '__main__':
    main()

