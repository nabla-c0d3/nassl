import logging
import unittest
import socket

from nassl.legacy_ssl_client import LegacySslClient
from nassl.ssl_client import ClientCertificateRequested, OpenSslVersionEnum, OpenSslVerifyEnum, SslClient, OpenSSLError
from tests.openssl_server import OpenSslServer, ClientAuthConfigEnum, OpenSslServerVersion


class CommonSslClientOnlineClientAuthenticationTests(unittest.TestCase):

    # To be defined in subclasses
    _SSL_CLIENT_CLS = None

    @classmethod
    def setUpClass(cls):
        if cls is CommonSslClientOnlineClientAuthenticationTests:
            raise unittest.SkipTest("Skip tests, it's a base class")
        super(CommonSslClientOnlineClientAuthenticationTests, cls).setUpClass()

    def test_client_authentication_no_certificate_supplied(self):
        # Given a server that requires client authentication
        with OpenSslServer(
            server_version=OpenSslServerVersion.MODERN,
            client_auth_config=ClientAuthConfigEnum.REQUIRED
        ) as server:
            # And the client does NOT provide a client certificate
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((server.hostname, server.port))

            ssl_client = self._SSL_CLIENT_CLS(
                ssl_version=OpenSslVersionEnum.SSLV23,
                underlying_socket=sock,
                ssl_verify=OpenSslVerifyEnum.NONE,
            )
            # When doing the handshake the right error is returned
            self.assertRaisesRegexp(
                ClientCertificateRequested,
                'Server requested a client certificate',
                ssl_client.do_handshake
            )
            sock.close()

    def test_client_authentication_no_certificate_supplied_but_ignore(self):
        # Given a server that accepts optional client authentication
        with OpenSslServer(
            server_version=OpenSslServerVersion.MODERN,
            client_auth_config=ClientAuthConfigEnum.OPTIONAL
        ) as server:
            # And the client does NOT provide a client cert but is configured to ignore the client auth request
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((server.hostname, server.port))

            ssl_client = self._SSL_CLIENT_CLS(
                ssl_version=OpenSslVersionEnum.SSLV23,
                underlying_socket=sock,
                ssl_verify=OpenSslVerifyEnum.NONE,
                ignore_client_authentication_requests=True,
            )
            # When doing the handshake
            try:
                ssl_client.do_handshake()
                # It succeeds
                self.assertTrue(ssl_client)
            finally:
                ssl_client.shutdown()
                sock.close()

    def test_client_authentication_succeeds(self):
        # Given a server that requires client authentication
        with OpenSslServer(
            server_version=OpenSslServerVersion.MODERN,
            client_auth_config=ClientAuthConfigEnum.REQUIRED
        ) as server:
            # And the client provides a client certificate
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((server.hostname, server.port))

            ssl_client = self._SSL_CLIENT_CLS(
                ssl_version=OpenSslVersionEnum.SSLV23,
                underlying_socket=sock,
                ssl_verify=OpenSslVerifyEnum.NONE,
                client_certchain_file=server.get_client_certificate_path(),
                client_key_file=server.get_client_key_path(),
            )

            # When doing the handshake, it succeeds
            try:
                ssl_client.do_handshake()
            finally:
                ssl_client.shutdown()
                sock.close()


class ModernSslClientOnlineClientAuthenticationTests(CommonSslClientOnlineClientAuthenticationTests):
    _SSL_CLIENT_CLS = SslClient


class LegacySslClientOnlineClientAuthenticationTests(CommonSslClientOnlineClientAuthenticationTests):
    _SSL_CLIENT_CLS = LegacySslClient


class CommonSslClientOnlineTests(unittest.TestCase):

    # To be defined in subclasses
    _SSL_CLIENT_CLS = None

    @classmethod
    def setUpClass(cls):
        if cls is CommonSslClientOnlineTests:
            raise unittest.SkipTest("Skip tests, it's a base class")
        super(CommonSslClientOnlineTests, cls).setUpClass()

    def test(self):
        # Given an SslClient connecting to Google
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(('www.google.com', 443))

        ssl_client = self._SSL_CLIENT_CLS(
            ssl_version=OpenSslVersionEnum.SSLV23,
            underlying_socket=sock,
            ssl_verify=OpenSslVerifyEnum.NONE
        )

        # When doing a TLS handshake, it succeeds
        try:
            ssl_client.do_handshake()

            # When sending a GET request
            self.assertGreater(ssl_client.write(b'GET / HTTP/1.0\r\n\r\n'), 1)
            # It gets response
            self.assertRegexpMatches(ssl_client.read(1024), b'google')

            # When requesting the server certificate, it returns it
            self.assertIsNotNone(ssl_client.get_peer_certificate())
            self.assertIsNotNone(ssl_client.get_peer_cert_chain())
            self.assertTrue(ssl_client.get_certificate_chain_verify_result()[0])
        finally:
            ssl_client.shutdown()
            sock.close()


class ModernSslClientOnlineTests(CommonSslClientOnlineTests):

    _SSL_CLIENT_CLS = SslClient


class LegacySslClientOnlineTests(CommonSslClientOnlineTests):

    _SSL_CLIENT_CLS = LegacySslClient


class LegacySslClientOnlineSsl2Tests(unittest.TestCase):

    def test_ssl_2(self):
        # Given a server that supports SSL 2.0
        with OpenSslServer(server_version=OpenSslServerVersion.LEGACY) as server:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((server.hostname, server.port))

            ssl_client = LegacySslClient(
                ssl_version=OpenSslVersionEnum.SSLV2,
                underlying_socket=sock,
                ssl_verify=OpenSslVerifyEnum.NONE,
                ignore_client_authentication_requests=True,
            )
            # When doing the special SSL 2.0 handshake, it succeeds
            try:
                ssl_client.do_handshake()
                self.assertTrue(ssl_client)
            finally:
                ssl_client.shutdown()
                sock.close()


class ModernSslClientOnlineTls13Tests(unittest.TestCase):
    def test_tls_1_3(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(('tls13.crypto.mozilla.org', 443))
        ssl_client = SslClient(ssl_version=OpenSslVersionEnum.TLSV1_3, underlying_socket=sock,
                               ssl_verify=OpenSslVerifyEnum.NONE)
        self.assertTrue(ssl_client)
        ssl_client.shutdown()
        sock.close()


class ModernSslClientOnlineEarlyDataTests(unittest.TestCase):

    _DATA_TO_SEND = b'GET / HTTP/1.1\r\nHost: tls13.crypto.mozilla.org\r\n\r\n'

    def setUp(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(('tls13.crypto.mozilla.org', 443))
        ssl_client = SslClient(ssl_version=OpenSslVersionEnum.TLSV1_3, underlying_socket=sock,
                               ssl_verify=OpenSslVerifyEnum.NONE)
        self.ssl_client = ssl_client

    def tearDown(self):
        self.ssl_client.shutdown()
        self.ssl_client.get_underlying_socket().close()

    @unittest.skip("Needs early data fix")
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

    @unittest.skip("Needs early data fix")
    def test_write_early_data_fail_when_used_on_non_reused_session(self):
        self.assertRaisesRegexp(OpenSSLError, 
                                'function you should not call',
                                self.ssl_client.write_early_data,
                                self._DATA_TO_SEND)

    @unittest.skip("Needs early data fix")
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

