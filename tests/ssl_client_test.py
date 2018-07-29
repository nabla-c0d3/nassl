import unittest
import socket

from nassl import _nassl
from build_tasks import CURRENT_PLATFORM, SupportedPlatformEnum
from nassl.legacy_ssl_client import LegacySslClient
from nassl.ssl_client import ClientCertificateRequested, OpenSslVersionEnum, OpenSslVerifyEnum, SslClient, \
    OpenSSLError, OpenSslEarlyDataStatusEnum
from tests.openssl_server import OpenSslServer, ClientAuthConfigEnum, OpenSslServerVersion


class CommonSslClientOnlineClientAuthenticationTests(unittest.TestCase):

    # To be defined in subclasses
    _SSL_CLIENT_CLS = None

    @classmethod
    def setUpClass(cls):
        if cls is CommonSslClientOnlineClientAuthenticationTests:
            raise unittest.SkipTest("Skip tests, it's a base class")
        super(CommonSslClientOnlineClientAuthenticationTests, cls).setUpClass()

    # TODO(AD): Do not skip this test
    @unittest.skipIf(
        CURRENT_PLATFORM not in [SupportedPlatformEnum.WINDOWS_64, SupportedPlatformEnum.WINDOWS_32],
        'Fails with OpenSSL 1.1.1 pre5 on Linux'
    )
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
            self.assertRaisesRegex(
                ClientCertificateRequested,
                'Server requested a client certificate',
                ssl_client.do_handshake
            )

    @unittest.skipIf(
        CURRENT_PLATFORM not in [SupportedPlatformEnum.WINDOWS_64, SupportedPlatformEnum.WINDOWS_32],
        'Fails with OpenSSL 1.1.1 pre5 on Linux'
    )
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
                
    @unittest.skipIf(
        CURRENT_PLATFORM not in [SupportedPlatformEnum.WINDOWS_64, SupportedPlatformEnum.WINDOWS_32],
        'Fails with OpenSSL 1.1.1 pre5 on Linux'
    )
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


class ModernSslClientOnlineTls13Tests(unittest.TestCase):

    def test_tls_1_3(self):
        # Given a server that supports TLS 1.3
        with OpenSslServer(server_version=OpenSslServerVersion.MODERN) as server:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((server.hostname, server.port))

            ssl_client = SslClient(
                ssl_version=OpenSslVersionEnum.TLSV1_3,
                underlying_socket=sock,
                ssl_verify=OpenSslVerifyEnum.NONE
            )
            # When doing the TLS 1.3 handshake, it succeeds
            try:
                ssl_client.do_handshake()
                self.assertTrue(ssl_client)
            finally:
                ssl_client.shutdown()

    @staticmethod
    def _create_tls_1_3_session(server_host: str, server_port: int) -> _nassl.SSL_SESSION:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((server_host, server_port))

        ssl_client = SslClient(
            ssl_version=OpenSslVersionEnum.TLSV1_3,
            underlying_socket=sock,
            ssl_verify=OpenSslVerifyEnum.NONE
        )

        try:
            ssl_client.do_handshake()
            ssl_client.write(OpenSslServer.HELLO_MSG)
            ssl_client.read(2048)
            session = ssl_client.get_session()

        finally:
            ssl_client.shutdown()
        return session

    def test_tls_1_3_write_early_data_does_not_finish_handshake(self):
        # Given a server that supports TLS 1.3
        with OpenSslServer(server_version=OpenSslServerVersion.MODERN) as server:
            # That has a previous TLS 1.3 session with the server
            session = self._create_tls_1_3_session(server.hostname, server.port)
            self.assertTrue(session)

            # And the server accepts early data
            max_early = session.get_max_early_data()
            self.assertGreater(max_early, 0)

            # When creating a new connection
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock_early_data:
                sock_early_data.settimeout(5)
                sock_early_data.connect((server.hostname, server.port))

                ssl_client_early_data = SslClient(
                    ssl_version=OpenSslVersionEnum.TLSV1_3,
                    underlying_socket=sock_early_data,
                    ssl_verify=OpenSslVerifyEnum.NONE
                )

                # That re-uses the previous TLS 1.3 session
                ssl_client_early_data.set_session(session)
                self.assertEqual(OpenSslEarlyDataStatusEnum.NOT_SENT, ssl_client_early_data.get_early_data_status())

                # When sending early data
                ssl_client_early_data.write_early_data(b'EARLY DATA')

                # It succeeds
                self.assertFalse(ssl_client_early_data.is_handshake_completed())
                self.assertEqual(OpenSslEarlyDataStatusEnum.REJECTED, ssl_client_early_data.get_early_data_status())

                # And after completing the handshake, the early data was accepted
                ssl_client_early_data.do_handshake()
                self.assertEqual(OpenSslEarlyDataStatusEnum.ACCEPTED, ssl_client_early_data.get_early_data_status())

    def test_tls_1_3_write_early_data_fail_when_used_on_non_reused_session(self):
        # Given a server that supports TLS 1.3
        with OpenSslServer(server_version=OpenSslServerVersion.MODERN) as server:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5)
                sock.connect((server.hostname, server.port))

                # That does NOT have a previous session with the server
                ssl_client = SslClient(
                    ssl_version=OpenSslVersionEnum.TLSV1_3,
                    underlying_socket=sock,
                    ssl_verify=OpenSslVerifyEnum.NONE
                )

                # When sending early data
                # It fails
                self.assertRaisesRegex(
                    OpenSSLError,
                    'function you should not call',
                    ssl_client.write_early_data,
                    b'EARLY DATA'
                )

    def test_tls_1_3_write_early_data_fail_when_trying_to_send_more_than_max_early_data(self):
        # Given a server that supports TLS 1.3
        with OpenSslServer(server_version=OpenSslServerVersion.MODERN, max_early_data=1) as server:
            # That has a previous TLS 1.3 session with the server
            session = self._create_tls_1_3_session(server.hostname, server.port)
            self.assertTrue(session)

            # And the server only accepts 1 byte of early data
            max_early = session.get_max_early_data()
            self.assertEqual(1, max_early)

            # When creating a new connection
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock_early_data:
                sock_early_data.settimeout(5)
                sock_early_data.connect((server.hostname, server.port))

                ssl_client_early_data = SslClient(
                    ssl_version=OpenSslVersionEnum.TLSV1_3,
                    underlying_socket=sock_early_data,
                    ssl_verify=OpenSslVerifyEnum.NONE
                )

                # That re-uses the previous TLS 1.3 session
                ssl_client_early_data.set_session(session)
                self.assertEqual(OpenSslEarlyDataStatusEnum.NOT_SENT, ssl_client_early_data.get_early_data_status())

                # When sending too much early data
                # It fails
                self.assertRaisesRegex(
                    OpenSSLError,
                    'too much early data',
                    ssl_client_early_data.write_early_data,
                    'GET / HTTP/1.1\r\nData: {}\r\n\r\n'.format('*' * max_early)
                )


def main():
    unittest.main()

if __name__ == '__main__':
    main()
