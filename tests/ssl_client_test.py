import socket
from pathlib import Path

import pytest

from nassl import _nassl
from nassl.legacy_ssl_client import LegacySslClient
from nassl.ssl_client import (
    ClientCertificateRequested,
    OpenSslVersionEnum,
    OpenSslVerifyEnum,
    SslClient,
    OpenSSLError,
    OpenSslEarlyDataStatusEnum,
)
from nassl.key_exchange_info import (
    OpenSslEvpPkeyEnum,
    OpenSslEcNidEnum,
    DhKeyExchangeInfo,
    NistEcDhKeyExchangeInfo,
    EcDhKeyExchangeInfo,
)
from nassl.cert_chain_verifier import CertificateChainVerificationFailed
from tests.openssl_server import ModernOpenSslServer, ClientAuthConfigEnum, LegacyOpenSslServer


# TODO(AD): Switch to legacy server and add a TODO; skip tests for TLS 1.3
@pytest.mark.parametrize("ssl_client_cls", [SslClient, LegacySslClient])
class TestSslClientClientAuthentication:
    def test_client_authentication_no_certificate_supplied(self, ssl_client_cls):
        # Given a server that requires client authentication
        with LegacyOpenSslServer(client_auth_config=ClientAuthConfigEnum.REQUIRED) as server:
            # And the client does NOT provide a client certificate
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((server.hostname, server.port))

            ssl_client = ssl_client_cls(
                ssl_version=OpenSslVersionEnum.TLSV1_2, underlying_socket=sock, ssl_verify=OpenSslVerifyEnum.NONE
            )
            # When doing the handshake the right error is returned
            with pytest.raises(ClientCertificateRequested):
                ssl_client.do_handshake()

            ssl_client.shutdown()

    def test_client_authentication_no_certificate_supplied_but_ignore(self, ssl_client_cls):
        # Given a server that accepts optional client authentication
        with LegacyOpenSslServer(client_auth_config=ClientAuthConfigEnum.OPTIONAL) as server:
            # And the client does NOT provide a client cert but is configured to ignore the client auth request
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((server.hostname, server.port))

            ssl_client = ssl_client_cls(
                ssl_version=OpenSslVersionEnum.TLSV1_2,
                underlying_socket=sock,
                ssl_verify=OpenSslVerifyEnum.NONE,
                ignore_client_authentication_requests=True,
            )
            # When doing the handshake, it succeeds
            try:
                ssl_client.do_handshake()
            finally:
                ssl_client.shutdown()

    def test_client_authentication_succeeds(self, ssl_client_cls):
        # Given a server that requires client authentication
        with LegacyOpenSslServer(client_auth_config=ClientAuthConfigEnum.REQUIRED) as server:
            # And the client provides a client certificate
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((server.hostname, server.port))

            ssl_client = ssl_client_cls(
                ssl_version=OpenSslVersionEnum.TLSV1_2,
                underlying_socket=sock,
                ssl_verify=OpenSslVerifyEnum.NONE,
                client_certificate_chain=server.get_client_certificate_path(),
                client_key=server.get_client_key_path(),
            )

            # When doing the handshake, it succeeds
            try:
                ssl_client.do_handshake()
            finally:
                ssl_client.shutdown()


@pytest.mark.parametrize("ssl_client_cls", [SslClient, LegacySslClient])
class TestSslClientOnline:
    def test(self, ssl_client_cls):
        # Given an SslClient connecting to Google
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(("www.google.com", 443))

        ssl_client = ssl_client_cls(
            ssl_version=OpenSslVersionEnum.SSLV23, underlying_socket=sock, ssl_verify=OpenSslVerifyEnum.NONE
        )

        # When doing a TLS handshake, it succeeds
        try:
            ssl_client.do_handshake()

            # When sending a GET request
            ssl_client.write(b"GET / HTTP/1.0\r\n\r\n")

            # It gets a response
            assert b"google" in ssl_client.read(1024)

            # And when requesting the server certificate, it returns it
            assert ssl_client.get_received_chain()
        finally:
            ssl_client.shutdown()

    def test_get_dh_info_ecdh(self, ssl_client_cls):
        with LegacyOpenSslServer(cipher="ECDHE-RSA-AES256-SHA") as server:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((server.hostname, server.port))

            ssl_client = ssl_client_cls(
                ssl_version=OpenSslVersionEnum.TLSV1_2, underlying_socket=sock, ssl_verify=OpenSslVerifyEnum.NONE
            )

            try:
                ssl_client.do_handshake()
            finally:
                ssl_client.shutdown()

            dh_info = ssl_client.get_dh_info()

            assert isinstance(dh_info, NistEcDhKeyExchangeInfo)
            assert dh_info.key_type == OpenSslEvpPkeyEnum.EC
            assert dh_info.key_size > 0
            assert len(dh_info.public_key) > 0
            assert len(dh_info.x) > 0
            assert len(dh_info.y) > 0

    def test_get_dh_info_dh(self, ssl_client_cls):
        with LegacyOpenSslServer(cipher="DHE-RSA-AES256-SHA") as server:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((server.hostname, server.port))

            ssl_client = ssl_client_cls(
                ssl_version=OpenSslVersionEnum.TLSV1_2, underlying_socket=sock, ssl_verify=OpenSslVerifyEnum.NONE
            )

            try:
                ssl_client.do_handshake()
            finally:
                ssl_client.shutdown()

            dh_info = ssl_client.get_dh_info()

            assert isinstance(dh_info, DhKeyExchangeInfo)
            assert dh_info.key_type == OpenSslEvpPkeyEnum.DH
            assert dh_info.key_size > 0
            assert len(dh_info.public_key) > 0
            assert len(dh_info.prime) > 0
            assert len(dh_info.generator) > 0

    def test_get_dh_info_no_dh(self, ssl_client_cls):
        with LegacyOpenSslServer(cipher="AES256-SHA") as server:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((server.hostname, server.port))

            ssl_client = ssl_client_cls(
                ssl_version=OpenSslVersionEnum.TLSV1_2, underlying_socket=sock, ssl_verify=OpenSslVerifyEnum.NONE
            )

            try:
                ssl_client.do_handshake()
            finally:
                ssl_client.shutdown()

            dh_info = ssl_client.get_dh_info()

            assert dh_info is None


class TestModernSslClientOnline:
    def test_get_verified_chain(self):
        # Given an SslClient connecting to Google
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(("www.yahoo.com", 443))
        print(str(Path(__file__).absolute().parent / "google_roots.pem"))
        ssl_client = SslClient(
            ssl_version=OpenSslVersionEnum.TLSV1_2,
            underlying_socket=sock,
            # That is configured to properly validate certificates
            ssl_verify=OpenSslVerifyEnum.PEER,
            ssl_verify_locations=Path(__file__).absolute().parent / "mozilla.pem",
        )

        # When doing a TLS handshake, it succeeds
        try:
            ssl_client.do_handshake()

            # And when requesting the verified certificate chain, it returns it
            assert ssl_client.get_verified_chain()
        finally:
            ssl_client.shutdown()

    def test_get_verified_chain_but_validation_failed(self):
        # Given an SslClient connecting to Google
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(("www.google.com", 443))

        ssl_client = SslClient(
            ssl_version=OpenSslVersionEnum.TLSV1_2,
            underlying_socket=sock,
            # That is configured to silently fail validation
            ssl_verify=OpenSslVerifyEnum.NONE,
        )

        # When doing a TLS handshake, it succeeds
        try:
            ssl_client.do_handshake()

            # And when requesting the verified certificate chain
            with pytest.raises(CertificateChainVerificationFailed):
                # It fails because certificate validation failed
                ssl_client.get_verified_chain()
        finally:
            ssl_client.shutdown()

    def test_get_dh_info_ecdh_p256(self):
        with ModernOpenSslServer(cipher="ECDHE-RSA-AES256-SHA", groups="P-256") as server:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((server.hostname, server.port))

            ssl_client = SslClient(
                ssl_version=OpenSslVersionEnum.TLSV1_2, underlying_socket=sock, ssl_verify=OpenSslVerifyEnum.NONE
            )

            try:
                ssl_client.do_handshake()
            finally:
                ssl_client.shutdown()

            dh_info = ssl_client.get_dh_info()

            assert isinstance(dh_info, NistEcDhKeyExchangeInfo)
            assert dh_info.key_type == OpenSslEvpPkeyEnum.EC
            assert dh_info.key_size == 256
            assert dh_info.curve == OpenSslEcNidEnum.PRIME256V1
            assert len(dh_info.public_key) == 65
            assert len(dh_info.x) == 32
            assert len(dh_info.y) == 32

    def test_get_dh_info_ecdh_x25519(self):
        with ModernOpenSslServer(cipher="ECDHE-RSA-AES256-SHA", groups="X25519") as server:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((server.hostname, server.port))

            ssl_client = SslClient(
                ssl_version=OpenSslVersionEnum.TLSV1_2, underlying_socket=sock, ssl_verify=OpenSslVerifyEnum.NONE
            )

            try:
                ssl_client.do_handshake()
            finally:
                ssl_client.shutdown()

            dh_info = ssl_client.get_dh_info()

            assert isinstance(dh_info, EcDhKeyExchangeInfo)
            assert dh_info.key_type == OpenSslEvpPkeyEnum.X25519
            assert dh_info.key_size == 253
            assert dh_info.curve == OpenSslEcNidEnum.X25519
            assert len(dh_info.public_key) == 32

    def test_get_dh_info_ecdh_x448(self):
        with ModernOpenSslServer(cipher="ECDHE-RSA-AES256-SHA", groups="X448") as server:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((server.hostname, server.port))

            ssl_client = SslClient(
                ssl_version=OpenSslVersionEnum.TLSV1_2, underlying_socket=sock, ssl_verify=OpenSslVerifyEnum.NONE
            )

            try:
                ssl_client.do_handshake()
            finally:
                ssl_client.shutdown()

            dh_info = ssl_client.get_dh_info()

            assert isinstance(dh_info, EcDhKeyExchangeInfo)
            assert dh_info.key_type == OpenSslEvpPkeyEnum.X448
            assert dh_info.key_size == 448
            assert dh_info.curve == OpenSslEcNidEnum.X448
            assert len(dh_info.public_key) == 56
            
    def test_set1_groups_list_curve_secp192k1(self):
        with ModernOpenSslServer(cipher="ECDHE-RSA-AES256-SHA", groups="X25519:prime256v1:secp384r1:secp192k1") as server:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((server.hostname, server.port))

            ssl_client = SslClient(
                ssl_version=OpenSslVersionEnum.TLSV1_2, underlying_socket=sock, ssl_verify=OpenSslVerifyEnum.NONE
            )

            ssl_client.set1_groups_list("secp192k1")

            try:
                ssl_client.do_handshake()
            finally:
                ssl_client.shutdown()

            dh_info = ssl_client.get_dh_info()

            assert isinstance(dh_info, NistEcDhKeyExchangeInfo)
            assert dh_info.key_type == OpenSslEvpPkeyEnum.EC
            assert dh_info.curve == OpenSslEcNidEnum.SECP192K1

    def test_set1_groups_list_curve_x448(self):
        with ModernOpenSslServer(cipher="ECDHE-RSA-AES256-SHA", groups="X25519:prime256v1:X448:secp384r1:secp192k1") as server:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((server.hostname, server.port))

            ssl_client = SslClient(
                ssl_version=OpenSslVersionEnum.TLSV1_2, underlying_socket=sock, ssl_verify=OpenSslVerifyEnum.NONE
            )

            ssl_client.set1_groups_list("X448")

            try:
                ssl_client.do_handshake()
            finally:
                ssl_client.shutdown()

            dh_info = ssl_client.get_dh_info()

            assert isinstance(dh_info, EcDhKeyExchangeInfo)
            assert dh_info.key_type == OpenSslEvpPkeyEnum.X448
            assert dh_info.curve == OpenSslEcNidEnum.X448


class TestLegacySslClientOnline:
    def test_ssl_2(self):
        # Given a server that supports SSL 2.0
        with LegacyOpenSslServer() as server:
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
            finally:
                ssl_client.shutdown()


class TestModernSslClientOnlineTls13:
    def test_set_ciphersuites(self):
        # Given an SslClient for TLS 1.3
        ssl_client = SslClient(
            ssl_version=OpenSslVersionEnum.TLSV1_3,
            ssl_verify=OpenSslVerifyEnum.NONE,
            ignore_client_authentication_requests=True,
        )

        # With the default list of cipher disabled
        ssl_client.set_cipher_list("")

        # When setting a specific TLS 1.3 cipher suite as the list of supported ciphers
        ssl_client.set_ciphersuites("TLS_CHACHA20_POLY1305_SHA256")

        # That one cipher suite is the only one enabled
        ciphers = ssl_client.get_cipher_list()
        assert ["TLS_CHACHA20_POLY1305_SHA256"] == ciphers

    def test_tls_1_3(self):
        # Given a server that supports TLS 1.3
        with ModernOpenSslServer() as server:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((server.hostname, server.port))

            ssl_client = SslClient(
                ssl_version=OpenSslVersionEnum.TLSV1_3, underlying_socket=sock, ssl_verify=OpenSslVerifyEnum.NONE
            )
            # When doing the TLS 1.3 handshake, it succeeds
            try:
                ssl_client.do_handshake()
            finally:
                ssl_client.shutdown()

    @staticmethod
    def _create_tls_1_3_session(server_host: str, server_port: int) -> _nassl.SSL_SESSION:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((server_host, server_port))

        ssl_client = SslClient(
            ssl_version=OpenSslVersionEnum.TLSV1_3, underlying_socket=sock, ssl_verify=OpenSslVerifyEnum.NONE
        )

        try:
            ssl_client.do_handshake()
            ssl_client.write(ModernOpenSslServer.HELLO_MSG)
            ssl_client.read(2048)
            session = ssl_client.get_session()

        finally:
            ssl_client.shutdown()
        return session

    def test_tls_1_3_write_early_data_does_not_finish_handshake(self):
        # Given a server that supports TLS 1.3 and early data
        with ModernOpenSslServer(max_early_data=512) as server:
            # That has a previous TLS 1.3 session with the server
            session = self._create_tls_1_3_session(server.hostname, server.port)
            assert session

            # And the server accepts early data
            max_early = session.get_max_early_data()
            assert max_early > 0

            # When creating a new connection
            sock_early_data = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_early_data.settimeout(5)
            sock_early_data.connect((server.hostname, server.port))

            ssl_client_early_data = SslClient(
                ssl_version=OpenSslVersionEnum.TLSV1_3,
                underlying_socket=sock_early_data,
                ssl_verify=OpenSslVerifyEnum.NONE,
            )

            # That re-uses the previous TLS 1.3 session
            ssl_client_early_data.set_session(session)
            assert OpenSslEarlyDataStatusEnum.NOT_SENT == ssl_client_early_data.get_early_data_status()

            # When sending early data
            ssl_client_early_data.write_early_data(b"EARLY DATA")

            # It succeeds
            assert not ssl_client_early_data.is_handshake_completed()
            assert OpenSslEarlyDataStatusEnum.REJECTED == ssl_client_early_data.get_early_data_status()

            # And after completing the handshake, the early data was accepted
            ssl_client_early_data.do_handshake()
            assert OpenSslEarlyDataStatusEnum.ACCEPTED == ssl_client_early_data.get_early_data_status()

            ssl_client_early_data.shutdown()

    def test_tls_1_3_write_early_data_fail_when_used_on_non_reused_session(self):
        # Given a server that supports TLS 1.3 and early data
        with ModernOpenSslServer(max_early_data=512) as server:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((server.hostname, server.port))

            # That does NOT have a previous session with the server
            ssl_client = SslClient(
                ssl_version=OpenSslVersionEnum.TLSV1_3, underlying_socket=sock, ssl_verify=OpenSslVerifyEnum.NONE
            )

            # When sending early data
            # It fails
            with pytest.raises(OpenSSLError, match="you should not call"):
                ssl_client.write_early_data(b"EARLY DATA")

            ssl_client.shutdown()

    def test_tls_1_3_write_early_data_fail_when_trying_to_send_more_than_max_early_data(self):
        # Given a server that supports TLS 1.3 and early data
        with ModernOpenSslServer(max_early_data=1) as server:
            # That has a previous TLS 1.3 session with the server
            session = self._create_tls_1_3_session(server.hostname, server.port)
            assert session

            # And the server only accepts 1 byte of early data
            max_early = session.get_max_early_data()
            assert 1 == max_early

            # When creating a new connection
            sock_early_data = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_early_data.settimeout(5)
            sock_early_data.connect((server.hostname, server.port))

            ssl_client_early_data = SslClient(
                ssl_version=OpenSslVersionEnum.TLSV1_3,
                underlying_socket=sock_early_data,
                ssl_verify=OpenSslVerifyEnum.NONE,
            )

            # That re-uses the previous TLS 1.3 session
            ssl_client_early_data.set_session(session)
            assert OpenSslEarlyDataStatusEnum.NOT_SENT == ssl_client_early_data.get_early_data_status()

            # When sending too much early data
            # It fails
            with pytest.raises(OpenSSLError, match="too much early data"):
                ssl_client_early_data.write_early_data(
                    "GET / HTTP/1.1\r\nData: {}\r\n\r\n".format("*" * max_early).encode("ascii")
                )

            ssl_client_early_data.shutdown()

    def test_client_authentication_tls_1_3(self):
        # Given a server that requires client authentication
        with ModernOpenSslServer(client_auth_config=ClientAuthConfigEnum.REQUIRED) as server:
            # And the client provides an invalid client certificate (actually the server cert)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((server.hostname, server.port))

            ssl_client = SslClient(
                ssl_version=OpenSslVersionEnum.TLSV1_3, underlying_socket=sock, ssl_verify=OpenSslVerifyEnum.NONE
            )

            # When doing the handshake the right error is returned
            with pytest.raises(ClientCertificateRequested):
                ssl_client.do_handshake()
