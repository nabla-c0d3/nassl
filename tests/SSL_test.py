from types import ModuleType
import pytest

from nassl.errors import OpenSSLError
from nassl.base_ssl_client import BaseSslClient, OpenSslVersionEnum, OpenSslVerifyEnum


import nassl.openssl_1_0_2._nassl
import nassl.openssl_1_1_1._nassl
import nassl.openssl_4_0_0._nassl


@pytest.mark.parametrize(
    "nassl_module, SSL_CTX_args",
    [
        # Not the same arguments with OpenSSL 1.0.2 VS 1.1.1 and 4.0.0
        (nassl.openssl_1_0_2._nassl, [OpenSslVersionEnum.TLSV1_2.value]),
        (nassl.openssl_1_1_1._nassl, []),
        (nassl.openssl_4_0_0._nassl, []),
    ],
)
class TestCommonSSL:
    def test_new(self, nassl_module: ModuleType, SSL_CTX_args: list[OpenSslVersionEnum]) -> None:
        nassl_module.SSL(nassl_module.SSL_CTX(*SSL_CTX_args))

    def test_new_bad(self, nassl_module: ModuleType, SSL_CTX_args: list[OpenSslVersionEnum]) -> None:
        # Invalid None SSL_CTX
        with pytest.raises(TypeError):
            nassl_module.SSL(None)

    def test_set_verify(self, nassl_module: ModuleType, SSL_CTX_args: list[OpenSslVersionEnum]) -> None:
        test_ssl = nassl_module.SSL(nassl_module.SSL_CTX(*SSL_CTX_args))
        test_ssl.set_verify(OpenSslVerifyEnum.PEER.value)

    def test_set_verify_bad(self, nassl_module: ModuleType, SSL_CTX_args: list[OpenSslVersionEnum]) -> None:
        # Invalid verify constant
        test_ssl = nassl_module.SSL(nassl_module.SSL_CTX(*SSL_CTX_args))
        with pytest.raises(ValueError):
            test_ssl.set_verify(1235)

    def test_set_bio(self, nassl_module: ModuleType, SSL_CTX_args: list[OpenSslVersionEnum]) -> None:
        test_ssl = nassl_module.SSL(nassl_module.SSL_CTX(*SSL_CTX_args))
        test_bio = nassl_module.BIO()
        test_ssl.set_bio(test_bio)

    def test_set_bio_bad(self, nassl_module: ModuleType, SSL_CTX_args: list[OpenSslVersionEnum]) -> None:
        # Invalid None BIO
        test_ssl = nassl_module.SSL(nassl_module.SSL_CTX(*SSL_CTX_args))
        with pytest.raises(TypeError):
            test_ssl.set_bio(None)

    def test_set_connect_state(self, nassl_module: ModuleType, SSL_CTX_args: list[OpenSslVersionEnum]) -> None:
        test_ssl = nassl_module.SSL(nassl_module.SSL_CTX(*SSL_CTX_args))
        test_ssl.set_connect_state()

    # Can't really unittest a full handshake, read or write
    def test_do_handshake_bad(self, nassl_module: ModuleType, SSL_CTX_args: list[OpenSslVersionEnum]) -> None:
        # Connection type not set
        test_ssl = nassl_module.SSL(nassl_module.SSL_CTX(*SSL_CTX_args))
        with pytest.raises(OpenSSLError, match="connection type not set"):
            test_ssl.do_handshake()

    def test_pending(self, nassl_module: ModuleType, SSL_CTX_args: list[OpenSslVersionEnum]) -> None:
        # No BIO attached to the SSL object
        test_ssl = nassl_module.SSL(nassl_module.SSL_CTX(*SSL_CTX_args))
        assert 0 == test_ssl.pending()

    def test_get_secure_renegotiation_support(
        self, nassl_module: ModuleType, SSL_CTX_args: list[OpenSslVersionEnum]
    ) -> None:
        test_ssl = nassl_module.SSL(nassl_module.SSL_CTX(*SSL_CTX_args))
        test_ssl.get_secure_renegotiation_support()

    def test_get_current_compression_method(
        self, nassl_module: ModuleType, SSL_CTX_args: list[OpenSslVersionEnum]
    ) -> None:
        test_ssl = nassl_module.SSL(nassl_module.SSL_CTX(*SSL_CTX_args))
        test_ssl.get_current_compression_method()

    def test_get_available_compression_methods_has_zlib(
        self, nassl_module: ModuleType, SSL_CTX_args: list[OpenSslVersionEnum]
    ) -> None:
        test_ssl = nassl_module.SSL(nassl_module.SSL_CTX(*SSL_CTX_args))
        assert ["zlib compression"] == test_ssl.get_available_compression_methods()

    def test_set_tlsext_host_name(self, nassl_module: ModuleType, SSL_CTX_args: list[OpenSslVersionEnum]) -> None:
        test_ssl = nassl_module.SSL(nassl_module.SSL_CTX(*SSL_CTX_args))
        test_ssl.set_tlsext_host_name("tests")

    def test_set_tlsext_host_name_bad(self, nassl_module: ModuleType, SSL_CTX_args: list[OpenSslVersionEnum]) -> None:
        test_ssl = nassl_module.SSL(nassl_module.SSL_CTX(*SSL_CTX_args))
        with pytest.raises(TypeError):
            test_ssl.set_tlsext_host_name(None)

    def test_set_cipher_list(self, nassl_module: ModuleType, SSL_CTX_args: list[OpenSslVersionEnum]) -> None:
        test_ssl = nassl_module.SSL(nassl_module.SSL_CTX(*SSL_CTX_args))
        test_ssl.set_cipher_list("HIGH")

    def test_shutdown_bad(self, nassl_module: ModuleType, SSL_CTX_args: list[OpenSslVersionEnum]) -> None:
        test_ssl = nassl_module.SSL(nassl_module.SSL_CTX(*SSL_CTX_args))
        with pytest.raises(OpenSSLError, match="uninitialized"):
            test_ssl.shutdown()

    def test_get_cipher_list(self, nassl_module: ModuleType, SSL_CTX_args: list[OpenSslVersionEnum]) -> None:
        test_ssl = nassl_module.SSL(nassl_module.SSL_CTX(*SSL_CTX_args))
        assert test_ssl.get_cipher_list()

    def test_get_cipher_name(self, nassl_module: ModuleType, SSL_CTX_args: list[OpenSslVersionEnum]) -> None:
        test_ssl = nassl_module.SSL(nassl_module.SSL_CTX(*SSL_CTX_args))
        test_ssl.get_cipher_name()

    def test_get_cipher_bits(self, nassl_module: ModuleType, SSL_CTX_args: list[OpenSslVersionEnum]) -> None:
        test_ssl = nassl_module.SSL(nassl_module.SSL_CTX(*SSL_CTX_args))
        assert 0 == test_ssl.get_cipher_bits()

    def test_get_client_CA_list_bad(self, nassl_module: ModuleType, SSL_CTX_args: list[OpenSslVersionEnum]) -> None:
        test_ssl = nassl_module.SSL(nassl_module.SSL_CTX(*SSL_CTX_args))
        assert [] == test_ssl.get_client_CA_list()

    def test_get_verify_result(self, nassl_module: ModuleType, SSL_CTX_args: list[OpenSslVersionEnum]) -> None:
        test_ssl = nassl_module.SSL(nassl_module.SSL_CTX(*SSL_CTX_args))
        assert 0 == test_ssl.get_verify_result()

    def test_renegotiate(self, nassl_module: ModuleType, SSL_CTX_args: list[OpenSslVersionEnum]) -> None:
        test_ssl = nassl_module.SSL(nassl_module.SSL_CTX(*SSL_CTX_args))
        test_ssl.renegotiate()

    def test_get_session(self, nassl_module: ModuleType, SSL_CTX_args: list[OpenSslVersionEnum]) -> None:
        test_ssl = nassl_module.SSL(nassl_module.SSL_CTX(*SSL_CTX_args))
        test_ssl.get_session()

    def test_set_session_bad(self, nassl_module: ModuleType, SSL_CTX_args: list[OpenSslVersionEnum]) -> None:
        test_ssl = nassl_module.SSL(nassl_module.SSL_CTX(*SSL_CTX_args))
        with pytest.raises(TypeError):
            test_ssl.set_session(None)

    def test_set_options_bad(self, nassl_module: ModuleType, SSL_CTX_args: list[OpenSslVersionEnum]) -> None:
        test_ssl = nassl_module.SSL(nassl_module.SSL_CTX(*SSL_CTX_args))
        assert 0 <= test_ssl.set_options(123)

    def test_set_tlsext_status_type(self, nassl_module: ModuleType, SSL_CTX_args: list[OpenSslVersionEnum]) -> None:
        test_ssl = nassl_module.SSL(nassl_module.SSL_CTX(*SSL_CTX_args))
        test_ssl.set_tlsext_status_type(BaseSslClient._TLSEXT_STATUSTYPE_ocsp)

    def test_get_tlsext_status_type(self, nassl_module: ModuleType, SSL_CTX_args: list[OpenSslVersionEnum]) -> None:
        test_ssl = nassl_module.SSL(nassl_module.SSL_CTX(*SSL_CTX_args))
        assert None is test_ssl.get_tlsext_status_ocsp_resp()


_SSL_CTX_OpenSSL_1_1_1 = nassl.openssl_1_1_1._nassl.SSL_CTX


class TestSSL_OpenSSL_1_1_1:
    def test_set_ciphersuites_bad_string(self) -> None:
        # Invalid cipher string
        test_ssl = nassl.openssl_1_1_1._nassl.SSL(_SSL_CTX_OpenSSL_1_1_1())
        with pytest.raises(OpenSSLError, match="no cipher match"):
            test_ssl.set_ciphersuites("lol")


_SSL_CTX_OpenSSL_1_0_2 = nassl.openssl_1_0_2._nassl.SSL_CTX


class TestSSL_OpenSSL_1_0_2:
    # The following tests don't pass with OpenSSL 1.1.1 - the API might have changed
    def test_set_cipher_list_bad(self) -> None:
        # Invalid cipher string
        test_ssl = nassl.openssl_1_0_2._nassl.SSL(_SSL_CTX_OpenSSL_1_0_2(OpenSslVersionEnum.TLSV1_2.value))
        with pytest.raises(OpenSSLError):
            test_ssl.set_cipher_list("badcipherstring")

    def test_do_handshake_but_bio_not_set(self) -> None:
        # No BIO attached to the SSL object
        test_ssl = nassl.openssl_1_0_2._nassl.SSL(_SSL_CTX_OpenSSL_1_0_2(OpenSslVersionEnum.TLSV1_2.value))
        test_ssl.set_connect_state()
        with pytest.raises(OpenSSLError, match="bio not set"):
            test_ssl.do_handshake()
