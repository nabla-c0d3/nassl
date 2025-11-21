import pytest

from nassl import _nassl
from nassl.ssl_client import OpenSslVersionEnum, OpenSslVerifyEnum, SslClient

try:
    from nassl import _nassl_legacy
except ImportError:
    _nassl_legacy = None

from tests.test_helpers import NASSL_MODULES


@pytest.mark.parametrize("nassl_module", NASSL_MODULES)
class TestCommonSSL:
    def test_new(self, nassl_module):
        nassl_module.SSL(nassl_module.SSL_CTX(OpenSslVersionEnum.SSLV23.value))

    def test_new_bad(self, nassl_module):
        # Invalid None SSL_CTX
        with pytest.raises(TypeError):
            nassl_module.SSL(None)

    def test_set_verify(self, nassl_module):
        test_ssl = nassl_module.SSL(nassl_module.SSL_CTX(OpenSslVersionEnum.SSLV23.value))
        test_ssl.set_verify(OpenSslVerifyEnum.PEER.value)

    def test_set_verify_bad(self, nassl_module):
        # Invalid verify constant
        test_ssl = nassl_module.SSL(nassl_module.SSL_CTX(OpenSslVersionEnum.SSLV23.value))
        with pytest.raises(ValueError):
            test_ssl.set_verify(1235)

    def test_set_bio(self, nassl_module):
        test_ssl = nassl_module.SSL(nassl_module.SSL_CTX(OpenSslVersionEnum.SSLV23.value))
        test_bio = nassl_module.BIO()
        test_ssl.set_bio(test_bio)

    def test_set_bio_bad(self, nassl_module):
        # Invalid None BIO
        test_ssl = nassl_module.SSL(nassl_module.SSL_CTX(OpenSslVersionEnum.SSLV23.value))
        with pytest.raises(TypeError):
            test_ssl.set_bio(None)

    def test_set_connect_state(self, nassl_module):
        test_ssl = nassl_module.SSL(nassl_module.SSL_CTX(OpenSslVersionEnum.SSLV23.value))
        test_ssl.set_connect_state()

    # Can't really unittest a full handshake, read or write
    def test_do_handshake_bad(self, nassl_module):
        # Connection type not set
        # OpenSSL 1.1.1: error:140940F5:SSL routines:ssl3_read_bytes:unexpected message
        # OpenSSL 3.x: error:0A000178:SSL routines::unexpected message
        test_ssl = nassl_module.SSL(nassl_module.SSL_CTX(OpenSslVersionEnum.SSLV23.value))
        with pytest.raises(_nassl.OpenSSLError, match="(connection type not set|unexpected message)"):
            test_ssl.do_handshake()

    def test_pending(self, nassl_module):
        # No BIO attached to the SSL object
        test_ssl = nassl_module.SSL(nassl_module.SSL_CTX(OpenSslVersionEnum.SSLV23.value))
        assert 0 == test_ssl.pending()

    def test_get_secure_renegotiation_support(self, nassl_module):
        test_ssl = nassl_module.SSL(nassl_module.SSL_CTX(OpenSslVersionEnum.SSLV23.value))
        test_ssl.get_secure_renegotiation_support()

    def test_get_current_compression_method(self, nassl_module):
        test_ssl = nassl_module.SSL(nassl_module.SSL_CTX(OpenSslVersionEnum.SSLV23.value))
        test_ssl.get_current_compression_method()

    def test_get_available_compression_methods_has_zlib(self, nassl_module):
        # OpenSSL 3.x removed zlib compression support by default
        test_ssl = nassl_module.SSL(nassl_module.SSL_CTX(OpenSslVersionEnum.SSLV23.value))
        methods = test_ssl.get_available_compression_methods()
        # OpenSSL 1.1.1 has zlib, OpenSSL 3.x returns empty list
        assert methods in (["zlib compression"], [])

    def test_set_tlsext_host_name(self, nassl_module):
        test_ssl = nassl_module.SSL(nassl_module.SSL_CTX(OpenSslVersionEnum.SSLV23.value))
        test_ssl.set_tlsext_host_name("tests")

    def test_set_tlsext_host_name_bad(self, nassl_module):
        test_ssl = nassl_module.SSL(nassl_module.SSL_CTX(OpenSslVersionEnum.SSLV23.value))
        with pytest.raises(TypeError):
            test_ssl.set_tlsext_host_name(None)

    def test_set_cipher_list(self, nassl_module):
        test_ssl = nassl_module.SSL(nassl_module.SSL_CTX(OpenSslVersionEnum.SSLV23.value))
        test_ssl.set_cipher_list("HIGH")

    def test_shutdown_bad(self, nassl_module):
        # OpenSSL 1.1.1: error:...:uninitialized
        # OpenSSL 3.x: error:0A000126:SSL routines::unexpected eof while reading
        test_ssl = nassl_module.SSL(nassl_module.SSL_CTX(OpenSslVersionEnum.SSLV23.value))
        with pytest.raises(_nassl.OpenSSLError, match="(uninitialized|unexpected eof)"):
            test_ssl.shutdown()

    def test_get_cipher_list(self, nassl_module):
        test_ssl = nassl_module.SSL(nassl_module.SSL_CTX(OpenSslVersionEnum.SSLV23.value))
        assert test_ssl.get_cipher_list()

    def test_get_cipher_name(self, nassl_module):
        test_ssl = nassl_module.SSL(nassl_module.SSL_CTX(OpenSslVersionEnum.SSLV23.value))
        test_ssl.get_cipher_name()

    def test_get_cipher_bits(self, nassl_module):
        test_ssl = nassl_module.SSL(nassl_module.SSL_CTX(OpenSslVersionEnum.SSLV23.value))
        assert 0 == test_ssl.get_cipher_bits()

    def test_get_client_CA_list_bad(self, nassl_module):
        test_ssl = nassl_module.SSL(nassl_module.SSL_CTX(OpenSslVersionEnum.SSLV23.value))
        assert [] == test_ssl.get_client_CA_list()

    def test_get_verify_result(self, nassl_module):
        test_ssl = nassl_module.SSL(nassl_module.SSL_CTX(OpenSslVersionEnum.SSLV23.value))
        assert 0 == test_ssl.get_verify_result()

    def test_renegotiate(self, nassl_module):
        test_ssl = nassl_module.SSL(nassl_module.SSL_CTX(OpenSslVersionEnum.SSLV23.value))
        test_ssl.renegotiate()

    def test_get_session(self, nassl_module):
        test_ssl = nassl_module.SSL(nassl_module.SSL_CTX(OpenSslVersionEnum.SSLV23.value))
        test_ssl.get_session()

    def test_set_session_bad(self, nassl_module):
        test_ssl = nassl_module.SSL(nassl_module.SSL_CTX(OpenSslVersionEnum.SSLV23.value))
        with pytest.raises(TypeError):
            test_ssl.set_session(None)

    def test_set_options_bad(self, nassl_module):
        test_ssl = nassl_module.SSL(nassl_module.SSL_CTX(OpenSslVersionEnum.SSLV23.value))
        assert 0 <= test_ssl.set_options(123)

    def test_set_tlsext_status_type(self, nassl_module):
        test_ssl = nassl_module.SSL(nassl_module.SSL_CTX(OpenSslVersionEnum.SSLV23.value))
        test_ssl.set_tlsext_status_type(SslClient._TLSEXT_STATUSTYPE_ocsp)

    def test_get_tlsext_status_type(self, nassl_module):
        test_ssl = nassl_module.SSL(nassl_module.SSL_CTX(OpenSslVersionEnum.SSLV23.value))
        assert None is test_ssl.get_tlsext_status_ocsp_resp()


class TestModernSSL:
    def test_set_ciphersuites_bad_string(self):
        # Invalid cipher string
        # OpenSSL 1.1.1: error:...:no cipher match
        # OpenSSL 3.x: error:0A0BA080:SSL routines::no ciphers available
        test_ssl = _nassl.SSL(_nassl.SSL_CTX(OpenSslVersionEnum.TLSV1_2.value))
        with pytest.raises(_nassl.OpenSSLError, match="(no cipher match|no ciphers available)"):
            test_ssl.set_ciphersuites("lol")


@pytest.mark.skipif(_nassl_legacy is None, reason="Legacy OpenSSL not available")
class TestLegacySSL:
    # The following tests don't pass with modern OpenSSL - the API might have changed
    def test_set_cipher_list_bad(self):
        # Invalid cipher string
        test_ssl = _nassl_legacy.SSL(_nassl_legacy.SSL_CTX(OpenSslVersionEnum.SSLV23.value))
        with pytest.raises(_nassl.OpenSSLError):
            test_ssl.set_cipher_list("badcipherstring")

    def test_do_handshake_bad_eof(self):
        # No BIO attached to the SSL object
        test_ssl = _nassl_legacy.SSL(_nassl_legacy.SSL_CTX(OpenSslVersionEnum.SSLV23.value))
        test_ssl.set_connect_state()
        with pytest.raises(_nassl.SslError, match="An EOF was observed that violates the protocol"):
            test_ssl.do_handshake()

    def test_read_bad(self):
        # No BIO attached to the SSL object
        test_ssl = _nassl_legacy.SSL(_nassl_legacy.SSL_CTX(OpenSslVersionEnum.SSLV23.value))
        test_ssl.set_connect_state()
        with pytest.raises(_nassl.OpenSSLError, match="ssl handshake failure"):
            test_ssl.read(128)

    def test_write_bad(self):
        # No BIO attached to the SSL object
        test_ssl = _nassl_legacy.SSL(_nassl_legacy.SSL_CTX(OpenSslVersionEnum.SSLV23.value))
        test_ssl.set_connect_state()
        with pytest.raises(_nassl.OpenSSLError, match="ssl handshake failure"):
            test_ssl.write("tests")
