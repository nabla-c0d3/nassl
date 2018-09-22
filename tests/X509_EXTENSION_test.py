import pytest

from nassl import _nassl_legacy
from nassl import _nassl
from nassl.legacy_ssl_client import LegacySslClient
from nassl.ssl_client import SslClient, OpenSslVerifyEnum
import socket


@pytest.mark.parametrize("nassl_module", [_nassl, _nassl_legacy])
class TestX509_EXTENSION:

    def test_new_bad(self, nassl_module):
        with pytest.raises(NotImplementedError):
            nassl_module.X509_EXTENSION(None)


@pytest.mark.parametrize("ssl_client_cls", [SslClient, LegacySslClient])
class TestOnlineX509_EXTENSION:

    def test(self, ssl_client_cls):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(('www.google.com', 443))

        sslClient = ssl_client_cls(underlying_socket=sock, ssl_verify=OpenSslVerifyEnum.NONE)
        sslClient.do_handshake()
        x509ext = sslClient.get_peer_certificate().get_extensions()[0]
        sslClient.shutdown()

        assert x509ext.get_data()
        assert x509ext.get_object()
        assert None is not x509ext.get_critical()
