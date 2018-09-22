import pytest

from nassl import _nassl_legacy
from nassl import _nassl
import socket

from nassl.legacy_ssl_client import LegacySslClient
from nassl.ssl_client import SslClient, OpenSslVerifyEnum


@pytest.mark.parametrize("nassl_module", [_nassl, _nassl_legacy])
class TestX509_NAME_ENTRY:

    def test_new_bad(self, nassl_module):
        with pytest.raises(NotImplementedError):
            nassl_module.X509_NAME_ENTRY(None)


@pytest.mark.parametrize("ssl_client_cls", [SslClient, LegacySslClient])
class TestOnlineX509_NAME_ENTRY_Tests_Online:

    def test(self, ssl_client_cls):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(('www.google.com', 443))

        ssl_client = ssl_client_cls(underlying_socket=sock, ssl_verify=OpenSslVerifyEnum.NONE)
        ssl_client.do_handshake()
        name_entry = ssl_client.get_peer_certificate().get_subject_name_entries()[0]
        ssl_client.shutdown()

        assert name_entry.get_data()
        assert name_entry.get_object()
