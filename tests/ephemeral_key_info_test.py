import pytest

from nassl.ephemeral_key_info import (
    EcDhEphemeralKeyInfo,
    OpenSslEcNidEnum,
    OpenSslEvpPkeyEnum,
    _OPENSSL_NID_TO_SECG_ANSI_X9_62,
    _OPENSSL_EVP_PKEY_TO_NAME_MAPPING,
    DhEphemeralKeyInfo,
)
from nassl.ssl_client import SslClient


class TestOpenSslEcNidEnum:
    def test_supported_by_ssl_client(self):
        # Ensure the expected NIDs can be used to configure an SslClient
        for ec_nid in OpenSslEcNidEnum.get_supported_by_ssl_client():
            ssl_client = SslClient()
            ssl_client.set_groups([ec_nid])

    @pytest.mark.skip("TODO: Fix brainpool support; see also https://github.com/nabla-c0d3/nassl/issues/104")
    def test_brainpool_fix_me(self):
        # Brainpool NIDs will trigger an OpenSslError
        ssl_client = SslClient()
        ssl_client.set_groups([OpenSslEcNidEnum.brainpoolP160r1])


class TestEphemeralKeyInfo:
    def test_evp_pkey_to_name_mapping(self):
        # Ensure all known EVP PKEYs have an associated name
        for evp_pkey in OpenSslEvpPkeyEnum:
            assert evp_pkey in _OPENSSL_EVP_PKEY_TO_NAME_MAPPING

    def test_ec_nid_to_name_mapping(self):
        # Ensure all known NIDs have an associated name
        for ec_nid in OpenSslEcNidEnum:
            assert ec_nid in _OPENSSL_NID_TO_SECG_ANSI_X9_62

    def test_ec_dh(self):
        # Given some key info returned by OpenSSL
        openssl_key_info = dict(
            type=OpenSslEvpPkeyEnum.EC,
            size=12,
            public_bytes=bytearray(b"123"),
            curve=OpenSslEcNidEnum.X448,
        )

        # When parsing it, it succeeds
        key_info = EcDhEphemeralKeyInfo(**openssl_key_info)
        assert key_info

    def test_ec_dh_unknown_curve(self):
        # Given some key info returned by OpenSSL with an unknown curve ID
        openssl_key_info = dict(
            curve=12345,
            type=OpenSslEvpPkeyEnum.EC,
            size=12,
            public_bytes=bytearray(b"123"),
        )

        # When parsing it, it succeeds
        key_info = EcDhEphemeralKeyInfo(**openssl_key_info)
        assert key_info
        assert "unknown" in key_info.curve_name

    def test_dh_unknown_type(self):
        # Given some key info returned by OpenSSL with an unknown type
        openssl_key_info = dict(
            type=12345,
            size=12,
            public_bytes=bytearray(b"123"),
            prime=bytearray(b"123"),
            generator=bytearray(b"123"),
        )

        # When parsing it, it succeeds
        key_info = DhEphemeralKeyInfo(**openssl_key_info)
        assert key_info
        assert "UNKNOWN" in key_info.type_name
