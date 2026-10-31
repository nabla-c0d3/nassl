import pytest

from nassl.ephemeral_key_info import (
    EcDhEphemeralKeyInfo,
    OpenSslEvpPkeyEnum,
    _OPENSSL_EVP_PKEY_TO_NAME_MAPPING,
    DhEphemeralKeyInfo,
    OpenSslGroupNameEnum,
)
from nassl.openssl_4_0_0.ssl_client import SslClient_OpenSSL_4_0_0
from nassl.tls_version_enum import TlsVersionEnum


class TestOpenSslGroupNameEnum:
    @pytest.mark.parametrize("tls_version", [TlsVersionEnum.TLS_1_3, TlsVersionEnum.TLS_1_2])
    def test_supported_by_tls_version(self, tls_version: TlsVersionEnum) -> None:
        # Ensure that for each TLS version, the list of supported groups returned by OpenSSL is as expected
        ssl_client = SslClient_OpenSSL_4_0_0(tls_version=tls_version)
        all_supported_groups = ssl_client.get_implemented_groups()
        all_expected_groups = OpenSslGroupNameEnum.get_supported_by_tls_version(tls_version)
        assert set(all_supported_groups) == all_expected_groups


class TestEphemeralKeyInfo:
    def test_evp_pkey_to_name_mapping(self) -> None:
        # Ensure all known EVP PKEYs have an associated name
        for evp_pkey in OpenSslEvpPkeyEnum:
            assert evp_pkey in _OPENSSL_EVP_PKEY_TO_NAME_MAPPING

    def test_ec_dh(self) -> None:
        # Given some key info returned by OpenSSL, when parsing it, it succeeds
        key_info = EcDhEphemeralKeyInfo(
            type=OpenSslEvpPkeyEnum.EC,
            size=12,
            public_bytes=bytearray(b"123"),
            curve=927,
        )
        assert key_info

    def test_ec_dh_unknown_curve(self) -> None:
        # Given some key info returned by OpenSSL with an unknown curve ID, when parsing it, it succeeds
        key_info = EcDhEphemeralKeyInfo(
            curve=12345,
            type=OpenSslEvpPkeyEnum.EC,
            size=12,
            public_bytes=bytearray(b"123"),
        )
        assert key_info
        assert "unknown" in key_info.curve_name

    def test_dh_unknown_type(self) -> None:
        # Given some key info returned by OpenSSL with an unknown type, when parsing it, it succeeds
        key_info = DhEphemeralKeyInfo(
            type=12345,  # type: ignore
            size=12,
            public_bytes=bytearray(b"123"),
            prime=bytearray(b"123"),
            generator=bytearray(b"123"),
        )
        assert key_info
        assert "UNKNOWN" in key_info.type_name
