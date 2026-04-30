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
    def test_supported_by_ssl_client(self) -> None:
        # Ensure the expected NIDs can be used to configure an SslClient
        for ec_nid in OpenSslEcNidEnum.get_supported_by_ssl_client():
            ssl_client = SslClient()
            ssl_client.set_groups([ec_nid])


class TestEphemeralKeyInfo:
    def test_evp_pkey_to_name_mapping(self) -> None:
        # Ensure all known EVP PKEYs have an associated name
        for evp_pkey in OpenSslEvpPkeyEnum:
            assert evp_pkey in _OPENSSL_EVP_PKEY_TO_NAME_MAPPING

    def test_ec_nid_to_name_mapping(self) -> None:
        # Ensure all known NIDs have an associated name
        for ec_nid in OpenSslEcNidEnum:
            assert ec_nid in _OPENSSL_NID_TO_SECG_ANSI_X9_62

    def test_ec_dh(self) -> None:
        # Given some key info returned by OpenSSL, when parsing it, it succeeds
        key_info = EcDhEphemeralKeyInfo(
            type=OpenSslEvpPkeyEnum.EC,
            size=12,
            public_bytes=bytearray(b"123"),
            curve=OpenSslEcNidEnum.X448,
        )
        assert key_info

    def test_ec_dh_unknown_curve(self) -> None:
        # Given some key info returned by OpenSSL with an unknown curve ID, when parsing it, it succeeds
        key_info = EcDhEphemeralKeyInfo(
            curve=12345,  # type: ignore
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

    def test_raw_int_type_is_coerced_to_enum(self) -> None:
        # Regression for #132: dh_info from the C extension carries raw ints,
        # so DhEphemeralKeyInfo(**dh_info) used to leave .type as an int.
        # The dataclass should coerce known values to the IntEnum.
        key_info = DhEphemeralKeyInfo(
            type=int(OpenSslEvpPkeyEnum.DH),  # type: ignore
            size=12,
            public_bytes=bytearray(b"123"),
            prime=bytearray(b"123"),
            generator=bytearray(b"123"),
        )
        assert isinstance(key_info.type, OpenSslEvpPkeyEnum)
        assert key_info.type is OpenSslEvpPkeyEnum.DH

    def test_raw_int_curve_is_coerced_to_enum(self) -> None:
        # Same coercion for EcDhEphemeralKeyInfo.curve.
        key_info = EcDhEphemeralKeyInfo(
            type=int(OpenSslEvpPkeyEnum.EC),  # type: ignore
            size=12,
            public_bytes=bytearray(b"123"),
            curve=int(OpenSslEcNidEnum.X448),  # type: ignore
        )
        assert isinstance(key_info.curve, OpenSslEcNidEnum)
        assert key_info.curve is OpenSslEcNidEnum.X448
