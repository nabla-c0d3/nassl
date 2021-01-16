from abc import ABC

from enum import IntEnum
from dataclasses import dataclass, field
from typing import Dict


class OpenSslEvpPkeyEnum(IntEnum):
    """Constants which map to the EVP_PKEY_XXX OpenSSL constants (obj_mac.h) used as the temporary key during key exchange"""

    DH = 28
    EC = 408
    X25519 = 1034
    X448 = 1035


class OpenSslEcNidEnum(IntEnum):
    """Constants which map to NID_XXX values valid for OpenSslEvpPkeyEnum.EC (obj_mac.h)
    Valid values for TLS taken from https://tools.ietf.org/html/rfc4492 and https://tools.ietf.org/html/rfc8422
    """

    # RFC4492 (now deprecated)
    SECT163K1 = 721
    SECT163R1 = 722
    SECT163R2 = 723
    SECT193R1 = 724
    SECT193R2 = 725
    SECT233K1 = 726
    SECT233R1 = 727
    SECT239K1 = 728
    SECT283K1 = 729
    SECT283R1 = 730
    SECT409K1 = 731
    SECT409R1 = 732
    SECT571K1 = 733
    SECT571R1 = 734
    SECP160K1 = 708
    SECP160R1 = 709
    SECP160R2 = 710
    SECP192K1 = 711
    SECP224K1 = 712
    SECP224R1 = 713
    SECP256K1 = 714

    # RFC8422 (current)
    SECP192R1 = 409
    PRIME192V1 = 409  # Intentional duplicate of SECP192R1
    SECP256R1 = 415
    PRIME256V1 = 415  # Intentional duplicate of SECP256R1
    SECP384R1 = 715
    SECP521R1 = 716
    X25519 = 1034
    X448 = 1035


# Mapping between OpenSSL EVP_PKEY_XXX value and display name
_OPENSSL_EVP_PKEY_TO_NAME_MAPPING: Dict[OpenSslEvpPkeyEnum, str] = {
    OpenSslEvpPkeyEnum.DH: "DH",
    OpenSslEvpPkeyEnum.EC: "ECDH",
    OpenSslEvpPkeyEnum.X25519: "ECDH",
    OpenSslEvpPkeyEnum.X448: "ECDH",
}


# Mapping between the OpenSSL NID_XXX value and NIST name defined in https://tools.ietf.org/html/rfc4492
_OPENSSL_NID_TO_NIST_MAPPING: Dict[OpenSslEcNidEnum, str] = {
    OpenSslEcNidEnum.SECT163R2: "B-163",
    OpenSslEcNidEnum.SECT233R1: "B-233",
    OpenSslEcNidEnum.SECT283R1: "B-283",
    OpenSslEcNidEnum.SECT409R1: "B-409",
    OpenSslEcNidEnum.SECT571R1: "B-571",
    OpenSslEcNidEnum.SECT163K1: "K-163",
    OpenSslEcNidEnum.SECT233K1: "K-233",
    OpenSslEcNidEnum.SECT283K1: "K-283",
    OpenSslEcNidEnum.SECT409K1: "K-409",
    OpenSslEcNidEnum.SECT571K1: "K-571",
    OpenSslEcNidEnum.PRIME192V1: "P-192",
    OpenSslEcNidEnum.SECP224R1: "P-224",
    OpenSslEcNidEnum.PRIME256V1: "P-256",
    OpenSslEcNidEnum.SECP384R1: "P-384",
    OpenSslEcNidEnum.SECP521R1: "P-521",
}


# Mapping between the OpenSSL NID_XXX value and the SECG or ANSI X9.62 name (https://tools.ietf.org/html/rfc4492)
# Where a ANSI X9.62 name is available, this is used in preference to the SECG
# X25519 and X448 also included from https://tools.ietf.org/html/rfc8422
_OPENSSL_NID_TO_SECG_ANSI_X9_62: Dict[OpenSslEcNidEnum, str] = {
    OpenSslEcNidEnum.SECT163K1: "sect163k1",
    OpenSslEcNidEnum.SECT163R1: "sect163r1",
    OpenSslEcNidEnum.SECT163R2: "sect163r2",
    OpenSslEcNidEnum.SECT193R1: "sect193r1",
    OpenSslEcNidEnum.SECT193R2: "sect193r2",
    OpenSslEcNidEnum.SECT233K1: "sect233k1",
    OpenSslEcNidEnum.SECT233R1: "sect233r1",
    OpenSslEcNidEnum.SECT239K1: "sect239k1",
    OpenSslEcNidEnum.SECT283K1: "sect283k1",
    OpenSslEcNidEnum.SECT283R1: "sect283r1",
    OpenSslEcNidEnum.SECT409K1: "sect409k1",
    OpenSslEcNidEnum.SECT409R1: "sect409r1",
    OpenSslEcNidEnum.SECT571K1: "sect571k1",
    OpenSslEcNidEnum.SECT571R1: "sect571r1",
    OpenSslEcNidEnum.SECP160K1: "secp160k1",
    OpenSslEcNidEnum.SECP160R1: "secp160r1",
    OpenSslEcNidEnum.SECP160R2: "secp160r2",
    OpenSslEcNidEnum.SECP192K1: "secp192k1",
    OpenSslEcNidEnum.SECP224K1: "secp224k1",
    OpenSslEcNidEnum.SECP224R1: "secp224r1",
    OpenSslEcNidEnum.SECP256K1: "secp256k1",
    OpenSslEcNidEnum.PRIME192V1: "prime192v1",  # Also valid for SECP192R1
    OpenSslEcNidEnum.PRIME256V1: "prime256v1",  # Also valid for SECP256R1
    OpenSslEcNidEnum.SECP384R1: "secp384r1",
    OpenSslEcNidEnum.SECP521R1: "secp521r1",
    OpenSslEcNidEnum.X25519: "X25519",
    OpenSslEcNidEnum.X448: "X448",
}


@dataclass(frozen=True)
class EphemeralKeyInfo(ABC):
    """Common fields shared by all kinds of TLS key exchanges."""

    type: OpenSslEvpPkeyEnum
    type_name: str = field(init=False)
    size: int
    public_bytes: bytearray

    def __post_init__(self) -> None:
        # Required because of frozen=True; https://docs.python.org/3/library/dataclasses.html#frozen-instances
        object.__setattr__(self, "type_name", _OPENSSL_EVP_PKEY_TO_NAME_MAPPING[self.type])


@dataclass(frozen=True)
class EcDhEphemeralKeyInfo(EphemeralKeyInfo):
    curve: OpenSslEcNidEnum
    curve_name: str = field(init=False)

    def __post_init__(self) -> None:
        super().__post_init__()
        # Required because of frozen=True; https://docs.python.org/3/library/dataclasses.html#frozen-instances
        object.__setattr__(self, "curve_name", _OPENSSL_NID_TO_SECG_ANSI_X9_62[self.curve])


@dataclass(frozen=True)
class NistEcDhKeyExchangeInfo(EcDhEphemeralKeyInfo):
    x: bytearray
    y: bytearray


@dataclass(frozen=True)
class DhEphemeralKeyInfo(EphemeralKeyInfo):
    prime: bytearray
    generator: bytearray
