from abc import ABC

from enum import Enum, IntEnum
from dataclasses import dataclass, field
from typing import Dict

from nassl.tls_version_enum import TlsVersionEnum


class OpenSslEvpPkeyEnum(IntEnum):
    """Maps to the EVP_PKEY_XXX OpenSSL constants (obj_mac.h) used as the temporary key during key exchange."""

    DH = 28
    EC = 408
    X25519 = 1034
    X448 = 1035
    RSA = 6
    DSA = 116
    RSA_PSS = 912


# Mapping between OpenSSL EVP_PKEY_XXX value and display name
_OPENSSL_EVP_PKEY_TO_NAME_MAPPING: Dict[OpenSslEvpPkeyEnum, str] = {
    OpenSslEvpPkeyEnum.DH: "DH",
    OpenSslEvpPkeyEnum.EC: "ECDH",
    OpenSslEvpPkeyEnum.X25519: "ECDH",
    OpenSslEvpPkeyEnum.X448: "ECDH",
    OpenSslEvpPkeyEnum.RSA: "RSA",
    OpenSslEvpPkeyEnum.DSA: "DSA",
    OpenSslEvpPkeyEnum.RSA_PSS: "RSA-PSS",
}


class OpenSslGroupTypeEnum(str, Enum):
    """Categories of OpenSslGroupNameEnum."""

    ELLIPTIC_CURVE = "elliptic_curve"
    FINITE_FIELD_DH = "finite_field_dh"
    POST_QUANTUM = "post_quantum"
    POST_QUANTUM_HYBRID = "post_quantum_hybrid"


class OpenSslGroupNameEnum(str, Enum):
    """TLS group names, which can be used with SslClient_OpenSSL_4_0_0.set_groups_list()."""

    # RFC8422
    secp192r1 = "secp192r1"
    secp256r1 = "secp256r1"
    secp384r1 = "secp384r1"
    secp521r1 = "secp521r1"
    x25519 = "x25519"
    x448 = "x448"

    # RFC4492
    sect163k1 = "sect163k1"
    sect163r1 = "sect163r1"
    sect163r2 = "sect163r2"
    sect193r1 = "sect193r1"
    sect193r2 = "sect193r2"
    sect233k1 = "sect233k1"
    sect233r1 = "sect233r1"
    sect239k1 = "sect239k1"
    sect283k1 = "sect283k1"
    sect283r1 = "sect283r1"
    sect409k1 = "sect409k1"
    sect409r1 = "sect409r1"
    sect571k1 = "sect571k1"
    sect571r1 = "sect571r1"
    secp160k1 = "secp160k1"
    secp160r1 = "secp160r1"
    secp160r2 = "secp160r2"
    secp192k1 = "secp192k1"
    secp224k1 = "secp224k1"
    secp224r1 = "secp224r1"
    secp256k1 = "secp256k1"

    # RFC 7027: Brainpool curves for TLS v1.2
    # Only specific Brainpool curves are supported (ie. have a IANA name/ID) in TLS;
    #  see also : https://github.com/openssl/openssl/issues/9124
    brainpoolP256r1 = "brainpoolP256r1"
    brainpoolP384r1 = "brainpoolP384r1"
    brainpoolP512r1 = "brainpoolP512r1"

    # RFC 8734: TLS 1.3 version of the Brainpool curves
    brainpoolP256r1tls13 = "brainpoolP256r1tls13"
    brainpoolP384r1tls13 = "brainpoolP384r1tls13"
    brainpoolP512r1tls13 = "brainpoolP512r1tls13"

    # RFC 7919: TLS 1.0 to TLS 1.3
    ffdhe2048 = "ffdhe2048"
    ffdhe3072 = "ffdhe3072"
    ffdhe4096 = "ffdhe4096"
    ffdhe6144 = "ffdhe6144"
    ffdhe8192 = "ffdhe8192"

    # Post-quantum ML-KEM groups (pure and hybrid with a classical curve), and the SM2 curve/hybrid -
    # All TLS 1.3 only
    MLKEM512 = "MLKEM512"
    MLKEM768 = "MLKEM768"
    MLKEM1024 = "MLKEM1024"
    SecP256r1MLKEM768 = "SecP256r1MLKEM768"
    SecP384r1MLKEM1024 = "SecP384r1MLKEM1024"
    X25519MLKEM768 = "X25519MLKEM768"
    curveSM2 = "curveSM2"
    curveSM2MLKEM768 = "curveSM2MLKEM768"

    @classmethod
    def get_supported_by_tls_version(cls, tls_version: TlsVersionEnum) -> set["OpenSslGroupNameEnum"]:
        """Get the subset of groups that are valid to advertise for the given TLS version."""
        if tls_version == TlsVersionEnum.TLS_1_3:
            return _GROUPS_FOR_TLS_1_3
        elif tls_version in [TlsVersionEnum.TLS_1_0, TlsVersionEnum.TLS_1_1, TlsVersionEnum.TLS_1_2]:
            return _GROUPS_FOR_TLS_1_0_TO_1_2
        else:
            raise ValueError(f"No groups supported for supplied TLS version {tls_version}")

    def get_type(self) -> OpenSslGroupTypeEnum:
        return _GROUP_NAME_TO_TYPE_MAPPING[self]


# Groups that are supported by TLS 1.3
# openssl list -tls1_3 -tls-groups
_GROUPS_FOR_TLS_1_3: set[OpenSslGroupNameEnum] = {
    OpenSslGroupNameEnum.secp256r1,
    OpenSslGroupNameEnum.secp384r1,
    OpenSslGroupNameEnum.secp521r1,
    OpenSslGroupNameEnum.x25519,
    OpenSslGroupNameEnum.x448,
    OpenSslGroupNameEnum.brainpoolP256r1tls13,
    OpenSslGroupNameEnum.brainpoolP384r1tls13,
    OpenSslGroupNameEnum.brainpoolP512r1tls13,
    OpenSslGroupNameEnum.curveSM2,
    OpenSslGroupNameEnum.MLKEM512,
    OpenSslGroupNameEnum.MLKEM768,
    OpenSslGroupNameEnum.MLKEM1024,
    OpenSslGroupNameEnum.SecP256r1MLKEM768,
    OpenSslGroupNameEnum.X25519MLKEM768,
    OpenSslGroupNameEnum.SecP384r1MLKEM1024,
    OpenSslGroupNameEnum.curveSM2MLKEM768,
    OpenSslGroupNameEnum.ffdhe2048,
    OpenSslGroupNameEnum.ffdhe3072,
    OpenSslGroupNameEnum.ffdhe4096,
    OpenSslGroupNameEnum.ffdhe6144,
    OpenSslGroupNameEnum.ffdhe8192,
}

# openssl list -tls1_2 -tls-groups
_GROUPS_FOR_TLS_1_0_TO_1_2: set[OpenSslGroupNameEnum] = {
    OpenSslGroupNameEnum.sect163k1,
    OpenSslGroupNameEnum.sect163r1,
    OpenSslGroupNameEnum.sect163r2,
    OpenSslGroupNameEnum.sect193r1,
    OpenSslGroupNameEnum.sect193r2,
    OpenSslGroupNameEnum.sect233k1,
    OpenSslGroupNameEnum.sect233r1,
    OpenSslGroupNameEnum.sect239k1,
    OpenSslGroupNameEnum.sect283k1,
    OpenSslGroupNameEnum.sect283r1,
    OpenSslGroupNameEnum.sect409k1,
    OpenSslGroupNameEnum.sect409r1,
    OpenSslGroupNameEnum.sect571k1,
    OpenSslGroupNameEnum.sect571r1,
    OpenSslGroupNameEnum.secp160k1,
    OpenSslGroupNameEnum.secp160r1,
    OpenSslGroupNameEnum.secp160r2,
    OpenSslGroupNameEnum.secp192k1,
    OpenSslGroupNameEnum.secp192r1,
    OpenSslGroupNameEnum.secp224k1,
    OpenSslGroupNameEnum.secp224r1,
    OpenSslGroupNameEnum.secp256k1,
    OpenSslGroupNameEnum.secp256r1,
    OpenSslGroupNameEnum.secp384r1,
    OpenSslGroupNameEnum.secp521r1,
    OpenSslGroupNameEnum.brainpoolP256r1,
    OpenSslGroupNameEnum.brainpoolP384r1,
    OpenSslGroupNameEnum.brainpoolP512r1,
    OpenSslGroupNameEnum.x25519,
    OpenSslGroupNameEnum.x448,
    OpenSslGroupNameEnum.ffdhe2048,
    OpenSslGroupNameEnum.ffdhe3072,
    OpenSslGroupNameEnum.ffdhe4096,
    OpenSslGroupNameEnum.ffdhe6144,
    OpenSslGroupNameEnum.ffdhe8192,
}

_GROUPS_THAT_ARE_ELLIPTIC_CURVES: set[OpenSslGroupNameEnum] = {
    OpenSslGroupNameEnum.sect163k1,
    OpenSslGroupNameEnum.sect163r1,
    OpenSslGroupNameEnum.sect163r2,
    OpenSslGroupNameEnum.sect193r1,
    OpenSslGroupNameEnum.sect193r2,
    OpenSslGroupNameEnum.sect233k1,
    OpenSslGroupNameEnum.sect233r1,
    OpenSslGroupNameEnum.sect239k1,
    OpenSslGroupNameEnum.sect283k1,
    OpenSslGroupNameEnum.sect283r1,
    OpenSslGroupNameEnum.sect409k1,
    OpenSslGroupNameEnum.sect409r1,
    OpenSslGroupNameEnum.sect571k1,
    OpenSslGroupNameEnum.sect571r1,
    OpenSslGroupNameEnum.secp160k1,
    OpenSslGroupNameEnum.secp160r1,
    OpenSslGroupNameEnum.secp160r2,
    OpenSslGroupNameEnum.secp192k1,
    OpenSslGroupNameEnum.secp192r1,
    OpenSslGroupNameEnum.secp224k1,
    OpenSslGroupNameEnum.secp224r1,
    OpenSslGroupNameEnum.secp256k1,
    OpenSslGroupNameEnum.secp256r1,
    OpenSslGroupNameEnum.secp384r1,
    OpenSslGroupNameEnum.secp521r1,
    OpenSslGroupNameEnum.x25519,
    OpenSslGroupNameEnum.x448,
    OpenSslGroupNameEnum.brainpoolP256r1,
    OpenSslGroupNameEnum.brainpoolP384r1,
    OpenSslGroupNameEnum.brainpoolP512r1,
    OpenSslGroupNameEnum.brainpoolP256r1tls13,
    OpenSslGroupNameEnum.brainpoolP384r1tls13,
    OpenSslGroupNameEnum.brainpoolP512r1tls13,
    OpenSslGroupNameEnum.curveSM2,
}

_GROUPS_THAT_ARE_FINITE_FIELD_DH: set[OpenSslGroupNameEnum] = {
    OpenSslGroupNameEnum.ffdhe2048,
    OpenSslGroupNameEnum.ffdhe3072,
    OpenSslGroupNameEnum.ffdhe4096,
    OpenSslGroupNameEnum.ffdhe6144,
    OpenSslGroupNameEnum.ffdhe8192,
}

_GROUPS_THAT_ARE_POST_QUANTUM: set[OpenSslGroupNameEnum] = {
    OpenSslGroupNameEnum.MLKEM512,
    OpenSslGroupNameEnum.MLKEM768,
    OpenSslGroupNameEnum.MLKEM1024,
}

_GROUPS_THAT_ARE_POST_QUANTUM_HYBRID: set[OpenSslGroupNameEnum] = {
    OpenSslGroupNameEnum.SecP256r1MLKEM768,
    OpenSslGroupNameEnum.SecP384r1MLKEM1024,
    OpenSslGroupNameEnum.X25519MLKEM768,
    OpenSslGroupNameEnum.curveSM2MLKEM768,
}

_GROUP_NAME_TO_TYPE_MAPPING: Dict[OpenSslGroupNameEnum, OpenSslGroupTypeEnum] = {
    **{group: OpenSslGroupTypeEnum.ELLIPTIC_CURVE for group in _GROUPS_THAT_ARE_ELLIPTIC_CURVES},
    **{group: OpenSslGroupTypeEnum.FINITE_FIELD_DH for group in _GROUPS_THAT_ARE_FINITE_FIELD_DH},
    **{group: OpenSslGroupTypeEnum.POST_QUANTUM for group in _GROUPS_THAT_ARE_POST_QUANTUM},
    **{group: OpenSslGroupTypeEnum.POST_QUANTUM_HYBRID for group in _GROUPS_THAT_ARE_POST_QUANTUM_HYBRID},
}
assert len(_GROUP_NAME_TO_TYPE_MAPPING) == len(OpenSslGroupNameEnum), "Every group must be classified"


# This is only needed to retrieve the name of the curve in EcDhEphemeralKeyInfo
_OPENSSL_NID_TO_GROUP_ENUM = {
    721: OpenSslGroupNameEnum.sect163k1,
    722: OpenSslGroupNameEnum.sect163r1,
    723: OpenSslGroupNameEnum.sect163r2,
    724: OpenSslGroupNameEnum.sect193r1,
    725: OpenSslGroupNameEnum.sect193r2,
    726: OpenSslGroupNameEnum.sect233k1,
    727: OpenSslGroupNameEnum.sect233r1,
    728: OpenSslGroupNameEnum.sect239k1,
    729: OpenSslGroupNameEnum.sect283k1,
    730: OpenSslGroupNameEnum.sect283r1,
    731: OpenSslGroupNameEnum.sect409k1,
    732: OpenSslGroupNameEnum.sect409r1,
    733: OpenSslGroupNameEnum.sect571k1,
    734: OpenSslGroupNameEnum.sect571r1,
    708: OpenSslGroupNameEnum.secp160k1,
    709: OpenSslGroupNameEnum.secp160r1,
    710: OpenSslGroupNameEnum.secp160r2,
    711: OpenSslGroupNameEnum.secp192k1,
    712: OpenSslGroupNameEnum.secp224k1,
    713: OpenSslGroupNameEnum.secp224r1,
    714: OpenSslGroupNameEnum.secp256k1,
    409: OpenSslGroupNameEnum.secp192r1,
    415: OpenSslGroupNameEnum.secp256r1,
    715: OpenSslGroupNameEnum.secp384r1,
    716: OpenSslGroupNameEnum.secp521r1,
    1034: OpenSslGroupNameEnum.x25519,
    1035: OpenSslGroupNameEnum.x448,
    927: OpenSslGroupNameEnum.brainpoolP256r1,
    931: OpenSslGroupNameEnum.brainpoolP384r1,
    933: OpenSslGroupNameEnum.brainpoolP512r1,
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
        object.__setattr__(
            self,
            "type_name",
            _OPENSSL_EVP_PKEY_TO_NAME_MAPPING.get(self.type, "UNKNOWN"),
        )


@dataclass(frozen=True)
class EcDhEphemeralKeyInfo(EphemeralKeyInfo):
    curve: int  # OpenSSL NID
    curve_name: str = field(init=False)

    def __post_init__(self) -> None:
        super().__post_init__()
        curve_name = _OPENSSL_NID_TO_GROUP_ENUM.get(self.curve, f"unknown-curve-with-openssl-nid-{self.curve}")
        # Required because of frozen=True; https://docs.python.org/3/library/dataclasses.html#frozen-instances
        object.__setattr__(self, "curve_name", curve_name)


@dataclass(frozen=True)
class NistEcDhKeyExchangeInfo(EcDhEphemeralKeyInfo):
    x: bytearray
    y: bytearray


@dataclass(frozen=True)
class DhEphemeralKeyInfo(EphemeralKeyInfo):
    prime: bytearray
    generator: bytearray
