from enum import IntEnum

import nassl.openssl_1_1_1._nassl
from nassl.base_ssl_client import BaseSslClient

from typing import List, Tuple

from nassl.ephemeral_key_info import (
    OpenSslEvpPkeyEnum,
)


class OpenSslDigestNidEnum(IntEnum):
    """SSL digest algorithms used for the signature algorithm, per obj_mac.h."""

    MD5 = 4
    SHA1 = 64
    SHA224 = 675
    SHA256 = 672
    SHA384 = 673
    SHA512 = 674


class OpenSslEarlyDataStatusEnum(IntEnum):
    """Early data status constants."""

    NOT_SENT = 0
    REJECTED = 1
    ACCEPTED = 2


class ExtendedMasterSecretSupportEnum(IntEnum):
    NOT_USED_IN_CURRENT_SESSION = 0
    USED_IN_CURRENT_SESSION = 1
    UNKNOWN = -1


class SslClient_OpenSSL_1_1_1(BaseSslClient):
    _NASSL_MODULE = nassl.openssl_1_1_1._nassl

    def _init_ssl_ctx(self) -> None:
        self._ssl_ctx = self._NASSL_MODULE.SSL_CTX()
        self._ssl_ctx.set_min_proto_version(self._ssl_version.value)
        self._ssl_ctx.set_max_proto_version(self._ssl_version.value)
        self._ssl_ctx.set_security_level(0)  # Needed by SSLyze to test bad ciphers, etc.

    def write_early_data(self, data: bytes) -> int:
        """Returns the number of (encrypted) bytes sent."""
        if self._is_handshake_completed:
            raise IOError("SSL Handshake was completed; cannot send early data.")

        # Pass the cleartext data to the SSL engine
        self._ssl.write_early_data(data)

        # Recover the corresponding encrypted data
        final_length = self._flush_ssl_engine()
        return final_length

    def get_early_data_status(self) -> OpenSslEarlyDataStatusEnum:
        return OpenSslEarlyDataStatusEnum(self._ssl.get_early_data_status())

    def set_ciphersuites(self, cipher_suites: str) -> None:
        """https://github.com/openssl/openssl/pull/5392
        ."""
        # TODO(AD): Eventually merge this method with get/set_cipher_list()
        self._ssl.set_ciphersuites(cipher_suites)

    def set_signature_algorithms(self, algorithms: List[Tuple[OpenSslDigestNidEnum, OpenSslEvpPkeyEnum]]) -> None:
        """Set the enabled signature algorithms for the key exchange.

        The algorithms parameter is a list of a public key algorithm and a digest."""
        flattened_sigalgs = [item for sublist in algorithms for item in sublist]
        self._ssl.set1_sigalgs(flattened_sigalgs)

    def get_peer_signature_nid(self) -> OpenSslDigestNidEnum:
        """Get the digest used for TLS message signing."""
        return OpenSslDigestNidEnum(self._ssl.get_peer_signature_nid())

    def get_extended_master_secret_support(self) -> ExtendedMasterSecretSupportEnum:
        """Indicates whether the current session used extended master secret."""
        support = self._ssl.get_extms_support()
        if support == 1:
            return ExtendedMasterSecretSupportEnum.USED_IN_CURRENT_SESSION
        elif support == 0:
            return ExtendedMasterSecretSupportEnum.NOT_USED_IN_CURRENT_SESSION
        elif support == -1:
            return ExtendedMasterSecretSupportEnum.UNKNOWN
        else:
            raise ValueError(f"Unexpected return value get_extms_support(): {support}")
