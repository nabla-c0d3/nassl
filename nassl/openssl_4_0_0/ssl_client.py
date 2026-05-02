from nassl.openssl_1_1_1.ssl_client import SslClient_OpenSSL_1_1_1
import nassl.openssl_4_0_0._nassl


# For now, the OpenSSL 4.0.0 client is almost identical to the OpenSSL 1.1.1 client
class SslClient_OpenSSL_4_0_0(SslClient_OpenSSL_1_1_1):
    _NASSL_MODULE = nassl.openssl_4_0_0._nassl

    def get_implemented_groups(self) -> list[str]:
        """Get the list of implemented groups, as IANA names."""
        return self._ssl_ctx.get0_implemented_groups()

    def get_group_name(self) -> str:
        """Get the IANA name of the negotiated group."""
        return self._ssl.get0_group_name()

    # SslClient_OpenSSL_1_1_1.set_groups() cannot be used to set groups such as X25519MLKEM768
    # https://github.com/openssl/openssl/issues/27834
    # Hence we also expose set_groups_list()
    def set_groups_list(self, groups: str) -> None:
        """Set the groups to be used in the handshake, using a colon-separated list of group names.

        The format is described here: https://docs.openssl.org/4.0/man3/SSL_CTX_set1_curves/"""
        self._ssl.set1_groups_list(groups)
