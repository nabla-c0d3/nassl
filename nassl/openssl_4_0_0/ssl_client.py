from nassl.ephemeral_key_info import OpenSslGroupNameEnum
from nassl.openssl_1_1_1.ssl_client import SslClient_OpenSSL_1_1_1
import nassl.openssl_4_0_0._nassl


# For now, the OpenSSL 4.0.0 client is almost identical to the OpenSSL 1.1.1 client
class SslClient_OpenSSL_4_0_0(SslClient_OpenSSL_1_1_1):
    _NASSL_MODULE = nassl.openssl_4_0_0._nassl

    def get_implemented_groups(self) -> list[OpenSslGroupNameEnum]:
        """Get the list of implemented groups, as IANA names."""
        return [OpenSslGroupNameEnum[grp] for grp in self._ssl_ctx.get0_implemented_groups()]

    def get_group_name(self) -> OpenSslGroupNameEnum:
        """Get the IANA name of the negotiated group."""
        group_name_as_str = self._ssl.get0_group_name()
        if group_name_as_str is None:
            # Happens with ffdhe groups and TLS 1.2; bug in OpenSSL
            raise ValueError("Could not determine the group's name: OpenSSL returned NULL")
        return OpenSslGroupNameEnum[self._ssl.get0_group_name()]

    def set_groups_list(self, all_groups: list[OpenSslGroupNameEnum]) -> None:
        """Set the groups to be used in the handshake.

        Raises a ValueError if a group is not valid for the TLS version this client was configured with; eg.
        SECP192R1 for TLS 1.3, or a "tls13"-only group for TLS 1.2 - see
        https://github.com/nabla-c0d3/sslyze/issues/722.
        """
        all_supported_groups = OpenSslGroupNameEnum.get_supported_by_tls_version(self._ssl_version)
        for group in all_groups:
            if group not in all_supported_groups:
                raise ValueError(f'Group "{group.name}" is not supported for TLS version {self._ssl_version.name}')

        # The format is described here: https://docs.openssl.org/4.0/man3/SSL_CTX_set1_curves/
        all_groups_as_str = ":".join(all_groups)
        self._ssl.set1_groups_list(all_groups_as_str)
