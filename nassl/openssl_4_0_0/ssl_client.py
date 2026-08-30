from nassl.ech_status_enum import OpenSslEchStatusEnum
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

    def set_ech_config(self, ech_config_list: bytes) -> None:
        """Configure the client to attempt ECH (Encrypted Client Hello) using the supplied ECHConfigList.

        The ECHConfigList is the raw, binary value normally published in the server's HTTPS/SVCB DNS record.
        """
        self._ssl.set1_ech_config_list(ech_config_list)

    def get_ech_status(self) -> tuple[OpenSslEchStatusEnum, str | None, str | None]:
        """Get the outcome of the ECH attempt made during the handshake.

        Returns a (status, inner_sni, outer_sni) tuple: inner_sni is the SNI that was encrypted/protected by ECH
        and outer_sni is the cleartext SNI that was visible on the wire, when applicable.
        """
        ech_status, inner_sni, outer_sni = self._ssl.ech_get1_status()
        return OpenSslEchStatusEnum(ech_status), inner_sni, outer_sni

    def get_ech_retry_config(self) -> bytes | None:
        """Get the server's retry ECHConfigList to use when ECH failed, if the server supplied one."""
        return self._ssl.ech_get1_retry_config()

    _SSL_OP_ECH_GREASE = 1 << 37  # Emit a GREASE'd ECH extension when no real ECHConfig was set

    def enable_ech_grease(self) -> None:
        """Configure the client to send a GREASE ECH extension, when no real ECHConfig was set via set_ech_config().

        This is used to probe whether a server reacts to the presence of an ECH extension at all, without knowing
        a real ECHConfig for it. See RFC 8701 for the GREASE mechanism."""
        self._ssl.set_options(self._SSL_OP_ECH_GREASE)
