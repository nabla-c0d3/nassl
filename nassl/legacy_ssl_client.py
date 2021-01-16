import socket
from pathlib import Path

from nassl._nassl import WantReadError, WantX509LookupError

from nassl.ssl_client import (
    ClientCertificateRequested,
    OpenSslVersionEnum,
    OpenSslVerifyEnum,
    OpenSslFileTypeEnum,
    BaseSslClient,
)
from typing import List
from typing import Optional
import sys


from nassl import _nassl_legacy  # type: ignore


class LegacySslClient(BaseSslClient):
    """An insecure SSL client with additional debug methods that no one should ever use (insecure renegotiation, etc.)."""

    # The legacy client uses the legacy OpenSSL
    _NASSL_MODULE = _nassl_legacy

    def __init__(
        self,
        underlying_socket: Optional[socket.socket] = None,
        ssl_version: OpenSslVersionEnum = OpenSslVersionEnum.SSLV23,
        ssl_verify: OpenSslVerifyEnum = OpenSslVerifyEnum.PEER,
        ssl_verify_locations: Optional[Path] = None,
        client_certificate_chain: Optional[Path] = None,
        client_key: Optional[Path] = None,
        client_key_type: OpenSslFileTypeEnum = OpenSslFileTypeEnum.PEM,
        client_key_password: str = "",
        ignore_client_authentication_requests: bool = False,
    ) -> None:
        super().__init__(
            underlying_socket,
            ssl_version,
            ssl_verify,
            ssl_verify_locations,
            client_certificate_chain,
            client_key,
            client_key_type,
            client_key_password,
            ignore_client_authentication_requests,
        )

        # Specific servers do not reply to a client hello that is bigger than 255 bytes
        # See http://rt.openssl.org/Ticket/Display.html?id=2771&user=guest&pass=guest
        # So we make the default cipher list smaller (to make the client hello smaller)
        if ssl_version != OpenSslVersionEnum.SSLV2:  # This makes SSLv2 fail
            self._ssl.set_cipher_list("HIGH:-aNULL:-eNULL:-3DES:-SRP:-PSK:-CAMELLIA")
        else:
            # Handshake workaround for SSL2 + IIS 7
            # TODO(AD): Provide a built-in mechansim for overriding the handshake logic
            self.do_handshake = self.do_ssl2_iis_handshake  # type: ignore

    def get_secure_renegotiation_support(self) -> bool:
        return self._ssl.get_secure_renegotiation_support()

    def get_current_compression_method(self) -> Optional[str]:
        return self._ssl.get_current_compression_method()

    @staticmethod
    def get_available_compression_methods() -> List[str]:
        """Returns the list of SSL compression methods supported by SslClient."""
        return _nassl_legacy.SSL.get_available_compression_methods()

    def do_renegotiate(self) -> None:
        """Initiate an SSL renegotiation."""
        if not self._is_handshake_completed:
            raise IOError("SSL Handshake was not completed; cannot renegotiate.")

        self._ssl.renegotiate()
        self.do_handshake()

    _SSL_MODE_SEND_FALLBACK_SCSV = 0x00000080

    def enable_fallback_scsv(self) -> None:
        self._ssl.set_mode(self._SSL_MODE_SEND_FALLBACK_SCSV)

    # TODO(AD): Allow the handshake method to be overridden instead of this
    def do_ssl2_iis_handshake(self) -> None:
        if self._sock is None:
            # TODO: Auto create a socket ?
            raise IOError("Internal socket set to None; cannot perform handshake.")

        while True:
            try:
                self._ssl.do_handshake()
                self._is_handshake_completed = True
                # Handshake was successful
                return

            except WantReadError:
                # OpenSSL is expecting more data from the peer
                # Send available handshake data to the peer
                lengh_to_read = self._network_bio.pending()
                while lengh_to_read:
                    # Get the data from the SSL engine
                    handshake_data_out = self._network_bio.read(lengh_to_read)

                    if "SSLv2 read server verify A" in self._ssl.state_string_long():
                        # Awful h4ck for SSLv2 when connecting to IIS7 (like in the 90s)
                        # OpenSSL sends the client's CMK and data message in the same packet without
                        # waiting for the server's response, causing IIS 7 to hang on the connection.
                        # This workaround forces our client to send the CMK message, then wait for the server's
                        # response, and then send the data packet
                        # if '\x02' in handshake_data_out[2]:  # Make sure we're looking at the CMK message
                        message_type = handshake_data_out[2]
                        IS_PYTHON_2 = sys.version_info < (3, 0)
                        if IS_PYTHON_2:
                            message_type = ord(message_type)

                        if message_type == 2:  # Make sure we're looking at the CMK message
                            # cmk_size = handshake_data_out[0:2]
                            if IS_PYTHON_2:
                                first_byte = ord(handshake_data_out[0])
                                second_byte = ord(handshake_data_out[1])
                            else:
                                first_byte = int(handshake_data_out[0])
                                second_byte = int(handshake_data_out[1])
                            first_byte = (first_byte & 0x7F) << 8
                            size = first_byte + second_byte
                            # Manually split the two records to force them to be sent separately
                            cmk_packet = handshake_data_out[0 : size + 2]  # noqa: E203
                            data_packet = handshake_data_out[size + 2 : :]  # noqa: E203
                            self._sock.send(cmk_packet)

                            handshake_data_in = self._sock.recv(self._DEFAULT_BUFFER_SIZE)
                            # print repr(handshake_data_in)
                            if len(handshake_data_in) == 0:
                                raise IOError("Nassl SSL handshake failed: peer did not send data back.")
                            # Pass the data to the SSL engine
                            self._network_bio.write(handshake_data_in)
                            handshake_data_out = data_packet

                    # Send it to the peer
                    self._sock.send(handshake_data_out)
                    lengh_to_read = self._network_bio.pending()

                handshake_data_in = self._sock.recv(self._DEFAULT_BUFFER_SIZE)
                if len(handshake_data_in) == 0:
                    raise IOError("Nassl SSL handshake failed: peer did not send data back.")
                # Pass the data to the SSL engine
                self._network_bio.write(handshake_data_in)

            except WantX509LookupError:
                # Server asked for a client certificate and we didn't provide one
                raise ClientCertificateRequested(self.get_client_CA_list())
