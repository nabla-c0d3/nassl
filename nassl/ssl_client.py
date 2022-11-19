import socket
from abc import ABC
from pathlib import Path

from nassl import _nassl
from nassl._nassl import WantReadError, OpenSSLError, WantX509LookupError

from enum import IntEnum
from typing import List, Any

try:
    from typing import Protocol
except ImportError:
    # Will happen on Python 3.7
    from typing_extensions import Protocol  # type: ignore


from typing import Optional
from nassl.ephemeral_key_info import (
    OpenSslEvpPkeyEnum,
    EphemeralKeyInfo,
    DhEphemeralKeyInfo,
    EcDhEphemeralKeyInfo,
    NistEcDhKeyExchangeInfo,
    OpenSslEcNidEnum,
)
from nassl.cert_chain_verifier import CertificateChainVerificationFailed


class OpenSslVerifyEnum(IntEnum):
    """SSL validation options which map to the SSL_VERIFY_XXX OpenSSL constants."""

    NONE = 0
    PEER = 1
    FAIL_IF_NO_PEER_CERT = 2
    CLIENT_ONCE = 4


class OpenSslVersionEnum(IntEnum):
    """SSL version constants."""

    SSLV23 = 0
    SSLV2 = 1
    SSLV3 = 2
    TLSV1 = 3
    TLSV1_1 = 4
    TLSV1_2 = 5
    TLSV1_3 = 6


class OpenSslFileTypeEnum(IntEnum):
    """Certificate and private key format constants which map to the SSL_FILETYPE_XXX OpenSSL constants."""

    PEM = 1
    ASN1 = 2


class ClientCertificateRequested(Exception):
    ERROR_MSG_CAS = "Server requested a client certificate issued by one of the following CAs: {0}."
    ERROR_MSG = "Server requested a client certificate."

    def __init__(self, ca_list: List[str]) -> None:
        self._ca_list = ca_list

    def __str__(self) -> str:
        exc_msg = self.ERROR_MSG

        if len(self._ca_list) > 0:
            exc_msg = self.ERROR_MSG_CAS.format(", ".join(self._ca_list))

        return exc_msg


class NasslModuleProtocol(Protocol):
    SSL_CTX: Any
    SSL: Any
    BIO: Any
    X509: Any
    X509_STORE_CTX: Any
    OCSP_RESPONSE: Any
    OpenSSLError: Any
    WantReadError: Any
    WantX509LookupError: Any
    SSL_SESSION: Any


class BaseSslClient(ABC):
    """Common code and methods to the modern and legacy SSL clients."""

    _DEFAULT_BUFFER_SIZE = 4096

    # The version of OpenSSL/nassl to use (modern VS legacy)
    _NASSL_MODULE: NasslModuleProtocol

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
        server_name_indication: Optional[str] = None,
    ) -> None:
        self._init_base_objects(ssl_version, underlying_socket)

        # Warning: Anything that modifies the SSL_CTX must be done before creating the SSL object
        # Otherwise changes to the SSL_CTX do not get propagated to future SSL objects
        self._init_server_authentication(ssl_verify, ssl_verify_locations)
        self._init_client_authentication(
            client_certificate_chain,
            client_key,
            client_key_type,
            client_key_password,
            ignore_client_authentication_requests,
        )
        # Now create the SSL object
        self._init_ssl_objects()
        if server_name_indication is not None:
            self._ssl.set_tlsext_host_name(server_name_indication)

    def _init_base_objects(
        self, ssl_version: OpenSslVersionEnum, underlying_socket: Optional[socket.socket]
    ) -> None:
        """Setup the socket and SSL_CTX objects."""
        self._is_handshake_completed = False
        self._ssl_version = ssl_version
        self._ssl_ctx = self._NASSL_MODULE.SSL_CTX(ssl_version.value)

        # A Python socket handles transmission of the data
        self._sock = underlying_socket

    def _init_server_authentication(
        self, ssl_verify: OpenSslVerifyEnum, ssl_verify_locations: Optional[Path]
    ) -> None:
        """Setup the certificate validation logic for authenticating the server."""
        self._ssl_ctx.set_verify(ssl_verify.value)
        if ssl_verify_locations:
            # Ensure the file exists
            with ssl_verify_locations.open():
                pass
            self._ssl_ctx.load_verify_locations(str(ssl_verify_locations))

    def _init_client_authentication(
        self,
        client_certificate_chain: Optional[Path],
        client_key: Optional[Path],
        client_key_type: OpenSslFileTypeEnum,
        client_key_password: str,
        ignore_client_authentication_requests: bool,
    ) -> None:
        """Setup client authentication using the supplied certificate and key."""
        if client_certificate_chain is not None and client_key is not None:
            self._use_private_key(client_certificate_chain, client_key, client_key_type, client_key_password)

        if ignore_client_authentication_requests:
            if client_certificate_chain:
                raise ValueError(
                    "Cannot enable both client_certchain_file and ignore_client_authentication_requests"
                )

            self._ssl_ctx.set_client_cert_cb_NULL()

    def _init_ssl_objects(self) -> None:
        self._ssl = self._NASSL_MODULE.SSL(self._ssl_ctx)
        self._ssl.set_connect_state()

        self._internal_bio = self._NASSL_MODULE.BIO()
        self._network_bio = self._NASSL_MODULE.BIO()

        # http://www.openssl.org/docs/crypto/BIO_s_bio.html
        self._NASSL_MODULE.BIO.make_bio_pair(self._internal_bio, self._network_bio)
        self._ssl.set_bio(self._internal_bio)
        self._ssl.set_network_bio_to_free_when_dealloc(self._network_bio)

    def set_underlying_socket(self, sock: socket.socket) -> None:
        if self._sock:
            raise RuntimeError("A socket was already set")
        self._sock = sock

    def get_underlying_socket(self) -> Optional[socket.socket]:
        return self._sock

    def do_handshake(self) -> None:
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
                self._flush_ssl_engine()

                # Recover the peer's encrypted response
                handshake_data_in = self._sock.recv(self._DEFAULT_BUFFER_SIZE)
                if len(handshake_data_in) == 0:
                    raise IOError("Nassl SSL handshake failed: peer did not send data back.")
                # Pass the data to the SSL engine
                self._network_bio.write(handshake_data_in)

            except WantX509LookupError:
                # Server asked for a client certificate and we didn't provide one
                raise ClientCertificateRequested(self.get_client_CA_list())

            except OpenSSLError as e:
                if "alert bad certificate" in e.args[0]:
                    # Bad certificate alert (https://github.com/nabla-c0d3/sslyze/issues/313 )
                    raise ClientCertificateRequested(self.get_client_CA_list())
                if "sslv3 alert certificate unknown" in e.args[0]:
                    # Some banking websites do that: https://github.com/nabla-c0d3/sslyze/issues/531
                    raise ClientCertificateRequested(self.get_client_CA_list())
                else:
                    raise

    def is_handshake_completed(self) -> bool:
        return self._is_handshake_completed

    # When sending early data, client can call read even if the handshake hasn't been
    # finished yet
    def read(self, size: int, handshake_must_be_completed: bool = True) -> bytes:
        if self._sock is None:
            raise IOError("Internal socket set to None; cannot perform handshake.")
        if handshake_must_be_completed and not self._is_handshake_completed:
            raise IOError("SSL Handshake was not completed; cannot receive data.")

        while True:
            # Receive available encrypted data from the peer
            encrypted_data = self._sock.recv(self._DEFAULT_BUFFER_SIZE)

            if len(encrypted_data) == 0:
                raise IOError("Could not read() - peer closed the connection.")

            # Pass it to the SSL engine
            self._network_bio.write(encrypted_data)

            try:
                # Try to read the decrypted data
                decrypted_data = self._ssl.read(size)
                return decrypted_data

            except WantReadError:
                # The SSL engine needs more data
                # before it can decrypt the whole message
                pass

            except OpenSSLError as e:
                if "tlsv13 alert certificate required" in str(e):
                    raise ClientCertificateRequested(self.get_client_CA_list())
                elif "alert bad certificate" in e.args[0]:
                    # Bad certificate alert (https://github.com/nabla-c0d3/sslyze/issues/532 )
                    raise ClientCertificateRequested(self.get_client_CA_list())
                else:
                    raise

    def write(self, data: bytes) -> int:
        """Returns the number of (encrypted) bytes sent."""
        if self._sock is None:
            raise IOError("Internal socket set to None; cannot perform handshake.")
        if not self._is_handshake_completed:
            raise IOError("SSL Handshake was not completed; cannot send data.")

        # Pass the cleartext data to the SSL engine
        self._ssl.write(data)

        # Recover the corresponding encrypted data
        final_length = self._flush_ssl_engine()

        return final_length

    def _flush_ssl_engine(self) -> int:
        if self._sock is None:
            raise IOError("Internal socket set to None; cannot perform handshake.")

        length_to_read = self._network_bio.pending()
        final_length = length_to_read
        while length_to_read:
            encrypted_data = self._network_bio.read(length_to_read)
            # Send the encrypted data to the peer
            self._sock.send(encrypted_data)
            length_to_read = self._network_bio.pending()
            final_length += length_to_read

        return final_length

    def shutdown(self) -> None:
        """Close the TLS connection and the underlying network socket."""
        self._is_handshake_completed = False
        try:
            self._flush_ssl_engine()
        except IOError:
            # Ensure shutting down the connection never raises an exception
            pass

        try:
            self._ssl.shutdown()
        except OpenSSLError as e:
            # Ignore "uninitialized" exception
            if "SSL_shutdown:uninitialized" not in str(e) and "shutdown while in init" not in str(e):
                raise
        if self._sock:
            self._sock.close()

    def set_tlsext_host_name(self, name_indication: str) -> None:
        """Set the hostname within the Server Name Indication extension in the client SSL Hello."""
        self._ssl.set_tlsext_host_name(name_indication)

    def set_cipher_list(self, cipher_list: str) -> None:
        self._ssl.set_cipher_list(cipher_list)

    def get_cipher_list(self) -> List[str]:
        return self._ssl.get_cipher_list()

    def get_current_cipher_name(self) -> str:
        return self._ssl.get_cipher_name()

    def get_current_cipher_bits(self) -> int:
        return self._ssl.get_cipher_bits()

    def get_ephemeral_key(self) -> Optional[EphemeralKeyInfo]:
        try:
            dh_info = self._ssl.get_dh_info()
        except TypeError:
            return None

        if dh_info["type"] == OpenSslEvpPkeyEnum.DH:
            return DhEphemeralKeyInfo(**dh_info)
        elif dh_info["type"] == OpenSslEvpPkeyEnum.EC:
            return NistEcDhKeyExchangeInfo(**dh_info)
        elif dh_info["type"] in [OpenSslEvpPkeyEnum.X25519, OpenSslEvpPkeyEnum.X448]:
            return EcDhEphemeralKeyInfo(**dh_info)
        else:
            return None

    def _use_private_key(
        self,
        client_certificate_chain: Path,
        client_key: Path,
        client_key_type: OpenSslFileTypeEnum,
        client_key_password: str,
    ) -> None:
        """The certificate chain file must be in PEM format. Private method because it should be set via the
        constructor.
        """
        # Ensure the files exist
        with client_certificate_chain.open():
            pass
        with client_key.open():
            pass

        self._ssl_ctx.use_certificate_chain_file(str(client_certificate_chain))
        self._ssl_ctx.set_private_key_password(client_key_password)
        try:
            self._ssl_ctx.use_PrivateKey_file(str(client_key), client_key_type.value)
        except OpenSSLError as e:
            if "bad password read" in str(e) or "bad decrypt" in str(e):
                raise ValueError("Invalid Private Key")
            else:
                raise

        self._ssl_ctx.check_private_key()

    _TLSEXT_STATUSTYPE_ocsp = 1

    def set_tlsext_status_ocsp(self) -> None:
        """Enable the OCSP Stapling extension."""
        self._ssl.set_tlsext_status_type(self._TLSEXT_STATUSTYPE_ocsp)

    def get_tlsext_status_ocsp_resp(self) -> Optional[_nassl.OCSP_RESPONSE]:
        """Retrieve the server's OCSP response.

        Will return None if OCSP Stapling was not enabled before the handshake or if the server did not return
        an OCSP response.

        The response can be parsed for example using cryptography:
            load_der_ocsp_response(ocsp_resp.as_der_bytes())
        """
        return self._ssl.get_tlsext_status_ocsp_resp()

    def get_client_CA_list(self) -> List[str]:
        return self._ssl.get_client_CA_list()

    def get_session(self) -> _nassl.SSL_SESSION:
        """Get the SSL connection's Session object."""
        return self._ssl.get_session()

    def set_session(self, ssl_session: _nassl.SSL_SESSION) -> None:
        """Set the SSL connection's Session object."""
        self._ssl.set_session(ssl_session)

    _SSL_OP_NO_TICKET = 0x00004000  # No TLS Session tickets

    def disable_stateless_session_resumption(self) -> None:
        self._ssl.set_options(self._SSL_OP_NO_TICKET)

    def get_received_chain(self) -> List[str]:
        """Returns the PEM-formatted certificate chain as sent by the server.

        The leaf certificate is at index 0.
        Each certificate can be parsed using the cryptography module at https://github.com/pyca/cryptography.
        """
        return [x509.as_pem() for x509 in self._ssl.get_peer_cert_chain()]


class OpenSslEarlyDataStatusEnum(IntEnum):
    """Early data status constants."""

    NOT_SENT = 0
    REJECTED = 1
    ACCEPTED = 2


class SslClient(BaseSslClient):
    """High level API implementing an SSL client.

    Hostname validation is NOT performed by the SslClient and MUST be implemented at the end of the SSL handshake on the
    server's certificate.
    """

    # The default client uses the modern OpenSSL
    _NASSL_MODULE = _nassl

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

    def set_groups(self, supported_groups: List[OpenSslEcNidEnum]) -> None:
        """Specify elliptic curves or DH groups that are supported by the client in descending order."""
        self._ssl.set1_groups(supported_groups)

    def get_verified_chain(self) -> List[str]:
        """Returns the verified PEM-formatted certificate chain.

        If certificate validation failed, CertificateChainValidationFailed will be raised.
        The leaf certificate is at index 0.
        Each certificate can be parsed using the cryptography module at https://github.com/pyca/cryptography.
        """
        verify_code = self._ssl.get_verify_result()
        if verify_code != 0:  # X509_V_OK
            raise CertificateChainVerificationFailed(verify_code)

        return [x509.as_pem() for x509 in self._ssl.get0_verified_chain()]
