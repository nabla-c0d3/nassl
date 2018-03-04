# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

import socket

from nassl import _nassl  # type: ignore
from nassl._nassl import WantReadError, OpenSSLError, WantX509LookupError, X509  # type: ignore

from enum import IntEnum
from typing import List
from typing import Optional
from typing import Text
from typing import Tuple
from nassl.ocsp_response import OcspResponse


class OpenSslVerifyEnum(IntEnum):
    """SSL validation options which map to the SSL_VERIFY_XXX OpenSSL constants.
    """
    NONE = 0
    PEER = 1
    FAIL_IF_NO_PEER_CERT = 2
    CLIENT_ONCE = 4


class OpenSslVersionEnum(IntEnum):
    """SSL version constants.
    """
    SSLV23 = 0
    SSLV2 = 1
    SSLV3 = 2
    TLSV1 = 3
    TLSV1_1 = 4
    TLSV1_2 = 5
    TLSV1_3 = 6


class OpenSslFileTypeEnum(IntEnum):
    """Certificate and private key format constants which map to the SSL_FILETYPE_XXX OpenSSL constants.
    """
    PEM = 1
    ASN1 = 2


class OpenSslEarlyDataStatusEnum(IntEnum):
    """Early data status constants.
    """
    NOT_SENT = 0
    REJECTED = 1
    ACCEPTED = 2


class ClientCertificateRequested(IOError):
    ERROR_MSG_CAS = 'Server requested a client certificate issued by one of the following CAs: {0}.'
    ERROR_MSG = 'Server requested a client certificate.'

    def __init__(self, ca_list):
        # type: (List[Text]) -> None
        self._ca_list = ca_list

    def __str__(self):
        exc_msg = self.ERROR_MSG

        if len(self._ca_list) > 0:
            exc_msg = self.ERROR_MSG_CAS.format(', '.join(self._ca_list))

        return exc_msg


class SslClient(object):
    """High level API implementing an SSL client.

    Hostname validation is NOT performed by the SslClient and MUST be implemented at the end of the SSL handshake on the
    server's certificate, available via get_peer_certificate().
    """

    _DEFAULT_BUFFER_SIZE = 4096


    # The default client uses the modern OpenSSL
    _NASSL_MODULE = _nassl

    def __init__(
            self,
            underlying_socket=None,                         # type: Optional[socket.socket]
            ssl_version=OpenSslVersionEnum.SSLV23,          # type: OpenSslVersionEnum
            ssl_verify=OpenSslVerifyEnum.PEER,              # type: OpenSslVerifyEnum
            ssl_verify_locations=None,                      # type: Optional[Text]
            client_certchain_file=None,                     # type: Optional[Text]
            client_key_file=None,                           # type: Optional[Text]
            client_key_type=OpenSslFileTypeEnum.PEM,        # type: OpenSslFileTypeEnum
            client_key_password='',                         # type: Text
            ignore_client_authentication_requests=False     # type: bool
    ):
        # type: (...) -> None
        self._init_base_objects(ssl_version, underlying_socket)

        # Warning: Anything that modifies the SSL_CTX must be done before creating the SSL object
        # Otherwise changes to the SSL_CTX do not get propagated to future SSL objects
        self._init_server_authentication(ssl_verify, ssl_verify_locations)
        self._init_client_authentication(client_certchain_file, client_key_file, client_key_type,
                                         client_key_password,ignore_client_authentication_requests)
        # Now create the SSL object
        self._init_ssl_objects()

    def _init_base_objects(self, ssl_version, underlying_socket):
        # type: (OpenSslVersionEnum, Optional[socket.socket]) -> None
        """Setup the socket and SSL_CTX objects.
        """
        self._is_handshake_completed = False
        self._ssl_version = ssl_version
        self._ssl_ctx = self._NASSL_MODULE.SSL_CTX(ssl_version.value)

        # A Python socket handles transmission of the data
        self._sock = underlying_socket

    def _init_server_authentication(self, ssl_verify, ssl_verify_locations):
        # type: (OpenSslVerifyEnum, Optional[Text]) -> None
        """Setup the certificate validation logic for authenticating the server.
        """
        self._ssl_ctx.set_verify(ssl_verify.value)
        if ssl_verify_locations:
            # Ensure the file exists
            with open(ssl_verify_locations):
                pass
            self._ssl_ctx.load_verify_locations(ssl_verify_locations)

    def _init_client_authentication(
            self,
            client_certchain_file,                  # type: Optional[Text]
            client_key_file,                        # type: Optional[Text]
            client_key_type,                        # type: OpenSslFileTypeEnum
            client_key_password,                    # type: Text
            ignore_client_authentication_requests   # type: bool
    ):
        # type: (...) -> None
        """Setup client authentication using the supplied certificate and key.
        """
        if client_certchain_file is not None and client_key_file is not None:
            self._use_private_key(client_certchain_file, client_key_file, client_key_type, client_key_password)

        if ignore_client_authentication_requests:
            if client_certchain_file:
                raise ValueError('Cannot enable both client_certchain_file and ignore_client_authentication_requests')

            self._ssl_ctx.set_client_cert_cb_NULL()

    def _init_ssl_objects(self):
        # type: (...) -> None
        self._ssl = self._NASSL_MODULE.SSL(self._ssl_ctx)
        self._ssl.set_connect_state()

        self._internal_bio = self._NASSL_MODULE.BIO()
        self._network_bio = self._NASSL_MODULE.BIO()

        # http://www.openssl.org/docs/crypto/BIO_s_bio.html
        self._NASSL_MODULE.BIO.make_bio_pair(self._internal_bio, self._network_bio)
        self._ssl.set_bio(self._internal_bio)
        self._ssl.set_network_bio_to_free_when_dealloc(self._network_bio)

    def set_underlying_socket(self, sock):
        # type: (socket.socket) -> None
        if self._sock:
            raise RuntimeError('A socket was already set')
        self._sock = sock

    def get_underlying_socket(self):
        # type: () -> Optional[socket.socket]
        return self._sock

    def do_handshake(self):
        # type: () -> None
        if self._sock is None:
            # TODO: Auto create a socket ?
            raise IOError('Internal socket set to None; cannot perform handshake.')

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
                    raise IOError('Nassl SSL handshake failed: peer did not send data back.')
                # Pass the data to the SSL engine
                self._network_bio.write(handshake_data_in)

            except WantX509LookupError:
                # Server asked for a client certificate and we didn't provide one
                raise ClientCertificateRequested(self.get_client_CA_list())

    def is_handshake_completed(self):
        # type: () -> bool
        return self._is_handshake_completed

    # When sending early data, client can call read even if the handshake hasn't been
    # finished yet
    def read(self, size, handshake_must_be_completed = True):
        # type: (int, bool) -> bytes
        if self._sock is None:
            raise IOError('Internal socket set to None; cannot perform handshake.')
        if handshake_must_be_completed and not self._is_handshake_completed:
            raise IOError('SSL Handshake was not completed; cannot receive data.')

        while True:
            # Receive available encrypted data from the peer
            encrypted_data = self._sock.recv(self._DEFAULT_BUFFER_SIZE)

            if len(encrypted_data) == 0:
                raise IOError('Could not read() - peer closed the connection.')

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

    def write(self, data):
        # type: (bytes) -> int
        """Returns the number of (encrypted) bytes sent.
        """
        if self._sock is None:
            raise IOError('Internal socket set to None; cannot perform handshake.')
        if not self._is_handshake_completed:
            raise IOError('SSL Handshake was not completed; cannot send data.')

        # Pass the cleartext data to the SSL engine
        self._ssl.write(data)

        # Recover the corresponding encrypted data
        final_length = self._flush_ssl_engine()

        return final_length

    def write_early_data(self, data):
        # type: (bytes) -> int
        """Returns the number of (encrypted) bytes sent.
        """
        if self._is_handshake_completed:
            raise IOError('SSL Handshake was completed; cannot send early data.')

        # Pass the cleartext data to the SSL engine
        self._ssl.write_early_data(data)

        # Recover the corresponding encrypted data
        final_length = self._flush_ssl_engine()
        return final_length

    def get_early_data_status(self):
        # type: () -> OpenSslEarlyDataStatusEnum
        return OpenSslEarlyDataStatusEnum[self._ssl.get_early_data_status()]

    def _flush_ssl_engine(self):
        # type: () -> int
        if self._sock is None:
            raise IOError('Internal socket set to None; cannot perform handshake.')

        length_to_read = self._network_bio.pending()
        final_length = length_to_read
        while length_to_read:
            encrypted_data = self._network_bio.read(length_to_read)
            # Send the encrypted data to the peer
            self._sock.send(encrypted_data)
            length_to_read = self._network_bio.pending()
            final_length += length_to_read

        return final_length

    def shutdown(self):
        # type: () -> None
        self._is_handshake_completed = False
        try:
            self._ssl.shutdown()
            self._flush_ssl_engine()
        except OpenSSLError as e:
            # Ignore "uninitialized" exception
            if 'SSL_shutdown:uninitialized' not in str(e) and 'shutdown while in init' not in str(e):
                raise

    def set_tlsext_host_name(self, name_indication):
        # type: (Text) -> None
        """Set the hostname within the Server Name Indication extension in the client SSL Hello.
        """
        self._ssl.set_tlsext_host_name(name_indication)

    def get_peer_certificate(self):
        # type: () -> Optional[X509]
        return self._ssl.get_peer_certificate()

    def get_peer_cert_chain(self):
        # type: () -> List[X509]
        """See the OpenSSL documentation for differences between get_peer_cert_chain() and get_peer_certificate().
        https://www.openssl.org/docs/ssl/SSL_get_peer_cert_chain.html
        """
        return self._ssl.get_peer_cert_chain()

    def set_cipher_list(self, cipher_list):
        # type: (Text) -> None
        self._ssl.set_cipher_list(cipher_list)

    def get_cipher_list(self):
        # type: () -> List[Text]
        return self._ssl.get_cipher_list()

    def get_current_cipher_name(self):
        # type: () -> Text
        return self._ssl.get_cipher_name()

    def get_current_cipher_bits(self):
        # type: () -> int
        return self._ssl.get_cipher_bits()

    def _use_private_key(self, client_certchain_file, client_key_file, client_key_type, client_key_password):
        # type: (Text, Text, OpenSslFileTypeEnum, Text) -> None
        """The certificate chain file must be in PEM format. Private method because it should be set via the
        constructor.
        """
        # Ensure the files exist
        with open(client_certchain_file):
            pass
        with open(client_key_file):
            pass

        self._ssl_ctx.use_certificate_chain_file(client_certchain_file)
        self._ssl_ctx.set_private_key_password(client_key_password)
        try:
            self._ssl_ctx.use_PrivateKey_file(client_key_file, client_key_type.value)
        except OpenSSLError as e:
            if 'bad password read' in str(e) or 'bad decrypt' in str(e):
                raise ValueError('Invalid Private Key')
            else:
                raise

        self._ssl_ctx.check_private_key()

    def get_certificate_chain_verify_result(self):
        # type: () -> Tuple[int, Text]
        verify_result = self._ssl.get_verify_result()
        verify_result_str = X509.verify_cert_error_string(verify_result)
        return verify_result, verify_result_str

    _TLSEXT_STATUSTYPE_ocsp = 1

    def set_tlsext_status_ocsp(self):
        # type: () -> None
        """Enable the OCSP Stapling extension.
        """
        self._ssl.set_tlsext_status_type(self._TLSEXT_STATUSTYPE_ocsp)

    def get_tlsext_status_ocsp_resp(self):
        # type: () -> Optional[OcspResponse]
        """Retrieve the server's OCSP Stapling status.
        """
        ocsp_response = self._ssl.get_tlsext_status_ocsp_resp()
        if ocsp_response:
            return OcspResponse(ocsp_response)
        else:
            return None

    def get_client_CA_list(self):
        # type: () -> List[Text]
        return self._ssl.get_client_CA_list()

    def get_session(self):
        # type: () -> _nassl.SSL_SESSION
        """Get the SSL connection's Session object.
        """
        return self._ssl.get_session()

    def set_session(self, ssl_session):
        # type: (_nassl.SSL_SESSION) -> None
        """Set the SSL connection's Session object.
        """
        self._ssl.set_session(ssl_session)

    _SSL_OP_NO_TICKET = 0x00004000  # No TLS Session tickets

    def disable_stateless_session_resumption(self):
        # type: () -> None
        self._ssl.set_options(self._SSL_OP_NO_TICKET)
