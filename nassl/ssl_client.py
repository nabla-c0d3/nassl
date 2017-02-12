# -*- coding: utf-8 -*-
import socket

from nassl._nassl import SSL_CTX, SSL, BIO, WantReadError, OpenSSLError, X509, WantX509LookupError

from enum import Enum
from typing import List
from typing import Optional
from typing import Text
from typing import Tuple
from x509_certificate import X509Certificate
from ocsp_response import OcspResponse


class OpenSslVerifyEnum(Enum):
    """SSL validation options which map to the SSL_VERIFY_XXX OpenSSL constants.
    """
    NONE = 0
    PEER = 1
    FAIL_IF_NO_PEER_CERT =  2
    CLIENT_ONCE = 4


class OpenSslVersionEnum(Enum):
    """SSL version constants.
    """
    SSLV23 = 0
    SSLV2 = 1
    SSLV3 = 2
    TLSV1 = 3
    TLSV1_1 = 4
    TLSV1_2 = 5


class OpenSslFileTypeEnum(Enum):
    """Certificate and private key format constants which map to the SSL_FILETYPE_XXX OpenSSL constants.
    """
    PEM = 1
    ASN1 = 2


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
    """

    _DEFAULT_BUFFER_SIZE = 4096

    def __init__(
            self,
            sock=None,                                      # type: Optional[socket.socket]
            ssl_version=OpenSslVersionEnum.SSLV23,          # type: OpenSslVersionEnum
            ssl_verify=OpenSslVerifyEnum.PEER,              # type: OpenSslVerifyEnum
            ssl_verify_locations=None,                      # type: Optional[Text]
            client_certchain_file=None,                     # type: Optional[Text]
            client_key_file=None,                           # type: Optional[Text]
            client_key_type=OpenSslFileTypeEnum.PEM,        # type: OpenSslFileTypeEnum
            client_key_password=u'',                        # type: Text
            ignore_client_authentication_requests=False     # type: bool
    ):
        # type: (...) -> None

        # A Python socket handles transmission of the data
        self._sock = sock
        self._is_handshake_completed = False
        self._client_CA_list = []

        # OpenSSL objects
        # SSL_CTX
        self._ssl_ctx = SSL_CTX(ssl_version.value)
        self._ssl_ctx.set_verify(ssl_verify.value)
        if ssl_verify_locations:
            # Ensure the file exists
            with open(ssl_verify_locations):
                pass
            self._ssl_ctx.load_verify_locations(ssl_verify_locations)

        if client_certchain_file is not None:
            self._use_private_key(client_certchain_file, client_key_file, client_key_type.value, client_key_password)

        if ignore_client_authentication_requests:
            if client_certchain_file:
                raise ValueError(u'Cannot enable both client_certchain_file and ignore_client_authentication_requests')

            self._ssl_ctx.set_client_cert_cb_NULL()

        # SSL
        self._ssl = SSL(self._ssl_ctx)
        self._ssl.set_connect_state()
        # Specific servers do not reply to a client hello that is bigger than 255 bytes
        # See http://rt.openssl.org/Ticket/Display.html?id=2771&user=guest&pass=guest
        # So we make the default cipher list smaller (to make the client hello smaller)
        if ssl_version != OpenSslVersionEnum.SSLV2: # This makes SSLv2 fail
            self._ssl.set_cipher_list(u'HIGH:-aNULL:-eNULL:-3DES:-SRP:-PSK:-CAMELLIA')
        else:
            # Handshake workaround for SSL2 + IIS 7
            self.do_handshake = self.do_ssl2_iis_handshake

        # BIOs
        self._internal_bio = BIO()
        self._network_bio = BIO()

        # http://www.openssl.org/docs/crypto/BIO_s_bio.html
        BIO.make_bio_pair(self._internal_bio, self._network_bio)
        self._ssl.set_bio(self._internal_bio)


    def do_handshake(self):
        # type: () -> None
        if self._sock is None:
            # TODO: Auto create a socket ?
            raise IOError(u'Internal socket set to None; cannot perform handshake.')

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
                    raise IOError(u'Nassl SSL handshake failed: peer did not send data back.')
                # Pass the data to the SSL engine
                self._network_bio.write(handshake_data_in)

            except WantX509LookupError:
                # Server asked for a client certificate and we didn't provide one
                raise ClientCertificateRequested(self.get_client_CA_list())
                

    def do_ssl2_iis_handshake(self):
        # type: () -> None
        if self._sock is None:
            # TODO: Auto create a socket ?
            raise IOError(u'Internal socket set to None; cannot perform handshake.')

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

                    if 'SSLv2 read server verify A' in self._ssl.state_string_long():
                        # Awful h4ck for SSLv2 when connecting to IIS7 (like in the 90s)
                        # OpenSSL sends the client's CMK and data message in the same packet without
                        # waiting for the server's response, causing IIS 7 to hang on the connection.
                        # This workaround forces our client to send the CMK message, then wait for the server's
                        # response, and then send the data packet
                        if '\x02' in handshake_data_out[2]:  # Make sure we're looking at the CMK message
                            # cmk_size = handshake_data_out[0:2]
                            test1 =  int(handshake_data_out[0].encode('hex'), base=16)
                            test2 = int(handshake_data_out[1].encode('hex'), base=16)
                            test1 = (test1 & 0x7f) << 8
                            size = test1 + test2
                            # Manually split the two records to force them to be sent separately
                            cmk_packet = handshake_data_out[0:size+2]
                            data_packet = handshake_data_out[size+2::]
                            self._sock.send(cmk_packet)

                            handshake_data_in = self._sock.recv(self._DEFAULT_BUFFER_SIZE)
                            # print repr(handshake_data_in)
                            if len(handshake_data_in) == 0:
                                raise IOError(u'Nassl SSL handshake failed: peer did not send data back.')
                            # Pass the data to the SSL engine
                            self._network_bio.write(handshake_data_in)
                            handshake_data_out = data_packet

                    # Send it to the peer
                    self._sock.send(handshake_data_out)
                    lengh_to_read = self._network_bio.pending()

                handshake_data_in = self._sock.recv(self._DEFAULT_BUFFER_SIZE)
                if len(handshake_data_in) == 0:
                    raise IOError(u'Nassl SSL handshake failed: peer did not send data back.')
                # Pass the data to the SSL engine
                self._network_bio.write(handshake_data_in)

            except WantX509LookupError:
                # Server asked for a client certificate and we didn't provide one
                raise ClientCertificateRequested(self.get_client_CA_list())



    def read(self, size):
        # type: (int) -> bytes
        if not self._is_handshake_completed:
            raise IOError(u'SSL Handshake was not completed; cannot receive data.')

        while True:
            # Receive available encrypted data from the peer
            encrypted_data = self._sock.recv(self._DEFAULT_BUFFER_SIZE)

            if len(encrypted_data) == 0:
                raise IOError(u'Could not read() - peer closed the connection.')

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
        if not self._is_handshake_completed:
            raise IOError(u'SSL Handshake was not completed; cannot send data.')

        # Pass the cleartext data to the SSL engine
        self._ssl.write(data)

        # Recover the corresponding encrypted data
        final_length = self._flush_ssl_engine()

        return final_length

    def _flush_ssl_engine(self):
        # type: () -> int
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
        # type: () -> Optional[X509Certificate]
        _x509 = self._ssl.get_peer_certificate()
        if _x509:
            return X509Certificate(_x509)
        else:
            return None


    def get_peer_cert_chain(self):
        # type: () -> List[X509Certificate]
        """See the OpenSSL documentation for differences between get_peer_cert_chain() and get_peer_certificate().
        https://www.openssl.org/docs/ssl/SSL_get_peer_cert_chain.html
        """
        x509_list = self._ssl.get_peer_cert_chain()
        final_list = []
        if x509_list:
            for x509_cert in x509_list:
                final_list.append(X509Certificate(x509_cert))
        return final_list


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
            if u'bad password read' in str(e) or u'bad decrypt' in str(e):
                raise ValueError(u'Invalid Private Key')
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
        if not self._client_CA_list:
            self._client_CA_list = self._ssl.get_client_CA_list()
        return self._client_CA_list
