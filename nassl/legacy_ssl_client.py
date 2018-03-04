# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

import socket

from nassl._nassl import WantReadError, WantX509LookupError  # type: ignore

from nassl.ssl_client import SslClient, ClientCertificateRequested, OpenSslVersionEnum, OpenSslVerifyEnum, \
    OpenSslFileTypeEnum
from typing import Dict
from typing import List
from typing import Optional
from typing import Text
import sys


from nassl import _nassl_legacy  # type: ignore


class LegacySslClient(SslClient):
    """An insecure SSL client with additional debug methods that no one should ever use (insecure renegotiation, etc.).
    """

    # The legacy client uses the legacy OpenSSL
    _NASSL_MODULE = _nassl_legacy

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

        # Specific servers do not reply to a client hello that is bigger than 255 bytes
        # See http://rt.openssl.org/Ticket/Display.html?id=2771&user=guest&pass=guest
        # So we make the default cipher list smaller (to make the client hello smaller)
        if ssl_version != OpenSslVersionEnum.SSLV2:  # This makes SSLv2 fail
            self._ssl.set_cipher_list('HIGH:-aNULL:-eNULL:-3DES:-SRP:-PSK:-CAMELLIA')
        else:
            # Handshake workaround for SSL2 + IIS 7
            # TODO(AD): Provide a built-in mechansim for overriding the handshake logic
            self.do_handshake = self.do_ssl2_iis_handshake  # type: ignore

    def get_secure_renegotiation_support(self):
        # type: () -> bool
        return self._ssl.get_secure_renegotiation_support()

    def get_current_compression_method(self):
        # type: () -> Optional[Text]
        return self._ssl.get_current_compression_method()

    @staticmethod
    def get_available_compression_methods():
        # type: () -> List[Text]
        """Returns the list of SSL compression methods supported by SslClient.
        """
        return _nassl_legacy.SSL.get_available_compression_methods()

    def do_renegotiate(self):
        # type: () -> None
        """Initiate an SSL renegotiation.
        """
        if not self._is_handshake_completed:
            raise IOError('SSL Handshake was not completed; cannot renegotiate.')

        self._ssl.renegotiate()
        self.do_handshake()

    _SSL_MODE_SEND_FALLBACK_SCSV = 0x00000080

    def enable_fallback_scsv(self):
        # type: () -> None
        self._ssl.set_mode(self._SSL_MODE_SEND_FALLBACK_SCSV)

    def get_dh_param(self):
        # type: () -> Dict[str, str]
        """Retrieve the negotiated Ephemeral Diffie Helmann parameters.
        """
        d = self._openssl_str_to_dic(self._ssl.get_dh_param())
        d['GroupSize'] = d.pop('DH_Parameters').strip('( bit)')
        d['Type'] = "DH"
        d['Generator'] = d.pop('generator').split(' ')[0]
        return d

    def get_ecdh_param(self):
        # type: () -> Dict[str, str]
        """Retrieve the negotiated Ephemeral EC Diffie Helmann parameters.
        """
        d = self._openssl_str_to_dic(self._ssl.get_ecdh_param(), '        ')
        d['GroupSize'] = d.pop('ECDSA_Parameters').strip('( bit)')
        d['Type'] = "ECDH"
        if 'Cofactor' in d :
            d['Cofactor'] = d['Cofactor'].split(' ')[0]

        for k in d.keys() :
            if k.startswith('Generator') :
                d['Generator'] = d.pop(k)
                d['GeneratorType'] = k.split('_')[1].strip('()')
                break
        else :
            d['GeneratorType'] = 'Unknown'
        return d

    @staticmethod
    def _openssl_str_to_dic(s, param_tab='            '):
        # type: (str, str) -> Dict[str, str]
        """EDH and ECDH parameters pretty-printing.
        """
        d = {}  # type: Dict[Text, Text]
        to_XML = lambda x : "_".join(m for m in x.replace('-', ' ').split(' '))
        current_arg = None
        for l in s.splitlines() :
            if not l.startswith(param_tab) :
                if current_arg :
                    d[current_arg] = "0x"+d[current_arg].replace(':', '')
                    current_arg = None
                args = tuple(arg.strip() for arg in l.split(':') if arg.strip())
                if len(args) > 1 :
                    # one line parameter
                    d[to_XML(args[0])] = args[1]
                else :
                    # multi-line parameter
                    current_arg = to_XML(args[0])
                    d[current_arg] = ''
            else :
                if current_arg:
                    d[current_arg] += l.strip()
        if current_arg:
            d[current_arg] = "0x"+d[current_arg].replace(':', '')
        return d

    # TODO(AD): Allow the handshake method to be overridden instead of this
    def do_ssl2_iis_handshake(self):
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
                        #if '\x02' in handshake_data_out[2]:  # Make sure we're looking at the CMK message
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
                            first_byte = (first_byte & 0x7f) << 8
                            size = first_byte + second_byte
                            # Manually split the two records to force them to be sent separately
                            cmk_packet = handshake_data_out[0:size+2]
                            data_packet = handshake_data_out[size+2::]
                            self._sock.send(cmk_packet)

                            handshake_data_in = self._sock.recv(self._DEFAULT_BUFFER_SIZE)
                            # print repr(handshake_data_in)
                            if len(handshake_data_in) == 0:
                                raise IOError('Nassl SSL handshake failed: peer did not send data back.')
                            # Pass the data to the SSL engine
                            self._network_bio.write(handshake_data_in)
                            handshake_data_out = data_packet

                    # Send it to the peer
                    self._sock.send(handshake_data_out)
                    lengh_to_read = self._network_bio.pending()

                handshake_data_in = self._sock.recv(self._DEFAULT_BUFFER_SIZE)
                if len(handshake_data_in) == 0:
                    raise IOError('Nassl SSL handshake failed: peer did not send data back.')
                # Pass the data to the SSL engine
                self._network_bio.write(handshake_data_in)

            except WantX509LookupError:
                # Server asked for a client certificate and we didn't provide one
                raise ClientCertificateRequested(self.get_client_CA_list())
