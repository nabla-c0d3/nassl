# -*- coding: utf-8 -*-
from nassl._nassl import SSL, SSL_SESSION
from ssl_client import SslClient
from typing import Dict
from typing import List
from typing import Optional
from typing import Text


class DebugSslClient(SslClient):
    """An SSL client with additional debug methods that no one should ever use (insecure renegotiation, etc.).
    """

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
        return SSL.get_available_compression_methods()


    def do_renegotiate(self):
        # type: () -> None
        """Initiate an SSL renegotiation.
        """
        if not self._is_handshake_completed:
            raise IOError(u'SSL Handshake was not completed; cannot renegotiate.')

        self._ssl.renegotiate()
        self.do_handshake()


    def get_session(self):
        # type: () -> SSL_SESSION
        """Get the SSL connection's Session object.
        """
        return self._ssl.get_session()


    def set_session(self, ssl_session):
        # type: (SSL_SESSION) -> None
        """Set the SSL connection's Session object.
        """
        self._ssl.set_session(ssl_session)


    _SSL_OP_NO_TICKET = 0x00004000  # No TLS Session tickets

    def disable_stateless_session_resumption(self):
        # type: () -> None
        self._ssl.set_options(self._SSL_OP_NO_TICKET)


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
        d = {}
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
                d[current_arg] += l.strip()
        if current_arg :
            d[current_arg] = "0x"+d[current_arg].replace(':', '')
        return d


