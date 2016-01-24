#!/usr/bin/python2.7
from nassl._nassl import SSL
from ssl_client import SslClient



class DebugSslClient(SslClient):
    """
    An SSL client with additional debug methods that no one should ever use (insecure renegotiation, etc.).
    """

    def get_secure_renegotiation_support(self):
        return self._ssl.get_secure_renegotiation_support()


    def get_current_compression_method(self):
        return self._ssl.get_current_compression_method()


    @staticmethod
    def get_available_compression_methods():
        """
        Returns the list of SSL compression methods supported by SslClient.
        """
        return SSL.get_available_compression_methods()


    def do_renegotiate(self):
        """Initiate an SSL renegotiation."""
        if not self._is_handshake_completed:
            raise IOError('SSL Handshake was not completed; cannot renegotiate.')

        self._ssl.renegotiate()
        return self.do_handshake()


    def get_session(self):
        """Get the SSL connection's Session object."""
        return self._ssl.get_session()


    def set_session(self, ssl_session):
        """Set the SSL connection's Session object."""
        return self._ssl.set_session(ssl_session)


    def set_options(self, options):
        return self._ssl.set_options(options)


    def get_dh_param(self):
        """Retrieve the negotiated Ephemeral Diffie Helmann parameters."""
        d = self._openssl_str_to_dic(self._ssl.get_dh_param())
        d['GroupSize'] = d.pop('DH_Parameters').strip('( bit)')
        d['Type'] = "DH"
        d['Generator'] = d.pop('generator').split(' ')[0]
        return d


    def get_ecdh_param(self):
        """Retrieve the negotiated Ephemeral EC Diffie Helmann parameters."""
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
        """EDH and ECDH parameters pretty-printing."""
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


