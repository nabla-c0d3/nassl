#!/usr/bin/python
from nassl._nassl import SSL_CTX, SSL, BIO, WantReadError, OpenSSLError, X509, WantX509LookupError
from nassl import SSLV23, SSLV2, SSL_VERIFY_PEER, TLSEXT_STATUSTYPE_ocsp
from X509Certificate import X509Certificate
from OcspResponse import OcspResponse

DEFAULT_BUFFER_SIZE = 4096


class ClientCertificateRequested(Exception):

    ERROR_MSG_CAS = 'Server requested a client certificate issued by one of the ' +\
    'following CAs: {0}.'
    ERROR_MSG = 'Server requested a client certificate.'

    def __init__(self, caList):
        self._caList = caList

    def __str__(self):
        exc_msg = ''
        if len(self._caList) > 0:
            caListStr = ''
            for ca in self._caList:
                if len(caListStr) > 0:
                    caListStr += ', '
                caListStr += '\'' + ca + '\''
            exc_msg = self.ERROR_MSG_CAS.format(caListStr)
        else:
            exc_msg = self.ERROR_MSG
        return exc_msg



class SslClient(object):
    """
    High level API implementing an insecure SSL client.
    """


    def __init__(self, sock=None, sslVersion=SSLV23, sslVerify=SSL_VERIFY_PEER, sslVerifyLocations=None):
        # A Python socket handles transmission of the data
        self._sock = sock
        self._handshakeDone = False

        # OpenSSL objects
        # SSL_CTX
        self._sslCtx = SSL_CTX(sslVersion)
        self._sslCtx.set_verify(sslVerify)
        if sslVerifyLocations:
            self._sslCtx.load_verify_locations(sslVerifyLocations)

        # SSL
        self._ssl = SSL(self._sslCtx)
        self._ssl.set_connect_state()
        # Specific servers do not reply to a client hello that is bigger than 255 bytes
        # See http://rt.openssl.org/Ticket/Display.html?id=2771&user=guest&pass=guest
        # So we make the default cipher list smaller (to make the client hello smaller)
        if sslVersion != SSLV2: # This makes SSLv2 fail
            self._ssl.set_cipher_list('HIGH:-aNULL:-eNULL:-3DES:-SRP:-PSK:-CAMELLIA')
        else:
            # Handshake workaround for SSL2 + IIS 7
            self.do_handshake = self.do_ssl2_iis_handshake

        # BIOs
        self._internalBio = BIO()
        self._networkBio = BIO()

        # http://www.openssl.org/docs/crypto/BIO_s_bio.html
        BIO.make_bio_pair(self._internalBio, self._networkBio)
        self._ssl.set_bio(self._internalBio)


    def do_handshake(self):
        if self._sock is None:
            # TODO: Auto create a socket ?
            raise IOError('Internal socket set to None; cannot perform handshake.')

        while True:
            try:
                if self._ssl.do_handshake() == 1:
                    self._handshakeDone = True
                    return True # Handshake was successful

            except WantReadError:
                # OpenSSL is expecting more data from the peer
                # Send available handshake data to the peer
                lenToRead = self._networkBio.pending()
                while lenToRead:
                    # Get the data from the SSL engine
                    handshakeDataOut = self._networkBio.read(lenToRead)
                    # Send it to the peer
                    self._sock.send(handshakeDataOut)
                    lenToRead = self._networkBio.pending()

                # Recover the peer's encrypted response
                handshakeDataIn = self._sock.recv(DEFAULT_BUFFER_SIZE)
                if len(handshakeDataIn) == 0:
                    raise IOError('Nassl SSL handshake failed: peer did not send data back.')
                # Pass the data to the SSL engine
                self._networkBio.write(handshakeDataIn)

            except WantX509LookupError:
                # Server asked for a client certificate and we didn't provide one
                raise ClientCertificateRequested(self._ssl.get_client_CA_list())


    def do_ssl2_iis_handshake(self):
        if self._sock is None:
            # TODO: Auto create a socket ?
            raise IOError('Internal socket set to None; cannot perform handshake.')

        while True:
            try:
                if self._ssl.do_handshake() == 1:
                    self._handshakeDone = True
                    return True # Handshake was successful

            except WantReadError:
                # OpenSSL is expecting more data from the peer
                # Send available handshake data to the peer
                lenToRead = self._networkBio.pending()
                while lenToRead:
                    # Get the data from the SSL engine
                    handshakeDataOut = self._networkBio.read(lenToRead)

                    if 'SSLv2 read server verify A' in self._ssl.state_string_long():
                        # Awful h4ck for SSLv2 when connecting to IIS7 (like in the 90s)
                        # OpenSSL sends the client's CMK and data message in the same packet without
                        # waiting for the server's response, causing IIS 7 to hang on the connection.
                        # This workaround forces our client to send the CMK message, then wait for the server's
                        # response, and then send the data packet
                        if '\x02' in handshakeDataOut[2]:  # Make sure we're looking at the CMK message
                            cmkSize = handshakeDataOut[0:2]
                            test1 =  int(handshakeDataOut[0].encode('hex'), base=16)
                            test2 = int(handshakeDataOut[1].encode('hex'), base=16)
                            test1 = (test1 & 0x7f) << 8
                            size = test1 + test2
                            # Manually split the two records to force them to be sent separately
                            cmkPacket = handshakeDataOut[0:size+2]
                            dataPacket = handshakeDataOut[size+2::]
                            self._sock.send(cmkPacket)
                            handshakeDataIn = self._sock.recv(DEFAULT_BUFFER_SIZE)
                            #print repr(handshakeDataIn)
                            if len(handshakeDataIn) == 0:
                                raise IOError('Nassl SSL handshake failed: peer did not send data back.')
                            # Pass the data to the SSL engine
                            self._networkBio.write(handshakeDataIn)
                            handshakeDataOut = dataPacket

                    # Send it to the peer
                    self._sock.send(handshakeDataOut)
                    lenToRead = self._networkBio.pending()

                handshakeDataIn = self._sock.recv(DEFAULT_BUFFER_SIZE)
                if len(handshakeDataIn) == 0:
                    raise IOError('Nassl SSL handshake failed: peer did not send data back.')
                # Pass the data to the SSL engine
                self._networkBio.write(handshakeDataIn)

            except WantX509LookupError:
                # Server asked for a client certificate and we didn't provide one
                raise ClientCertificateRequested(self._ssl.get_client_CA_list())



    def read(self, size):
        if not self._handshakeDone:
            raise IOError('SSL Handshake was not completed; cannot receive data.')

        while True:
            # Receive available encrypted data from the peer
            encData = self._sock.recv(DEFAULT_BUFFER_SIZE)
            # Pass it to the SSL engine
            self._networkBio.write(encData)

            try:
                # Try to read the decrypted data
                decData = self._ssl.read(size)
                return decData

            except WantReadError:
                # The SSL engine needs more data
                # before it can decrypt the whole message
                pass


    def write(self, data):
        """
        Returns the number of (encrypted) bytes sent.
        """
        if not self._handshakeDone:
            raise IOError('SSL Handshake was not completed; cannot send data.')

        # Pass the cleartext data to the SSL engine
        self._ssl.write(data)

        # Recover the corresponding encrypted data
        lenToRead = self._networkBio.pending()
        finalLen = lenToRead
        while lenToRead:
            encData = self._networkBio.read(lenToRead)
            # Send the encrypted data to the peer
            self._sock.send(encData)
            lenToRead = self._networkBio.pending()
            finalLen += lenToRead

        return finalLen


    def shutdown(self):
        self._handshakeDone = False
        try:
            self._ssl.shutdown()
        except OpenSSLError as e:
            # Ignore "uninitialized" exception
            if 'SSL_shutdown:uninitialized' not in str(e):
                raise


    def set_verify(self, verifyMode):
        """Set the OpenSSL verify mode."""
        return self._ssl.set_verify(verifyMode)


    def set_tlsext_host_name(self, nameIndication):
        """Set the hostname within the Server Name Indication extension in the client SSL Hello."""
        return self._ssl.set_tlsext_host_name(nameIndication)


    def get_peer_certificate(self):
        _x509 = self._ssl.get_peer_certificate()
        if _x509:
            return X509Certificate(_x509)
        else:
            return None


    def get_peer_cert_chain(self):
        """
        See the OpenSSL documentation for differences between get_peer_cert_chain() and get_peer_certificate().
        https://www.openssl.org/docs/ssl/SSL_get_peer_cert_chain.html
        """
        _x509_list = self._ssl.get_peer_cert_chain()
        final_list = []
        if _x509_list:
            for _x509 in _x509_list:
                final_list.append(X509Certificate(_x509))

        return final_list


    def set_cipher_list(self, cipherList):
        return self._ssl.set_cipher_list(cipherList)


    def get_cipher_list(self):
        return self._ssl.get_cipher_list()


    def get_current_cipher_name(self):
        return self._ssl.get_cipher_name()


    def get_current_cipher_bits(self):
        return self._ssl.get_cipher_bits()


    def use_private_key(self, certFile, certType, keyFile, keyType, keyPassword=''):

        self._ssl.use_certificate_file(certFile, certType)

        if isinstance(keyPassword, basestring):
            self._sslCtx.set_private_key_password(keyPassword)
        else:
            raise TypeError('keyPassword is not a string')

        self._ssl.use_PrivateKey_file(keyFile, keyType)
        return self._ssl.check_private_key()


    def get_certificate_chain_verify_result(self):
        verifyResult = self._ssl.get_verify_result()
        verifyResultStr = X509.verify_cert_error_string(verifyResult)
        return verifyResult, verifyResultStr


    def set_tlsext_status_ocsp(self):
        """Enable the OCSP Stapling extension."""
        return self._ssl.set_tlsext_status_type(TLSEXT_STATUSTYPE_ocsp)


    def get_tlsext_status_ocsp_resp(self):
        """Retrieve the server's OCSP Stapling status."""
        ocspResp = self._ssl.get_tlsext_status_ocsp_resp()
        if ocspResp:
            return OcspResponse(ocspResp)
        else:
            return None

