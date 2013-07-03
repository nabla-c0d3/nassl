#!/usr/bin/python
from nassl._nassl import SSL_CTX, SSL, BIO, WantReadError, OpenSSLError
from nassl import SSLV23, SSLV2, SSL_VERIFY_PEER
from X509Certificate import X509Certificate

DEFAULT_BUFFER_SIZE = 4096

# OpenSSL certificate verification return codes. Taken from
#  https://www.openssl.org/docs/apps/verify.htm
X509_V_STRINGS = {
    0 : "ok",
    2 : "unable to get issuer certificate",
    3 : "unable to get certificate CRL",
    4 : "unable to decrypt certificate's signature",
    5 : "unable to decrypt CRL's signature",
    6 : "unable to decode issuer public key",
    7 : "certificate signature failure",
    8 : "CRL signature failure",
    9 : "certificate is not yet valid",
    10 : "certificate has expired",
    11 : "CRL is not yet valid",
    12 : "CRL has expired",
    13 : "format error in certificate's notBefore field",
    14 : "format error in certificate's notAfter field",
    15 : "format error in CRL's lastUpdate field",
    16 : "format error in CRL's nextUpdate field",
    17 : "out of memory",
    18 : "self signed certificate",
    19 : "self signed certificate in certificate chain",
    20 : "unable to get local issuer certificate",
    21 : "unable to verify the first certificate",
    22 : "certificate chain too long",
    23 : "certificate revoked",
    24 : "invalid CA certificate",
    25 : "path length constraint exceeded",
    26 : "unsupported certificate purpose",
    27 : "certificate not trusted",
    28 : "certificate rejected",
    29 : "subject issuer mismatch",
    30 : "authority and subject key identifier mismatch",
    31 : "authority and issuer serial number mismatch",
    32 : "key usage does not include certificate signing",
    50 : "application verification failure"}



class SslClient(object):
    """
    High level API implementing an SSL client.
    """
    

    def __init__(self, sock=None, sslVersion=SSLV23, sslVerifyLocations=None):
        # A Python socket handles transmission of the data
        self._sock = sock
        self._handshakeDone = False
        
        # OpenSSL objects
        # SSL_CTX
        self._sslCtx = SSL_CTX(sslVersion)
        if sslVerifyLocations:
            self._sslCtx.load_verify_locations(sslVerifyLocations)
            self._sslCtx.set_verify(SSL_VERIFY_PEER)
        
        # SSL
        self._ssl = SSL(self._sslCtx)
        # Specific servers do not reply to a client hello that is bigger than 255 bytes
        # See http://rt.openssl.org/Ticket/Display.html?id=2771&user=guest&pass=guest
        # So we make the default cipher list smaller (to make the client hello smaller)
        if sslVersion != SSLV2: # This makes SSLv2 fail
            self._ssl.set_cipher_list('HIGH:-aNULL:-eNULL:-3DES:-SRP:-PSK:-CAMELLIA') 
        
        # BIOs
        self._internalBio = BIO()
        self._networkBio = BIO()
        
        # http://www.openssl.org/docs/crypto/BIO_s_bio.html
        BIO.make_bio_pair(self._internalBio, self._networkBio)
        self._ssl.set_bio(self._internalBio)


    def do_handshake(self):
        if (self._sock == None):
            # TODO: Auto create a socket ?
            raise IOError('Internal socket set to None; cannot perform handshake.')

        self._ssl.set_connect_state()
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
                    raise IOError('Nassl SSL handshake failed: unexpected EOF')
                # Pass the data to the SSL engine
                self._networkBio.write(handshakeDataIn)


    def read(self, size):
        if (self._handshakeDone == False):
            raise IOError('SSL Handshake was not completed; cannot read data.')

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
        if (self._handshakeDone == False):
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

    
    def get_secure_renegotiation_support(self):
        return self._ssl.get_secure_renegotiation_support()
    
    
    def get_current_compression_name(self):
        #TODO: test this
        return self._ssl.get_current_compression_name()
    
    
    def set_verify(self, verifyMode):
        return self._ssl.set_verify(verifyMode)
    
    
    def set_tlsext_host_name(self, nameIndication):
        return self._ssl.set_tlsext_host_name(nameIndication)    
    
    
    def get_peer_certificate(self):
        return X509Certificate(self._ssl.get_peer_certificate())
    
    
    def set_cipher_list(self, cipherList):
        return self._ssl.set_cipher_list(cipherList)
    
    
    def get_cipher_list(self):
        return self._ssl.get_cipher_list()


    def get_cipher_name(self):
        return self._ssl.get_cipher_name()
    
    
    def get_cipher_bits(self):
        return self._ssl.get_cipher_bits()


    def use_certificate_file(self, certFile, certType):
        return self._ssl.use_certificate_file(certFile, certType)


    def use_privateKey_file(self, keyFile, keyType, keyPassword=''):
        if isinstance(keyPassword, basestring):
            self._sslCtx.set_private_key_password(keyPassword)
        else: 
            raise TypeError('keyPassword is not a string')

        return self._ssl.use_PrivateKey_file(keyFile, keyType)


    def check_private_key(self):
        return self._ssl.check_private_key()


    def get_client_CA_list(self):
        return self._ssl.get_client_CA_list()


    def get_verify_result(self):
        verifyResult = self._ssl.get_verify_result()


    def get_verify_result_string(self):
        verifyResult = self.get_verify_result()
        return X509_V_STRINGS[verifyResult]



