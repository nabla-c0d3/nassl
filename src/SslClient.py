
from nassl import SSL_CTX, SSL, BIO, WantReadError

DEFAULT_BUFFER_SIZE = 4096


class SslClient:

    def __init__(self, sslVersion, sock=None):
        # A Python socket handles transmission of the data
        self._socket = sock 
        
        # OpenSSL objects
        self._sock = sock
        self._sslCtx = SSL_CTX(sslVersion)
        self._ssl = SSL(self._sslCtx)
        self._internalBio = BIO()
        self._networkBio = BIO()
        
        # http://www.openssl.org/docs/crypto/BIO_s_bio.html
        BIO.make_bio_pair(self._internalBio, self._networkBio)
        self._ssl.set_bio(self._internalBio)


    def do_handshake(self):
        self._ssl.set_connect_state()
        while True:
            try:
                if self._ssl.do_handshake() == 1:
                    break # Handshake was successful

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
                    raise IOError('Handshake failed: Unexpected EOF')
                # Pass the data to the SSL engine
                self._networkBio.write(handshakeDataIn)


    def set_socket(self):
        pass
    
    def get_socket(self):
        pass


    def read(self, size):
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
        # Pass the cleartext data to the SSL engine
        self._ssl.write(data)
        
        # Recover the corresponding encrypted data
        lenToRead = self._networkBio.pending()
        while lenToRead:
            encData = self._networkBio.read(lenToRead)
            # Send the encrypted data to the peer
            self._sock.send(encData)
            lenToRead = self._networkBio.pending()

        

    def shutdown(self):
        pass




