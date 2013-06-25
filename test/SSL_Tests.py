#!/usr/bin/python
import unittest
import nassl

class SSL_Tests(unittest.TestCase):

    def test_new(self):
        self.assertTrue(nassl.SSL(nassl.SSL_CTX(nassl.SSLV23)))

    def test_new_bad(self):
    	# Invalid None SSL_CTX
        self.assertRaises(TypeError, nassl.SSL, (None))

    
    def test_set_verify(self):
        testSsl = nassl.SSL(nassl.SSL_CTX(nassl.SSLV23))
        self.assertIsNone(testSsl.set_verify(nassl.SSL_VERIFY_PEER))

    def test_set_verify_bad(self):
    	# Invalid verify constant
    	testSsl = nassl.SSL(nassl.SSL_CTX(nassl.SSLV23))
        self.assertRaises(ValueError,testSsl.set_verify, (1235))


    def test_set_bio(self):
        testSsl = nassl.SSL(nassl.SSL_CTX(nassl.SSLV23))
        testBio = nassl.BIO()
        self.assertIsNone(testSsl.set_bio(testBio))
        
    def test_set_bio_bad(self):
        # Invalid None BIO
        testSsl = nassl.SSL(nassl.SSL_CTX(nassl.SSLV23))
        self.assertRaises(TypeError, testSsl.set_bio, (None))


    def test_set_connect_state(self):
        testSsl = nassl.SSL(nassl.SSL_CTX(nassl.SSLV23))
        self.assertIsNone(testSsl.set_connect_state())
        
        
    # Can't really unittest a full handshake, read or write
    def test_do_handshake_bad(self):
        # No BIO attached to the SSL object
        testSsl = nassl.SSL(nassl.SSL_CTX(nassl.SSLV23))
        self.assertRaisesRegexp(nassl.OpenSSLError, 'connection type not set', testSsl.do_handshake)
        
        
    def test_read_bad(self):
        # No BIO attached to the SSL object
        testSsl = nassl.SSL(nassl.SSL_CTX(nassl.SSLV23))
        testSsl.set_connect_state()
        self.assertRaisesRegexp(nassl.OpenSSLError, 'ssl handshake failure', testSsl.read, (128)) 
        
        
    def test_write_bad(self):
        # No BIO attached to the SSL object
        testSsl = nassl.SSL(nassl.SSL_CTX(nassl.SSLV23))
        testSsl.set_connect_state()
        self.assertRaisesRegexp(nassl.OpenSSLError, 'ssl handshake failure', testSsl.write, ('test'))
        
        
    def test_pending(self):
        # No BIO attached to the SSL object
        testSsl = nassl.SSL(nassl.SSL_CTX(nassl.SSLV23))
        self.assertGreaterEqual(testSsl.pending(), 0)
        
        
    def test_get_secure_renegotiation_support(self):
        testSsl = nassl.SSL(nassl.SSL_CTX(nassl.SSLV23))
        self.assertFalse(testSsl.get_secure_renegotiation_support())
        
        
    def test_get_current_compression_name(self):
        testSsl = nassl.SSL(nassl.SSL_CTX(nassl.SSLV23))
        self.assertIsNone(testSsl.get_current_compression_name())
        
        
    def test_set_tlsext_host_name(self):
        testSsl = nassl.SSL(nassl.SSL_CTX(nassl.SSLV23))
        self.assertIsNone(testSsl.set_tlsext_host_name('test'))
    
    def test_set_tlsext_host_name_bad(self):
        testSsl = nassl.SSL(nassl.SSL_CTX(nassl.SSLV23))
        self.assertRaises(TypeError, testSsl.set_tlsext_host_name, (None))
        

    def test_get_peer_certificate_bad(self):
        testSsl = nassl.SSL(nassl.SSL_CTX(nassl.SSLV23))
        self.assertIsNone(testSsl.get_peer_certificate())


    def test_set_cipher_list(self):
        testSsl = nassl.SSL(nassl.SSL_CTX(nassl.SSLV23))
        self.assertIsNone(testSsl.set_cipher_list("LOW"))

    def test_set_cipher_list_bad(self):
        # Invalid cipher string
        testSsl = nassl.SSL(nassl.SSL_CTX(nassl.SSLV23))
        self.assertRaises(nassl.OpenSSLError,testSsl.set_cipher_list, ("badcipherstring"))
 


def main():
    unittest.main()

if __name__ == '__main__':
    main()