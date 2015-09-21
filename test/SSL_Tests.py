#!/usr/bin/python2.7
import unittest
import tempfile
from nassl import _nassl, SSLV23, SSL_VERIFY_PEER, SSL_FILETYPE_PEM, TLSEXT_STATUSTYPE_ocsp

class SSL_Tests(unittest.TestCase):

    def test_new(self):
        self.assertTrue(_nassl.SSL(_nassl.SSL_CTX(SSLV23)))

    def test_new_bad(self):
        # Invalid None SSL_CTX
        self.assertRaises(TypeError, _nassl.SSL, (None))


    def test_set_verify(self):
        testSsl = _nassl.SSL(_nassl.SSL_CTX(SSLV23))
        self.assertIsNone(testSsl.set_verify(SSL_VERIFY_PEER))

    def test_set_verify_bad(self):
        # Invalid verify constant
        testSsl = _nassl.SSL(_nassl.SSL_CTX(SSLV23))
        self.assertRaises(ValueError,testSsl.set_verify, (1235))


    def test_set_bio(self):
        testSsl = _nassl.SSL(_nassl.SSL_CTX(SSLV23))
        testBio = _nassl.BIO()
        self.assertIsNone(testSsl.set_bio(testBio))

    def test_set_bio_bad(self):
        # Invalid None BIO
        testSsl = _nassl.SSL(_nassl.SSL_CTX(SSLV23))
        self.assertRaises(TypeError, testSsl.set_bio, (None))


    def test_set_connect_state(self):
        testSsl = _nassl.SSL(_nassl.SSL_CTX(SSLV23))
        self.assertIsNone(testSsl.set_connect_state())


    # Can't really unittest a full handshake, read or write
    def test_do_handshake_bad(self):
        # Connection type not set
        testSsl = _nassl.SSL(_nassl.SSL_CTX(SSLV23))
        self.assertRaisesRegexp(_nassl.OpenSSLError, 'connection type not set', testSsl.do_handshake)


    def test_do_handshake_bad_eof(self):
        # No BIO attached to the SSL object
        testSsl = _nassl.SSL(_nassl.SSL_CTX(SSLV23))
        testSsl.set_connect_state()
        self.assertRaisesRegexp(_nassl.SslError, 'An EOF was observed that violates the protocol',
                                testSsl.do_handshake)


    def test_read_bad(self):
        # No BIO attached to the SSL object
        testSsl = _nassl.SSL(_nassl.SSL_CTX(SSLV23))
        testSsl.set_connect_state()
        self.assertRaisesRegexp(_nassl.OpenSSLError, 'ssl handshake failure', testSsl.read, (128))


    def test_write_bad(self):
        # No BIO attached to the SSL object
        testSsl = _nassl.SSL(_nassl.SSL_CTX(SSLV23))
        testSsl.set_connect_state()
        self.assertRaisesRegexp(_nassl.OpenSSLError, 'ssl handshake failure', testSsl.write, ('test'))


    def test_pending(self):
        # No BIO attached to the SSL object
        testSsl = _nassl.SSL(_nassl.SSL_CTX(SSLV23))
        self.assertGreaterEqual(testSsl.pending(), 0)


    def test_get_secure_renegotiation_support(self):
        testSsl = _nassl.SSL(_nassl.SSL_CTX(SSLV23))
        self.assertFalse(testSsl.get_secure_renegotiation_support())


    def test_get_current_compression_method(self):
        testSsl = _nassl.SSL(_nassl.SSL_CTX(SSLV23))
        self.assertIsNone(testSsl.get_current_compression_method())


    def test_get_available_compression_methods_has_zlib(self):
        testSsl = _nassl.SSL(_nassl.SSL_CTX(SSLV23))
        self.assertEqual(['zlib compression'],testSsl.get_available_compression_methods())


    def test_set_tlsext_host_name(self):
        testSsl = _nassl.SSL(_nassl.SSL_CTX(SSLV23))
        self.assertIsNone(testSsl.set_tlsext_host_name('test'))

    def test_set_tlsext_host_name_bad(self):
        testSsl = _nassl.SSL(_nassl.SSL_CTX(SSLV23))
        self.assertRaises(TypeError, testSsl.set_tlsext_host_name, (None))


    def test_get_peer_certificate_bad(self):
        testSsl = _nassl.SSL(_nassl.SSL_CTX(SSLV23))
        self.assertIsNone(testSsl.get_peer_certificate())


    def test_set_cipher_list(self):
        testSsl = _nassl.SSL(_nassl.SSL_CTX(SSLV23))
        self.assertIsNone(testSsl.set_cipher_list("LOW"))

    def test_set_cipher_list_bad(self):
        # Invalid cipher string
        testSsl = _nassl.SSL(_nassl.SSL_CTX(SSLV23))
        self.assertRaises(_nassl.OpenSSLError,testSsl.set_cipher_list, ("badcipherstring"))

    def test_shutdown_bad(self):
        testSsl = _nassl.SSL(_nassl.SSL_CTX(SSLV23))
        self.assertRaisesRegexp(_nassl.OpenSSLError, 'no cipher match', testSsl.shutdown)


    def test_get_cipher_list(self):
        testSsl = _nassl.SSL(_nassl.SSL_CTX(SSLV23))
        self.assertIsNotNone(testSsl.get_cipher_list())


    def test_get_cipher_name(self):
        testSsl = _nassl.SSL(_nassl.SSL_CTX(SSLV23))
        self.assertIsNotNone(testSsl.get_cipher_name())


    def test_get_cipher_bits(self):
        testSsl = _nassl.SSL(_nassl.SSL_CTX(SSLV23))
        self.assertIsNotNone(testSsl.get_cipher_bits())


    def test_get_client_CA_list_bad(self):
        testSsl = _nassl.SSL(_nassl.SSL_CTX(SSLV23))
        self.assertEqual([],testSsl.get_client_CA_list())


    def test_get_verify_result(self):
        testSsl = _nassl.SSL(_nassl.SSL_CTX(SSLV23))
        self.assertEqual(0, testSsl.get_verify_result())


    def test_renegotiate(self):
        testSsl = _nassl.SSL(_nassl.SSL_CTX(SSLV23))
        self.assertIsNone(testSsl.renegotiate())


    def test_get_session(self):
        testSsl = _nassl.SSL(_nassl.SSL_CTX(SSLV23))
        self.assertIsNone(testSsl.get_session())

    def test_set_session_bad(self):
        testSsl = _nassl.SSL(_nassl.SSL_CTX(SSLV23))
        self.assertRaisesRegexp(TypeError, 'must be _nassl.SSL_SESSION', testSsl.set_session, None)


    def test_set_options_bad(self):
        testSsl = _nassl.SSL(_nassl.SSL_CTX(SSLV23))
        self.assertGreaterEqual(testSsl.set_options(123), 0);


    def test_set_tlsext_status_type(self):
        testSsl = _nassl.SSL(_nassl.SSL_CTX(SSLV23))
        self.assertIsNone(testSsl.set_tlsext_status_type(TLSEXT_STATUSTYPE_ocsp))


    def test_set_tlsext_status_type(self):
        testSsl = _nassl.SSL(_nassl.SSL_CTX(SSLV23))
        self.assertIsNone(testSsl.get_tlsext_status_ocsp_resp())


def main():
    unittest.main()

if __name__ == '__main__':
    main()