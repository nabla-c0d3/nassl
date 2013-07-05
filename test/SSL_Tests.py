#!/usr/bin/python
import unittest
import tempfile
from nassl import _nassl, SSLV23, SSL_VERIFY_PEER, SSL_FILETYPE_PEM

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
        # No BIO attached to the SSL object
        testSsl = _nassl.SSL(_nassl.SSL_CTX(SSLV23))
        self.assertRaisesRegexp(_nassl.OpenSSLError, 'connection type not set', testSsl.do_handshake)
        
        
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
        
        
    def test_get_current_compression_name(self):
        testSsl = _nassl.SSL(_nassl.SSL_CTX(SSLV23))
        self.assertIsNone(testSsl.get_current_compression_name())
        
        
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


    def test_use_certificate_file(self):
        testSsl = _nassl.SSL(_nassl.SSL_CTX(SSLV23))
        testFile = tempfile.NamedTemporaryFile(delete=False)
        testFile.write("""-----BEGIN CERTIFICATE-----
MIIDCjCCAnOgAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBgDELMAkGA1UEBhMCRlIx
DjAMBgNVBAgMBVBhcmlzMQ4wDAYDVQQHDAVQYXJpczEWMBQGA1UECgwNRGFzdGFy
ZGx5IEluYzEMMAoGA1UECwwDMTIzMQ8wDQYDVQQDDAZBbCBCYW4xGjAYBgkqhkiG
9w0BCQEWC2xvbEBsb2wuY29tMB4XDTEzMDEyNzAwMDM1OFoXDTE0MDEyNzAwMDM1
OFowgZcxCzAJBgNVBAYTAkZSMQwwCgYDVQQIDAMxMjMxDTALBgNVBAcMBFRlc3Qx
IjAgBgNVBAoMGUludHJvc3B5IFRlc3QgQ2xpZW50IENlcnQxCzAJBgNVBAsMAjEy
MRUwEwYDVQQDDAxBbGJhbiBEaXF1ZXQxIzAhBgkqhkiG9w0BCQEWFG5hYmxhLWMw
ZDNAZ21haWwuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDlnvP1ltVO
8JDNT3AA99QqtiqCi/7BeEcFDm2al46mv7looz6CmB84osrusNVFsS5ICLbrCmeo
w5sxW7VVveGueBQyWynngl2PmmufA5Mhwq0ZY8CvwV+O7m0hEXxzwbyGa23ai16O
zIiaNlBAb0mC2vwJbsc3MTMovE6dHUgmzQIDAQABo3sweTAJBgNVHRMEAjAAMCwG
CWCGSAGG+EIBDQQfFh1PcGVuU1NMIEdlbmVyYXRlZCBDZXJ0aWZpY2F0ZTAdBgNV
HQ4EFgQUYR45okpFsqTYB1wlQQblLH9cRdgwHwYDVR0jBBgwFoAUP0X2HQlaca7D
NBzVbsjsdhzOqUQwDQYJKoZIhvcNAQEFBQADgYEAWEOxpRjvKvTurDXK/sEUw2KY
gmbbGP3tF+fQ/6JS1VdCdtLxxJAHHTW62ugVTlmJZtpsEGlg49BXAEMblLY/K7nm
dWN8oZL+754GaBlJ+wK6/Nz4YcuByJAnN8OeTY4Acxjhks8PrAbZgcf0FdpJaAlk
Pd2eQ9+DkopOz3UGU7c=
-----END CERTIFICATE-----
""")
        testFile.close()
        self.assertIsNone(testSsl.use_certificate_file(testFile.name, SSL_FILETYPE_PEM))

    def test_use_certificate_file_bad(self):
        # Bad filename
        testSsl = _nassl.SSL(_nassl.SSL_CTX(SSLV23))
        self.assertRaisesRegexp(_nassl.OpenSSLError, 'system lib', testSsl.use_certificate_file, 'invalidPath', SSL_FILETYPE_PEM)


    def test_use_PrivateKey_file(self):
        testSsl = _nassl.SSL(_nassl.SSL_CTX(SSLV23))
        testFile = tempfile.NamedTemporaryFile(delete=False)
        testFile.write("""-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAOWe8/WW1U7wkM1P
cAD31Cq2KoKL/sF4RwUObZqXjqa/uWijPoKYHziiyu6w1UWxLkgItusKZ6jDmzFb
tVW94a54FDJbKeeCXY+aa58DkyHCrRljwK/BX47ubSERfHPBvIZrbdqLXo7MiJo2
UEBvSYLa/AluxzcxMyi8Tp0dSCbNAgMBAAECgYAl0ZpItsEHMWQIDK9b2XWeW0aB
HeGlp9O6p3ex4IhkOmulKk3fYIKz50wZKBLYWahPwO+vopUUHLNw27PwHUgQDmOY
QKAZowO3X5RT5URNzeiI2KTE431uNFqeMR9+XrnjQIZPDDaltACTTZpFp1rFqM+C
/WbZ2VHS/52Vrrj7wQJBAPW64ts+UHNQn1Y+CyYQGVERICdPwC4nSu/+MYpvo0r+
XX1bali8kTdBs2ByoWQOaFr3B4qffd4vb8lIMxt6f3kCQQDvN7ZUsyM/HcSw/4go
pGakZx1OJKBCet6uNA6ymglhDzmFoiAR3QAIxYTVQlc87m0v4ExjVC/nlbdNa4MX
m2j1AkAHgagAbozimOnlJowMo51CXrWOvd7vCgA+CJPW2MYyOkb811gOUeRVvcoO
/jFz7wS9EqLGV0zvBp/xlCULh9hxAkEA2x+tZOiy4J3kDj4D+zaczvulXG8wXbUv
RWNqEzAGZ2IKzt4zgiluXpqPksmyH55HZhOP5Wy4dOovfjt9WaKCAQJAEzgPLx+6
iuiRanrS8dy8Q5UXavmPgBeHXZ4gxWbXD3vC5Qzorgp+P04GhofSCFklXokTPrKN
jsXbhxAIkrdmpg==
-----END PRIVATE KEY-----
""")
        testFile.close()
        self.assertIsNone(testSsl.use_PrivateKey_file(testFile.name, SSL_FILETYPE_PEM))

    def test_use_PrivateKey_file_bad(self):
        # Bad filename
        testSsl = _nassl.SSL(_nassl.SSL_CTX(SSLV23))
        self.assertRaisesRegexp(_nassl.OpenSSLError, 'uninitialized', testSsl.use_PrivateKey_file, 'invalidPath', SSL_FILETYPE_PEM)


    def test_check_private_key(self):
        testSsl = _nassl.SSL(_nassl.SSL_CTX(SSLV23))
        testFile = tempfile.NamedTemporaryFile(delete=False)
        testFile.write("""-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAOWe8/WW1U7wkM1P
cAD31Cq2KoKL/sF4RwUObZqXjqa/uWijPoKYHziiyu6w1UWxLkgItusKZ6jDmzFb
tVW94a54FDJbKeeCXY+aa58DkyHCrRljwK/BX47ubSERfHPBvIZrbdqLXo7MiJo2
UEBvSYLa/AluxzcxMyi8Tp0dSCbNAgMBAAECgYAl0ZpItsEHMWQIDK9b2XWeW0aB
HeGlp9O6p3ex4IhkOmulKk3fYIKz50wZKBLYWahPwO+vopUUHLNw27PwHUgQDmOY
QKAZowO3X5RT5URNzeiI2KTE431uNFqeMR9+XrnjQIZPDDaltACTTZpFp1rFqM+C
/WbZ2VHS/52Vrrj7wQJBAPW64ts+UHNQn1Y+CyYQGVERICdPwC4nSu/+MYpvo0r+
XX1bali8kTdBs2ByoWQOaFr3B4qffd4vb8lIMxt6f3kCQQDvN7ZUsyM/HcSw/4go
pGakZx1OJKBCet6uNA6ymglhDzmFoiAR3QAIxYTVQlc87m0v4ExjVC/nlbdNa4MX
m2j1AkAHgagAbozimOnlJowMo51CXrWOvd7vCgA+CJPW2MYyOkb811gOUeRVvcoO
/jFz7wS9EqLGV0zvBp/xlCULh9hxAkEA2x+tZOiy4J3kDj4D+zaczvulXG8wXbUv
RWNqEzAGZ2IKzt4zgiluXpqPksmyH55HZhOP5Wy4dOovfjt9WaKCAQJAEzgPLx+6
iuiRanrS8dy8Q5UXavmPgBeHXZ4gxWbXD3vC5Qzorgp+P04GhofSCFklXokTPrKN
jsXbhxAIkrdmpg==
-----END PRIVATE KEY-----
""")
        testFile.close()        
        testFile2 = tempfile.NamedTemporaryFile(delete=False)
        testFile2.write("""-----BEGIN CERTIFICATE-----
MIIDCjCCAnOgAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBgDELMAkGA1UEBhMCRlIx
DjAMBgNVBAgMBVBhcmlzMQ4wDAYDVQQHDAVQYXJpczEWMBQGA1UECgwNRGFzdGFy
ZGx5IEluYzEMMAoGA1UECwwDMTIzMQ8wDQYDVQQDDAZBbCBCYW4xGjAYBgkqhkiG
9w0BCQEWC2xvbEBsb2wuY29tMB4XDTEzMDEyNzAwMDM1OFoXDTE0MDEyNzAwMDM1
OFowgZcxCzAJBgNVBAYTAkZSMQwwCgYDVQQIDAMxMjMxDTALBgNVBAcMBFRlc3Qx
IjAgBgNVBAoMGUludHJvc3B5IFRlc3QgQ2xpZW50IENlcnQxCzAJBgNVBAsMAjEy
MRUwEwYDVQQDDAxBbGJhbiBEaXF1ZXQxIzAhBgkqhkiG9w0BCQEWFG5hYmxhLWMw
ZDNAZ21haWwuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDlnvP1ltVO
8JDNT3AA99QqtiqCi/7BeEcFDm2al46mv7looz6CmB84osrusNVFsS5ICLbrCmeo
w5sxW7VVveGueBQyWynngl2PmmufA5Mhwq0ZY8CvwV+O7m0hEXxzwbyGa23ai16O
zIiaNlBAb0mC2vwJbsc3MTMovE6dHUgmzQIDAQABo3sweTAJBgNVHRMEAjAAMCwG
CWCGSAGG+EIBDQQfFh1PcGVuU1NMIEdlbmVyYXRlZCBDZXJ0aWZpY2F0ZTAdBgNV
HQ4EFgQUYR45okpFsqTYB1wlQQblLH9cRdgwHwYDVR0jBBgwFoAUP0X2HQlaca7D
NBzVbsjsdhzOqUQwDQYJKoZIhvcNAQEFBQADgYEAWEOxpRjvKvTurDXK/sEUw2KY
gmbbGP3tF+fQ/6JS1VdCdtLxxJAHHTW62ugVTlmJZtpsEGlg49BXAEMblLY/K7nm
dWN8oZL+754GaBlJ+wK6/Nz4YcuByJAnN8OeTY4Acxjhks8PrAbZgcf0FdpJaAlk
Pd2eQ9+DkopOz3UGU7c=
-----END CERTIFICATE-----
""")
        testFile2.close()
        self.assertIsNone(testSsl.use_certificate_file(testFile2.name, SSL_FILETYPE_PEM))
        self.assertIsNone(testSsl.use_PrivateKey_file(testFile.name, SSL_FILETYPE_PEM))
        self.assertIsNone(testSsl.check_private_key())


    def test_check_private_key_bad(self):
        testSsl = _nassl.SSL(_nassl.SSL_CTX(SSLV23))
        self.assertRaisesRegexp(_nassl.OpenSSLError, 'no certificate assigned', testSsl.check_private_key)


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


def main():
    unittest.main()

if __name__ == '__main__':
    main()