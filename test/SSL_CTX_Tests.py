import unittest
import tempfile
import nassl

class SSL_CTX_Tests(unittest.TestCase):

    def test_new(self):
        self.assertTrue(nassl.SSL_CTX(nassl.SSLV23))

    def test_new_bad(self):
    	# Invalid protocol constant
        self.assertRaises(ValueError, nassl.SSL_CTX, (1234))

    def test_set_verify(self):
    	testCTX = nassl.SSL_CTX(nassl.SSLV23)
        self.assertIsNone(testCTX.set_verify(nassl.SSL_VERIFY_PEER))

    def test_set_verify_bad(self):
    	# Invalid verify constant
    	testCTX = nassl.SSL_CTX(nassl.SSLV23)
        self.assertRaises(ValueError,testCTX.set_verify, (1235))

    def test_set_cipher_list(self):
    	testCTX = nassl.SSL_CTX(nassl.SSLV23)
        self.assertIsNone(testCTX.set_cipher_list("LOW"))

    def test_set_cipher_list_bad(self):
    	# Invalid cipher string
    	testCTX = nassl.SSL_CTX(nassl.SSLV23)
        self.assertRaises(nassl.OpenSSLError,testCTX.set_cipher_list, ("badcipherstring"))

    def test_load_verify_locations(self):
    	testCTX = nassl.SSL_CTX(nassl.SSLV23)
    	testFile = tempfile.NamedTemporaryFile(delete=False)
    	testFile.write("""-----BEGIN CERTIFICATE-----
MIIDIDCCAomgAwIBAgIENd70zzANBgkqhkiG9w0BAQUFADBOMQswCQYDVQQGEwJV
UzEQMA4GA1UEChMHRXF1aWZheDEtMCsGA1UECxMkRXF1aWZheCBTZWN1cmUgQ2Vy
dGlmaWNhdGUgQXV0aG9yaXR5MB4XDTk4MDgyMjE2NDE1MVoXDTE4MDgyMjE2NDE1
MVowTjELMAkGA1UEBhMCVVMxEDAOBgNVBAoTB0VxdWlmYXgxLTArBgNVBAsTJEVx
dWlmYXggU2VjdXJlIENlcnRpZmljYXRlIEF1dGhvcml0eTCBnzANBgkqhkiG9w0B
AQEFAAOBjQAwgYkCgYEAwV2xWGcIYu6gmi0fCG2RFGiYCh7+2gRvE4RiIcPRfM6f
BeC4AfBONOziipUEZKzxa1NfBbPLZ4C/QgKO/t0BCezhABRP/PvwDN1Dulsr4R+A
cJkVV5MW8Q+XarfCaCMczE1ZMKxRHjuvK9buY0V7xdlfUNLjUA86iOe/FP3gx7kC
AwEAAaOCAQkwggEFMHAGA1UdHwRpMGcwZaBjoGGkXzBdMQswCQYDVQQGEwJVUzEQ
MA4GA1UEChMHRXF1aWZheDEtMCsGA1UECxMkRXF1aWZheCBTZWN1cmUgQ2VydGlm
aWNhdGUgQXV0aG9yaXR5MQ0wCwYDVQQDEwRDUkwxMBoGA1UdEAQTMBGBDzIwMTgw
ODIyMTY0MTUxWjALBgNVHQ8EBAMCAQYwHwYDVR0jBBgwFoAUSOZo+SvSspXXR9gj
IBBPM5iQn9QwHQYDVR0OBBYEFEjmaPkr0rKV10fYIyAQTzOYkJ/UMAwGA1UdEwQF
MAMBAf8wGgYJKoZIhvZ9B0EABA0wCxsFVjMuMGMDAgbAMA0GCSqGSIb3DQEBBQUA
A4GBAFjOKer89961zgK5F7WF0bnj4JXMJTENAKaSbn+2kmOeUJXRmm/kEd5jhW6Y
7qj/WsjTVbJmcVfewCHrPSqnI0kBBIZCe/zuf6IWUrVnZ9NA2zsmWLIodz2uFHdh
1voqZiegDfqnc1zqcPGUIWVEX/r87yloqaKHee9570+sB3c4
-----END CERTIFICATE-----
        """)
        testFile.close()
        self.assertIsNone(testCTX.load_verify_locations(testFile.name))

    def test_load_verify_locations_bad(self):
    	# Certificate file doesn't exist
    	testCTX = nassl.SSL_CTX(nassl.SSLV23)
        self.assertRaises(nassl.OpenSSLError, testCTX.load_verify_locations, ("test"))





def main():
    unittest.main()

if __name__ == '__main__':
    main()