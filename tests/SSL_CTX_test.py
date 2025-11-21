import tempfile

import pytest

from nassl import _nassl
from nassl.ssl_client import OpenSslVersionEnum, OpenSslVerifyEnum, OpenSslFileTypeEnum
from tests.test_helpers import NASSL_MODULES, MODERN_NASSL_MODULES


@pytest.mark.parametrize("nassl_module", NASSL_MODULES)
class TestCommonSSL_CTX:
    KEY = """-----BEGIN PRIVATE KEY-----
          MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDcv8sh+L2buSdu
          It3UBHd4bHl7waq8E//F1yjbfeYMtHCR6cgiapVJAw9z5FJxm8R0NAFED+/vOpk3
          jh0WoE7NmwGA3afJc/5tfkhjiXkEAvV5sSHOBKqxlvYIZNtHIy1zmgRGPFuUyvVz
          7DnVvBGly4Ye13l1OnKMgy2bCmcu2DOjdwBhbGYvINrUZb+1gb5oH8tKYtWSSjN3
          XPj8NKXP9eO+BXswLC0SFlMAeVwIR/CHxUdvs8erKGIqzW9fAi7tWn64vdVpS+Oc
          nGG/XOjWU8KzlWQGAXnHvkgLlRduQvYOFmYQmblDpnbOyRRbBBtVFPpAW8D8hL5B
          QCzq70ELAgMBAAECggEAENp1vEC83SQ8LezsibDTnDaP6dJl4hkWyHh+To+kniiy
          hXlXRcVkY2Af8GWoo7LUQ1jrFdKvq1CKfRLVBrKzgYAJk9iYZEl+Tca76RmISzWc
          ny9WWN/DVm6jlw14Lkyxvicul1wpU8lRBwosejRzFnjc4wLpa3lMYIztUO5w5UMJ
          FaViyjYsfT5SdKmNxPD6k59ZszbZNa5P60OMOD9DKiq9gJdct3raaTvg0rY/S5ue
          eSuQH4w+dIIB6wIKMMm5xbADkgRQHI6c54Ivs3kIsMqzj8zQANh86fF9NzCxvCW3
          b9ZkrAVYuLOn2TUbr29xeQnp/74iiApQ91I4ZfwUDQKBgQDupb8uhs4adjJgxs/e
          cAHDVYeJiMhaD8JSiRaAAQyk7oV6OHFMkhei+kCfNINP0K4Oz+pWo7NkaPWKuEEH
          hx8i1dH91JxNSjkGO/g9BBls966bjN0+id5LYy7Of/36YR4mnkCCimO14Vvz5bYw
          V0+9IliRko5PCdT+9fr5YY+vRwKBgQDszOIiw+CyVh4ZtjJRZeZVcvDOOWbjJDVf
          C+03rjTMixQuGmwhX8I4yewpFgSG3XrSJkQET3L4Quq0Mc1mSqcHUAD7YGotpOhf
          98aKaYRM73vR3EgoeEzxiVo69llWKJ8WoQnfACjtqYshEOG6NgslqaW3NTouOSW7
          RUZKRMNqHQKBgGHB56TJd9gDHvPhvPjjbPV1LcY7D8dEuVdR7LOWunU9d9PvFwpE
          tgX++UW+HyQs2YAbz2SaPjwdeqfOfmT1Bt4gNJsD4tsOUnmpSzDDYx7t/sqdU2vw
          0eyTvnK8n29XJSCwpsBSrDGvFRm9uXnn6jQRw7IuFLlvz555aMuLGW61AoGAdW8B
          8oW7iBWHJe8iMxXazaOL4mm7KYgKY9FxWfytuIZ8goSd/UsU8b7JvHJr2ko6H7/U
          WWLhPFdLOAO+vizleo3lfsSIw4wVpYomTvwXHWRivmeE7XUDi4E3WyhSk5TfmIRS
          deIJaht7oPFTUFp+2rWwNhRSfxveJ2oqeqhxVM0CgYEAzdB1t38X2PdxIoUPFSzl
          YY6LF9kCfjo677vST5bthcWI0kTnCgkY++FsR9bncozvou/C9keOa35AMj+q3Erg
          i37hSBkj4Q0z1hExFVdDTPBRn5kpZZ0uBXrejYUQYG0uupkZ7ZghI2tlWKynppFx
          Ql6fTe81EAJKeTwww/msXRM=
          -----END PRIVATE KEY-----"""

    CERT = """-----BEGIN CERTIFICATE-----
           MIID8DCCAtigAwIBAgIUPKePcjuBmkDYjcYbL0mG9UfG4MQwDQYJKoZIhvcNAQEL
           BQAwgZcxCzAJBgNVBAYTAkZSMQwwCgYDVQQIDAMxMjMxDTALBgNVBAcMBFRlc3Qx
           IjAgBgNVBAoMGUludHJvc3B5IFRlc3QgQ2xpZW50IENlcnQxCzAJBgNVBAsMAjEy
           MRUwEwYDVQQDDAxBbGJhbiBEaXF1ZXQxIzAhBgkqhkiG9w0BCQEWFG5hYmxhLWMw
           ZDNAZ21haWwuY29tMB4XDTI1MTEyMTAxNTYwNloXDTM1MTExOTAxNTYwNlowgZcx
           CzAJBgNVBAYTAkZSMQwwCgYDVQQIDAMxMjMxDTALBgNVBAcMBFRlc3QxIjAgBgNV
           BAoMGUludHJvc3B5IFRlc3QgQ2xpZW50IENlcnQxCzAJBgNVBAsMAjEyMRUwEwYD
           VQQDDAxBbGJhbiBEaXF1ZXQxIzAhBgkqhkiG9w0BCQEWFG5hYmxhLWMwZDNAZ21h
           aWwuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3L/LIfi9m7kn
           biLd1AR3eGx5e8GqvBP/xdco233mDLRwkenIImqVSQMPc+RScZvEdDQBRA/v7zqZ
           N44dFqBOzZsBgN2nyXP+bX5IY4l5BAL1ebEhzgSqsZb2CGTbRyMtc5oERjxblMr1
           c+w51bwRpcuGHtd5dTpyjIMtmwpnLtgzo3cAYWxmLyDa1GW/tYG+aB/LSmLVkkoz
           d1z4/DSlz/XjvgV7MCwtEhZTAHlcCEfwh8VHb7PHqyhiKs1vXwIu7Vp+uL3VaUvj
           nJxhv1zo1lPCs5VkBgF5x75IC5UXbkL2DhZmEJm5Q6Z2zskUWwQbVRT6QFvA/IS+
           QUAs6u9BCwIDAQABozIwMDAdBgNVHQ4EFgQUCKGkCzTOT8ShwlVzCG0TljYmHiYw
           DwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAwJVtxIgoeACuiYPp
           /uOFBY3Iq070YrzQWENOW6UIbGwizNoMBx4EVWxn0+dGW+0ejQAfEiJpjcFkZWY7
           vupGDfWLiXd9T61YWJBwLEsnGmFa1O8RNXjarfjLXWcYBm4mbam1UZDG6mJ8SPv1
           xC/zGN/p53Tc2ytxRQUwu7bf4beE6kbKQoLQ1A1DZsLeTozTg+GPmOlXGb7g7gP/
           pTXNNAqhzvtZ2oJwIAzZEJT/nkLgU8vvmcR9ckreH1fdcOBXPTavmrkEbz98eJRw
           uQyh5TqJvERj4wv7E2GQX6ws/+XqUhPSNQbrhkDyaFnNecEM+dymuCUhuI93t+We
           AEkZ5g==
           -----END CERTIFICATE-----"""
    def test_new(self, nassl_module):
        assert nassl_module.SSL_CTX(OpenSslVersionEnum.SSLV23.value)

    def test_new_bad(self, nassl_module):
        # Invalid protocol constant
        with pytest.raises(ValueError):
            nassl_module.SSL_CTX(1234)

    def test_set_verify(self, nassl_module):
        test_ssl_ctx = nassl_module.SSL_CTX(OpenSslVersionEnum.SSLV23.value)
        test_ssl_ctx.set_verify(OpenSslVerifyEnum.PEER.value)

    def test_set_verify_bad(self, nassl_module):
        # Invalid verify constant
        test_ssl_ctx = nassl_module.SSL_CTX(OpenSslVersionEnum.SSLV23.value)
        with pytest.raises(ValueError):
            test_ssl_ctx.set_verify(1235)

    def test_load_verify_locations(self, nassl_module):
        test_ssl_ctx = nassl_module.SSL_CTX(OpenSslVersionEnum.SSLV23.value)
        test_file = tempfile.NamedTemporaryFile(delete=False, mode="wt")
        test_file.write(self.CERT)
        test_file.close()
        test_ssl_ctx.load_verify_locations(test_file.name)

    def test_load_verify_locations_bad(self, nassl_module):
        # Certificate file doesn't exist
        # OpenSSL 1.1.1: error:02001002:system library:fopen:No such file or directory
        # OpenSSL 3.x: error:05800088:x509 certificate routines::no certificate or crl found
        test_ssl_ctx = nassl_module.SSL_CTX(OpenSslVersionEnum.SSLV23.value)
        with pytest.raises(_nassl.OpenSSLError, match="(system library|x509 certificate routines|no certificate or crl found)"):
            test_ssl_ctx.load_verify_locations("tests")

    def test_set_private_key_password_null_byte(self, nassl_module):
        # NULL byte embedded in the password
        test_ssl_ctx = nassl_module.SSL_CTX(OpenSslVersionEnum.SSLV23.value)
        # It raises a TypeError on Python 2.7 and 3.4, and a ValueError on 3.5
        with pytest.raises(Exception, match=" null"):
            test_ssl_ctx.set_private_key_password("AAA\x00AAAA")

    def test_use_certificate_file(self, nassl_module):
        test_ssl_ctx = nassl_module.SSL_CTX(OpenSslVersionEnum.SSLV23.value)
        test_file = tempfile.NamedTemporaryFile(delete=False, mode="wt")
        test_file.write(self.CERT)
        test_file.close()
        test_ssl_ctx.use_certificate_chain_file(test_file.name)

    def test_use_certificate_file_bad(self, nassl_module):
        # Bad filename
        test_ssl_ctx = nassl_module.SSL_CTX(OpenSslVersionEnum.SSLV23.value)
        with pytest.raises(_nassl.OpenSSLError, match="No such file"):
            test_ssl_ctx.use_certificate_chain_file("invalidPath")

    def test_use_PrivateKey_file(self, nassl_module):
        test_ssl_ctx = nassl_module.SSL_CTX(OpenSslVersionEnum.SSLV23.value)
        test_file = tempfile.NamedTemporaryFile(delete=False, mode="wt")
        test_file.write(self.KEY)
        test_file.close()
        test_ssl_ctx.use_PrivateKey_file(test_file.name, OpenSslFileTypeEnum.PEM.value)

    def test_use_PrivateKey_file_bad(self, nassl_module):
        # Bad filename
        test_ssl_ctx = nassl_module.SSL_CTX(OpenSslVersionEnum.SSLV23.value)
        with pytest.raises(_nassl.OpenSSLError, match="No such file"):
            test_ssl_ctx.use_PrivateKey_file("invalidPath", OpenSslFileTypeEnum.PEM.value)

    def test_check_private_key(self, nassl_module):
        test_ssl_ctx = nassl_module.SSL_CTX(OpenSslVersionEnum.SSLV23.value)
        test_file = tempfile.NamedTemporaryFile(delete=False, mode="wt")
        test_file.write(self.KEY)
        test_file.close()
        test_file2 = tempfile.NamedTemporaryFile(delete=False, mode="wt")
        test_file2.write(self.CERT)
        test_file2.close()
        test_ssl_ctx.use_certificate_chain_file(test_file2.name)
        test_ssl_ctx.use_PrivateKey_file(test_file.name, OpenSslFileTypeEnum.PEM.value)
        test_ssl_ctx.check_private_key()

    def test_check_private_key_bad(self, nassl_module):
        test_ssl_ctx = nassl_module.SSL_CTX(OpenSslVersionEnum.SSLV23.value)
        with pytest.raises(_nassl.OpenSSLError, match="no certificate assigned"):
            test_ssl_ctx.check_private_key()

    # TODO: add get_ca_list tests


@pytest.mark.parametrize("nassl_module", MODERN_NASSL_MODULES)
class TestModernSSL_CTX:
    def test_tlsv1_3(self, nassl_module):
        ssl_ctx = nassl_module.SSL_CTX(OpenSslVersionEnum.TLSV1_3)
        assert ssl_ctx
