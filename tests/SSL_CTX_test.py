import tempfile
from types import ModuleType

import pytest

from nassl.errors import OpenSSLError
from nassl.base_ssl_client import TlsVersionEnum, OpenSslVerifyEnum, OpenSslFileTypeEnum


import nassl.openssl_1_0_2._nassl
import nassl.openssl_1_1_1._nassl
import nassl.openssl_4_0_0._nassl


@pytest.mark.parametrize(
    "nassl_module, SSL_CTX_args",
    [
        # Not the same arguments with OpenSSL 1.0.2 VS 1.1.1 and 4.0.0
        (nassl.openssl_1_0_2._nassl, [TlsVersionEnum.TLS_1_2.value]),
        (nassl.openssl_1_1_1._nassl, []),
        (nassl.openssl_4_0_0._nassl, []),
    ],
)
class TestCommonSSL_CTX:
    def test_new(self, nassl_module: ModuleType, SSL_CTX_args: list[TlsVersionEnum]) -> None:
        assert nassl_module.SSL_CTX(*SSL_CTX_args)

    def test_set_verify(self, nassl_module: ModuleType, SSL_CTX_args: list[TlsVersionEnum]) -> None:
        test_ssl_ctx = nassl_module.SSL_CTX(*SSL_CTX_args)
        test_ssl_ctx.set_verify(OpenSslVerifyEnum.PEER.value)

    def test_set_verify_bad(self, nassl_module: ModuleType, SSL_CTX_args: list[TlsVersionEnum]) -> None:
        # Invalid verify constant
        test_ssl_ctx = nassl_module.SSL_CTX(*SSL_CTX_args)
        with pytest.raises(ValueError):
            test_ssl_ctx.set_verify(1235)

    def test_load_verify_locations(self, nassl_module: ModuleType, SSL_CTX_args: list[TlsVersionEnum]) -> None:
        test_ssl_ctx = nassl_module.SSL_CTX(*SSL_CTX_args)
        test_file = tempfile.NamedTemporaryFile(delete=False, mode="wt")
        test_file.write(
            """-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----"""
        )
        test_file.close()
        test_ssl_ctx.load_verify_locations(test_file.name)

    def test_load_verify_locations_bad(self, nassl_module: ModuleType, SSL_CTX_args: list[TlsVersionEnum]) -> None:
        # Certificate file doesn't exist
        test_ssl_ctx = nassl_module.SSL_CTX(*SSL_CTX_args)
        with pytest.raises(OpenSSLError):
            test_ssl_ctx.load_verify_locations("tests")

    def test_set_private_key_password_null_byte(
        self, nassl_module: ModuleType, SSL_CTX_args: list[TlsVersionEnum]
    ) -> None:
        # NULL byte embedded in the password
        test_ssl_ctx = nassl_module.SSL_CTX(*SSL_CTX_args)
        # It raises a TypeError on Python 2.7 and 3.4, and a ValueError on 3.5
        with pytest.raises(Exception, match=" null"):
            test_ssl_ctx.set_private_key_password("AAA\x00AAAA")

    def test_use_certificate_file(self, nassl_module: ModuleType, SSL_CTX_args: list[TlsVersionEnum]) -> None:
        test_ssl_ctx = nassl_module.SSL_CTX(*SSL_CTX_args)
        test_file = tempfile.NamedTemporaryFile(delete=False, mode="wt")
        test_file.write(
            """-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUUWfzyGnF+G0KRPNS7c6iMaXkSX4wDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yNjA0MzAxNjU2MTFaFw0yNzA0
MzAxNjU2MTFaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDTnAP5w077B0K9dpJsMkTAiNHI21EYXn2LCwLKb3YL
0cHpwkzc4T4+q7ahIiSlwHMp5wT0MhhuJUYZVJ/YQH9bPdLDuN5SoreBspVwbe5m
Ncf6DVduBdBn0vhLa+RinpEHb4EYS1rJVIsrvdLqx3yQtDaURCgm0xQfdVAoahkg
ENj+cl2IgKvdL4KX82cCerchHj6zpxgELF8EOGuLmjLslZmGnTwK4oZFWjbKLqgp
YgTyjlGK5S0LXcWr5a34XCCK3M4Bd4+IaPMyMAnqfiMkzM/bGYdyYqRboiF9Ri+U
p6i0Sl/Gs3bhXxsiKodQhXT8bc26BZQ3lj/uhpelQIpRAgMBAAGjUzBRMB0GA1Ud
DgQWBBTm2UcUD9M9eoNgTIuwwFJLwIc1+TAfBgNVHSMEGDAWgBTm2UcUD9M9eoNg
TIuwwFJLwIc1+TAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQC4
AHVSPPJ9kX2XZO6mNUspRwcBM9DDuFiGTi6dQF8fQggXzm9+KPepLa/3Oat2pvIG
j5SQdd/ePyp2OLIMkryiVk9uHkpXoZNZktf+xiae3iOZpf3iIpOryGUsPim/8oDU
Bor7kPn3Iy35hSLmx/cIPvGAdS3k+ia8c8WVXXUspYJVWLyWYgBGKHuapbCeDVNd
HcHpn/2Adg+bvn9onArcNx3bPVyio+Jox7ui4Zu8UFHdfBxA0Q1unHWIP5ovvg8z
0zniDzNPuom+YSZ6KQ3Q0PenePFveDwTFuxOuHg+Ph66pmXE8mrcScNUGPdahj/0
Aa90JFIAvU4MWQCKNoWp
-----END CERTIFICATE-----"""
        )
        test_file.close()
        test_ssl_ctx.use_certificate_chain_file(test_file.name)

    def test_use_certificate_file_bad(self, nassl_module: ModuleType, SSL_CTX_args: list[TlsVersionEnum]) -> None:
        # Bad filename
        test_ssl_ctx = nassl_module.SSL_CTX(*SSL_CTX_args)
        with pytest.raises(OpenSSLError, match="system lib"):
            test_ssl_ctx.use_certificate_chain_file("invalidPath")

    def test_use_PrivateKey_file(self, nassl_module: ModuleType, SSL_CTX_args: list[TlsVersionEnum]) -> None:
        test_ssl_ctx = nassl_module.SSL_CTX(*SSL_CTX_args)
        test_file = tempfile.NamedTemporaryFile(delete=False, mode="wt")
        test_file.write(
            """-----BEGIN PRIVATE KEY-----
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
-----END PRIVATE KEY-----"""
        )
        test_file.close()
        test_ssl_ctx.use_PrivateKey_file(test_file.name, OpenSslFileTypeEnum.PEM.value)

    def test_use_PrivateKey_file_bad(self, nassl_module: ModuleType, SSL_CTX_args: list[TlsVersionEnum]) -> None:
        # Bad filename
        test_ssl_ctx = nassl_module.SSL_CTX(*SSL_CTX_args)
        with pytest.raises(OpenSSLError, match="No such file"):
            test_ssl_ctx.use_PrivateKey_file("invalidPath", OpenSslFileTypeEnum.PEM.value)

    def test_check_private_key(self, nassl_module: ModuleType, SSL_CTX_args: list[TlsVersionEnum]) -> None:
        test_ssl_ctx = nassl_module.SSL_CTX(*SSL_CTX_args)
        test_file = tempfile.NamedTemporaryFile(delete=False, mode="wt")
        test_file.write(
            """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDTnAP5w077B0K9
dpJsMkTAiNHI21EYXn2LCwLKb3YL0cHpwkzc4T4+q7ahIiSlwHMp5wT0MhhuJUYZ
VJ/YQH9bPdLDuN5SoreBspVwbe5mNcf6DVduBdBn0vhLa+RinpEHb4EYS1rJVIsr
vdLqx3yQtDaURCgm0xQfdVAoahkgENj+cl2IgKvdL4KX82cCerchHj6zpxgELF8E
OGuLmjLslZmGnTwK4oZFWjbKLqgpYgTyjlGK5S0LXcWr5a34XCCK3M4Bd4+IaPMy
MAnqfiMkzM/bGYdyYqRboiF9Ri+Up6i0Sl/Gs3bhXxsiKodQhXT8bc26BZQ3lj/u
hpelQIpRAgMBAAECggEAPbpFqJ6SFAUmsVj81oYFazqeI57idZ7etWg1XLMN9t2t
2NA+lrI385UolbF9ikJs9by3w7o3SS4jWDFI3Y7W99k9ea2cYPOpXzKmiCDxSayH
lMg+iFA23op6tpmXCjOiL86VlG4q4g8A9/YMKEOf8SA4yaBmLAkn1hNlGhz1DlaD
ohAEC1ptqLhWFRYff2IHazvDQN21lqkgt/X3bU5hu9uNELLwyE6ZKRfUa7ceR0dj
dk9h5q7DsD8BR0c/oOtDF6AOpLMPbGEPOrt7lfLb+Md3ZhumFnnZK9DvlNv08Eit
AOwi7/2Nt+gIR2GLv2kXNJKACaIJmHb2elej08UX/wKBgQD63jQYduzBX3zfhOm+
9a/FEaKThHA+V+kKrWjIcjT9dvfxh7/tFJ/SDb4SwOpIquKqWtuRL2OfIfZxr+Qw
NWWvQQB78NdK3jqLz2Q6lZ5tDI6d/x0WoXyiM6K1uFAyP+lmvfpmxKuBncHnE0+B
Zbfeci0SRrugs2JMcQerzSSpcwKBgQDX8DcCsR30o6k2ZSQfVD8ADOjbqFyqreuq
78rpYKaW12KvEb0k0UvxsTFGVGH10knjOULeKibcFK/hJa2IH7WVbOAxkYz2sMbI
qPYiWWMoPJR01TCJBmjEsJ+VeKcKKbd/hMhfNJM2sUTBEKiy0GRJkS/Dt6liikSp
6PS5plKcKwKBgHa5wp3xaor5zfdax+UAEXeKqQ53l0dqA3hyKSz0H+/05dMBE+v3
3stihZoKgtZxSWSmK1PCwbsGL8QOIkhOfRk8AiamDL35/ms8c4rmVFv3nWdY3UNg
mcOJ/G9UE2A0rxlYv7DzUte8+Y+KrA3pPeOg1YPYxeOAAf17YM4GAFvRAoGAHjlk
Kb9KtxQ1OgTcEnqDOumTqjMdjVI8mzdnClVZ2+EX0fNEqyOUYqbvg62J7JNbfi9k
mZ4CxGks2PGiIVx22QxdMPLzbQ//MtTbZqFmTJp2GQhB+9vmzCkAnTY/AyAlq/aU
6SZ9uHkFa5R+WFDsyJNGwTkyvzUlOTb/EgEirPMCgYEApk1MXlSZ3fOwWmoUR50l
ITZxcc5j1eqYMuJ//cU0pJ3Wm7ASoyDaDV6pZDPG1gga2X95JpMmcx+hDZUnwUQK
LVZGDxernMwpy+S+/mFu9gcilngVPZUeL/muEWBgasZO4xrUfxaTHiF8p3fBqU+O
5WLKp0UZT2fkDEZxVp0M8h0=
-----END PRIVATE KEY-----"""
        )
        test_file.close()
        test_file2 = tempfile.NamedTemporaryFile(delete=False, mode="wt")
        test_file2.write(
            """-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUUWfzyGnF+G0KRPNS7c6iMaXkSX4wDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yNjA0MzAxNjU2MTFaFw0yNzA0
MzAxNjU2MTFaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDTnAP5w077B0K9dpJsMkTAiNHI21EYXn2LCwLKb3YL
0cHpwkzc4T4+q7ahIiSlwHMp5wT0MhhuJUYZVJ/YQH9bPdLDuN5SoreBspVwbe5m
Ncf6DVduBdBn0vhLa+RinpEHb4EYS1rJVIsrvdLqx3yQtDaURCgm0xQfdVAoahkg
ENj+cl2IgKvdL4KX82cCerchHj6zpxgELF8EOGuLmjLslZmGnTwK4oZFWjbKLqgp
YgTyjlGK5S0LXcWr5a34XCCK3M4Bd4+IaPMyMAnqfiMkzM/bGYdyYqRboiF9Ri+U
p6i0Sl/Gs3bhXxsiKodQhXT8bc26BZQ3lj/uhpelQIpRAgMBAAGjUzBRMB0GA1Ud
DgQWBBTm2UcUD9M9eoNgTIuwwFJLwIc1+TAfBgNVHSMEGDAWgBTm2UcUD9M9eoNg
TIuwwFJLwIc1+TAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQC4
AHVSPPJ9kX2XZO6mNUspRwcBM9DDuFiGTi6dQF8fQggXzm9+KPepLa/3Oat2pvIG
j5SQdd/ePyp2OLIMkryiVk9uHkpXoZNZktf+xiae3iOZpf3iIpOryGUsPim/8oDU
Bor7kPn3Iy35hSLmx/cIPvGAdS3k+ia8c8WVXXUspYJVWLyWYgBGKHuapbCeDVNd
HcHpn/2Adg+bvn9onArcNx3bPVyio+Jox7ui4Zu8UFHdfBxA0Q1unHWIP5ovvg8z
0zniDzNPuom+YSZ6KQ3Q0PenePFveDwTFuxOuHg+Ph66pmXE8mrcScNUGPdahj/0
Aa90JFIAvU4MWQCKNoWp
-----END CERTIFICATE-----"""
        )
        test_file2.close()
        test_ssl_ctx.use_certificate_chain_file(test_file2.name)
        test_ssl_ctx.use_PrivateKey_file(test_file.name, OpenSslFileTypeEnum.PEM.value)
        test_ssl_ctx.check_private_key()

    def test_check_private_key_bad(self, nassl_module: ModuleType, SSL_CTX_args: list[TlsVersionEnum]) -> None:
        test_ssl_ctx = nassl_module.SSL_CTX(*SSL_CTX_args)
        with pytest.raises(OpenSSLError, match="no certificate assigned"):
            test_ssl_ctx.check_private_key()

    # TODO: add get_ca_list tests
