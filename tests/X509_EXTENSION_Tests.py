#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals
import unittest
from nassl import _nassl
from nassl.ssl_client import SslClient, OpenSslVerifyEnum
from nassl.x509_certificate import X509Certificate
import socket


class X509_EXTENSION_Tests(unittest.TestCase):

    def test_new_bad(self):
        self.assertRaises(NotImplementedError, _nassl.X509_EXTENSION, (None))


class X509_EXTENSION_Tests_Online(unittest.TestCase):

    def test(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(('www.google.com', 443))

        sslClient = SslClient(sock=sock, ssl_verify=OpenSslVerifyEnum.NONE)
        sslClient.do_handshake()
        self.x509ext = sslClient.get_peer_certificate()._x509.get_extensions()[0]

        self.assertIsNotNone(self.x509ext.get_data())
        self.assertIsNotNone(self.x509ext.get_object())
        self.assertIsNotNone(self.x509ext.get_critical())


    def test_parse_subject_alt_name(self):
        # Certificate with all sorts of SANs
        pem = """-----BEGIN CERTIFICATE-----
MIID4TCCAsmgAwIBAgIJAMeVemVoHWLHMA0GCSqGSIb3DQEBBQUAMGQxCzAJBgNV
BAYTAlVTMQswCQYDVQQIDAJWQTESMBAGA1UEBwwJU29tZXdoZXJlMQ4wDAYDVQQK
DAVNeU9yZzENMAsGA1UECwwETXlPVTEVMBMGA1UEAwwMTXlTZXJ2ZXJOYW1lMB4X
DTE2MTIyNjA3MjQ0MVoXDTE4MTIyNjA3MjQ0MVowZDELMAkGA1UEBhMCVVMxCzAJ
BgNVBAgMAlZBMRIwEAYDVQQHDAlTb21ld2hlcmUxDjAMBgNVBAoMBU15T3JnMQ0w
CwYDVQQLDARNeU9VMRUwEwYDVQQDDAxNeVNlcnZlck5hbWUwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQCfIwykqele/KvoKfnn74gzOiRCOMz92f4Iti7l
Vkw7vTQANv+MrvYrwcnAU7mp13ogbdgxfy0WJ82/RLj5jjpu1bvA/X4dIsdqhjAA
WEcZmmz2WCOp6oL420Fj3PZ0scqg8o0186NH5M5f92Iw3RpddCYE4ZF1M/+nFGWW
ivcikmQ1wZlIFtTEYOFLK6dsJCnTni43NguDP1R4yZi0WRrFBLXh/oNMUKc8wYut
YCI4aUNaDxbD2N07vJ27RWZ3JlYw7R1G0EaIJ6W5VBo+SmooEgBX+gUz6zWriywL
Yf9gTppLPWzkT5HYfRltRTXZOeUZDP4zLjbCtiW2QT2LXnmbAgMBAAGjgZUwgZIw
CwYDVR0PBAQDAgQwMBMGA1UdJQQMMAoGCCsGAQUFBwMBMG4GA1UdEQRnMGWCCHRl
c3QuY29tggkxMC4wLjEuMzSHBAoAASKHECABSGBIYAAAAAAAAAAAiIiGF2h0dHBz
Oi8vd3d3Lmdvb2dsZS5jb20vgQ10ZXN0QHRlc3QuY29tgQ50ZXN0MkB0ZXN0LmNv
bTANBgkqhkiG9w0BAQUFAAOCAQEAOigh9BwJML8XhA74wMzT6K5AoQb+VKI7BcZN
HUofmG+/wKxnXGJw4JbRUai14azsmq/FclXfB0dhRCDwJrEimeW0qzz683Kb6d/5
YH95uEvbDXGsgeNEJqMyZWR4HoIopYig/55VzT8/VkHgo9sesRyXHUUu6F8/kXVQ
+X12hrVR6ZBayrpOZK/zU8DvdsIfmp6n/ESABmKc4Utgq91Y8bwNJH6xzbBinYH6
n/vAwbwt6Cm1ewtnDyWjMX7kXDkG608n80Y1efuzfiL36oMok9/uXrm1qv4bjJnj
+9wyx/zu3r+Ij1KtUCocMMxPMnaMZzmL4Yh5l7reaOAgUTWDew==
-----END CERTIFICATE-----"""

        cert = X509Certificate.from_pem(pem)
        expected_sans = {
            'IP Address': ['10.0.1.34', ':2001:4860:4860:0:0:0:0:8888'],
            'URI': ['https://www.google.com/'],
            'DNS': ['test.com', '10.0.1.34'],
            'email': ['test@test.com', 'test2@test.com']
        }
        self.assertEqual(cert.as_dict()['extensions']['X509v3 Subject Alternative Name'], expected_sans)


    def test_parse_subject_alt_name_allsans(self):
        # Certificate with all sorts of SANs from the Python tests suite
        # https://github.com/python/cpython/blob/master/Lib/test/allsans.pem
        pem = """-----BEGIN CERTIFICATE-----
MIIDcjCCAtugAwIBAgIJAN5dc9TOWjB7MA0GCSqGSIb3DQEBCwUAMF0xCzAJBgNV
BAYTAlhZMRcwFQYDVQQHDA5DYXN0bGUgQW50aHJheDEjMCEGA1UECgwaUHl0aG9u
IFNvZnR3YXJlIEZvdW5kYXRpb24xEDAOBgNVBAMMB2FsbHNhbnMwHhcNMTYwODA1
MTAyMTExWhcNMjYwODAzMTAyMTExWjBdMQswCQYDVQQGEwJYWTEXMBUGA1UEBwwO
Q2FzdGxlIEFudGhyYXgxIzAhBgNVBAoMGlB5dGhvbiBTb2Z0d2FyZSBGb3VuZGF0
aW9uMRAwDgYDVQQDDAdhbGxzYW5zMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB
gQDqMu/0DrU40NJ4hOrg3E8LZAtEdk78tQI1Z16IQp7WX3c20xg6GE4F0ji7D/AO
ve41IifFQnjxh+dMRmeAypwBd2vTt2vZ69qS129ImN1zjL/mBAYouwnyPt6MRWIA
pdLDIB8ww9mU1WALJg1oC1FbBNoBxHHEcKzNrT39hIEfhQIDAQABo4IBODCCATQw
ggEwBgNVHREEggEnMIIBI4IHYWxsc2Fuc6AeBgMqAwSgFwwVc29tZSBvdGhlciBp
ZGVudGlmaWVyoDUGBisGAQUCAqArMCmgEBsOS0VSQkVST1MuUkVBTE2hFTAToAMC
AQGhDDAKGwh1c2VybmFtZYEQdXNlckBleGFtcGxlLm9yZ4IPd3d3LmV4YW1wbGUu
b3JnpGcwZTELMAkGA1UEBhMCWFkxFzAVBgNVBAcMDkNhc3RsZSBBbnRocmF4MSMw
IQYDVQQKDBpQeXRob24gU29mdHdhcmUgRm91bmRhdGlvbjEYMBYGA1UEAwwPZGly
bmFtZSBleGFtcGxlhhdodHRwczovL3d3dy5weXRob24ub3JnL4cEfwAAAYcQAAAA
AAAAAAAAAAAAAAAAAYgEKgMEBTANBgkqhkiG9w0BAQsFAAOBgQAy16h+F+nOmeiT
VWR0fc8F/j6FcadbLseAUaogcC15OGxCl4UYpLV88HBkABOoGCpP155qwWTwOrdG
iYPGJSusf1OnJEbvzFejZf6u078bPd9/ZL4VWLjv+FPGkjd+N+/OaqMvgj8Lu99f
3Y/C4S7YbHxxwff6C6l2Xli+q6gnuQ==
-----END CERTIFICATE-----"""

        cert = X509Certificate.from_pem(pem)
        expected_sans = {
            'othername': ['<unsupported>', '<unsupported>'],
            'URI': ['https://www.python.org/'],
            'IP Address': ['127.0.0.1', ':0:0:0:0:0:0:0:1'],
            'Registered ID': ['1.2.3.4.5'],
            'DNS': ['allsans', 'www.example.org'],
            'DirName': ['C = XY, L = Castle Anthrax, O = Python Software Foundation, CN = dirname example'],
            'email': ['user@example.org']
        }
        self.assertEqual(cert.as_dict()['extensions']['X509v3 Subject Alternative Name'], expected_sans)


    def test_parse_subject_alt_name_null_bytes(self):
        # Certificate with SANs that have null bytes, from the Python tests suite
        # https://github.com/python/cpython/blob/master/Lib/test/nullbytecert.pem
        pem = """-----BEGIN CERTIFICATE-----
MIIE2DCCA8CgAwIBAgIBADANBgkqhkiG9w0BAQUFADCBxTELMAkGA1UEBhMCVVMx
DzANBgNVBAgMBk9yZWdvbjESMBAGA1UEBwwJQmVhdmVydG9uMSMwIQYDVQQKDBpQ
eXRob24gU29mdHdhcmUgRm91bmRhdGlvbjEgMB4GA1UECwwXUHl0aG9uIENvcmUg
RGV2ZWxvcG1lbnQxJDAiBgNVBAMMG251bGwucHl0aG9uLm9yZwBleGFtcGxlLm9y
ZzEkMCIGCSqGSIb3DQEJARYVcHl0aG9uLWRldkBweXRob24ub3JnMB4XDTEzMDgw
NzEzMTE1MloXDTEzMDgwNzEzMTI1MlowgcUxCzAJBgNVBAYTAlVTMQ8wDQYDVQQI
DAZPcmVnb24xEjAQBgNVBAcMCUJlYXZlcnRvbjEjMCEGA1UECgwaUHl0aG9uIFNv
ZnR3YXJlIEZvdW5kYXRpb24xIDAeBgNVBAsMF1B5dGhvbiBDb3JlIERldmVsb3Bt
ZW50MSQwIgYDVQQDDBtudWxsLnB5dGhvbi5vcmcAZXhhbXBsZS5vcmcxJDAiBgkq
hkiG9w0BCQEWFXB5dGhvbi1kZXZAcHl0aG9uLm9yZzCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBALXq7cn7Rn1vO3aA3TrzA5QLp6bb7B3f/yN0CJ2XFj+j
pHs+Gw6WWSUDpybiiKnPec33BFawq3kyblnBMjBU61ioy5HwQqVkJ8vUVjGIUq3P
vX/wBmQfzCe4o4uM89gpHyUL9UYGG8oCRa17dgqcv7u5rg0Wq2B1rgY+nHwx3JIv
KRrgSwyRkGzpN8WQ1yrXlxWjgI9de0mPVDDUlywcWze1q2kwaEPTM3hLAmD1PESA
oY/n8A/RXoeeRs9i/Pm/DGUS8ZPINXk/yOzsR/XvvkTVroIeLZqfmFpnZeF0cHzL
08LODkVJJ9zjLdT7SA4vnne4FEbAxDbKAq5qkYzaL4UCAwEAAaOB0DCBzTAMBgNV
HRMBAf8EAjAAMB0GA1UdDgQWBBSIWlXAUv9hzVKjNQ/qWpwkOCL3XDALBgNVHQ8E
BAMCBeAwgZAGA1UdEQSBiDCBhYIeYWx0bnVsbC5weXRob24ub3JnAGV4YW1wbGUu
Y29tgSBudWxsQHB5dGhvbi5vcmcAdXNlckBleGFtcGxlLm9yZ4YpaHR0cDovL251
bGwucHl0aG9uLm9yZwBodHRwOi8vZXhhbXBsZS5vcmeHBMAAAgGHECABDbgAAAAA
AAAAAAAAAAEwDQYJKoZIhvcNAQEFBQADggEBAKxPRe99SaghcI6IWT7UNkJw9aO9
i9eo0Fj2MUqxpKbdb9noRDy2CnHWf7EIYZ1gznXPdwzSN4YCjV5d+Q9xtBaowT0j
HPERs1ZuytCNNJTmhyqZ8q6uzMLoht4IqH/FBfpvgaeC5tBTnTT0rD5A/olXeimk
kX4LxlEx5RAvpGB2zZVRGr6LobD9rVK91xuHYNIxxxfEGE8tCCWjp0+3ksri9SXx
VHWBnbM9YaL32u3hxm8sYB/Yb8WSBavJCWJJqRStVRHM1koZlJmXNx2BX4vPo6iW
RFEIPQsFZRLrtnCAiEhyT8bC2s/Njlu6ly9gtJZWSV46Q3ZjBL4q9sHKqZQ=
-----END CERTIFICATE-----"""

        cert = X509Certificate.from_pem(pem)
        expected_sans = {
            'IP Address': ['192.0.2.1', ':2001:DB8:0:0:0:0:0:1'],
            'email': ['null@python.org\x00user@example.org'],
            'DNS': ['altnull.python.org\x00example.com'],
            'URI': ['http://null.python.org\x00http://example.org']
        }
        self.assertEqual(cert.as_dict()['extensions']['X509v3 Subject Alternative Name'], expected_sans)


def main():
    unittest.main()

if __name__ == '__main__':
    main()