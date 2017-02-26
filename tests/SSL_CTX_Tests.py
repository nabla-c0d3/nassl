#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals
import unittest
import tempfile
from nassl import _nassl
from nassl.ssl_client import OpenSslVersionEnum, OpenSslVerifyEnum, OpenSslFileTypeEnum


class SSL_CTX_Tests(unittest.TestCase):

    def test_new(self):
        self.assertTrue(_nassl.SSL_CTX(OpenSslVersionEnum.SSLV23.value))

    def test_new_bad(self):
        # Invalid protocol constant
        self.assertRaises(ValueError, _nassl.SSL_CTX, (1234))

    def test_set_verify(self):
        test_ssl_ctx = _nassl.SSL_CTX(OpenSslVersionEnum.SSLV23.value)
        self.assertIsNone(test_ssl_ctx.set_verify(OpenSslVerifyEnum.PEER.value))

    def test_set_verify_bad(self):
        # Invalid verify constant
        test_ssl_ctx = _nassl.SSL_CTX(OpenSslVersionEnum.SSLV23.value)
        self.assertRaises(ValueError, test_ssl_ctx.set_verify, (1235))

    def test_load_verify_locations(self):
        test_ssl_ctx = _nassl.SSL_CTX(OpenSslVersionEnum.SSLV23.value)
        test_file = tempfile.NamedTemporaryFile(delete=False, mode='wt')
        test_file.write("""-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----""")
        test_file.close()
        self.assertIsNone(test_ssl_ctx.load_verify_locations(test_file.name))

    def test_load_verify_locations_bad(self):
        # Certificate file doesn't exist
        test_ssl_ctx = _nassl.SSL_CTX(OpenSslVersionEnum.SSLV23.value)
        self.assertRaises(_nassl.OpenSSLError, test_ssl_ctx.load_verify_locations, 'tests')

    def test_set_private_key_password_null_byte(self):
        # NULL byte embedded in the password
        test_ssl_ctx = _nassl.SSL_CTX(OpenSslVersionEnum.SSLV23.value)
        self.assertRaisesRegexp(TypeError, 'without null', test_ssl_ctx.set_private_key_password, ('AAA\x00AAAA'))


    def test_use_certificate_file(self):
        test_ssl_ctx = _nassl.SSL_CTX(OpenSslVersionEnum.SSLV23.value)
        test_file = tempfile.NamedTemporaryFile(delete=False, mode='wt')
        test_file.write("""-----BEGIN CERTIFICATE-----
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
-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----""")
        test_file.close()
        self.assertIsNone(test_ssl_ctx.use_certificate_chain_file(test_file.name))

    def test_use_certificate_file_bad(self):
        # Bad filename
        test_ssl_ctx = _nassl.SSL_CTX(OpenSslVersionEnum.SSLV23.value)
        self.assertRaisesRegexp(_nassl.OpenSSLError, 'system lib', test_ssl_ctx.use_certificate_chain_file,
                                'invalidPath')


    def test_use_PrivateKey_file(self):
        test_ssl_ctx = _nassl.SSL_CTX(OpenSslVersionEnum.SSLV23.value)
        test_file = tempfile.NamedTemporaryFile(delete=False, mode='wt')
        test_file.write("""-----BEGIN PRIVATE KEY-----
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
-----END PRIVATE KEY-----""")
        test_file.close()
        self.assertIsNone(test_ssl_ctx.use_PrivateKey_file(test_file.name, OpenSslFileTypeEnum.PEM.value))

    def test_use_PrivateKey_file_bad(self):
        # Bad filename
        test_ssl_ctx = _nassl.SSL_CTX(OpenSslVersionEnum.SSLV23.value)
        self.assertRaisesRegexp(_nassl.OpenSSLError, 'No such file', test_ssl_ctx.use_PrivateKey_file, 'invalidPath',
                                OpenSslFileTypeEnum.PEM.value)


    def test_check_private_key(self):
        test_ssl_ctx = _nassl.SSL_CTX(OpenSslVersionEnum.SSLV23.value)
        test_file = tempfile.NamedTemporaryFile(delete=False, mode='wt')
        test_file.write("""-----BEGIN PRIVATE KEY-----
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
-----END PRIVATE KEY-----""")
        test_file.close()
        test_file2 = tempfile.NamedTemporaryFile(delete=False, mode='wt')
        test_file2.write("""-----BEGIN CERTIFICATE-----
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
-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----""")
        test_file2.close()
        self.assertIsNone(test_ssl_ctx.use_certificate_chain_file(test_file2.name))
        self.assertIsNone(test_ssl_ctx.use_PrivateKey_file(test_file.name, OpenSslFileTypeEnum.PEM.value))
        self.assertIsNone(test_ssl_ctx.check_private_key())


    def test_check_private_key_bad(self):
        test_ssl_ctx = _nassl.SSL_CTX(OpenSslVersionEnum.SSLV23.value)
        self.assertRaisesRegexp(_nassl.OpenSSLError, 'no certificate assigned', test_ssl_ctx.check_private_key)

    # TODO: add get_ca_list tests

def main():
    unittest.main()

if __name__ == '__main__':
    main()