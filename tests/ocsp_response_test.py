import pytest

from nassl import _nassl
import socket
import tempfile

from nassl.legacy_ssl_client import LegacySslClient
from nassl.ocsp_response import OcspResponseNotTrustedError, OcspResponseStatusEnum
from nassl.ssl_client import SslClient, OpenSslVerifyEnum


class TestOcspResponse:

    def test_new_bad(self):
        with pytest.raises(NotImplementedError):
            _nassl.OCSP_RESPONSE()


@pytest.mark.parametrize("ssl_client_cls", [SslClient, LegacySslClient])
class TestCommonOcspResponseOnline:

    def test(self, ssl_client_cls):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(('www.cloudflare.com', 443))

        ssl_client = ssl_client_cls(underlying_socket=sock, ssl_verify=OpenSslVerifyEnum.NONE)
        ssl_client.set_tlsext_status_ocsp()
        ssl_client.do_handshake()
        ocsp_response = ssl_client.get_tlsext_status_ocsp_resp()
        ssl_client.shutdown()

        assert ocsp_response.status == OcspResponseStatusEnum.SUCCESSFUL
        assert ocsp_response.as_text()

        # Test verify with a wrong certificate
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
-----END CERTIFICATE-----""")
        test_file.close()
        with pytest.raises(OcspResponseNotTrustedError):
            ocsp_response.verify(test_file.name)

        # No SCT extension
        assert 'singleExtensions' not in ocsp_response.as_dict()['responses'][0].keys()

    def test_sct_parsing(self, ssl_client_cls):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(('sslanalyzer.comodoca.com', 443))

        ssl_client = ssl_client_cls(underlying_socket=sock, ssl_verify=OpenSslVerifyEnum.NONE)
        ssl_client.set_tlsext_status_ocsp()
        ssl_client.do_handshake()
        ocsp_response = ssl_client.get_tlsext_status_ocsp_resp()
        ssl_client.shutdown()

        assert ocsp_response.as_dict()['responses'][0]['singleExtensions']['ctCertificateScts']
