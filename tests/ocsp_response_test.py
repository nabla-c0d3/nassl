from pathlib import Path

import pytest

import socket
import tempfile

from nassl.legacy_ssl_client import LegacySslClient
from nassl.ocsp_response import OcspResponseNotTrustedError, verify_ocsp_response
from nassl.ssl_client import SslClient, OpenSslVerifyEnum


_CERTIFICATE_AS_PEM = """-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----"""


@pytest.mark.parametrize("ssl_client_cls", [SslClient, LegacySslClient])
class TestCommonOcspResponseOnline:
    def test(self, ssl_client_cls):
        # Given a website that support OCSP stapling
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(("www.apple.com", 443))

        ssl_client = ssl_client_cls(underlying_socket=sock, ssl_verify=OpenSslVerifyEnum.NONE)
        ssl_client.set_tlsext_status_ocsp()
        ssl_client.do_handshake()

        # When retrieving the stapled OCSP response, it succeeds
        ocsp_response = ssl_client.get_tlsext_status_ocsp_resp()
        ssl_client.shutdown()

        # And the OCSP response is valid
        assert ocsp_response.as_text()
        assert ocsp_response.as_der_bytes()

        # And given a wrong certificate
        with tempfile.NamedTemporaryFile(delete=False, mode="wt") as test_file:
            test_file.write(_CERTIFICATE_AS_PEM)
            test_file.close()
            # Trying to verify fails with the right error
            with pytest.raises(OcspResponseNotTrustedError):
                verify_ocsp_response(ocsp_response, Path(test_file.name))
