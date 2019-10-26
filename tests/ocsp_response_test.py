from datetime import datetime
from pathlib import Path

import pytest

from nassl import _nassl
import socket
import tempfile

from nassl.legacy_ssl_client import LegacySslClient
from nassl.ocsp_response import OcspResponseNotTrustedError, OcspResponseStatusEnum, OcspResponse
from nassl.ssl_client import SslClient, OpenSslVerifyEnum


class TestOcspResponse:
    def test_new_bad(self):
        with pytest.raises(NotImplementedError):
            _nassl.OCSP_RESPONSE()


OCSP_RESPONSE_OPENSSL_OUTPUT = b"""
OCSP Response Data:
    OCSP Response Status: successful (0x0)
    Response Type: Basic OCSP Response
    Version: 1 (0x0)
    Responder Id: C = US, O = Let's Encrypt, CN = Let's Encrypt Authority X3
    Produced At: Oct 12 02:56:00 2018 GMT
    Responses:
    Certificate ID:
      Hash Algorithm: sha1
      Issuer Name Hash: 7EE66AE7729AB3FCF8A220646C16A12D6071085D
      Issuer Key Hash: A84A6A63047DDDBAE6D139B7A64565EFF3A8ECA1
      Serial Number: 039048428EE710E751C1EC96E355B05FADF7
    Cert Status: good
    This Update: Oct 12 02:00:00 2018 GMT
    Next Update: Oct 19 02:00:00 2018 GMT

    Signature Algorithm: sha256WithRSAEncryption
         76:f4:7f:ff:4a:c5:26:c2:60:88:fe:ef:90:dd:c7:0a:39:fd:
         d0:df:fe:17:4b:71:78:08:60:e0:ee:14:4b:98:91:ef:77:59:
         81:51:ee:cc:b6:16:99:92:7d:98:64:e2:a7:be:f2:cb:24:61:
         47:67:0c:62:2c:06:95:4b:73:34:0c:7a:ce:ce:1c:27:85:14:
         97:f7:2e:76:3e:21:8b:83:ab:29:1f:55:48:25:f4:61:6a:d8:
         bf:65:10:90:71:04:10:45:4d:9a:37:84:02:9e:eb:06:45:3f:
         85:4c:e4:a4:b6:3f:54:fa:4d:4b:9e:d4:8f:1b:44:4f:fb:6c:
         e3:18:11:ba:3c:e1:21:64:97:4b:4a:28:d7:c5:b1:b3:46:fe:
         36:99:da:da:aa:e4:32:57:a1:14:d5:54:b9:6d:e4:49:59:a2:
         77:d4:87:97:95:8d:e6:7c:5b:64:db:60:ab:3e:e3:a7:a6:bc:
         00:0e:b8:dd:0c:42:a0:18:f8:d5:73:16:80:50:3c:b3:24:d0:
         01:da:3d:09:29:4e:93:d7:81:27:91:39:9c:67:99:53:d4:5f:
         ab:6a:42:67:1e:ca:9d:4c:40:a7:f8:71:e4:bf:43:e8:a0:20:
         62:9c:d5:25:16:8a:41:f5:70:85:c4:e4:45:9d:b6:95:4f:4f:
         79:3f:84:53
    Response Single Extensions:
        CT Certificate SCTs:
            Signed Certificate Timestamp:
                Version   : v1(0)
                Log ID    : 68:F6:98:F8:1F:64:82:BE:3A:8C:EE:B9:28:1D:4C:FC:
                            71:51:5D:67:93:D4:44:D1:0A:67:AC:BB:4F:4F:FB:C4
                Timestamp : Apr 25 11:35:28.002 2014 GMT
                Extensions: none
                Signature : ecdsa-with-SHA256
                            30:44:02:20:19:AA:26:AF:C0:2C:92:B1:DD:71:75:1E:
                            AE:16:0C:9B:4E:8A:23:90:E4:75:A1:90:3C:E5:69:EF:
                            EE:9B:AD:2D:02:20:20:FB:14:DB:1E:3E:09:09:51:74:
                            1A:97:68:38:0E:64:18:2A:FA:F6:5F:2A:5C:77:EB:73:
                            3B:0D:D6:4D:CF:BB
            Signed Certificate Timestamp:
                Version   : v1(0)
                Log ID    : A4:B9:09:90:B4:18:58:14:87:BB:13:A2:CC:67:70:0A:
                            3C:35:98:04:F9:1B:DF:B8:E3:77:CD:0E:C8:0D:DC:10
                Timestamp : Apr 23 21:08:37.767 2014 GMT
                Extensions: none
                Signature : ecdsa-with-SHA256
                            30:45:02:20:16:C2:50:36:17:32:AC:AC:B5:74:50:2B:
                            02:76:39:94:18:70:8A:7C:2C:0D:04:81:2A:09:C0:2F:
                            FE:26:20:71:02:21:00:F3:ED:1C:92:D2:A6:AC:3C:C5:
                            B3:54:DD:FE:4C:D1:DE:95:60:58:43:73:03:5E:6C:06:
                            12:D0:8E:EF:9A:F2:3D
"""


class TestOcspResponseOpensslOutputParsing:
    def test(self):
        # Given an OCSP response as returned by OpenSSL
        class MockOpenSslOcspResponse:
            def as_text(self):
                return OCSP_RESPONSE_OPENSSL_OUTPUT

            def get_status(self):
                return OcspResponseStatusEnum.SUCCESSFUL

        raw_ocsp_response = MockOpenSslOcspResponse()

        # When parsing it, it succeeds
        ocsp_response = OcspResponse.from_openssl(raw_ocsp_response)

        # And the fields were correctly parsed
        assert ocsp_response.status == OcspResponseStatusEnum.SUCCESSFUL
        assert ocsp_response.type == "Basic OCSP Response"
        assert ocsp_response.version == 1
        assert ocsp_response.responder_id == "C = US, O = Let's Encrypt, CN = Let's Encrypt Authority X3"
        assert ocsp_response.produced_at == datetime(2018, 10, 12, 2, 56)
        assert ocsp_response.certificate_status == "good"
        assert ocsp_response.this_update == datetime(2018, 10, 12, 2, 0)
        assert ocsp_response.next_update == datetime(2018, 10, 19, 2, 0)
        assert ocsp_response.hash_algorithm == "sha1"
        assert ocsp_response.issuer_name_hash == "7EE66AE7729AB3FCF8A220646C16A12D6071085D"
        assert ocsp_response.issuer_key_hash == "A84A6A63047DDDBAE6D139B7A64565EFF3A8ECA1"
        assert ocsp_response.serial_number == "039048428EE710E751C1EC96E355B05FADF7"

        # Including the SCT extension
        assert len(ocsp_response.extensions) == 1
        sct_timestamps = ocsp_response.extensions[0].signed_certificate_timestamps
        assert len(sct_timestamps) == 2

        assert sct_timestamps[0].version == "v1(0)"
        assert (
            sct_timestamps[0].log_id
            == "68:F6:98:F8:1F:64:82:BE:3A:8C:EE:B9:28:1D:4C:FC:71:51:5D:67:93:D4:44:D1:0A:67:AC:BB:4F:4F:FB:C4"
        )
        assert sct_timestamps[0].timestamp == datetime(2014, 4, 25, 11, 35, 28)


@pytest.mark.parametrize("ssl_client_cls", [SslClient, LegacySslClient])
class TestCommonOcspResponseOnline:
    def test(self, ssl_client_cls):
        # Given a website that support OCSP stapling
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(("www.cloudflare.com", 443))

        ssl_client = ssl_client_cls(underlying_socket=sock, ssl_verify=OpenSslVerifyEnum.NONE)
        ssl_client.set_tlsext_status_ocsp()
        ssl_client.do_handshake()

        # When retrieving the stapled OCSP response
        ocsp_response = ssl_client.get_tlsext_status_ocsp_resp()
        ssl_client.shutdown()

        # It succeeds
        assert ocsp_response.status == OcspResponseStatusEnum.SUCCESSFUL

        # And given a wrong certificate
        test_file = tempfile.NamedTemporaryFile(delete=False, mode="wt")
        test_file.write(
            """-----BEGIN CERTIFICATE-----
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
        )
        test_file.close()
        # Trying to verify fails with the right error
        with pytest.raises(OcspResponseNotTrustedError):
            ocsp_response.verify(Path(test_file.name))
