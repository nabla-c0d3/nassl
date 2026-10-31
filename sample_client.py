from pathlib import Path

from nassl.ocsp_response import verify_ocsp_response
from nassl.base_ssl_client import TlsVersionEnum, OpenSslVerifyEnum
from nassl.openssl_4_0_0.ssl_client import SslClient_OpenSSL_4_0_0
import socket

mozilla_store = Path("tests") / "mozilla.pem"
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(5)

hostname = "www.cloudflare.com"
sock.connect((hostname, 443))

ssl_client = SslClient_OpenSSL_4_0_0(
    tls_version=TlsVersionEnum.TLS_1_3,
    underlying_socket=sock,
    ssl_verify=OpenSslVerifyEnum.PEER,
    ssl_verify_locations=mozilla_store,
)
ssl_client.set_tlsext_status_ocsp()
ssl_client.do_handshake()


print("Received certificate chain")
for pem_cert in ssl_client.get_received_chain():
    print(pem_cert)

ocsp_resp = ssl_client.get_tlsext_status_ocsp_resp()
if ocsp_resp:
    print("OCSP Stapling")
    verify_ocsp_response(ocsp_resp, Path(mozilla_store))

print("\nCipher suite")
print(ssl_client.get_current_cipher_name())

print("\nEphemeral Key")
print(ssl_client.get_ephemeral_key())

print("\nGroup name:")
print(ssl_client.get_group_name())

print("\nHTTP response")
ssl_client.write(f"GET / HTTP/1.0\r\nUser-Agent: Test\r\nHost: {hostname}\r\n\r\n".encode("ascii"))
print(ssl_client.read(2048))
