from pathlib import Path

from nassl.ssl_client import OpenSslVersionEnum, SslClient, OpenSslVerifyEnum
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(5)
sock.connect(("localhost", 443))

ssl_client = SslClient(
    ssl_version=OpenSslVersionEnum.TLSV1_2,
    underlying_socket=sock,
    ssl_verify=OpenSslVerifyEnum.PEER,
    ssl_verify_locations=Path("ca_cert.pem"),
)

ssl_client.set1_groups_list("prime256v1")

ssl_client.set_cipher_list("ECDH")

ssl_client.set_tlsext_status_ocsp()
ssl_client.do_handshake()

# print(ssl_client.get_dh_info())

print("\nCipher suite")
print(ssl_client.get_current_cipher_name())

print("\nHTTP response")
ssl_client.write(b"GET / HTTP/1.0\r\nUser-Agent: Test\r\nHost: tls.dev.intranet\r\n\r\n")
print(ssl_client.read(2048))
