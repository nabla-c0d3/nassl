
import socket
from nassl import TLSV1, SSL_VERIFY_NONE
from nassl.DebugSslClient import DebugSslClient


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(5)
sock.connect(("www.google.com", 443))

sslClient = DebugSslClient(sslVersion=TLSV1, sock=sock, sslVerify=SSL_VERIFY_NONE)
sslClient.do_handshake()
print sslClient.get_current_cipher_name()
for cert in sslClient.get_peer_cert_chain():
    print cert.as_dict()['subject']['commonName']
