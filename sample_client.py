#!/usr/bin/python2.7
import socket
from nassl import TLSV1, SSL_VERIFY_NONE, SSL_FILETYPE_PEM, SSL_MODE_SEND_FALLBACK_SCSV
from nassl.debug_ssl_client import DebugSslClient


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(5)
sock.connect(("www.google.com", 443))

sslClient = DebugSslClient(ssl_version=TLSV1, sock=sock, ssl_verify=SSL_VERIFY_NONE, ignore_client_authentication_requests=True)
sslClient.set_mode(SSL_MODE_SEND_FALLBACK_SCSV)
sslClient.do_handshake()
print sslClient.get_current_cipher_name()
print 'lol'
print sslClient.get_client_CA_list()
for cert in sslClient.get_peer_cert_chain():
    print cert.as_dict()#['extensions']['X509v3 Basic Constraints']


sslClient2 = DebugSslClient(ssl_version=TLSV1, sock=sock, ssl_verify=SSL_VERIFY_NONE, client_certchain_file="certificate.pem",
                            client_key_file= 'client.key', client_key_type=SSL_FILETYPE_PEM,
                            client_key_password='')
sslClient2.do_handshake()

for cert in sslClient2.get_peer_cert_chain():
    print cert.as_dict()['subject']['commonName']

sslClient2.write('GET / HTTP/1.0/r/nUser-Agent: Test/r/nHost: auth.startssl.com/r/n/r/n')
print sslClient2.read(2048)