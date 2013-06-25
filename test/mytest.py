import nassl
from SslClient import SslClient
import tempfile
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(5)
sock.connect(("www.google.com", 443))

sslClient = SslClient(sslVersion=nassl.SSLV23, sock=sock)
sslClient.do_handshake()
sslClient.write('GET / HTTP/1.0\r\n\r\n')
#print sslClient.read(4096)
cert = sslClient.get_peer_certificate()
#print cert.as_text()
#print cert.get_version()
#print cert.get_notBefore()
#print cert.get_notAfter()
#print cert.get_serialNumber()
print sslClient.get_secure_renegotiation_support()
print sslClient.get_current_compression_name()

#print cert.digest()
#print cert.as_pem()
#print cert.get_ext_count()
#print cert.get_ext(1).get_object()
#print cert.get_ext(1).get_data()



print cert.as_dict()

raise Exception

testCTX = nassl.SSL_CTX(nassl.SSLV23)
testCTX.set_verify(nassl.SSL_VERIFY_NONE)

testCTX.set_cipher_list("LOW")

testCTX = nassl.SSL_CTX(nassl.SSLV23)


#print testFile.read(100)
testFile.close()
print testCTX.load_verify_locations(testFile.name)


testSSL = nassl.SSL(testCTX)
print testSSL


testSSL.set_verify(nassl.SSL_VERIFY_NONE)
testSSL.set_tlsext_host_name("www.lol.com")

testSSL.do_handshake()
#certpointer = testSSL.get_peer_certificate()
#print certpointer
#cert = nassl.X509(certpointer)
#print cert.as_text()

testSSL.write("GET / HTTP/1.0\n\n")


print testSSL.read(2048)
while testSSL.pending():
	print testSSL.read(2048)

print testSSL.get_secure_renegotiation_support()


print testSSL.get_current_compression_name()


raise nassl.OpenSSLError

# Wrong ssl version
test = nassl.SSL_CTX(1,2)
print test



test = nassl.SSL_CTX(0x123)
print test



