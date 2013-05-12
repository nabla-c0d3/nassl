import nassl


testCTX = nassl.SSL_CTX(nassl.SSLV23)
testCTX.set_verify(nassl.SSL_VERIFY_NONE)

testCTX.set_cipher_list("LOW")
testCTX.load_verify_locations("lol")

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



