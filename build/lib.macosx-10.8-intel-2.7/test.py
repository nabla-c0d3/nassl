import nassl



testCTX = nassl.SSL_CTX(nassl.SSLV23)
testCTX.set_verify(nassl.SSL_VERIFY_NONE)

testSSL = nassl.SSL(testCTX)
print testSSL

testSSL.do_handshake()
testSSL.write("GET / HTTP/1.0\n\n")


print testSSL.read(2048)
while testSSL.pending():
	print testSSL.read(2048)



# Wrong ssl version
test = nassl.SSL_CTX(1,2)
print test



test = nassl.SSL_CTX(0x123)
print test



