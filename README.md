nassl
=====

Experimental Python wrapper for OpenSSL. **Do NOT use for anything serious**. This code has not been properly tested/reviewed and is absolutely not production ready.


Notes
=====

### src/

Classes implemented in Python are part of the nassl namespace. This currently includes SslClient.py and X509Certificate.py. Such classes are designed to provide a simpler, higher-level interface to perform SSL connections.

### src/_nassl/

Classes implemented in C are part of the nassl._nassl namespace. They try to stay as close as possible to OpenSSL's API. In most cases, Python methods of such objects directly match the OpenSSL function with same name. For example the _nassl.SSL.read() Python method matches OpenSSL's SSL_read() function. Those C classes should be considered internal.


Build
=====

A build script is available in ./build.py. It was tested on OS X Lion and will try to build OpenSSL, Zlib and nassl.

	python build.py


Why ???
=======

I'm the author of SSLyze, an SSL scanner written in Python: https://github.com/iSECPartners/sslyze. Scanning SSL servers requires access to low-level SSL functions within the OpenSSL API, for example to test for things like insecure renegotiation or session resumption. None of the existing OpenSSL wrappers for Python (including ssl, M2Crypto and pyOpenSSL) expose the APIs that I need for SSLyze, so I had to write my own OpenSSL wrapper.


Author
======

Alban Diquet - http://nabla-c0d3.github.io
