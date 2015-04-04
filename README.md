nassl
=====

Experimental Python wrapper for OpenSSL. **Do NOT use for anything serious**.
This code has not been properly tested/reviewed and is absolutely not
production ready. For example, SslClient uses an **insecure, outdated version 
of OpenSSL**.


Usage
-----

See test/test_client.py for an example.


Build
-----

Multiple build scripts are available. They will consecutively build Zlib,
OpenSSL and nassl.

Regardless of the platform you're targeting, you will need to:
* Download OpenSSL 1.0.2a at
https://www.openssl.org/source/ and extract the content of
the source package to nassl/openssl-1.0.2a
* Download Zlib at http://zlib.net/zlib-1.2.8.tar.gz and extract the content
of the source package to nassl/zlib-1.2.8.

### buildAll_unix.py

Build script for OS X 64 bits and Linux 32/64 bits. It was tested on OS X
Mavericks, Ubuntu 13.04 and Debian 7. This is the easiest build script to use.


### buildAll_win32.py

Build script for Windows 7 32 bits. It expects Python to be installed in
C:\Python27_32.


### buildAll_win64.py

Build script for Windows 7 64 bits. It expects Python to be installed in
C:\Python27. This build script will crash after building OpenSSL but you can
still manage to get a full build of nassl by manually copying the OpenSSL libs
from openssl/out32 to the right location in build/. Look at win32 builds.


Unit Tests
----------

    python -m unittest discover test -p *Tests.py


Structure
---------

### src/

Classes implemented in Python are part of the nassl namespace. This currently
includes SslClient.py, OcspResponse.py and X509Certificate.py. Such classes
are designed to provide a simpler, higher-level interface to perform SSL
connections.


### src/_nassl/

Classes implemented in C are part of the nassl.\_nassl namespace. They try to
stay as close as possible to OpenSSL's API. In most cases, Python methods of
such objects directly match the OpenSSL function with same name. For example
the \_nassl.SSL.read() Python method matches OpenSSL's SSL\_read() function.
These C classes should be considered internal.


Why ???
-------

I'm the author of SSLyze, an SSL scanner written in Python:
https://github.com/iSECPartners/sslyze. Scanning SSL servers requires access
to low-level SSL functions within the OpenSSL API, for example to test for
things like insecure renegotiation or session resumption.

None of the existing OpenSSL wrappers for Python (including ssl, M2Crypto and
pyOpenSSL) expose the APIs that I need for SSLyze, so I had to write my own
wrapper.


License
-------

Copyright 2013 Alban Diquet

Licensed under the GPLv2; see ./LICENSE

Please contact me if this license doesn't work for you.


Author
------

Alban Diquet - https://nabla-c0d3.github.io
