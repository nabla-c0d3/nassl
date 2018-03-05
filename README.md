nassl
=====


[![Build Status](https://travis-ci.org/nabla-c0d3/nassl.svg?branch=master)](https://travis-ci.org/nabla-c0d3/nassl)
[![Coverage Status](https://coveralls.io/repos/github/nabla-c0d3/nassl/badge.svg?branch=master)](https://coveralls.io/github/nabla-c0d3/nassl?branch=master)
[![PyPI version](https://badge.fury.io/py/nassl.svg)](https://badge.fury.io/py/nassl)

Experimental OpenSSL wrapper for Python 2.7 / 3.4+ and SSLyze. **Do NOT use for anything serious**. This code has not
been properly tested/reviewed and is absolutely not production ready.

Quick Start
-----------

Nassl can be installed directly via pip:

    pip install nassl

On OS X and Linux, it is also easy to directly clone the repository, build the `_nassl` C extension and then run the
sample client:

    git clone https://github.com/nabla-c0d3/nassl.git
    cd nassl
    pip install -r requirements.txt
    python setup.py build_ext -i
    python sample_client.py

Building the C extension
------------------------

Nassl relies on a C extension to call into OpenSSL; the extension can be directly built using the pre-compiled OpenSSL
binaries available in ./bin, by running the following command:

    python setup.py build_ext -i

On Windows, a "Platform Wheel" can be built using:

    python setup.py bdist_wheel

Building everything from scratch
--------------------------------

If you do not want to use the pre-compiled binaries, compiling the C extension requires successively building:

* [Zlib 1.2.11](http://zlib.net/zlib-1.2.11.tar.gz)
* [OpenSSL 1.0.2e](https://ftp.openssl.org/source/old/1.0.2/openssl-1.0.2e.tar.gz)
* [OpenSSL 1.1.x dev](https://github.com/openssl/openssl/commit/1f5878b8e25a785dde330bf485e6ed5a6ae09a1a)
* The `_nassl` and `_nassl_legacy` C extensions

The whole build process is all taken care of by the _build\_from\_scratch.py_ script:

    git clone https://github.com/nabla-c0d3/nassl.git
    cd nassl
    pip install -r requirements.txt
    wget http://zlib.net/zlib-1.2.11.tar.gz
    tar xvfz  zlib-1.2.11.tar.gz
    wget https://ftp.openssl.org/source/old/1.0.2/openssl-1.0.2e.tar.gz
    tar xvfz openssl-1.0.2e.tar.gz
    git clone -b tls1.3-draft-18 https://github.com/openssl/openssl.git ./openssl-tls1.3-draft-18
    python build_from_scratch.py

For Windows builds, Visual Studio is expected to be installed at the default location.

The build script was tested on the following platforms: Windows 7 (32 and 64 bits), Debian 7 (32 and 64 bits),
macOS Sierra. It will build the C extension for the interpreter and platform that was used to run the script
(ie. no cross-compiling).

Building Linux wheels using Docker
----------------------------------

The [manylinux](https://github.com/pypa/manylinux) Docker image can be used to build the C extension and its 
dependencies, and package everything into a [Python wheel](https://pythonwheels.com/) for all the supported versions of 
Python.

To build the linux32 nassl wheels:

    docker run --rm -v C:\path\to\nassl\:/io quay.io/pypa/manylinux1_i686 bash /io/build_linux_wheels.sh
    
    
To build the linux64 nassl wheels:

    docker run --rm -v C:\path\to\nassl\:/io quay.io/pypa/manylinux1_x86_64 bash /io/build_linux_wheels.sh


Project structure
-----------------

### nassl/

Classes implemented in Python are part of the `nassl` namespace; they are designed to provide a simpler, higher-level
interface to perform SSL connections.


### nassl/_nassl/

Classes implemented in C are part of the `nassl._nassl` namespace; they try to stay as close as possible to OpenSSL's
API. In most cases, Python methods of such objects directly match the OpenSSL function with same name. For example the
`_nassl.SSL.read()` Python method matches OpenSSL's `SSL_read()` function.

These classes should be considered internal.


Why another SSL library?
------------------------

I'm the author of [SSLyze](https://github.com/nabla-c0d3/sslyze), an SSL scanner written in Python. Scanning SSL servers
requires access to low-level SSL functions within the OpenSSL API, for example to test for things like insecure
renegotiation or session resumption.

None of the existing OpenSSL wrappers for Python (including ssl, M2Crypto and pyOpenSSL) expose the APIs that I need for
SSLyze, so I had to write my own wrapper.


License
-------

See ./LICENSE.txt

Please contact me if this license doesn't work for you.


Author
------

Alban Diquet - @nabla_c0d3 - https://nabla-c0d3.github.io
