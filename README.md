nassl
=====


[![Build Status](https://travis-ci.org/nabla-c0d3/nassl.svg?branch=master)](https://travis-ci.org/nabla-c0d3/nassl)
[![PyPI version](https://badge.fury.io/py/nassl.svg)](https://badge.fury.io/py/nassl)

Experimental OpenSSL wrapper for Python 2.7 and SSLyze. **Do NOT use for anything serious**. This code has not been 
properly tested/reviewed and is absolutely not production ready.

Quick Start
-----------

Nassl can be installed directly via pip:
    
    pip install nassl

On OS X and Linux, it is also easy to directly clone the repository, build the `_nassl` C extension and then run the
sample client:

    git clone https://github.com/nabla-c0d3/nassl.git
    cd nassl
    python setup.py build_ext -i
    python sample_client.py
    

Building the C extension
------------------------

Nassl relies on a C extension to call into OpenSSL; the extension can be directly built using the pre-compiled OpenSSL
binaries available in ./bin, by running the following command:

    python setup.py build_ext -i

On Windows, a "Platform Wheel" can be built using:

    python setup.py bdist_wheel
    
If you do not want to use the pre-compiled binaries, compiling the C extension requires successively building:
 
* [Zlib 1.2.8](http://zlib.net/zlib-1.2.8.tar.gz)
* A [special fork of OpenSSL 1.0.2](https://github.com/PeterMosmans/openssl) (or the official OpenSSL 1.0.2e)
* The `_nassl` C extension itself

The whole build process is all taken care of by the _build\_from\_scratch.py_ script: 

    git clone https://github.com/nabla-c0d3/nassl.git
    cd nassl
    wget http://zlib.net/zlib-1.2.8.tar.gz
    tar xvfz  zlib-1.2.8.tar.gz
    git clone https://github.com/PeterMosmans/openssl
    python build_from_scratch.py
    
For Windows builds, Visual Studio is expected to be installed at the default location. 

The build script was tested on the following platforms: Windows 7 (32 and 64 bits), Debian 7 (32 and 64 bits),
macOS Sierra. It will build the C extension for the interpreter and platform that was used to run the script
(ie. no cross-compiling).
    

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

Licensed under the GPLv2; see ./LICENSE

Please contact me if this license doesn't work for you.


Author
------

Alban Diquet - @nabla_c0d3 - https://nabla-c0d3.github.io
