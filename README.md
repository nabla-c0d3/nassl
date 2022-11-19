nassl
=====

![Build Wheels](https://github.com/nabla-c0d3/nassl/workflows/Build%20Wheels/badge.svg)
[![PyPI version](https://img.shields.io/pypi/v/nassl.svg)](https://pypi.org/project/nassl/)
[![PyPI wheel](https://img.shields.io/pypi/wheel/nassl.svg)](https://pypi.org/project/nassl/)
[![PyPI version](https://img.shields.io/pypi/pyversions/nassl.svg)](https://pypi.org/project/nassl/)

Experimental OpenSSL wrapper for Python 3.7+ and [SSLyze](https://github.com/nabla-c0d3/sslyze).

**Do NOT use for anything serious**. This code has not been properly tested/reviewed and is not production ready.


Quick Start
-----------

Nassl can be installed directly via pip:

    pip install nassl

Development environment
-----------------------

To setup a development environment:

    $ pip install --upgrade pip setuptools wheel
    $ pip install -r requirements-dev.txt

Nassl relies on a C extension to call into OpenSSL; you can compile everything using:

    $ invoke build.all

Then, the tests can be run using:

    $ invoke test


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
