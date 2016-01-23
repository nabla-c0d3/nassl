#!/usr/bin/python2.7
from distutils.core import setup, Extension

from os.path import join

from buildAll_unix import OPENSSL_INSTALL_DIR
from nassl import __author__, __version__

NASSL_SETUP = {
    'name': "nassl",
    'version': __version__,
    'package_dir': {'nassl': 'nassl'},
    'py_modules': ['nassl.__init__', 'nassl.SslClient', 'nassl.DebugSslClient', 'nassl.X509Certificate',
                   'nassl.OcspResponse'],
    'description': 'OpenSSL wrapper for SSLyze',
    'author': __author__,
    'author_email': 'nabla.c0d3@gmail.com',
    'url': 'https://github.com/nabla-c0d3/nassl'
}

NASSL_EXT_SETUP = {
    'name': "nassl._nassl",
    'sources': ["nassl/_nassl/nassl.c", "nassl/_nassl/nassl_SSL_CTX.c", "nassl/_nassl/nassl_SSL.c",
                "nassl/_nassl/nassl_X509.c", "nassl/_nassl/nassl_errors.c", "nassl/_nassl/nassl_BIO.c",
                "nassl/_nassl/nassl_X509_EXTENSION.c", "nassl/_nassl/nassl_X509_NAME_ENTRY.c",
                "nassl/_nassl/nassl_SSL_SESSION.c", "nassl/_nassl/openssl_utils.c", "nassl/_nassl/nassl_OCSP_RESPONSE.c"]
}

extra_compile_args = ['-Wall', '-Wno-deprecated-declarations']

# Add arguments specific to Unix builds
unix_ext_args = NASSL_EXT_SETUP.copy()
unix_ext_args.update({
    'include_dirs': [join('bin', 'openssl', 'include')],
    'extra_compile_args': extra_compile_args,
    'extra_objects': [join(OPENSSL_INSTALL_DIR, 'libssl.a'), join(OPENSSL_INSTALL_DIR, 'libcrypto.a')]})


unix_setup = NASSL_SETUP.copy()
unix_setup.update({
    'ext_modules': [Extension(**unix_ext_args)] })

setup(**unix_setup)
