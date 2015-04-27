#!/usr/bin/python2.7
from distutils.core import setup, Extension
from sys import platform

from setup_config import NASSL_SETUP, NASSL_EXT_SETUP
from buildAll_config import OPENSSL_DIR, ZLIB_DIR
from buildAll_unix import OPENSSL_INSTALL_DIR


extra_compile_args = ['-Wall', '-Wno-deprecated-declarations']


# Add arguments specific to Unix builds
unix_ext_args = NASSL_EXT_SETUP.copy()
unix_ext_args.update({
    'include_dirs' : [OPENSSL_INSTALL_DIR + '/include'],
    'extra_compile_args' : extra_compile_args,
    'extra_objects': [OPENSSL_INSTALL_DIR + '/lib/libssl.a', OPENSSL_INSTALL_DIR + '/lib/libcrypto.a', ZLIB_DIR + '/libz.a']})


unix_setup = NASSL_SETUP.copy()
unix_setup.update({
    'ext_modules' : [Extension(**unix_ext_args)] })

setup(**unix_setup)
