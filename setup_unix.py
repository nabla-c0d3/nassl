#!/usr/bin/python2.7
from distutils.core import setup, Extension

from os.path import join

from setup_config import NASSL_SETUP, NASSL_EXT_SETUP
from buildAll_unix import OPENSSL_INSTALL_DIR


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
