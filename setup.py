#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import absolute_import

import os
import sys
from os.path import join
from platform import architecture
from sys import platform
from nassl import __author__, __version__
from setuptools import setup, Extension


_ROOT_BUILD_PATH = os.path.join(os.path.dirname(__file__), 'bin')

# TODO(AD): Switch to an enum after dropping support for Python 2
class SupportedPlatformEnum(object):
    """Platforms supported by nassl.
    """
    OSX_64 = 1
    LINUX_64 = 2
    LINUX_32 = 3
    WINDOWS_32 = 4
    WINDOWS_64 = 5
    OPENBSD_64 = 6


CURRENT_PLATFORM = None
if architecture()[0] == '64bit':
    if platform == 'darwin':
        CURRENT_PLATFORM = SupportedPlatformEnum.OSX_64
    elif platform in ['linux', 'linux2']:
        CURRENT_PLATFORM = SupportedPlatformEnum.LINUX_64
    elif platform == 'win32':
        CURRENT_PLATFORM = SupportedPlatformEnum.WINDOWS_64
    elif platform == 'openbsd5':
        CURRENT_PLATFORM = SupportedPlatformEnum.OPENBSD_64
elif architecture()[0] == '32bit':
    if platform in ['linux', 'linux2']:
        CURRENT_PLATFORM = SupportedPlatformEnum.LINUX_32
    elif platform == 'win32':
        CURRENT_PLATFORM = SupportedPlatformEnum.WINDOWS_32

LEGACY_OPENSSL_INSTALL_PATH_DICT = {
    # Need full paths (hence the getcwd()) as they get passed to OpenSSL in build_from_scratch.py
    SupportedPlatformEnum.OSX_64: join(_ROOT_BUILD_PATH, 'openssl-legacy', 'darwin64'),
    SupportedPlatformEnum.LINUX_64: join(_ROOT_BUILD_PATH, 'openssl-legacy', 'linux64'),
    SupportedPlatformEnum.LINUX_32: join(_ROOT_BUILD_PATH, 'openssl-legacy', 'linux32'),
    SupportedPlatformEnum.WINDOWS_32: join(_ROOT_BUILD_PATH, 'openssl-legacy', 'win32'),
    SupportedPlatformEnum.WINDOWS_64: join(_ROOT_BUILD_PATH, 'openssl-legacy', 'win64'),
    SupportedPlatformEnum.OPENBSD_64: join(_ROOT_BUILD_PATH, 'openssl-legacy', 'openbsd64'),
}

MODERN_OPENSSL_INSTALL_PATH_DICT = {
    SupportedPlatformEnum.OSX_64: join(_ROOT_BUILD_PATH, 'openssl-modern', 'darwin64'),
    SupportedPlatformEnum.LINUX_64: join(_ROOT_BUILD_PATH, 'openssl-modern', 'linux64'),
    SupportedPlatformEnum.LINUX_32: join(_ROOT_BUILD_PATH, 'openssl-modern', 'linux32'),
    SupportedPlatformEnum.WINDOWS_32: join(_ROOT_BUILD_PATH, 'openssl-modern', 'win32'),
    SupportedPlatformEnum.WINDOWS_64: join(_ROOT_BUILD_PATH, 'openssl-modern', 'win64'),
    SupportedPlatformEnum.OPENBSD_64: join(_ROOT_BUILD_PATH, 'openssl-modern', 'openbsd64'),
}

ZLIB_INSTALL_PATH_DICT = {
    SupportedPlatformEnum.OSX_64: join(_ROOT_BUILD_PATH, 'zlib', 'darwin64', 'libz.a'),
    SupportedPlatformEnum.LINUX_64: join(_ROOT_BUILD_PATH, 'zlib', 'linux64', 'libz.a'),
    SupportedPlatformEnum.LINUX_32: join(_ROOT_BUILD_PATH, 'zlib', 'linux32', 'libz.a'),
    SupportedPlatformEnum.WINDOWS_32: join(_ROOT_BUILD_PATH, 'zlib', 'win32', 'zlibstat.lib'),
    SupportedPlatformEnum.WINDOWS_64: join(_ROOT_BUILD_PATH, 'zlib', 'win64', 'zlibstat.lib'),
    SupportedPlatformEnum.OPENBSD_64: join(_ROOT_BUILD_PATH, 'zlib', 'openbsd64', 'libz.a'),
}


LEGACY_OPENSSL_LIB_INSTALL_PATH = LEGACY_OPENSSL_INSTALL_PATH_DICT[CURRENT_PLATFORM]
LEGACY_OPENSSL_HEADERS_INSTALL_PATH = join(_ROOT_BUILD_PATH, 'openssl-legacy', 'include')

MODERN_OPENSSL_LIB_INSTALL_PATH = MODERN_OPENSSL_INSTALL_PATH_DICT[CURRENT_PLATFORM]
MODERN_OPENSSL_HEADERS_INSTALL_PATH = join(_ROOT_BUILD_PATH, 'openssl-modern', 'include')

ZLIB_LIB_INSTALL_PATH = ZLIB_INSTALL_PATH_DICT[CURRENT_PLATFORM]


NASSL_SETUP = {
    'name': "nassl",
    'version': __version__,
    'package_dir': {'nassl': 'nassl'},
    'py_modules': ['nassl.__init__', 'nassl.ssl_client', 'nassl.debug_ssl_client',
                   'nassl.ocsp_response'],
    'description': 'Experimental OpenSSL wrapper for Python 2.7 / 3.3+ and SSLyze.',
    'extras_require': {':python_version < "3.4"': ['enum34'],
                       ':python_version < "3.5"': ['typing']},
    'author': __author__,
    'author_email': 'nabla.c0d3@gmail.com',
    'url': 'https://github.com/nabla-c0d3/nassl',

    'test_suite':    'nose.collector',
    'tests_require': ['nose'],
}

# There are two native extensions: the "legacy" OpenSSL one and the "modern" OpenSSL one
BASE_NASSL_EXT_SETUP = {
    'extra_compile_args': [],
    'extra_link_args': [],
    'sources': ["nassl/_nassl/nassl.c", "nassl/_nassl/nassl_SSL_CTX.c", "nassl/_nassl/nassl_SSL.c",
                "nassl/_nassl/nassl_X509.c", "nassl/_nassl/nassl_errors.c", "nassl/_nassl/nassl_BIO.c",
                "nassl/_nassl/nassl_X509_EXTENSION.c", "nassl/_nassl/nassl_X509_NAME_ENTRY.c",
                "nassl/_nassl/nassl_SSL_SESSION.c", "nassl/_nassl/openssl_utils.c",
                "nassl/_nassl/nassl_OCSP_RESPONSE.c", "nassl/_nassl/python_utils.c"],
}

if CURRENT_PLATFORM in [SupportedPlatformEnum.WINDOWS_32, SupportedPlatformEnum.WINDOWS_64]:
    # Build using the Python that was used to run this script; will not work for cross-compiling
    PYTHON_LIBS_PATH = join(os.path.dirname(sys.executable), 'libs')

    BASE_NASSL_EXT_SETUP.update({
        'library_dirs': [PYTHON_LIBS_PATH],
        'libraries': ['user32', 'kernel32', 'Gdi32', 'Advapi32', 'Ws2_32', 'crypt32',]
    })
else:
    BASE_NASSL_EXT_SETUP['extra_compile_args'].append('-Wall')


LEGACY_NASSL_EXT_SETUP = BASE_NASSL_EXT_SETUP.copy()
LEGACY_NASSL_EXT_SETUP['name'] = 'nassl._nassl_legacy'
LEGACY_NASSL_EXT_SETUP['define_macros'] = [('LEGACY_OPENSSL', '1')]

MODERN_NASSL_EXT_SETUP = BASE_NASSL_EXT_SETUP.copy()
MODERN_NASSL_EXT_SETUP['name'] = 'nassl._nassl'


if CURRENT_PLATFORM in [SupportedPlatformEnum.WINDOWS_32, SupportedPlatformEnum.WINDOWS_64]:
    LEGACY_NASSL_EXT_SETUP.update({
        'include_dirs': [LEGACY_OPENSSL_HEADERS_INSTALL_PATH],
        'extra_objects': [ZLIB_LIB_INSTALL_PATH,
                          join(LEGACY_OPENSSL_LIB_INSTALL_PATH, 'libeay32.lib'),
                          join(LEGACY_OPENSSL_LIB_INSTALL_PATH, 'ssleay32.lib')],
    })

    MODERN_NASSL_EXT_SETUP.update({
        'include_dirs': [MODERN_OPENSSL_HEADERS_INSTALL_PATH],
        'extra_objects': [ZLIB_LIB_INSTALL_PATH,
                          join(MODERN_OPENSSL_LIB_INSTALL_PATH, 'libcrypto.lib'),
                          join(MODERN_OPENSSL_LIB_INSTALL_PATH, 'libssl.lib')]
    })

else:
    # Add arguments specific to Unix builds
    LEGACY_NASSL_EXT_SETUP.update({
        'include_dirs': [LEGACY_OPENSSL_HEADERS_INSTALL_PATH, join('nassl', '_nassl')],
        'extra_objects': [join(LEGACY_OPENSSL_LIB_INSTALL_PATH, 'libssl.a'),
                          join(LEGACY_OPENSSL_LIB_INSTALL_PATH, 'libcrypto.a'),
                          ZLIB_LIB_INSTALL_PATH]
    })
    MODERN_NASSL_EXT_SETUP.update({
        'include_dirs': [MODERN_OPENSSL_HEADERS_INSTALL_PATH, join('nassl', '_nassl')],
        'extra_objects': [join(MODERN_OPENSSL_LIB_INSTALL_PATH, 'libssl.a'),
                          join(MODERN_OPENSSL_LIB_INSTALL_PATH, 'libcrypto.a'),
                          ZLIB_LIB_INSTALL_PATH]
    })


NASSL_SETUP.update({'ext_modules': [Extension(**LEGACY_NASSL_EXT_SETUP), Extension(**MODERN_NASSL_EXT_SETUP)]})


if __name__ == "__main__":
    setup(**NASSL_SETUP)
