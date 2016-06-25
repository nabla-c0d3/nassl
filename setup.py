#!/usr/bin/python2.7
import os
import sys
from os import getcwd
from os.path import join
from platform import architecture
from sys import platform
from nassl import __author__, __version__


class SupportedPlatformEnum:
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
    elif platform == 'linux2':
        CURRENT_PLATFORM = SupportedPlatformEnum.LINUX_64
    elif platform == 'win32':
        CURRENT_PLATFORM = SupportedPlatformEnum.WINDOWS_64
    elif platform == 'openbsd5':
        CURRENT_PLATFORM = SupportedPlatformEnum.OPENBSD_64
elif architecture()[0] == '32bit':
    if platform == 'linux2':
        CURRENT_PLATFORM = SupportedPlatformEnum.LINUX_32
    elif platform == 'win32':
        CURRENT_PLATFORM = SupportedPlatformEnum.WINDOWS_32


if CURRENT_PLATFORM in [SupportedPlatformEnum.WINDOWS_32, SupportedPlatformEnum.WINDOWS_64]:
    # Needed for binary distributions (bdist_wheel) on Windows
    from setuptools import setup, Extension
else:
    # Keeping things simple for Unix as we don't need binary distros
    from distutils.core import setup, Extension


OPENSSL_INSTALL_PATH_DICT = {
    # Need full paths (hence the getcwd()) as they get passed to OpenSSL in build_from_scratch.py
    SupportedPlatformEnum.OSX_64: join(getcwd(), 'bin', 'openssl', 'darwin64'),
    SupportedPlatformEnum.LINUX_64: join(getcwd(), 'bin', 'openssl', 'linux64'),
    SupportedPlatformEnum.LINUX_32: join(getcwd(), 'bin', 'openssl', 'linux32'),
    SupportedPlatformEnum.WINDOWS_32: join(getcwd(), 'bin', 'openssl', 'win32'),
    SupportedPlatformEnum.WINDOWS_64: join(getcwd(), 'bin', 'openssl', 'win64'),
    SupportedPlatformEnum.OPENBSD_64: join(getcwd(), 'bin', 'openssl', 'openbsd64'),
}

ZLIB_INSTALL_PATH_DICT = {
    SupportedPlatformEnum.OSX_64: join(getcwd(), 'bin', 'zlib', 'darwin64', 'libz.a'),
    SupportedPlatformEnum.LINUX_64: join(getcwd(), 'bin', 'zlib', 'linux64', 'libz.a'),
    SupportedPlatformEnum.LINUX_32: join(getcwd(), 'bin', 'zlib', 'linux32', 'libz.a'),
    SupportedPlatformEnum.WINDOWS_32: join(getcwd(), 'bin', 'zlib', 'win32', 'zlibstat.lib'),
    SupportedPlatformEnum.WINDOWS_64: join(getcwd(), 'bin', 'zlib', 'win64', 'zlibstat.lib'),
    SupportedPlatformEnum.OPENBSD_64: join(getcwd(), 'bin', 'zlib', 'openbsd64', 'libz.a'),
}


OPENSSL_LIB_INSTALL_PATH = OPENSSL_INSTALL_PATH_DICT[CURRENT_PLATFORM]
OPENSSL_HEADERS_INSTALL_PATH = join('bin', 'openssl', 'include')
ZLIB_LIB_INSTALL_PATH = ZLIB_INSTALL_PATH_DICT[CURRENT_PLATFORM]


NASSL_SETUP = {
    'name': "nassl",
    'version': __version__,
    'package_dir': {'nassl': 'nassl'},
    'py_modules': ['nassl.__init__', 'nassl.ssl_client', 'nassl.debug_ssl_client', 'nassl.x509_certificate',
                   'nassl.ocsp_response'],
    'description': 'Experimental OpenSSL wrapper for Python 2.7 and SSLyze.',
    'author': __author__,
    'author_email': 'nabla.c0d3@gmail.com',
    'url': 'https://github.com/nabla-c0d3/nassl',
}

NASSL_EXT_SETUP = {
    'name': "nassl._nassl",
    'sources': ["nassl/_nassl/nassl.c", "nassl/_nassl/nassl_SSL_CTX.c", "nassl/_nassl/nassl_SSL.c",
                "nassl/_nassl/nassl_X509.c", "nassl/_nassl/nassl_errors.c", "nassl/_nassl/nassl_BIO.c",
                "nassl/_nassl/nassl_X509_EXTENSION.c", "nassl/_nassl/nassl_X509_NAME_ENTRY.c",
                "nassl/_nassl/nassl_SSL_SESSION.c", "nassl/_nassl/openssl_utils.c",
                "nassl/_nassl/nassl_OCSP_RESPONSE.c"],
}


if CURRENT_PLATFORM in [SupportedPlatformEnum.WINDOWS_32, SupportedPlatformEnum.WINDOWS_64]:
    # Add arguments specific to Windows builds
    # Visual Studio is expected to be in the default folder
    WIN_VISUAL_STUDIO_PATH = 'C:\\Program Files (x86)\\Microsoft Visual Studio 9.0\\VC\\'
    if CURRENT_PLATFORM == SupportedPlatformEnum.WINDOWS_32:
        WIN_VISUAL_STUDIO_LIB_PATH = join(WIN_VISUAL_STUDIO_PATH, 'lib')
    else:
        WIN_VISUAL_STUDIO_LIB_PATH = join(WIN_VISUAL_STUDIO_PATH, 'lib', 'amd64')

    # Build using the Python that was used to run this script; will not work for cross-compiling
    PYTHON_LIBS_PATH = join(os.path.dirname(sys.executable), 'libs')

    NASSL_EXT_SETUP.update({
        'include_dirs': [OPENSSL_HEADERS_INSTALL_PATH, join(WIN_VISUAL_STUDIO_PATH, 'include')],
        'library_dirs': [PYTHON_LIBS_PATH, WIN_VISUAL_STUDIO_LIB_PATH],
        'libraries': ['user32', 'kernel32', 'Gdi32', 'Advapi32', 'Ws2_32'],
        'extra_objects': [ZLIB_LIB_INSTALL_PATH, join(OPENSSL_LIB_INSTALL_PATH, 'ssleay32.lib'),
                          join(OPENSSL_LIB_INSTALL_PATH, 'libeay32.lib')]
    })

else:
    # Add arguments specific to Unix builds
    NASSL_EXT_SETUP.update({
        'include_dirs': [OPENSSL_HEADERS_INSTALL_PATH, join('nassl', '_nassl')],
        'extra_compile_args': ['-Wall'],
        'extra_objects': [join(OPENSSL_LIB_INSTALL_PATH, 'libssl.a'), join(OPENSSL_LIB_INSTALL_PATH, 'libcrypto.a'),
                          ZLIB_LIB_INSTALL_PATH]
    })


NASSL_SETUP.update({'ext_modules': [Extension(**NASSL_EXT_SETUP)]})


if __name__ == "__main__":
    setup(**NASSL_SETUP)
