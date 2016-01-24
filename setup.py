#!/usr/bin/python2.7
from distutils.core import setup, Extension
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


CURRENT_PLATFORM = None
if architecture()[0] == '64bit':
    if platform == 'darwin':
        CURRENT_PLATFORM = SupportedPlatformEnum.OSX_64
    elif platform == 'linux2':
        CURRENT_PLATFORM = SupportedPlatformEnum.LINUX_64
elif architecture()[0] == '32bit':
    if platform == 'linux2':
        CURRENT_PLATFORM = SupportedPlatformEnum.LINUX_32
# TODO: Add Windows



OPENSSL_INSTALL_PATH_DICT = {
    # Need full paths (hence the getcwd()) as they get passed to OpenSSL in build_from_scratch.py
    SupportedPlatformEnum.OSX_64: join(getcwd(), 'bin', 'openssl', 'darwin64'),
    SupportedPlatformEnum.LINUX_64: join(getcwd(), 'openssl', 'linux64'),
    SupportedPlatformEnum.LINUX_32: join(getcwd(), 'bin', 'openssl', 'linux32'),
    SupportedPlatformEnum.WINDOWS_32: join(getcwd(), 'bin', 'openssl', 'windows32'),
    SupportedPlatformEnum.WINDOWS_64: join(getcwd(), 'bin', 'openssl', 'windows64'),
}


OPENSSL_LIB_INSTALL_PATH = OPENSSL_INSTALL_PATH_DICT[CURRENT_PLATFORM]
OPENSSL_HEADERS_INSTALL_PATH = join('bin', 'openssl', 'include')


NASSL_SETUP = {
    'name': "nassl",
    'version': __version__,
    'package_dir': {'nassl': 'nassl'},
    'py_modules': ['nassl.__init__', 'nassl.SslClient', 'nassl.DebugSslClient', 'nassl.X509Certificate',
                   'nassl.OcspResponse'],
    'description': 'Experimental OpenSSL wrapper for SSLyze.',
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

# Add arguments specific to Unix builds
unix_ext_args = NASSL_EXT_SETUP.copy()
unix_ext_args.update({
    'include_dirs': [OPENSSL_HEADERS_INSTALL_PATH, join('nassl', '_nassl')],
    'extra_compile_args': ['-Wall'],
    'extra_objects': [join(OPENSSL_LIB_INSTALL_PATH, 'libssl.a'), join(OPENSSL_LIB_INSTALL_PATH, 'libcrypto.a')]
})


unix_setup = NASSL_SETUP.copy()
unix_setup.update({'ext_modules': [Extension(**unix_ext_args)]})


if __name__ == "__main__":
    setup(**unix_setup)
