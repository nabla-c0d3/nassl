#!/usr/bin/python2.7
import os
import shutil
from platform import architecture
from sys import platform
from os.path import join
import distutils.util
from buildAll_config import OPENSSL_CONF_CMD, BUILD_DIR, PY_VERSION, OPENSSL_DIR, ZLIB_DIR, TEST_DIR, perform_build_task, create_folder


NASSL_INSTALL_DIR = ''

# I've only tried building nassl on OS X 64 bits and Linux 32/64 bits
# This will fail if you're cross-compiling
if architecture()[0] == '64bit':
    if platform == 'darwin':
        OPENSSL_TARGET = 'darwin64-x86_64-cc'
        NASSL_INSTALL_DIR = join('build', 'lib.' + distutils.util.get_platform() + '-' + PY_VERSION, 'nassl')
        OPENSSL_INSTALL_DIR = join(BUILD_DIR, 'openssl', 'darwin64')

    elif platform == 'linux2':
        OPENSSL_TARGET = 'linux-x86_64'
        NASSL_INSTALL_DIR = join('build', 'lib.linux-x86_64-' + PY_VERSION + '/')
        OPENSSL_INSTALL_DIR = join(BUILD_DIR, 'openssl', 'linux64')

elif architecture()[0] == '32bit':
    if platform == 'linux2':
        OPENSSL_TARGET = 'linux-elf'
        NASSL_INSTALL_DIR = join('build', 'lib.linux-i686-' + PY_VERSION + '/')
        OPENSSL_INSTALL_DIR = join(BUILD_DIR, 'openssl', 'linux32')


if NASSL_INSTALL_DIR == '':
    raise Exception('Plaftorm ' + platform + ' ' + architecture()[0] + ' not supported.')


def main():
    # Build Zlib
    ZLIB_BUILD_TASKS = [
        'CFLAGS="-fPIC" ./configure -static',
        'make clean',
        'make'
    ]
    perform_build_task('ZLIB', ZLIB_BUILD_TASKS, ZLIB_DIR)


    # Build OpenSSL
    OPENSSL_BUILD_TASKS = [
        OPENSSL_CONF_CMD(OPENSSL_TARGET, OPENSSL_INSTALL_DIR, ZLIB_DIR,  ZLIB_DIR) + ' -fPIC',
        'make clean',
        #'make depend',  # This makes building with Clang on OS X fail
        'make',
        'make test',
        'make install_sw',  # Don't build documentation, else will fail on Debian
    ]
    perform_build_task('OPENSSL', OPENSSL_BUILD_TASKS, OPENSSL_DIR)

    # Setup the OpenSSL folder
    # Move the static libraries to the root folder
    shutil.copy(join(OPENSSL_INSTALL_DIR, 'lib', 'libcrypto.a'), OPENSSL_INSTALL_DIR)
    shutil.copy(join(OPENSSL_INSTALL_DIR, 'lib', 'libssl.a'), OPENSSL_INSTALL_DIR)

    # Move the headers
    shutil.rmtree(join(BUILD_DIR, 'openssl', 'include'))
    shutil.move(join(OPENSSL_INSTALL_DIR, 'include'), join(BUILD_DIR, 'openssl'))

    # Copy some internal headers for accessing EDH and ECDH parameters
    HEADERS_PATH = join(BUILD_DIR, 'openssl', 'include', 'openssl-internal')
    if not os.path.isdir(HEADERS_PATH):
        os.makedirs(HEADERS_PATH)
    shutil.copy(join(OPENSSL_DIR, 'e_os.h'), HEADERS_PATH)
    shutil.copy(join(OPENSSL_DIR, 'ssl', 'ssl_locl.h'), HEADERS_PATH)

    # Erase everything else
    shutil.rmtree(join(OPENSSL_INSTALL_DIR, 'lib'))
    shutil.rmtree(join(OPENSSL_INSTALL_DIR, 'bin'))
    shutil.rmtree(join(OPENSSL_INSTALL_DIR, 'ssl'))


    # Build nassl
    NASSL_BUILD_TASKS = ['python2.7 setup_unix.py build_ext -i']
    perform_build_task('NASSL', NASSL_BUILD_TASKS)

    # Test nassl
    NASSL_TEST_TASKS = [
        'python2.7 -m unittest discover --pattern=*_Tests.py']

    perform_build_task('NASSL Tests', NASSL_TEST_TASKS, TEST_DIR)


    print '=== All Done! Compiled module is available in ./test/nassl/ ==='


if __name__ == "__main__":
    # TODO: Take the platform as a parameter?
    main()
