#!/usr/bin/python2.7
import os
import shutil
from setup import OPENSSL_LIB_INSTALL_PATH, CURRENT_PLATFORM, SupportedPlatformEnum, OPENSSL_HEADERS_INSTALL_PATH
from os import getcwd
from os.path import join
import subprocess

# Base script to build Zlib, OpenSSL and nassl from scratch
# The build scripts expect the OpenSSL and Zlib src packages to be in nassl's root folder
# Warning: use a fresh Zlib src tree on Windows or build will fail ie. do not use the same Zlib src folder for Windows
# and Unix build
ZLIB_PATH = join(getcwd(), 'zlib-1.2.8')
OPENSSL_PATH = join(getcwd(), 'openssl')
OPENSSL_CONF_CMD = (
    'perl Configure {target} --prefix={install_path} zlib no-zlib-dynamic no-shared enable-rc5 enable-md2 enable-gost '
    'enable-cast enable-idea enable-ripemd enable-mdc2 --with-zlib-include={zlib_path} '
    '--with-zlib-lib={zlib_install_path} {extra_args}'
).format


# I've only tried building nassl on OS X 64 bits and Linux 32/64 bits
# This will fail if you're cross-compiling
ZLIB_INSTALL_PATH = ZLIB_PATH
OPENSSL_BUILD_EXTRA_ARGS = ' -fPIC'

if CURRENT_PLATFORM == SupportedPlatformEnum.OSX_64:
    OPENSSL_TARGET = 'darwin64-x86_64-cc'

elif CURRENT_PLATFORM == SupportedPlatformEnum.LINUX_64:
    OPENSSL_TARGET = 'linux-x86_64'

elif CURRENT_PLATFORM == SupportedPlatformEnum.LINUX_32:
    OPENSSL_TARGET = 'linux-elf'

elif CURRENT_PLATFORM == SupportedPlatformEnum.WINDOWS_32:
    OPENSSL_TARGET = 'VC-WIN32'
    ZLIB_INSTALL_PATH = ZLIB_PATH + '\\contrib\\vstudio\\vc9\\x86\\ZlibStatRelease\\zlibstat.lib'
    OPENSSL_BUILD_EXTRA_ARGS = ' no-asm -DZLIB_WINAPI'  # *hate* zlib

elif CURRENT_PLATFORM == SupportedPlatformEnum.WINDOWS_64:
    OPENSSL_TARGET = 'VC-WIN64A'
    ZLIB_INSTALL_PATH = ZLIB_PATH + '\\contrib\\vstudio\\vc9\\x64\\ZlibStatRelease\\zlibstat.lib'
    OPENSSL_BUILD_EXTRA_ARGS = ' -DZLIB_WINAPI'



def perform_build_task(title, commandsDict, cwd=None):
    print '===BUILDING {0}==='.format(title)
    for command in commandsDict:
        subprocess.check_call(command, shell=True, cwd=cwd)


def main():
    # Build Zlib
    ZLIB_BUILD_TASKS = [
        'CFLAGS="-fPIC" ./configure -static',
        'make clean',
        'make'
    ]
    perform_build_task('ZLIB', ZLIB_BUILD_TASKS, ZLIB_PATH)


    # Build OpenSSL
    OPENSSL_BUILD_TASKS = [
        OPENSSL_CONF_CMD(target=OPENSSL_TARGET, install_path=OPENSSL_LIB_INSTALL_PATH, zlib_path=ZLIB_PATH,
                         zlib_install_path=ZLIB_INSTALL_PATH, extra_args=OPENSSL_BUILD_EXTRA_ARGS),
        'make clean',
        'make depend',
        'make',
        'make test',
        'make install_sw',  # Don't build documentation, else will fail on Debian
    ]
    perform_build_task('OPENSSL', OPENSSL_BUILD_TASKS, OPENSSL_PATH)

    # Setup the OpenSSL folder
    # Move the static libraries to the root folder
    shutil.copy(join(OPENSSL_LIB_INSTALL_PATH, 'lib', 'libcrypto.a'), OPENSSL_LIB_INSTALL_PATH)
    shutil.copy(join(OPENSSL_LIB_INSTALL_PATH, 'lib', 'libssl.a'), OPENSSL_LIB_INSTALL_PATH)

    # Move the header to ./bin/openssl
    shutil.rmtree(OPENSSL_HEADERS_INSTALL_PATH)
    shutil.move(join(OPENSSL_LIB_INSTALL_PATH, 'include'), OPENSSL_HEADERS_INSTALL_PATH)

    # Copy some internal headers for accessing EDH and ECDH parameters
    INTERNAL_HEADERS_INSTALL_PATH = join(OPENSSL_HEADERS_INSTALL_PATH, 'openssl-internal')
    if not os.path.isdir(INTERNAL_HEADERS_INSTALL_PATH):
        os.makedirs(INTERNAL_HEADERS_INSTALL_PATH)
    shutil.copy(join(OPENSSL_PATH, 'e_os.h'), INTERNAL_HEADERS_INSTALL_PATH)
    shutil.copy(join(OPENSSL_PATH, 'ssl', 'ssl_locl.h'), INTERNAL_HEADERS_INSTALL_PATH)

    # Erase everything else
    shutil.rmtree(join(OPENSSL_LIB_INSTALL_PATH, 'lib'))
    shutil.rmtree(join(OPENSSL_LIB_INSTALL_PATH, 'bin'))
    shutil.rmtree(join(OPENSSL_LIB_INSTALL_PATH, 'ssl'))


    # Build nassl
    NASSL_BUILD_TASKS = ['python2.7 setup.py build_ext -i']
    perform_build_task('NASSL', NASSL_BUILD_TASKS)

    # Test nassl
    NASSL_TEST_TASKS = ['python2.7 run_tests.py']
    perform_build_task('NASSL Tests', NASSL_TEST_TASKS)


    print '=== All Done! ==='


if __name__ == "__main__":
    # TODO: Take the platform as a parameter?
    main()
