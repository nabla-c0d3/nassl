#!/usr/bin/python
""" Base script to successively build Zlib, OpenSSL and nassl from scratch.

It will build the _nassl C extension for the python interpreter/platform that was used to run this script (ie. no
cross-compiling).
"""
from __future__ import absolute_import
from __future__ import unicode_literals
import os
import sys
import shutil
from setup import MODERN_OPENSSL_LIB_INSTALL_PATH, CURRENT_PLATFORM, SupportedPlatformEnum, \
    MODERN_OPENSSL_HEADERS_INSTALL_PATH, LEGACY_OPENSSL_LIB_INSTALL_PATH, LEGACY_OPENSSL_HEADERS_INSTALL_PATH, \
    ZLIB_LIB_INSTALL_PATH
from os import getcwd
from os.path import join
import subprocess

# The build script expects the OpenSSL and Zlib src packages to be in nassl's root folder
# Warning: use a fresh Zlib src tree on Windows or build will fail ie. do not use the same Zlib src folder for Windows
# and Unix build
ZLIB_PATH = join(getcwd(), 'zlib-1.2.11')

MODREN_OPENSSL_PATH = join(getcwd(), 'openssl-1.1.0f')
LEGACY_OPENSSL_PATH = join(getcwd(), 'openssl-1.0.2e')


OPENSSL_CONF_CMD = (
    'perl Configure {target} --prefix={install_path} --openssldir={install_path} enable-weak-ssl-ciphers zlib '
    'no-zlib-dynamic no-shared enable-rc5 enable-md2 enable-gost '
    'enable-cast enable-idea enable-ripemd enable-mdc2 --with-zlib-include={zlib_path} '
    '--with-zlib-lib={zlib_install_path} {extra_args}'
).format



def perform_build_task(title, commands_dict, cwd=None):
    print ('===BUILDING {0}==='.format(title))
    for command in commands_dict:
        subprocess.check_call(command, shell=True, cwd=cwd)


def build_legacy_openssl():
    if CURRENT_PLATFORM in [SupportedPlatformEnum.WINDOWS_32, SupportedPlatformEnum.WINDOWS_64]:
        if CURRENT_PLATFORM == SupportedPlatformEnum.WINDOWS_32:
            openssl_target = 'VC-WIN32'
            first_build_step = 'ms\\do_ms'
        else:
            openssl_target = 'VC-WIN64A'
            first_build_step = 'ms\\do_win64a.bat'

        build_tasks = [
            OPENSSL_CONF_CMD(target=openssl_target, install_path=LEGACY_OPENSSL_LIB_INSTALL_PATH, zlib_path=ZLIB_PATH,
                             zlib_install_path=ZLIB_LIB_INSTALL_PATH, extra_args=' -no-asm -DZLIB_WINAPI'),  # *hate* zlib
            first_build_step,
            #'nmake -f ms\\nt.mak clean',
            'nmake -f ms\\nt.mak',
            'nmake -f ms\\nt.mak install',
        ]
    else:
        if CURRENT_PLATFORM == SupportedPlatformEnum.OSX_64:
            openssl_target = 'darwin64-x86_64-cc'
        elif CURRENT_PLATFORM == SupportedPlatformEnum.LINUX_64:
            openssl_target = 'linux-x86_64'
        elif CURRENT_PLATFORM == SupportedPlatformEnum.LINUX_32:
            openssl_target = 'linux-elf'

        else:
            raise ValueError('Unkown platform')

        build_tasks = [
            OPENSSL_CONF_CMD(target=openssl_target, install_path=LEGACY_OPENSSL_HEADERS_INSTALL_PATH, zlib_path=ZLIB_PATH,
                             zlib_install_path=ZLIB_LIB_INSTALL_PATH, extra_args=' -fPIC'),
            'make clean',
            'make depend',
            'make',
            'make test',
            'make install_sw',  # Don't build documentation, else will fail on Debian
        ]

    perform_build_task('LEGACY OPENSSL', build_tasks, LEGACY_OPENSSL_PATH)

    # Setup the OpenSSL folder
    # Move the static libraries to the root folder
    if CURRENT_PLATFORM in [SupportedPlatformEnum.WINDOWS_32, SupportedPlatformEnum.WINDOWS_64]:
        shutil.copy(join(LEGACY_OPENSSL_LIB_INSTALL_PATH, 'lib', 'libeay32.lib'), LEGACY_OPENSSL_LIB_INSTALL_PATH)
        shutil.copy(join(LEGACY_OPENSSL_LIB_INSTALL_PATH, 'lib', 'ssleay32.lib'), LEGACY_OPENSSL_LIB_INSTALL_PATH)
    else:
        shutil.copy(join(LEGACY_OPENSSL_LIB_INSTALL_PATH, 'lib', 'libcrypto.a'), LEGACY_OPENSSL_LIB_INSTALL_PATH)
        shutil.copy(join(LEGACY_OPENSSL_LIB_INSTALL_PATH, 'lib', 'libssl.a'), LEGACY_OPENSSL_LIB_INSTALL_PATH)

    shutil.rmtree(LEGACY_OPENSSL_HEADERS_INSTALL_PATH)
    shutil.move(join(LEGACY_OPENSSL_LIB_INSTALL_PATH, 'include'), LEGACY_OPENSSL_HEADERS_INSTALL_PATH)

    # Copy some internal headers for accessing EDH and ECDH parameters
    INTERNAL_HEADERS_INSTALL_PATH = join(LEGACY_OPENSSL_HEADERS_INSTALL_PATH, 'openssl-internal')
    if not os.path.isdir(INTERNAL_HEADERS_INSTALL_PATH):
        os.makedirs(INTERNAL_HEADERS_INSTALL_PATH)
    shutil.copy(join(LEGACY_OPENSSL_PATH, 'e_os.h'), INTERNAL_HEADERS_INSTALL_PATH)
    shutil.copy(join(LEGACY_OPENSSL_PATH, 'ssl', 'ssl_locl.h'), INTERNAL_HEADERS_INSTALL_PATH)

    # Erase everything else
    shutil.rmtree(join(LEGACY_OPENSSL_LIB_INSTALL_PATH, 'lib'))
    shutil.rmtree(join(LEGACY_OPENSSL_LIB_INSTALL_PATH, 'bin'))


def build_modern_openssl():
    if CURRENT_PLATFORM in [SupportedPlatformEnum.WINDOWS_32, SupportedPlatformEnum.WINDOWS_64]:
        if CURRENT_PLATFORM == SupportedPlatformEnum.WINDOWS_32:
            openssl_target = 'VC-WIN32'
        else:
            openssl_target = 'VC-WIN64A'

        build_tasks = [
            OPENSSL_CONF_CMD(target=openssl_target, install_path=MODERN_OPENSSL_LIB_INSTALL_PATH, zlib_path=ZLIB_PATH,
                             zlib_install_path=ZLIB_LIB_INSTALL_PATH, extra_args=' -no-asm -DZLIB_WINAPI'),  # *hate* zlib
            'nmake',
            'nmake test',
            'nmake install',
        ]
    else:
        if CURRENT_PLATFORM == SupportedPlatformEnum.OSX_64:
            openssl_target = 'darwin64-x86_64-cc'
        elif CURRENT_PLATFORM == SupportedPlatformEnum.LINUX_64:
            openssl_target = 'linux-x86_64'
        elif CURRENT_PLATFORM == SupportedPlatformEnum.LINUX_32:
            openssl_target = 'linux-elf'
        else:
            raise ValueError('Unkown platform')

        build_tasks = [
            OPENSSL_CONF_CMD(target=openssl_target, install_path=MODERN_OPENSSL_LIB_INSTALL_PATH, zlib_path=ZLIB_PATH,
                             zlib_install_path=ZLIB_LIB_INSTALL_PATH, extra_args=' -fPIC'),
            'make clean',
            'make depend',
            'make',
            'make test',
            'make install_sw',  # Don't build documentation, else will fail on Debian
        ]

    perform_build_task('MODERN OPENSSL', build_tasks, MODREN_OPENSSL_PATH)

    # Setup the OpenSSL folder
    # Move the static libraries to the root folder
    if CURRENT_PLATFORM in [SupportedPlatformEnum.WINDOWS_32, SupportedPlatformEnum.WINDOWS_64]:
        # In "modern" OpenSSL, the windows binaries have been renamed to match the Unix names
        shutil.copy(join(MODERN_OPENSSL_LIB_INSTALL_PATH, 'lib', 'libcrypto.lib'), MODERN_OPENSSL_LIB_INSTALL_PATH)
        shutil.copy(join(MODERN_OPENSSL_LIB_INSTALL_PATH, 'lib', 'libssl.lib'), MODERN_OPENSSL_LIB_INSTALL_PATH)
    else:
        shutil.copy(join(MODERN_OPENSSL_LIB_INSTALL_PATH, 'lib', 'libcrypto.a'), MODERN_OPENSSL_LIB_INSTALL_PATH)
        shutil.copy(join(MODERN_OPENSSL_LIB_INSTALL_PATH, 'lib', 'libssl.a'), MODERN_OPENSSL_LIB_INSTALL_PATH)

    # Move the header to ./bin/openssl
    shutil.rmtree(MODERN_OPENSSL_HEADERS_INSTALL_PATH)
    shutil.move(join(MODERN_OPENSSL_LIB_INSTALL_PATH, 'include'), MODERN_OPENSSL_HEADERS_INSTALL_PATH)

    # Erase everything else
    shutil.rmtree(join(MODERN_OPENSSL_LIB_INSTALL_PATH, 'lib'))
    shutil.rmtree(join(MODERN_OPENSSL_LIB_INSTALL_PATH, 'bin'))
    shutil.rmtree(join(MODERN_OPENSSL_LIB_INSTALL_PATH, 'certs'))
    shutil.rmtree(join(MODERN_OPENSSL_LIB_INSTALL_PATH, 'html'))
    shutil.rmtree(join(MODERN_OPENSSL_LIB_INSTALL_PATH, 'misc'))
    shutil.rmtree(join(MODERN_OPENSSL_LIB_INSTALL_PATH, 'private'))


def main():
    # Build Zlib
    if CURRENT_PLATFORM == SupportedPlatformEnum.WINDOWS_32:
        ZLIB_LIB_PATH = ZLIB_PATH + '\\contrib\\vstudio\\vc14\\x86\\ZlibStatRelease\\zlibstat.lib'
        ZLIB_BUILD_TASKS = [
            'bld_ml32.bat',
            'msbuild ..\\vstudio\\vc14\\zlibvc.sln /P:Configuration=Release /P:Platform=Win32"'
        ]
        perform_build_task('ZLIB', ZLIB_BUILD_TASKS, ZLIB_PATH + '\\contrib\\masmx86\\')

    elif CURRENT_PLATFORM == SupportedPlatformEnum.WINDOWS_64:
        ZLIB_LIB_PATH = ZLIB_PATH + '\\contrib\\vstudio\\vc14\\x64\\ZlibStatRelease\\zlibstat.lib'
        ZLIB_BUILD_TASKS = [
            'bld_ml64.bat',
            'msbuild ..\\vstudio\\vc14\\zlibvc.sln /P:Configuration=Release /P:Platform=x64"'
        ]
        perform_build_task('ZLIB', ZLIB_BUILD_TASKS, ZLIB_PATH + '\\contrib\\masmx64\\')

    else:
        ZLIB_LIB_PATH = join(ZLIB_PATH, 'libz.a')
        ZLIB_BUILD_TASKS = [
            'CFLAGS="-fPIC" ./configure -static',
            'make clean',
            'make'
        ]
        perform_build_task('ZLIB', ZLIB_BUILD_TASKS, ZLIB_PATH)

    # Keep the Zlib around as it is linked into _nassl
    if not os.path.isdir(os.path.dirname(ZLIB_LIB_INSTALL_PATH)):
        os.makedirs(os.path.dirname(ZLIB_LIB_INSTALL_PATH))
    shutil.copy(ZLIB_LIB_PATH, ZLIB_LIB_INSTALL_PATH)

    # Build the two versions of OpenSSL
    build_legacy_openssl()
    build_modern_openssl()


    # Build nassl
    NASSL_EXTRA_ARGS = ''
    if CURRENT_PLATFORM == SupportedPlatformEnum.WINDOWS_32:
        NASSL_EXTRA_ARGS = ' --plat-name=win32'
    elif CURRENT_PLATFORM == SupportedPlatformEnum.WINDOWS_64:
        NASSL_EXTRA_ARGS = ' --plat-name=win-amd64'

    NASSL_BUILD_TASKS = ['{python} setup.py build_ext -i{extra_args}'.format(python=sys.executable,
                                                                             extra_args=NASSL_EXTRA_ARGS)]
    perform_build_task('NASSL', NASSL_BUILD_TASKS)

    # Test nassl
    NASSL_TEST_TASKS = ['{python} setup.py test'.format(python=sys.executable)]
    perform_build_task('NASSL Tests', NASSL_TEST_TASKS)


    print ('=== All Done! ===')


if __name__ == "__main__":
    # TODO: Take the platform as a parameter?
    main()
