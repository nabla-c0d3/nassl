#!/usr/bin/python2.7
""" Base script to successively build Zlib, OpenSSL and nassl from scratch.

It will build the _nassl C extension for the python interpreter/platform that was used to run this script (ie. no
cross-compiling).
"""
import os
import sys
import shutil
from setup import OPENSSL_LIB_INSTALL_PATH, CURRENT_PLATFORM, SupportedPlatformEnum, OPENSSL_HEADERS_INSTALL_PATH, \
    ZLIB_LIB_INSTALL_PATH
from os import getcwd
from os.path import join
import subprocess

# The build script expects the OpenSSL and Zlib src packages to be in nassl's root folder
# Warning: use a fresh Zlib src tree on Windows or build will fail ie. do not use the same Zlib src folder for Windows
# and Unix build
ZLIB_PATH = join(getcwd(), 'zlib-1.2.11')
OPENSSL_PATH = join(getcwd(), 'openssl')
OPENSSL_CONF_CMD = (
    'perl Configure {target} --prefix={install_path} zlib no-zlib-dynamic no-shared enable-rc5 enable-md2 enable-gost '
    'enable-cast enable-idea enable-ripemd enable-mdc2 --with-zlib-include={zlib_path} '
    '--with-zlib-lib={zlib_install_path} {extra_args}'
).format



def perform_build_task(title, commands_dict, cwd=None):
    print '===BUILDING {0}==='.format(title)
    for command in commands_dict:
        subprocess.check_call(command, shell=True, cwd=cwd)


def main():
    # Build Zlib
    if CURRENT_PLATFORM == SupportedPlatformEnum.WINDOWS_32:
        ZLIB_LIB_PATH = ZLIB_PATH + '\\contrib\\vstudio\\vc9\\x86\\ZlibStatRelease\\zlibstat.lib'
        ZLIB_BUILD_TASKS = [
            'bld_ml32.bat',
            'vcbuild /rebuild ..\\vstudio\\vc9\\zlibvc.sln "Release|Win32"'
        ]
        perform_build_task('ZLIB', ZLIB_BUILD_TASKS, ZLIB_PATH + '\\contrib\\masmx86\\')

    elif CURRENT_PLATFORM == SupportedPlatformEnum.WINDOWS_64:
        ZLIB_LIB_PATH = ZLIB_PATH + '\\contrib\\vstudio\\vc9\\x64\\ZlibStatRelease\\zlibstat.lib'
        ZLIB_BUILD_TASKS = [
            'bld_ml64.bat',
            'vcbuild /rebuild ..\\vstudio\\vc9\\zlibvc.sln "Release|x64"'
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


    # Build OpenSSL
    if CURRENT_PLATFORM == SupportedPlatformEnum.WINDOWS_32:
        OPENSSL_BUILD_TASKS = [
            OPENSSL_CONF_CMD(target='VC-WIN32', install_path=OPENSSL_LIB_INSTALL_PATH, zlib_path=ZLIB_PATH,
                             zlib_install_path=ZLIB_LIB_INSTALL_PATH, extra_args=' no-asm -DZLIB_WINAPI'), # *hate* zlib
            'ms\\do_ms',
            #'nmake -f ms\\nt.mak clean',  # This fails when there is nothing to clean
            'nmake -f ms\\nt.mak',
            'nmake -f ms\\nt.mak install',
        ]

    elif CURRENT_PLATFORM == SupportedPlatformEnum.WINDOWS_64:
        OPENSSL_BUILD_TASKS = [
            OPENSSL_CONF_CMD(target='VC-WIN64A', install_path=OPENSSL_LIB_INSTALL_PATH, zlib_path=ZLIB_PATH,
                             zlib_install_path=ZLIB_LIB_INSTALL_PATH, extra_args=' no-asm -DZLIB_WINAPI'),
            'ms\\do_win64a.bat',
            #'nmake -f ms\\nt.mak clean',
            # The build script will crash during the next step at the very end of the OpenSSL build but you can still
            # manage to get a full build of nassl by manually copying the OpenSSL libs from openssl/out32 to
            # bin/openssl/win64.
            'nmake -f ms\\nt.mak',
            'nmake -f ms\\nt.mak install',
        ]
    else:
        if CURRENT_PLATFORM == SupportedPlatformEnum.OSX_64:
            OPENSSL_TARGET = 'darwin64-x86_64-cc'

        elif CURRENT_PLATFORM == SupportedPlatformEnum.LINUX_64:
            OPENSSL_TARGET = 'linux-x86_64'

        elif CURRENT_PLATFORM == SupportedPlatformEnum.LINUX_32:
            OPENSSL_TARGET = 'linux-elf'

        OPENSSL_BUILD_TASKS = [
            OPENSSL_CONF_CMD(target=OPENSSL_TARGET, install_path=OPENSSL_LIB_INSTALL_PATH, zlib_path=ZLIB_PATH,
                             zlib_install_path=ZLIB_LIB_INSTALL_PATH, extra_args=' -fPIC'),
            'make clean',
            'make depend',
            'make',
            'make test',
            'make install_sw',  # Don't build documentation, else will fail on Debian
        ]
    perform_build_task('OPENSSL', OPENSSL_BUILD_TASKS, OPENSSL_PATH)

    # Setup the OpenSSL folder
    # Move the static libraries to the root folder
    if CURRENT_PLATFORM in [SupportedPlatformEnum.WINDOWS_32, SupportedPlatformEnum.WINDOWS_64]:
        shutil.copy(join(OPENSSL_LIB_INSTALL_PATH, 'lib', 'libeay32.lib'), OPENSSL_LIB_INSTALL_PATH)
        shutil.copy(join(OPENSSL_LIB_INSTALL_PATH, 'lib', 'ssleay32.lib'), OPENSSL_LIB_INSTALL_PATH)
    else:
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
    NASSL_EXTRA_ARGS = ''
    if CURRENT_PLATFORM == SupportedPlatformEnum.WINDOWS_32:
        NASSL_EXTRA_ARGS = ' --plat-name=win32'
    elif CURRENT_PLATFORM == SupportedPlatformEnum.WINDOWS_64:
        NASSL_EXTRA_ARGS = ' --plat-name=win-amd64'

    NASSL_BUILD_TASKS = ['{python} setup.py build_ext -i{extra_args}'.format(python=sys.executable,
                                                                             extra_args=NASSL_EXTRA_ARGS)]
    perform_build_task('NASSL', NASSL_BUILD_TASKS)

    # Test nassl
    NASSL_TEST_TASKS = ['{python} run_tests.py'.format(python=sys.executable)]
    perform_build_task('NASSL Tests', NASSL_TEST_TASKS)


    print '=== All Done! ==='


if __name__ == "__main__":
    # TODO: Take the platform as a parameter?
    main()
