#!/usr/bin/python

from os import mkdir, getcwd
from os.path import join
from sys import platform, version_info

from buildAll_config import OPENSSL_CONF_CMD, BUILD_DIR, PY_VERSION, OPENSSL_DIR, ZLIB_DIR, TEST_DIR, perform_build_task, create_folder


NASSL_INSTALL_DIR = join(BUILD_DIR, 'lib.win32-' + PY_VERSION)
OPENSSL_INSTALL_DIR = join(BUILD_DIR, 'openssl-win32')

ZLIB_LIB_DIR = ZLIB_DIR + '\\contrib\\vstudio\\vc9\\x86\\ZlibStatRelease\\zlibstat.lib'


def main():
    # Create folder
    create_folder(join(TEST_DIR, 'nassl'))
    openssl_internal_dir = join(OPENSSL_INSTALL_DIR, "include", "openssl-internal")
    create_folder(openssl_internal_dir)

    # Build Zlib
    ZLIB_BUILD_TASKS = [
        'bld_ml32.bat',
        'vcbuild /rebuild ..\\vstudio\\vc9\\zlibvc.sln "Release|Win32"']

    perform_build_task('ZLIB', ZLIB_BUILD_TASKS, ZLIB_DIR + '\\contrib\\masmx86\\')


    # Build OpenSSL
    OPENSSL_BUILD_TASKS = [
        OPENSSL_CONF_CMD('VC-WIN32' , OPENSSL_INSTALL_DIR, ZLIB_DIR, ZLIB_LIB_DIR) + ' -DZLIB_WINAPI', # *hate* zlib
        'ms\\do_ms',
        'nmake -f ms\\nt.mak clean',
        'nmake -f ms\\nt.mak',
        'nmake -f ms\\nt.mak install',
        'xcopy /y %s %s'%(join(OPENSSL_DIR, 'e_os.h'), openssl_internal_dir), # copy some internal headers for accessing EDH and ECDH parameters
        'xcopy /y %s %s'%(join(OPENSSL_DIR, 'ssl', 'ssl_locl.h'), openssl_internal_dir)]

    perform_build_task('OPENSSL', OPENSSL_BUILD_TASKS, OPENSSL_DIR)


    # Build nassl
    NASSL_BUILD_TASKS = [
        'python setup_win32.py build --plat-name=win32',
        'xcopy /y /s ' + NASSL_INSTALL_DIR + ' ' + TEST_DIR]

    perform_build_task('NASSL', NASSL_BUILD_TASKS)


    # Test nassl
    NASSL_TEST_TASKS = [
        'C:\\Python27_32\\python.exe -m unittest discover --pattern=*_Tests.py']

    perform_build_task('NASSL Tests', NASSL_TEST_TASKS, TEST_DIR)


    print '=== All Done! Compiled module is available in ./test/nassl/ ==='


if __name__ == "__main__":
    main()
