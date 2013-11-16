#!/usr/bin/python

from os import mkdir, getcwd
from os.path import join
from sys import platform, version_info

from buildAll_config import OPENSSL_CONF_CMD, BUILD_DIR, PY_VERSION, OPENSSL_DIR, ZLIB_DIR, TEST_DIR, perform_build_task, create_folder

##### Full build fails right now on win64 #####
# The Openssl build fails at the very end but libeay32.lib and
# ssleay32.lib are still generated. You need to copy them manually
# to ./build/openssl-win64/lib and run the rest of the script

NASSL_INSTALL_DIR = join(BUILD_DIR, 'lib.win-amd64-' + PY_VERSION)
OPENSSL_INSTALL_DIR = join(BUILD_DIR, 'openssl-win64')

ZLIB_LIB_DIR = ZLIB_DIR + '\\contrib\\vstudio\\vc9\\x64\\ZlibStatRelease\\zlibstat.lib'


def main():
    # Create folder
    create_folder(join(TEST_DIR, 'nassl'))

    # Build Zlib
    ZLIB_BUILD_TASKS = [
        'bld_ml64.bat',
        'vcbuild /rebuild ..\\vstudio\\vc9\\zlibvc.sln "Release|x64"']

    perform_build_task('ZLIB', ZLIB_BUILD_TASKS, ZLIB_DIR + '\\contrib\\masmx64\\')


    # Build OpenSSL
    OPENSSL_BUILD_TASKS = [
        OPENSSL_CONF_CMD('VC-WIN64A' , OPENSSL_INSTALL_DIR, ZLIB_DIR, ZLIB_LIB_DIR) + ' -DZLIB_WINAPI', # *hate* zlib
        'ms\\do_win64a.bat',
        'nmake -f ms\\nt.mak clean',
        'nmake -f ms\\nt.mak',
        'nmake -f ms\\nt.mak install']

    perform_build_task('OPENSSL', OPENSSL_BUILD_TASKS, OPENSSL_DIR)


    # Build nassl
    NASSL_BUILD_TASKS = [
        'python setup_win64.py build --plat-name=win-amd64',
        'xcopy /y /s ' + NASSL_INSTALL_DIR + ' ' + TEST_DIR]

    perform_build_task('NASSL', NASSL_BUILD_TASKS)


    # Test nassl
    NASSL_TEST_TASKS = [
        'C:\\Python27\\python.exe -m unittest discover --pattern=*_Tests.py']

    perform_build_task('NASSL Tests', NASSL_TEST_TASKS, TEST_DIR)


    print '=== All Done! Compiled module is available in ./test/nassl/ ==='


if __name__ == "__main__":
    main()

