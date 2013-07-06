#!/usr/bin/python
import subprocess
from os import mkdir, getcwd
from sys import platform, version_info


OPENSSL_DIR =   getcwd() + '/openssl-1.0.1e/'
ZLIB_DIR =      getcwd() + '/zlib-1.2.8/'


TEST_DIR = getcwd() + '/test/'


def perform_build_task(title, commandsDict, cwd=None):
    print '===BUILDING {0}==='.format(title)
    for command in commandsDict:
        subprocess.check_call(command, shell=True, cwd=cwd)


def create_folder(path):
    try:
        mkdir(path)
    except OSError as e:
        if 'exists' in str(e.args):
            pass


def main():
    # Create folder
    create_folder(TEST_DIR + '/nassl/')


    # Build Zlib
    ZLIB_BUILD_TASKS = [
        'CFLAGS="-fPIC" ./configure -static',
        'make',
        'cp libz.a ../']

    perform_build_task('ZLIB', ZLIB_BUILD_TASKS, ZLIB_DIR)


    # Build OpenSSL
    OPENSSL_BUILD_DICT = {'darwin' :    'darwin64-x86_64-cc',
                          'linux2' :    'linux-x86_64'}

    OPENSSL_CONF_CMD = (
        './Configure {0} zlib no-zlib-dynamic no-shared enable-rc5 '
        'enable-md2 enable-gost enable-cast enable-idea enable-ripemd '
        'enable-mdc2 --with-zlib-include={1} '
        '--with-zlib-lib={1} -fPIC').format

    OPENSSL_BUILD_TASKS = [
        OPENSSL_CONF_CMD(OPENSSL_BUILD_DICT[platform], ZLIB_DIR),
        'make depend',
        'make',
        'make test',
        'cp libssl.a ../',
        'cp libcrypto.a ../']

    perform_build_task('OPENSSL', OPENSSL_BUILD_TASKS, OPENSSL_DIR)


    # Build nassl
    PY_VERSION = str(version_info[0]) + '.' + str(version_info[1])
    BUILD_PATH = './build/lib.{0}-{1}/nassl/'.format
    BUILD_PATH_DICT = {'darwin' : BUILD_PATH('macosx-10.8-intel', PY_VERSION),
                       'linux2' : BUILD_PATH('linux-x86_64', PY_VERSION) } 

    NASSL_BUILD_TASKS = [
        'python setup.py build',
        'cp -R ' + BUILD_PATH_DICT[platform] + ' ' + TEST_DIR + '/nassl/']

    perform_build_task('NASSL', NASSL_BUILD_TASKS)


    # Test nassl
    NASSL_TEST_TASKS = [
        'python -m unittest discover --pattern=*_Tests.py']

    perform_build_task('NASSL Tests', NASSL_TEST_TASKS, TEST_DIR)


    print '=== All Done! Compiled module is available in ./test/nassl/ ==='


if __name__ == "__main__":
    main()

