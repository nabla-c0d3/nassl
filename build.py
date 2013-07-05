#!/usr/bin/python
import subprocess
from os import mkdir
from sys import platform


OPENSSL_DIR =    "./openssl-1.0.1e/"
ZLIB_DIR =       "./zlib-1.2.8/"
FINAL_DIR =     './nassl/'



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


# Create folders
create_folder(FINAL_DIR)
create_folder('./test/nassl')


# Build OpenSSL
OPENSSL_BUILD_DICT = {'darwin' : 'darwin64-x86_64-cc'}

OPENSSL_CONF_CMD = './Configure {0} zlib no-shared enable-rc5 enable-md2 enable-gost enable-cast enable-idea enable-ripemd enable-mdc2'.format

OPENSSL_BUILD_TASKS = [
    OPENSSL_CONF_CMD(OPENSSL_BUILD_DICT[platform]),
    'make depend',
    'make',
    'make test',
    'cp libssl.a ../',
    'cp libcrypto.a ../']

perform_build_task('OPENSSL', OPENSSL_BUILD_TASKS, OPENSSL_DIR)


# Build Zlib
ZLIB_BUILD_TASKS = [
    'make',
    'cp libz.a ../']

perform_build_task('ZLIB', ZLIB_BUILD_TASKS, ZLIB_DIR)


# Build nassl
BUILD_PATH_DICT = {'darwin' : './build/lib.macosx-10.8-intel-2.7/_nassl.so'}

NASSL_BUILD_TASKS = [
    'python setup.py build',
    'cp ' + BUILD_PATH_DICT[platform] + ' ' + FINAL_DIR,
    'cp ./src/SslClient.py ' + FINAL_DIR,
    'cp ./src/X509Certificate.py ' + FINAL_DIR,
    'cp ./src/__init__.py ' + FINAL_DIR]

perform_build_task('NASSL', NASSL_BUILD_TASKS)
 

# Test nassl
NASSL_TEST_TASKS = [
    'cp -R ../' + FINAL_DIR + ' ./nassl/',
    'python -m unittest discover --pattern=*_Tests.py']

perform_build_task('NASSL Tests', NASSL_TEST_TASKS, './test')


