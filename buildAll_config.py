from os import mkdir, getcwd
from os.path import join
from sys import version_info
import subprocess


# Base script to configure win/unix build scripts


# The build scripts expect the OpenSSL and Zlib src packages to be in nassl's root folder
OPENSSL_DIR = join(getcwd(), 'openssl')

# Warning: use a fresh Zlib src tree on Windows or build will fail ie. do not use the same Zlib src folder for Windows
# and Unix build
ZLIB_DIR = join(getcwd(), 'zlib-1.2.8')


TEST_DIR = join(getcwd(), 'test')
BUILD_DIR = join(getcwd(), 'build')


PY_VERSION = str(version_info[0]) + '.' + str(version_info[1])


OPENSSL_CONF_CMD = (
    'perl Configure {0} --prefix={1} zlib no-zlib-dynamic no-shared enable-rc5 '
    'enable-md2 enable-gost enable-cast enable-idea enable-ripemd '
    'enable-mdc2 --with-zlib-include={2} '
    '--with-zlib-lib={3}').format


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

