from distutils.core import setup, Extension

from setup_config import NASSL_SETUP, NASSL_EXT_SETUP
from buildAll_win64 import OPENSSL_INSTALL_DIR, ZLIB_LIB_DIR


# Add arguments specific to Win64 builds
win64_ext_args = NASSL_EXT_SETUP.copy()

# Python 64 is expected to be in C:\Python27
# Visual Studio is expected to be in the default folder
win64_ext_args.update({
    'include_dirs' : [OPENSSL_INSTALL_DIR+'\\include', 'C:\\Program Files (x86)\\Microsoft Visual Studio 9.0\\VC\\include'],
    'library_dirs' : [OPENSSL_INSTALL_DIR + '\\lib', 'C:\\Python27\\libs\\', 'C:\\Program Files (x86)\\Microsoft Visual Studio 9.0\\VC\\lib\\amd64' ],
    'libraries' : ['ssleay32', 'libeay32', 'user32', 'kernel32', 'Gdi32', 'Advapi32', 'Ws2_32'],
	'extra_objects' : [ZLIB_LIB_DIR]})

win64_setup = NASSL_SETUP.copy()
win64_setup.update({
    'ext_modules' : [Extension(**win64_ext_args)]})


setup(**win64_setup)
