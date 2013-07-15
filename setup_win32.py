from distutils.core import setup, Extension

from setup_config import NASSL_SETUP, NASSL_EXT_SETUP
from buildAll_win32 import OPENSSL_INSTALL_DIR


# Add arguments specific to Win32 builds
win32_ext_args = NASSL_EXT_SETUP.copy()

# Python 32 is expected to be in C:\Python27_32
# Visual Studio is expected to be in the default folder
win32_ext_args.update({
    'include_dirs' : [OPENSSL_INSTALL_DIR+'\\include', 'C:\\Program Files (x86)\\Microsoft Visual Studio 9.0\\VC\\include'],
    'library_dirs' : [OPENSSL_INSTALL_DIR + '\\lib', 'C:\\Python27_32\\libs\\', 'C:\\Program Files (x86)\\Microsoft Visual Studio 9.0\\VC\\lib' ],
    'libraries' : ['ssleay32', 'libeay32', 'user32', 'kernel32', 'Gdi32', 'Advapi32', 'Ws2_32']})

win32_setup = NASSL_SETUP.copy()
win32_setup.update({
    'ext_modules' : [Extension(**win32_ext_args)] })


setup(**win32_setup)
