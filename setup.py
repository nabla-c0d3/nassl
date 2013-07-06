from distutils.core import setup, Extension

from build import OPENSSL_DIR

setup(name="_nassl", version="1.0",
      ext_modules=[Extension(
      	"_nassl", 
      	["src/_nassl/nassl.c", "src/_nassl/nassl_SSL_CTX.c", "src/_nassl/nassl_SSL.c", "src/_nassl/nassl_X509.c", "src/_nassl/nassl_errors.c", "src/_nassl/nassl_BIO.c", "src/_nassl/nassl_X509_EXTENSION.c", "src/_nassl/nassl_X509_NAME_ENTRY.c", "src/_nassl/nassl_SSL_SESSION.c", "src/_nassl/openssl_utils.c"], 
      	include_dirs = [OPENSSL_DIR],
        extra_compile_args = ['-std=c99', '-Wall', '-pedantic', '-Wno-deprecated-declarations'],
      	extra_objects=['./libcrypto.a', './libssl.a', './libz.a'])])