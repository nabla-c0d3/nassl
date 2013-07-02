from distutils.core import setup, Extension
setup(name="_nassl", version="1.0",
      ext_modules=[Extension(
      	"_nassl", 
      	["src/_nassl/nassl.c", "src/_nassl/nassl_SSL_CTX.c", "src/_nassl/nassl_SSL.c", "src/_nassl/nassl_X509.c", "src/_nassl/nassl_errors.c", "src/_nassl/nassl_BIO.c", "src/_nassl/nassl_X509_EXTENSION.c", "src/_nassl/nassl_X509_NAME_ENTRY.c"], 
      	include_dirs = ['/Users/nabla/Downloads/openssl-1.0.1e/include/'],
      	extra_objects=['./libcrypto.a', './libssl.a'])])