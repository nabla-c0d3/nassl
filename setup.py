from distutils.core import setup, Extension
setup(name="_nassl", version="1.0",
      ext_modules=[Extension(
      	"_nassl", 
      	["src/nassl.c", "src/nassl_SSL_CTX.c", "src/nassl_SSL.c", "src/nassl_X509.c", "src/nassl_errors.c", "src/nassl_BIO.c", "src/nassl_X509_EXTENSION.c", "src/nassl_X509_NAME_ENTRY.c"], 
      	include_dirs = ['/Users/nabla/Downloads/openssl-1.0.1e/include/'],
      	extra_objects=['./libcrypto.a', './libssl.a'])])