from distutils.core import setup, Extension
setup(name="nassl", version="1.0",
      ext_modules=[Extension(
      	"nassl", 
      	["nassl.c", "nassl_SSL_CTX.c", "nassl_SSL.c", "nassl_X509.c", "nassl_errors.c"], 
      	include_dirs = ['/Users/nabla/Downloads/openssl-1.0.1e/include/'],
      	extra_objects=['./libcrypto.a', './libssl.a'])])