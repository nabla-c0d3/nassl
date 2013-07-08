from distutils.core import setup, Extension

from build import OPENSSL_DIR, ZLIB_DIR

setup(name="nassl", 
      version="0.7",
      package_dir = {'nassl' : 'src'},
      py_modules=['nassl.__init__', 'nassl.SslClient', 'nassl.X509Certificate'],
      description='OpenSSL wrapper for SSLyze',
      author='Alban Diquet',
      author_email='nabla.c0d3@gmail.com',
      url='https://github.com/nabla-c0d3/nassl',
      ext_modules=[Extension("nassl._nassl", 
                             ["src/_nassl/nassl.c", "src/_nassl/nassl_SSL_CTX.c", "src/_nassl/nassl_SSL.c", 
                              "src/_nassl/nassl_X509.c", "src/_nassl/nassl_errors.c", "src/_nassl/nassl_BIO.c", 
                              "src/_nassl/nassl_X509_EXTENSION.c", "src/_nassl/nassl_X509_NAME_ENTRY.c", 
                              "src/_nassl/nassl_SSL_SESSION.c", "src/_nassl/openssl_utils.c"], 
                             include_dirs = [OPENSSL_DIR+'/include'],
                             extra_compile_args = ['-Wall', '-pedantic', '-Wno-deprecated-declarations'],
                             library_dirs=[OPENSSL_DIR, ZLIB_DIR],
                             libraries=['ssl', 'z', 'crypto'])])
