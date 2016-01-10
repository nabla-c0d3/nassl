from src import __author__, __version__

NASSL_SETUP = {
    'name' : "nassl",
    'version' : __version__,
    'package_dir' : {'nassl' : 'src'},
    'py_modules' : ['nassl.__init__', 'nassl.SslClient', 'nassl.DebugSslClient', 'nassl.X509Certificate', 'nassl.OcspResponse'],
    'description' : 'OpenSSL wrapper for SSLyze',
    'author' : __author__,
    'author_email' : 'nabla.c0d3@gmail.com',
    'url' : 'https://github.com/nabla-c0d3/nassl'
    }


NASSL_EXT_SETUP = {
    'name' : "nassl._nassl",
    'sources' : ["src/_nassl/nassl.c", "src/_nassl/nassl_SSL_CTX.c", "src/_nassl/nassl_SSL.c",
                 "src/_nassl/nassl_X509.c", "src/_nassl/nassl_errors.c", "src/_nassl/nassl_BIO.c",
                 "src/_nassl/nassl_X509_EXTENSION.c", "src/_nassl/nassl_X509_NAME_ENTRY.c",
                 "src/_nassl/nassl_SSL_SESSION.c", "src/_nassl/openssl_utils.c", "src/_nassl/nassl_OCSP_RESPONSE.c"]
}

