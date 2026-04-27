from nassl.openssl_1_1_1.ssl_client import SslClient_OpenSSL_1_1_1
import nassl.openssl_4_0_0._nassl


# For now, the OpenSSL 4.0.0 client is identical to the OpenSSL 1.1.1 client
class SslClient_OpenSSL_4_0_0(SslClient_OpenSSL_1_1_1):
    _NASSL_MODULE = nassl.openssl_4_0_0._nassl
