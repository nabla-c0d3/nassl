from enum import IntEnum


class TlsVersionEnum(IntEnum):
    # The values here must match SslProtocolVersion in nassl_SSL_CTX.c
    SSL_2_0 = 1
    SSL_3_0 = 2
    TLS_1_0 = 3
    TLS_1_1 = 4
    TLS_1_2 = 5
    TLS_1_3 = 6
