class OpenSSLError(Exception):
    pass


class SslError(OpenSSLError):
    pass


class WantReadError(SslError):
    pass


class WantWriteError(SslError):
    pass


class WantX509LookupError(SslError):
    pass
