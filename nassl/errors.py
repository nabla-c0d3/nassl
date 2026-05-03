class OpenSSLError(Exception):
    pass


class SslError(OpenSSLError):
    pass


class WantReadError(OpenSSLError):
    pass


class WantWriteError(OpenSSLError):
    pass


class WantX509LookupError(OpenSSLError):
    pass
