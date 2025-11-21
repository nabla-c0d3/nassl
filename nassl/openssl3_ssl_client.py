"""SSL client implementation using OpenSSL 3.x."""

try:
    from nassl import _nassl3 as nassl3_module
except ImportError:
    nassl3_module = None  # type: ignore

from nassl.ssl_client import SslClient


class OpenSSL3SslClient(SslClient):
    """High-level SSL client using OpenSSL 3.x via nassl._nassl3.

    Inherits from SslClient to support all modern OpenSSL features (TLS 1.3, etc.)
    since OpenSSL 3.x is fully compatible with OpenSSL 1.1.1+ APIs.
    """

    # Use OpenSSL 3.x module instead of OpenSSL 1.1.1
    _NASSL_MODULE = nassl3_module  # type: ignore
