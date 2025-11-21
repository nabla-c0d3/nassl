"""Common test helpers and fixtures for nassl tests."""

from nassl import _nassl

# Try to import legacy OpenSSL module
try:
    from nassl import _nassl_legacy
    _LEGACY_AVAILABLE = True
except ImportError:
    _nassl_legacy = None
    _LEGACY_AVAILABLE = False

# Try to import OpenSSL 3 module
try:
    from nassl import _nassl3
    _NASSL3_AVAILABLE = True
except ImportError:
    _nassl3 = None
    _NASSL3_AVAILABLE = False


# Create the list of nassl modules to test (only include available ones)
NASSL_MODULES = [_nassl]
if _LEGACY_AVAILABLE and _nassl_legacy is not None:
    NASSL_MODULES.append(_nassl_legacy)
if _NASSL3_AVAILABLE and _nassl3 is not None:
    NASSL_MODULES.append(_nassl3)


# TLS 1.3 is only available in modern OpenSSL (1.1.1+) and OpenSSL 3
MODERN_NASSL_MODULES = [_nassl]
if _NASSL3_AVAILABLE and _nassl3 is not None:
    MODERN_NASSL_MODULES.append(_nassl3)


# Try to import SSL client classes
from nassl.ssl_client import SslClient

try:
    from nassl.legacy_ssl_client import LegacySslClient
    _LEGACY_CLIENT_AVAILABLE = True
except (ImportError, RuntimeError):
    LegacySslClient = None
    _LEGACY_CLIENT_AVAILABLE = False

try:
    from nassl.openssl3_ssl_client import OpenSSL3SslClient
    _OPENSSL3_CLIENT_AVAILABLE = True
except (ImportError, RuntimeError):
    OpenSSL3SslClient = None
    _OPENSSL3_CLIENT_AVAILABLE = False


# Create the list of SSL client classes to test (only include available ones)
SSL_CLIENT_CLASSES = [SslClient]
if _LEGACY_CLIENT_AVAILABLE and LegacySslClient is not None:
    SSL_CLIENT_CLASSES.append(LegacySslClient)
if _OPENSSL3_CLIENT_AVAILABLE and OpenSSL3SslClient is not None:
    SSL_CLIENT_CLASSES.append(OpenSSL3SslClient)


# Modern SSL client classes (1.1.1+ features like set_groups, TLS 1.3, etc.)
MODERN_SSL_CLIENT_CLASSES = [SslClient]
if _OPENSSL3_CLIENT_AVAILABLE and OpenSSL3SslClient is not None:
    MODERN_SSL_CLIENT_CLASSES.append(OpenSSL3SslClient)
