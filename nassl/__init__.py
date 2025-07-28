__author__ = "Alban Diquet"
__version__ = "5.3.0"


def _detect_available_openssl_versions():
    """Detect which OpenSSL versions are available."""
    available_versions = []
    
    # Try legacy OpenSSL
    try:
        import nassl._nassl_legacy  # noqa: F401
        available_versions.append("legacy")
    except ImportError:
        pass
    
    # Try modern OpenSSL (1.1.1)
    try:
        import nassl._nassl  # noqa: F401
        available_versions.append("modern")
    except ImportError:
        pass
    
    # Try OpenSSL 3
    try:
        import nassl._nassl3  # noqa: F401
        available_versions.append("openssl3")
    except ImportError:
        pass
    
    return available_versions


def get_openssl_versions():
    """Get a list of available OpenSSL versions."""
    return _detect_available_openssl_versions()


def has_openssl3_support():
    """Check if OpenSSL 3 support is available."""
    return "openssl3" in _detect_available_openssl_versions()
