"""SSL client implementation using OpenSSL 3.x."""

import socket
from pathlib import Path
from typing import List, Any, Tuple, Optional

try:
    from nassl import _nassl3 as nassl3_module
    from nassl._nassl3 import WantReadError, OpenSSLError, WantX509LookupError
    _OPENSSL3_AVAILABLE = True
except ImportError:
    _OPENSSL3_AVAILABLE = False
    nassl3_module = None  # type: ignore

# Define enums locally to avoid circular imports - using same values as ssl_client.py
class OpenSslVersionEnum:
    SSLV23 = 0
    SSLV2 = 1  
    SSLV3 = 2
    TLSV1 = 3
    TLSV1_1 = 4
    TLSV1_2 = 5
    TLSV1_3 = 6

class OpenSslVerifyEnum:
    NONE = 0
    PEER = 1
    
from nassl.ephemeral_key_info import EphemeralKeyInfo


class OpenSSL3UnavailableError(Exception):
    """Raised when OpenSSL 3 functionality is requested but not available."""
    pass


class OpenSSL3SslClient:
    """SSL client implementation using OpenSSL 3.x.
    
    This class provides an interface to OpenSSL 3.x functionality through
    the _nassl3 C extension. It offers similar functionality to the regular
    SslClient but uses the newer OpenSSL 3 API.
    """

    def __init__(
        self,
        ssl_version: OpenSslVersionEnum = OpenSslVersionEnum.TLSV1_2,
        ssl_verify: OpenSslVerifyEnum = OpenSslVerifyEnum.NONE,
        ssl_verify_locations: Optional[Path] = None,
        client_certchain_file: Optional[Path] = None,
        client_key_file: Optional[Path] = None,
        client_key_type: int = 1,  # PEM format
        client_key_password: str = "",
        ignore_client_authentication_requests: bool = False,
    ) -> None:
        """Initialize the OpenSSL 3 SSL client.
        
        Args:
            ssl_version: The SSL/TLS version to use
            ssl_verify: SSL verification mode
            ssl_verify_locations: Path to CA certificates for verification
            client_certchain_file: Path to client certificate chain file
            client_key_file: Path to client private key file
            client_key_type: Type of the client key file (PEM or DER)
            client_key_password: Password for the client key file
            ignore_client_authentication_requests: Whether to ignore client auth requests
            
        Raises:
            OpenSSL3UnavailableError: If OpenSSL 3 support is not available
        """
        if not _OPENSSL3_AVAILABLE:
            raise OpenSSL3UnavailableError(
                "OpenSSL 3 support is not available. Make sure the _nassl3 extension was built."
            )
        
        # Store configuration
        self._ssl_version = ssl_version
        self._ssl_verify = ssl_verify
        self._ssl_verify_locations = ssl_verify_locations
        self._client_certchain_file = client_certchain_file
        self._client_key_file = client_key_file
        self._client_key_type = client_key_type
        self._client_key_password = client_key_password
        self._ignore_client_authentication_requests = ignore_client_authentication_requests
        
        # Initialize SSL context and connection objects
        self._ssl_ctx = None
        self._ssl = None
        self._socket = None
        
        self._init_ssl_ctx()

    def _init_ssl_ctx(self) -> None:
        """Initialize the SSL context with OpenSSL 3."""
        # Create SSL context - use the enum value directly since our local enums are just integers
        ssl_version_value = self._ssl_version if isinstance(self._ssl_version, int) else self._ssl_version.value
        self._ssl_ctx = nassl3_module.SSL_CTX(ssl_version_value)
        
        # Set verification mode
        ssl_verify_value = self._ssl_verify if isinstance(self._ssl_verify, int) else self._ssl_verify.value
        self._ssl_ctx.set_verify(ssl_verify_value)
        
        # Set CA certificate locations if provided
        if self._ssl_verify_locations:
            self._ssl_ctx.load_verify_locations(str(self._ssl_verify_locations))
        
        # Set client certificate and key if provided
        if self._client_certchain_file:
            self._ssl_ctx.use_certificate_chain_file(str(self._client_certchain_file))
        
        if self._client_key_file:
            self._ssl_ctx.use_PrivateKey_file(
                str(self._client_key_file), 
                self._client_key_type
            )

    def set_underlying_socket(self, sock: socket.socket) -> None:
        """Set the underlying socket for the SSL connection."""
        self._socket = sock
        
        # Create SSL object
        self._ssl = nassl3_module.SSL(self._ssl_ctx)
        
        # Create BIO and set it to the SSL object
        sock_bio = nassl3_module.BIO()
        sock_bio.set_sock(sock)
        self._ssl.set_bio(sock_bio)

    def do_handshake(self) -> None:
        """Perform the SSL handshake."""
        if not self._ssl:
            raise ValueError("Socket must be set before performing handshake")
        self._ssl.do_handshake()

    def write(self, data: bytes) -> int:
        """Write data to the SSL connection."""
        if not self._ssl:
            raise ValueError("Socket must be set before writing")
        return self._ssl.write(data)

    def read(self, size: int = 1024) -> bytes:
        """Read data from the SSL connection."""
        if not self._ssl:
            raise ValueError("Socket must be set before reading")
        return self._ssl.read(size)

    def get_peer_certificate(self):
        """Get the peer's certificate."""
        if not self._ssl:
            raise ValueError("Socket must be set before getting peer certificate")
        return self._ssl.get_peer_certificate()

    def get_peer_cert_chain(self):
        """Get the peer's certificate chain."""
        if not self._ssl:
            raise ValueError("Socket must be set before getting peer certificate chain")
        return self._ssl.get_peer_cert_chain()

    def get_current_cipher(self):
        """Get the current cipher being used."""
        if not self._ssl:
            raise ValueError("Socket must be set before getting current cipher")
        return self._ssl.get_current_cipher()

    def shutdown(self) -> None:
        """Shutdown the SSL connection."""
        if self._ssl:
            try:
                self._ssl.shutdown()
            except OpenSSLError:
                # Ignore shutdown errors
                pass

    @staticmethod
    def is_available() -> bool:
        """Check if OpenSSL 3 support is available."""
        return _OPENSSL3_AVAILABLE 