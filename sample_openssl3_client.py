#!/usr/bin/env python3

"""
Sample script demonstrating OpenSSL 3 support in nassl.
"""

import socket
import sys
from nassl import has_openssl3_support, get_openssl_versions


def main():
    print("nassl OpenSSL 3 Support Demo")
    print("=" * 30)
    
    # Check available OpenSSL versions
    print(f"Available OpenSSL versions: {get_openssl_versions()}")
    print(f"OpenSSL 3 support available: {has_openssl3_support()}")
    
    if not has_openssl3_support():
        print("\nOpenSSL 3 support is not available.")
        print("Make sure you have built the _nassl3 extension:")
        print("  python -c 'from build_tasks import *; build_openssl3(ctx)'")
        print("  python setup.py build_ext --inplace")
        return 1
    
    # Try to import and use the OpenSSL 3 client
    try:
        from nassl.openssl3_ssl_client import OpenSSL3SslClient, OpenSslVersionEnum
        
        print(f"\nOpenSSL 3 client available: {OpenSSL3SslClient.is_available()}")
        
        # Create an OpenSSL 3 SSL client
        ssl_client = OpenSSL3SslClient(ssl_version=OpenSslVersionEnum.TLSV1_2)
        print("✓ Successfully created OpenSSL 3 SSL client")
        
        # Example connection (commented out to avoid actual network calls)
        """
        # Example usage:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('www.google.com', 443))
        
        ssl_client.set_underlying_socket(sock)
        ssl_client.do_handshake()
        
        # Get peer certificate
        cert = ssl_client.get_peer_certificate()
        print(f"Peer certificate subject: {cert.get_subject()}")
        
        # Send HTTP request
        request = b"GET / HTTP/1.0\r\nHost: www.google.com\r\n\r\n"
        ssl_client.write(request)
        
        # Read response
        response = ssl_client.read(1024)
        print(f"Response: {response[:100]}...")
        
        ssl_client.shutdown()
        sock.close()
        """
        
        print("✓ OpenSSL 3 support is working correctly!")
        
    except Exception as e:
        print(f"✗ Error using OpenSSL 3 client: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main()) 