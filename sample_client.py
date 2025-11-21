#!/usr/bin/env python3
"""
Sample client demonstrating nassl usage across all supported OpenSSL versions.
This script defaults to OpenSSL 3.x but supports legacy and modern versions via arguments.

Usage:
    python sample_client.py                      # Uses OpenSSL 3.x (default)
    python sample_client.py --client openssl3    # Uses OpenSSL 3.x explicitly
    python sample_client.py --client modern      # Uses OpenSSL 1.1.1
    python sample_client.py --client legacy      # Uses OpenSSL 1.0.2
"""

import argparse
from pathlib import Path
import socket
import sys

from nassl.ocsp_response import verify_ocsp_response


def main():
    """Main function demonstrating nassl usage with version detection."""
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description='Sample SSL client demonstrating nassl usage',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        '--client',
        choices=['openssl3', 'modern', 'legacy'],
        default='openssl3',
        help='OpenSSL client version to use (default: openssl3)'
    )
    args = parser.parse_args()

    # Import the appropriate client based on arguments
    # Let the import fail naturally if the requested version isn't available
    try:
        if args.client == 'legacy':
            print("Using OpenSSL 1.0.2 (legacy) client\n")
            from nassl.legacy_ssl_client import LegacySslClient as ClientClass
        elif args.client == 'modern':
            print("Using OpenSSL 1.1.1 (modern) client\n")
            from nassl.ssl_client import SslClient as ClientClass
        else:  # openssl3
            print("Using OpenSSL 3.x client\n")
            from nassl.openssl3_ssl_client import OpenSSL3SslClient as ClientClass

        from nassl.ssl_client import OpenSslVersionEnum, OpenSslVerifyEnum
    except ImportError as e:
        print(f"ERROR: Failed to import requested OpenSSL client: {e}")
        print("\nTry a different value with --client (openssl3, modern, or legacy).")
        return 1

    # Setup connection
    mozilla_store = Path("tests") / "mozilla.pem"
    hostname = "www.cloudflare.com"
    print(f"Connecting to {hostname}:443...")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)

    try:
        sock.connect((hostname, 443))

        # Now both clients share the same API thanks to BaseSslClient
        ssl_client = ClientClass(
            ssl_version=OpenSslVersionEnum.TLSV1_2,
            underlying_socket=sock,
            ssl_verify=OpenSslVerifyEnum.PEER,
            ssl_verify_locations=mozilla_store,
        )
        ssl_client.set_tlsext_status_ocsp()
        ssl_client.do_handshake()

        print("Successfully connected and completed handshake\n")

        print("Received certificate chain")
        for pem_cert in ssl_client.get_received_chain():
            print(pem_cert)

        print("Verified certificate chain")
        for pem_cert in ssl_client.get_verified_chain():
            print(pem_cert)

        ocsp_resp = ssl_client.get_tlsext_status_ocsp_resp()
        if ocsp_resp:
            print("OCSP Stapling")
            verify_ocsp_response(ocsp_resp, Path(mozilla_store))

        print("\nCipher suite")
        print(ssl_client.get_current_cipher_name())

        print("\nEphemeral Key")
        print(ssl_client.get_ephemeral_key())

        print("\nHTTP response")
        ssl_client.write(f"GET / HTTP/1.0\r\nUser-Agent: Test\r\nHost: {hostname}\r\n\r\n".encode("ascii"))
        print(ssl_client.read(2048))

        return 0

    except Exception as e:
        print(f"ERROR: {e}")
        return 1
    finally:
        try:
            sock.close()
        except:
            pass


if __name__ == "__main__":
    sys.exit(main())
