import unittest
import sys
from pathlib import Path

# Add the parent directory to the path to import nassl
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestOpenSSL3Extension(unittest.TestCase):
    """Test suite for OpenSSL 3 extension functionality."""

    def test_can_import_openssl3_extension(self):
        """Test that the OpenSSL 3 extension can be imported."""
        try:
            import nassl._nassl3 as nassl3
            self.assertIsNotNone(nassl3)
        except ImportError as e:
            self.fail(f"Failed to import OpenSSL 3 extension: {e}")

    def test_openssl3_ssl_ctx_creation(self):
        """Test that SSL_CTX can be created using OpenSSL 3."""
        try:
            import nassl._nassl3 as nassl3
            
            # Try to create an SSL_CTX object using TLSV1_2 (value 5)
            ssl_ctx = nassl3.SSL_CTX(5)  # TLSV1_2
            self.assertIsNotNone(ssl_ctx)
            
            # Also test with TLSV1_3 (value 6)
            ssl_ctx_v13 = nassl3.SSL_CTX(6)  # TLSV1_3
            self.assertIsNotNone(ssl_ctx_v13)
            
        except ImportError:
            self.skipTest("OpenSSL 3 extension not available")
        except Exception as e:
            self.fail(f"Failed to create SSL_CTX with OpenSSL 3: {e}")

    def test_openssl3_has_required_attributes(self):
        """Test that the OpenSSL 3 extension has the required attributes."""
        try:
            import nassl._nassl3 as nassl3
            
            # Check for required classes
            required_classes = [
                'SSL_CTX', 'SSL', 'BIO', 'X509', 'X509_STORE_CTX', 
                'OCSP_RESPONSE', 'SSL_SESSION'
            ]
            
            for class_name in required_classes:
                self.assertTrue(hasattr(nassl3, class_name), 
                              f"OpenSSL 3 extension missing {class_name}")
                
            # Check for required error types
            required_errors = [
                'OpenSSLError', 'SslError', 'WantReadError', 'WantX509LookupError'
            ]
            
            for error_name in required_errors:
                self.assertTrue(hasattr(nassl3, error_name), 
                              f"OpenSSL 3 extension missing {error_name}")
                              
        except ImportError:
            self.skipTest("OpenSSL 3 extension not available")


if __name__ == '__main__':
    unittest.main() 