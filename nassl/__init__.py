#!/usr/bin/python2.7

__author__ = 'Alban Diquet'
__version__ = '0.14.2'

# TODO(ad): Switch to enums
# Verify constants
SSL_VERIFY_NONE =                   0x00
SSL_VERIFY_PEER =                   0x01
SSL_VERIFY_FAIL_IF_NO_PEER_CERT =   0x02
SSL_VERIFY_CLIENT_ONCE =            0x04


# SSL version constants
SSLV23 = 0
SSLV2 = 1
SSLV3 = 2
TLSV1 = 3
TLSV1_1 = 4
TLSV1_2 = 5


# SSL mode constants
SSL_MODE_SEND_FALLBACK_SCSV =       0x00000080L


# Certificate and private key formats
SSL_FILETYPE_PEM =  1
SSL_FILETYPE_ASN1 = 2


# SSL Options
SSL_OP_NO_TICKET = 0x00004000L # No TLS Session Tickets


# OCSP Stapling
TLSEXT_STATUSTYPE_ocsp = 1


# Hostname validation constants - nassl constants (not OpenSSL)
X509_NAME_MISMATCH = 0
X509_NAME_MATCHES_SAN = 1
X509_NAME_MATCHES_CN = 2
