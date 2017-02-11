# -*- coding: utf-8 -*-
from enum import Enum

__author__ = u'Alban Diquet'
__version__ = u'0.14.2'


class OpenSslVerifyEnum(Enum):
    """SSL validation options which map to the SSL_VERIFY_XXX OpenSSL constants.
    """
    NONE = 0
    PEER = 1
    FAIL_IF_NO_PEER_CERT =  2
    CLIENT_ONCE = 4


class OpenSslVersionEnum(Enum):
    """SSL version constants.
    """
    SSLV23 = 0
    SSLV2 = 1
    SSLV3 = 2
    TLSV1 = 3
    TLSV1_1 = 4
    TLSV1_2 = 5


class OpenSslModeEnum(Enum):
    """SSL mode constants which map to SSL_MODE_XXX OpenSSL constants.
    """
    SEND_FALLBACK_SCSV = 0x00000080


class OpenSslFileTypeEnum(Enum):
    """Certificate and private key format constants which map to the SSL_FILETYPE_XXX OpenSSL constants.
    """
    PEM = 1
    ASN1 = 2


class OpenSslOptionEnum(Enum):
    """SSL option constants which map to SSL_OP_XXX OpenSSL constants.
    """
    SSL_OP_NO_TICKET = 0x00004000  # No TLS Session Tickets

