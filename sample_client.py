#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function
from __future__ import absolute_import
from __future__ import unicode_literals

import os
import sys
sys.path.insert(1, os.path.join(os.path.dirname(__file__), u'lib'))

from nassl.ssl_client import OpenSslVersionEnum
import socket
from nassl.debug_ssl_client import DebugSslClient

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(5)
sock.connect(('www.yahoo.com', 443))

ssl_client = DebugSslClient(ssl_version=OpenSslVersionEnum.TLSV1_2, sock=sock, ssl_verify_locations=u'mozilla.pem')
ssl_client.set_tlsext_status_ocsp()
ssl_client.do_handshake()

print('Certificate chain')
for cert in ssl_client.get_peer_cert_chain():
    print(cert.as_pem())

print('OCSP Stapling')
ocsp_resp = ssl_client.get_tlsext_status_ocsp_resp()
ocsp_resp.verify('mozilla.pem')
print(ocsp_resp.as_dict())

print('\nCipher suite')
print(ssl_client.get_current_cipher_name())

print('\nHTTP response')
ssl_client.write(b'GET / HTTP/1.0\r\nUser-Agent: Test\r\nHost: www.google.com\r\n\r\n')
print(ssl_client.read(2048))
