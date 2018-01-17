#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function
from __future__ import absolute_import
from __future__ import unicode_literals
from nassl.ssl_client import OpenSslVersionEnum, SslClient, OpenSslEarlyDataStatusEnum, OpenSslVerifyEnum
import socket


class EarlyDataClient():
    def __init__(self, **kw):
        self.socket = None
        self.session = None
        self.client = None

        self.dest = kw.get('dest', 'localhost')
        self.port = kw.get('port', 443)
        self.socket_timeout = kw.get('socket_timeout', 5)
        self.regular_data = kw.get('regular_data', b'XXX-REGULAR-DATA-XXX')
        self.early_data = kw.get('early_data', b'XXX-EARLY-DATA-XXX')
        self.read_size = kw.get('read_size', 2048)

    def _init(self, dest='localhost', port=443, timeout=5):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(timeout)
        self.socket.connect((dest, port))
        self.client = SslClient(ssl_version=OpenSslVersionEnum.TLSV1_3, underlying_socket=self.socket,
                           ssl_verify_locations=u'mozilla.pem')

    def _finish_handshake(self):
        if not self.client.is_handshake_completed():
            self.client.do_handshake()
            print('\tCipher suite:', self.client.get_current_cipher_name())

    def _close(self):
        self.client.shutdown()
        self.socket.close()
        print('\n')

    def _write_read_close(self, data_to_send=b'XXX-REGULAR-DATA-XXX', read_size=2048):
        try:
            self.client.write(data_to_send)
            self.client.read(2048)
            self.session = self.client.get_session()
        except socket.timeout as e:
            print('\n\tSocket was timed out. Closing...')
        finally:
            self._close()

    def _send_early_data(self, early_data_to_send=b'XXX-EARLY-DATA-XXX'):
        self.client.set_session(self.session)
        self.client.write_early_data(early_data_to_send)
        self._finish_handshake()
        print('\t', self.client.get_early_data_status())
        self._close()

    def test_early(self, early_data_to_send=b'XXX-EARLY-DATA-XXX'):
        print('First Session:')
        self._init(dest=self.dest, port=self.port)
        self._finish_handshake()
        self._write_read_close(data_to_send=self.regular_data)
        
        if self.session:
            print('Reused Session:')
            self._init(dest=self.dest, port=self.port)
            if self.session.get_max_early_data() > 0:
                self._send_early_data()
            else:
                print('\n\tServer does not support Early-Data. Closing...')
                self._close
        else:
            print('\nPrevious session failed, can`t send early data. Closing...')

        print('='*80, '\n')


if __name__ == '__main__':
    print('='*80, '\n')

    '''
    # To run the test localy, just use openssl s_server (locally) as follows (linux only):
    # while [ 1 ]; do echo "1"; done | ./openssl s_server -accept 8443 -early_data

    print('='*5, 'Check against local server', '='*5)
    ed_client = EarlyDataClient(port=8443)
    ed_client.test_early()
    '''

    print('='*5, 'Check against tls13.baishancloud.com:44344', '='*5)
    ed_client = EarlyDataClient(dest='tls13.baishancloud.com', port=44344, 
        regular_data=b'GET / HTTP/1.1\r\nUser-Agent: Test\r\nHost: tls13.baishancloud.com:44344\r\n\r\n')
    ed_client.test_early()
