#pragma once

extern PyObject *nassl_OpenSSLError_Exception; // Needed by nassl_X509.c

PyObject* raise_OpenSSL_error();
PyObject* raise_OpenSSL_ssl_error(SSL *ssl, int returnValue);
void module_add_errors(PyObject* m);
