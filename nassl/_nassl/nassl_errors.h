#pragma once

#include <Python.h>
#include <openssl/ssl.h>

extern PyObject *nassl_OpenSSLError_Exception; // Needed by nassl_X509.c

PyObject* raise_OpenSSL_error(void);
PyObject* raise_OpenSSL_ssl_error(SSL *ssl, int returnValue);
void module_add_errors(PyObject* m);
