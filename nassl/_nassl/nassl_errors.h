#pragma once

#include <Python.h>
#include <openssl/ssl.h>

PyObject* raise_OpenSSL_error(void);
PyObject* raise_OpenSSL_ssl_error(SSL *ssl, int returnValue);
int module_add_errors(PyObject* m);
