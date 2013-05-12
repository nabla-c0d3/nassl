#pragma once

// nassl.SSL_CTX Python class
typedef struct {
    PyObject_HEAD
    SSL_CTX *sslCtx; // OpenSSL SSL_CTX C struct
} nassl_SSL_CTX_Object;


void module_add_SSL_CTX(PyObject* m);
