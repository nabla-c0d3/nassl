#pragma once

// nassl.SSL_CTX Python class
typedef struct {
    PyObject_HEAD
    SSL_CTX *sslCtx; // OpenSSL SSL_CTX C struct
    char *pkeyPasswordBuf; // Buffer where the passcode to unlock the private key will be stored
    int ignoreClientCertRequests; // continue even if client certificate is missing
} nassl_SSL_CTX_Object;

// Type needs to be accessible to nassl_SSL.c
extern PyTypeObject nassl_SSL_CTX_Type;

void module_add_SSL_CTX(PyObject* m);
