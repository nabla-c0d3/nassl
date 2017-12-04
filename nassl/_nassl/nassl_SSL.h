#pragma once

#include "nassl_SSL_CTX.h"
#include "nassl_BIO.h"

// nassl.SSL Python class
typedef struct {
    PyObject_HEAD
    SSL *ssl;
    nassl_SSL_CTX_Object *sslCtx_Object;

    // We only keep a reference of the network BIO so we know when to free the BIO object
    // The internal BIO is auto-freed by SSL_free() which is called in nassl_SSL_dealloc
    nassl_BIO_Object *networkBio_Object;
} nassl_SSL_Object;


void module_add_SSL(PyObject* m);


