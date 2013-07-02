#pragma once

#include "nassl_SSL_CTX.h"
#include "nassl_BIO.h"

// nassl.SSL Python class
typedef struct {
    PyObject_HEAD
    SSL *ssl;
    nassl_SSL_CTX_Object *sslCtx_Object;
    nassl_BIO_Object *bio_Object;
} nassl_SSL_Object;


void module_add_SSL(PyObject* m);


