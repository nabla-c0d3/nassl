#pragma once

#include "nassl_SSL_CTX.h"

// nasslyze.SSL Python class
typedef struct {
    PyObject_HEAD
    SSL *ssl;
    BIO *socketBio;
    nassl_SSL_CTX_Object *sslCtx_Object;
} nassl_SSL_Object;


void module_add_SSL(PyObject* m);


