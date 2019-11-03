#pragma once

// nassl.X509_STORE_CTX Python class
typedef struct {
    PyObject_HEAD
    X509_STORE_CTX *x509storeCtx;
} nassl_X509_STORE_CTX_Object;

// Type needs to be accessible to nassl_X509.c
extern PyTypeObject nassl_X509_STORE_CTX_Type;

void module_add_X509_STORE_CTX(PyObject* m);
