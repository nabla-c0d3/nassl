#pragma once

// nassl.X509_STORE_CTX Python class
typedef struct {
    PyObject_HEAD
    X509_STORE_CTX *x509storeCtx;

    // Extra arguments for doing certificate validation; we have to store them here so we can properly free them after
    // validation has been completed
    STACK_OF(X509) *trustedCertificates;
    STACK_OF(X509) *untrustedCertificates;
    X509 *leafCertificate;
} nassl_X509_STORE_CTX_Object;

// Type needs to be accessible to nassl_X509.c
extern PyTypeObject nassl_X509_STORE_CTX_Type;

void module_add_X509_STORE_CTX(PyObject* m);
