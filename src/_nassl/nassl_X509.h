#pragma once

// nassl.X509 Python class
typedef struct {
    PyObject_HEAD
    X509 *x509; // OpenSSL X509 C struct
} nassl_X509_Object;

// Type needs to be accessible to nassl_SSL.c
extern PyTypeObject nassl_X509_Type;

void module_add_X509(PyObject* m);
