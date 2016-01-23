#pragma once

typedef struct {
    PyObject_HEAD
    X509_EXTENSION *x509ext; // OpenSSL X509_EXTENSION C struct
} nassl_X509_EXTENSION_Object;

// Type needs to be accessible to nassl_X509.c
extern PyTypeObject nassl_X509_EXTENSION_Type;

void module_add_X509_EXTENSION(PyObject* m);
