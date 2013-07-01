#pragma once

typedef struct {
    PyObject_HEAD
    X509_NAME_ENTRY *x509NameEntry; // OpenSSL X509_NAME_ENTRY C struct
} nassl_X509_NAME_ENTRY_Object;

// Type needs to be accessible to nassl_X509.c
extern PyTypeObject nassl_X509_NAME_ENTRY_Type;

void module_add_X509_NAME_ENTRY(PyObject* m);
