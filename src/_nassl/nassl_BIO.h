#pragma once

// nassl.BIO_Pair Python class
typedef struct {
    PyObject_HEAD
    BIO *bio;
} nassl_BIO_Object;

// Type needs to be accessible to nassl_SSL.c
extern PyTypeObject nassl_BIO_Type;

void module_add_BIO(PyObject* m);
