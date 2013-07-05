#pragma once

typedef struct {
    PyObject_HEAD
    SSL_SESSION *sslSession; // OpenSSL SSL_SESSION C struct
} nassl_SSL_SESSION_Object;

// Type needs to be accessible to nassl_SSL.c
extern PyTypeObject nassl_SSL_SESSION_Type;

void module_add_SSL_SESSION(PyObject* m);
