#pragma once

#include <Python.h>
#include <openssl/ssl.h>

#include "nassl_errors.h"

// Takes an XXX_print() function and a pointer to the structure to be printed
// Returns a Python string
// Used by nassl_X509.c and nassl_SSL_SESSION.c
PyObject* generic_print_to_string(int (*openSslPrintFunction)(BIO *fp, const void *a), const void *dataStruct);


PyObject *bioToPyString(BIO *memBio);
