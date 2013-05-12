
#include <Python.h>

#include <openssl/err.h>

#include "nassl_errors.h"

static PyObject *nassl_OpenSSLError_Exception;


void raise_OpenSSL_error() {    
    unsigned long openSslError;
    char *errorString;

    openSslError = ERR_get_error();
    errorString = ERR_error_string(openSslError, NULL);
    PyErr_SetString(nassl_OpenSSLError_Exception, errorString);
}


void module_add_errors(PyObject* m) {
    nassl_OpenSSLError_Exception = PyErr_NewException("nassl.OpenSSLError", NULL, NULL);
    Py_INCREF(nassl_OpenSSLError_Exception);
    PyModule_AddObject(m, "OpenSSLError", nassl_OpenSSLError_Exception);
}