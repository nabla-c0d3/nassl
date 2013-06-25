#include <Python.h>


#include <openssl/err.h>
#include <openssl/ssl.h>
#include <sys/errno.h>

#include "nassl_errors.h"


PyObject *nassl_OpenSSLError_Exception;
static PyObject *nassl_SslError_Exception;
static PyObject *nassl_WantReadError_Exception;
static PyObject *nassl_WantWriteError_Exception;


PyObject* raise_OpenSSL_error() {
    unsigned long openSslError;
    char *errorString;

    openSslError = ERR_get_error();
    errorString = ERR_error_string(openSslError, NULL);
    PyErr_SetString(nassl_OpenSSLError_Exception, errorString);
    return NULL;
}


PyObject* raise_OpenSSL_ssl_error(SSL *ssl, int returnValue) {
    // TODO: Better error handling
    int sslError = SSL_get_error(ssl, returnValue);

    switch(sslError) {

        case SSL_ERROR_NONE:
            break;

        case SSL_ERROR_SSL:
        	return raise_OpenSSL_error();
        
        case SSL_ERROR_SYSCALL:
            if (ERR_peek_error() == 0) {
                if (returnValue == 0) {
                    PyErr_SetString(nassl_SslError_Exception, "An EOF was observed that violates the protocol");
                    return NULL;
                }
                else if (returnValue == -1) {
                    // TODO: Windows
                    PyErr_SetFromErrno(nassl_SslError_Exception);
                    return NULL;
                }
                else {
                    PyErr_SetString(nassl_SslError_Exception, "SSL_ERROR_SYSCALL");
                    return NULL;
                }
            } 
            else {
                return raise_OpenSSL_error();
            }

        case SSL_ERROR_ZERO_RETURN:
            PyErr_SetString(nassl_SslError_Exception, "Connection was shut down by peer");
            return NULL;

        case SSL_ERROR_WANT_WRITE:
            PyErr_SetString(nassl_WantWriteError_Exception, "");
            return NULL;

        case SSL_ERROR_WANT_READ:
            PyErr_SetString(nassl_WantReadError_Exception, "");
            return NULL;

        default:
            PyErr_SetString(nassl_SslError_Exception, "TODO: Better error handling");
            return NULL;
    }
    
    Py_RETURN_NONE;
}


void module_add_errors(PyObject* m) {
    nassl_OpenSSLError_Exception = PyErr_NewException("nassl.OpenSSLError", NULL, NULL);
    Py_INCREF(nassl_OpenSSLError_Exception);
    PyModule_AddObject(m, "OpenSSLError", nassl_OpenSSLError_Exception);
    nassl_SslError_Exception = PyErr_NewException("nassl.SslError", nassl_OpenSSLError_Exception, NULL);
    Py_INCREF(nassl_SslError_Exception);
    PyModule_AddObject(m, "SslError", nassl_SslError_Exception);
    nassl_WantWriteError_Exception = PyErr_NewException("nassl.WantWriteError", nassl_SslError_Exception, NULL);
    Py_INCREF(nassl_WantWriteError_Exception);
    PyModule_AddObject(m, "WantWriteError", nassl_WantWriteError_Exception);
    nassl_WantReadError_Exception = PyErr_NewException("nassl.WantReadError", nassl_SslError_Exception, NULL);
    Py_INCREF(nassl_WantReadError_Exception);
    PyModule_AddObject(m, "WantReadError", nassl_WantReadError_Exception);
}
