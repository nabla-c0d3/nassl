
#include <openssl/err.h>

#ifdef _WIN32
#define PyErr_SetFromErrGeneric(x) PyErr_SetExcFromWindowsErr(x, 0)
#else
#define PyErr_SetFromErrGeneric(x) PyErr_SetFromErrno(x)
#endif

#include "nassl_errors.h"


PyObject *nassl_OpenSSLError_Exception;
static PyObject *nassl_SslError_Exception;
static PyObject *nassl_WantReadError_Exception;
static PyObject *nassl_WantWriteError_Exception;
static PyObject *nassl_WantX509LookupError_Exception;


PyObject* raise_OpenSSL_error()
{
    PyObject *pyFinalErrorString = NULL;
    PyObject *pyNewLineString = NULL;
    unsigned long iterateOpenSslError = 0;

    iterateOpenSslError = ERR_get_error();
    if (iterateOpenSslError == 0) 
    {
        // No actual errors in the OpenSSL error queue; this usually means that the function that returned a 0
        // to indicate an error had an invalid input; return a generic error message
        pyFinalErrorString = PyUnicode_FromString("Unknown error: invalid input, usage, or OpenSSL build configuration?");
    }
    else 
    {
        // We will concatenate all the errors in the error queue to create a giant error string
        pyFinalErrorString = PyUnicode_FromString("");
    }

    if (pyFinalErrorString == NULL)
    {
        return PyErr_NoMemory();
    }

    pyNewLineString = PyUnicode_FromString("\n");
    if (pyNewLineString == NULL)
    {
        return PyErr_NoMemory();
    }

    while(iterateOpenSslError != 0)
    {
        PyObject *oldPyFinalErrorString = NULL;
        // Get the current error string
        char *iterateErrorString = ERR_error_string(iterateOpenSslError, NULL);  // This includes a NUL character
        PyObject *pyIterateErrorString = PyUnicode_FromString(iterateErrorString);
        if (pyIterateErrorString == NULL)
            {
                return PyErr_NoMemory();
            }

        // Add it to our final error
        oldPyFinalErrorString = pyFinalErrorString;
        pyFinalErrorString = PyUnicode_Concat(pyFinalErrorString, pyIterateErrorString);
        if (pyFinalErrorString == NULL)
            {
                return PyErr_NoMemory();
            }
        Py_DECREF(oldPyFinalErrorString);

        // Add a new line
        oldPyFinalErrorString = pyFinalErrorString;
        pyFinalErrorString = PyUnicode_Concat(pyFinalErrorString, pyNewLineString);
        if (pyFinalErrorString == NULL)
            {
                return PyErr_NoMemory();
            }
        Py_DECREF(oldPyFinalErrorString);

        Py_DECREF(pyIterateErrorString);
        iterateOpenSslError = ERR_get_error();
    }

    PyErr_SetString(nassl_OpenSSLError_Exception, PyUnicode_AsUTF8(pyFinalErrorString));
    Py_DECREF(pyFinalErrorString);
    Py_DECREF(pyNewLineString);
    return NULL;
}


PyObject* raise_OpenSSL_ssl_error(SSL *ssl, int returnValue)
{
    // TODO: Better error handling
    int sslError = SSL_get_error(ssl, returnValue);
    switch(sslError)
    {
        case SSL_ERROR_NONE:
            break;

        case SSL_ERROR_SSL:
        	return raise_OpenSSL_error();

        case SSL_ERROR_SYSCALL:
            if (ERR_peek_error() == 0)
            {
                if (returnValue == 0)
                {
                    PyErr_SetString(nassl_SslError_Exception, "An EOF was observed that violates the protocol");
                    return NULL;
                }
                else if (returnValue == -1)
                {
                    PyErr_SetFromErrGeneric(nassl_SslError_Exception);
                    return NULL;
                }
                else
                {
                    PyErr_SetString(nassl_SslError_Exception, "SSL_ERROR_SYSCALL");
                    return NULL;
                }
            }
            else
            {
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

        case SSL_ERROR_WANT_X509_LOOKUP:
            PyErr_SetString(nassl_WantX509LookupError_Exception, "");
            return NULL;

        default:
            PyErr_SetString(nassl_SslError_Exception, "TODO: Better error handling");
            return NULL;
    }
    Py_RETURN_NONE;
}


int module_add_errors(PyObject* m)
{
    // Import all exceptions from the Python module nassl.errors
    PyObject* errors_module = PyImport_ImportModule("nassl.errors");
    if (!errors_module)
    {
        PyErr_SetString(PyExc_RuntimeError, "Could not import nassl.errors");
        return 0;
    }

    nassl_OpenSSLError_Exception = PyObject_GetAttrString(errors_module, "OpenSSLError");
    if (!nassl_OpenSSLError_Exception)
    {
        PyErr_SetString(PyExc_RuntimeError, "Could not import OpenSSLError from nassl.errors");
        Py_DECREF(errors_module);
        return 0;
    }

    nassl_SslError_Exception = PyObject_GetAttrString(errors_module, "SslError");
    if (!nassl_SslError_Exception)
    {
        PyErr_SetString(PyExc_RuntimeError, "Could not import SslError from nassl.errors");
        Py_DECREF(errors_module);
        return 0;
    }

    nassl_WantX509LookupError_Exception = PyObject_GetAttrString(errors_module, "WantX509LookupError");
    if (!nassl_WantX509LookupError_Exception)
    {
        PyErr_SetString(PyExc_RuntimeError, "Could not import WantX509LookupError from nassl.errors");
        Py_DECREF(errors_module);
        return 0;
    }

    nassl_WantReadError_Exception = PyObject_GetAttrString(errors_module, "WantReadError");
    if (!nassl_WantReadError_Exception)
    {
        PyErr_SetString(PyExc_RuntimeError, "Could not import WantReadError from nassl.errors");
        Py_DECREF(errors_module);
        return 0;
    }

    nassl_WantWriteError_Exception = PyObject_GetAttrString(errors_module, "WantWriteError");
    if (!nassl_WantWriteError_Exception)
    {
        PyErr_SetString(PyExc_RuntimeError, "Could not import WantWriteError from nassl.errors");
        Py_DECREF(errors_module);
        return 0;
    }

    Py_DECREF(errors_module);
    return 1;
}
