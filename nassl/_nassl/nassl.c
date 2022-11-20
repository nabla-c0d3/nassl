#include <Python.h>

// Fix symbol clashing on Windows
// https://bugs.launchpad.net/pyopenssl/+bug/570101
#ifdef _WIN32
#include "winsock.h"
#endif

#include <openssl/ssl.h>
#include <openssl/rand.h>

#include "nassl_errors.h"
#include "nassl_SSL_CTX.h"
#include "nassl_SSL.h"
#include "nassl_BIO.h"
#include "nassl_X509.h"
#include "nassl_SSL_SESSION.h"
#include "nassl_OCSP_RESPONSE.h"

#ifndef LEGACY_OPENSSL
#include "nassl_X509_STORE_CTX.h"
#endif


static PyMethodDef nassl_methods[] =
{
    {NULL}  /* Sentinel */
};

struct module_state
{
    PyObject *error;
};

#define GETSTATE(m) ((struct module_state*)PyModule_GetState(m))


static int nassl_traverse(PyObject *m, visitproc visit, void *arg)
{
    Py_VISIT(GETSTATE(m)->error);
    return 0;
}

static int nassl_clear(PyObject *m)
{
    Py_CLEAR(GETSTATE(m)->error);
    return 0;
}


static struct PyModuleDef moduledef =
{
        PyModuleDef_HEAD_INIT,

#ifdef LEGACY_OPENSSL
        "_nassl_legacy",
#else
        "_nassl",
#endif

        NULL,
        sizeof(struct module_state),
        nassl_methods,
        NULL,
        nassl_traverse,
        nassl_clear,
        NULL
};

#define INITERROR return NULL


#ifndef PyMODINIT_FUNC	/* declarations for DLL import/export */
#define PyMODINIT_FUNC void
#endif


#ifdef LEGACY_OPENSSL
PyMODINIT_FUNC PyInit__nassl_legacy(void)
#else
PyMODINIT_FUNC PyInit__nassl(void)
#endif

{
    PyObject* module;
    struct module_state *state;

    // Initialize OpenSSL
#ifdef LEGACY_OPENSSL
    SSL_library_init();
    SSL_load_error_strings();
#else
    OPENSSL_init_ssl(0, NULL);
#endif

    // Check OpenSSL PRNG
    if(RAND_status() != 1) {
        PyErr_SetString(PyExc_EnvironmentError, "OpenSSL PRNG not seeded with enough data");
        INITERROR;
    }

    // Initialize the module
    module = PyModule_Create(&moduledef);
    if (module == NULL)
    {
        INITERROR;
    }

    if (!module_add_errors(module))
    {
        INITERROR;
    }
    module_add_SSL_CTX(module);
    module_add_SSL(module);
    module_add_BIO(module);
    module_add_X509(module);
    module_add_SSL_SESSION(module);
    module_add_OCSP_RESPONSE(module);


#ifndef LEGACY_OPENSSL
    // Only available in modern nassl
    module_add_X509_STORE_CTX(module);
#endif

    state = GETSTATE(module);
    state->error = PyErr_NewException("nassl._nassl.Error", NULL, NULL);
    if (state->error == NULL)
    {
        Py_DECREF(module);
        INITERROR;
    }

    return module;
}
