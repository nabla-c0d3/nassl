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
#include "nassl_X509_EXTENSION.h"
#include "nassl_X509_NAME_ENTRY.h"
#include "nassl_SSL_SESSION.h"
#include "nassl_OCSP_RESPONSE.h"


static PyMethodDef nassl_methods[] =
{
    {NULL}  /* Sentinel */
};

struct module_state
{
    PyObject *error;
};

#if PY_MAJOR_VERSION >= 3
#define GETSTATE(m) ((struct module_state*)PyModule_GetState(m))
#else
#define GETSTATE(m) (&_state)
static struct module_state _state;
#endif


#if PY_MAJOR_VERSION >= 3

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
        "_nassl",
        NULL,
        sizeof(struct module_state),
        nassl_methods,
        NULL,
        nassl_traverse,
        nassl_clear,
        NULL
};

#define INITERROR return NULL

#else

#define INITERROR return

#endif

#ifndef PyMODINIT_FUNC	/* declarations for DLL import/export */
#define PyMODINIT_FUNC void
#endif



#if PY_MAJOR_VERSION >= 3
PyMODINIT_FUNC PyInit__nassl(void)
#else
PyMODINIT_FUNC init_nassl(void)
#endif
{
    PyObject* module;
    struct module_state *state;

    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();

    // Check OpenSSL PRNG
    if(RAND_status() != 1) {
        PyErr_SetString(PyExc_EnvironmentError, "OpenSSL PRNG not seeded with enough data");
        INITERROR;
    }

    // Initalize the module
#if PY_MAJOR_VERSION >= 3
    module = PyModule_Create(&moduledef);
#else
    module = Py_InitModule3("_nassl", nassl_methods, "Nassl internal module.");
#endif
    if (module == NULL)
    {
        INITERROR;
    }

    module_add_errors(module);
    module_add_SSL_CTX(module);
    module_add_SSL(module);
    module_add_BIO(module);
    module_add_X509(module);
    module_add_X509_EXTENSION(module);
    module_add_X509_NAME_ENTRY(module);
    module_add_SSL_SESSION(module);
    module_add_OCSP_RESPONSE(module);

    state = GETSTATE(module);
    state->error = PyErr_NewException("_nassl.Error", NULL, NULL);
    if (state->error == NULL)
    {
        Py_DECREF(module);
        INITERROR;
    }

#if PY_MAJOR_VERSION >= 3
    return module;
#endif
}
