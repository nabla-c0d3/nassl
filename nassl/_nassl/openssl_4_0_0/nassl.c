#include <Python.h>

// Fix symbol clashing on Windows
// https://bugs.launchpad.net/pyopenssl/+bug/570101
#ifdef _WIN32
#include "winsock.h"
#endif

#include <openssl/ssl.h>
#include <openssl/rand.h>

#include "../nassl_errors.h"
#include "../nassl_BIO.h"
#include "../nassl_SSL_CTX.h"


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
        "openssl_4_0_0._nassl",

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


PyMODINIT_FUNC PyInit__nassl(void)
{
    PyObject* module;
    struct module_state *state;

    // Initialize OpenSSL
    OPENSSL_init_ssl(0, NULL);

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
    module_add_BIO(module);
    module_add_SSL_CTX(module);

    state = GETSTATE(module);
    state->error = PyErr_NewException("nassl._nassl.Error", NULL, NULL);
    if (state->error == NULL)
    {
        Py_DECREF(module);
        INITERROR;
    }

    return module;
}
