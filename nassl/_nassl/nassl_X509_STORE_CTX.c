
#include <Python.h>

// Fix symbol clashing on Windows
// https://bugs.launchpad.net/pyopenssl/+bug/570101
#ifdef _WIN32
#include "winsock.h"
#endif


#include <openssl/x509_vfy.h>
#include "nassl_X509_STORE_CTX.h"
#include "nassl_X509.h"


static PyObject* nassl_X509_STORE_CTX_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    nassl_X509_STORE_CTX_Object *self;
	
    self = (nassl_X509_STORE_CTX_Object *)type->tp_alloc(type, 0);
    if (self == NULL)
    {
    	return NULL;
    }

    self->x509storeCtx = X509_STORE_CTX_new();
    if (self->x509storeCtx == NULL)
    {
        PyErr_SetString(PyExc_ValueError, "Could not initialize context");
        return NULL;
    }
    X509_STORE_CTX_init(self->x509storeCtx, NULL, NULL, NULL);

    self->trustedCertificates = NULL;
    self->untrustedCertificates = NULL;
    self->leafCertificate = NULL;

    return (PyObject *)self;
}


static void nassl_X509_STORE_CTX_dealloc(nassl_X509_STORE_CTX_Object *self)
{
 	if (self->x509storeCtx != NULL)
 	{
 	    // First free the "related" OpenSSL structures
 	    if (self->trustedCertificates != NULL)
        {
            sk_X509_pop_free(self->trustedCertificates, X509_free);
            self->trustedCertificates = NULL;
        }

        if (self->untrustedCertificates != NULL)
        {
            sk_X509_pop_free(self->untrustedCertificates, X509_free);
            self->untrustedCertificates = NULL;
        }

        if (self->leafCertificate != NULL)
        {
            X509_free(self->leafCertificate);
            self->leafCertificate = NULL;
        }

 	    // Then free the actual object
  		X509_STORE_CTX_free(self->x509storeCtx);
  		self->x509storeCtx = NULL;
  	}
    Py_TYPE(self)->tp_free((PyObject*)self);
}


static STACK_OF(X509) *parseCertificateList(PyObject *args)
{
    int i = 0;
    Py_ssize_t certsCount = 0;
    PyObject *pyListOfX509Objects;
    nassl_X509_Object *x509Object;
    STACK_OF(X509) *parsedCertificates = sk_X509_new_null();

    // Parse the Python list
    if (!PyArg_ParseTuple(args, "O!", &PyList_Type, &pyListOfX509Objects))
    {
        return NULL;
    }
    // Extract each x509 python object from the list
    certsCount = PyList_Size(pyListOfX509Objects);
    for (i=0; i<certsCount; i++)
    {
        // We get a borrowed reference here
        x509Object = (nassl_X509_Object *) PyList_GetItem(pyListOfX509Objects, i);
        if (x509Object == NULL)
        {
            return NULL;
        }
        sk_X509_push(parsedCertificates, x509Object->x509);
    }
    return parsedCertificates;
}


static PyObject* nassl_X509_STORE_CTX_set0_trusted_stack(nassl_X509_STORE_CTX_Object *self, PyObject *args)
{
    STACK_OF(X509) *trustedCerts = NULL;
    if (self->trustedCertificates != NULL)
    {
        PyErr_SetString(PyExc_ValueError, "set0_trusted_stack() has already been called.");
        return NULL;
    }

    trustedCerts = parseCertificateList(args);
    if (trustedCerts == NULL)
    {
        return NULL;
    }

    // Increase the OpenSSL ref count of each certificate in the chain; it get decreased in nassl_X509_STORE_CTX_dealloc()
    self->trustedCertificates = X509_chain_up_ref(trustedCerts);

    X509_STORE_CTX_set0_trusted_stack(self->x509storeCtx, trustedCerts);
    Py_RETURN_NONE;
}


static PyObject* nassl_X509_STORE_CTX_set0_untrusted(nassl_X509_STORE_CTX_Object *self, PyObject *args)
{
    STACK_OF(X509) *untrustedCerts = NULL;
    if (self->untrustedCertificates != NULL)
    {
        PyErr_SetString(PyExc_ValueError, "set0_untrusted() has already been called.");
        return NULL;
    }

    untrustedCerts = parseCertificateList(args);
    if (untrustedCerts == NULL)
    {
        return NULL;
    }

    // Increase the OpenSSL ref count of each certificate in the chain; it get decreased in nassl_X509_STORE_CTX_dealloc()
    self->untrustedCertificates = X509_chain_up_ref(untrustedCerts);

    X509_STORE_CTX_set0_untrusted(self->x509storeCtx, untrustedCerts);
    Py_RETURN_NONE;
}


static PyObject* nassl_X509_STORE_CTX_set_cert(nassl_X509_STORE_CTX_Object *self, PyObject *args)
{
    nassl_X509_Object* x509Object;
    if (self->leafCertificate != NULL)
    {
        PyErr_SetString(PyExc_ValueError, "set_cert() has already been called.");
        return NULL;
    }

    if (!PyArg_ParseTuple(args, "O!", &nassl_X509_Type, &x509Object))
    {
        return NULL;
    }
    // Increase the OpenSSL ref count of the cert; it get decreased in nassl_X509_STORE_CTX_dealloc()
    X509_up_ref(x509Object->x509);
    self->leafCertificate = x509Object->x509;

    X509_STORE_CTX_set_cert(self->x509storeCtx, x509Object->x509);
    Py_RETURN_NONE;
}


static PyObject* nassl_X509_STORE_CTX_get_error(nassl_X509_STORE_CTX_Object *self, PyObject *args)
{
    int errorValue = X509_STORE_CTX_get_error(self->x509storeCtx);
    return Py_BuildValue("i", errorValue);
}


static PyObject* nassl_X509_STORE_CTX_get1_chain(nassl_X509_STORE_CTX_Object *self, PyObject *args)
{
    STACK_OF(X509) *verifiedCertChain = NULL;
    PyObject* certChainPyList = NULL;

    verifiedCertChain = X509_STORE_CTX_get1_chain(self->x509storeCtx); // NOT automatically freed
    if (verifiedCertChain == NULL)
    {
        PyErr_SetString(PyExc_ValueError, "Error getting the verified certificate chain.");
        return NULL;
    }

    // We'll return a Python list containing each certificate
    certChainPyList = stackOfX509ToPyList(verifiedCertChain);

    // Manually free the chain returned by get1_chain()
    sk_X509_pop_free(verifiedCertChain, X509_free);

    if (certChainPyList == NULL)
    {
        return NULL;
    }
    return certChainPyList;
}


static PyMethodDef nassl_X509_STORE_CTX_Object_methods[] =
{
    {"set0_trusted_stack", (PyCFunction)nassl_X509_STORE_CTX_set0_trusted_stack, METH_VARARGS,
     "OpenSSL's X509_STORE_CTX_set0_trusted_stack()."
    },
    {"set0_untrusted", (PyCFunction)nassl_X509_STORE_CTX_set0_untrusted, METH_VARARGS,
     "OpenSSL's X509_STORE_CTX_set0_untrusted()."
    },
    {"set_cert", (PyCFunction)nassl_X509_STORE_CTX_set_cert, METH_VARARGS,
     "OpenSSL's 509_STORE_CTX_set_cert()."
    },
    {"get_error", (PyCFunction)nassl_X509_STORE_CTX_get_error, METH_NOARGS,
     "OpenSSL's X509_STORE_CTX_get_error()."
    },
    {"get1_chain", (PyCFunction)nassl_X509_STORE_CTX_get1_chain, METH_NOARGS,
     "OpenSSL's X509_STORE_CTX_get1_chain()."
    },
    {NULL}  // Sentinel
};


PyTypeObject nassl_X509_STORE_CTX_Type =
{
    PyVarObject_HEAD_INIT(NULL, 0)
    "_nassl.X509_STORE_CTX",             /*tp_name*/
    sizeof(nassl_X509_STORE_CTX_Object),             /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)nassl_X509_STORE_CTX_dealloc, /*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    0,                         /*tp_compare*/
    0,                         /*tp_repr*/
    0,                         /*tp_as_number*/
    0,                         /*tp_as_sequence*/
    0,                         /*tp_as_mapping*/
    0,                         /*tp_hash */
    0,                         /*tp_call*/
    0,                         /*tp_str*/
    0,                         /*tp_getattro*/
    0,                         /*tp_setattro*/
    0,                         /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
    "X509_STORE_CTX objects",           /* tp_doc */
    0,                     /* tp_traverse */
    0,                     /* tp_clear */
    0,                     /* tp_richcompare */
    0,                     /* tp_weaklistoffset */
    0,                     /* tp_iter */
    0,                     /* tp_iternext */
    nassl_X509_STORE_CTX_Object_methods,             /* tp_methods */
    0,             /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    0,      /* tp_init */
    0,                         /* tp_alloc */
    nassl_X509_STORE_CTX_new,                 /* tp_new */
};


void module_add_X509_STORE_CTX(PyObject* m)
{
	nassl_X509_STORE_CTX_Type.tp_new = nassl_X509_STORE_CTX_new;
	if (PyType_Ready(&nassl_X509_STORE_CTX_Type) < 0)
	{
    	return;
	}

    Py_INCREF(&nassl_X509_STORE_CTX_Type);
    PyModule_AddObject(m, "X509_STORE_CTX", (PyObject *)&nassl_X509_STORE_CTX_Type);
}
