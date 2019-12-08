
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
    return (PyObject *)self;
}


static void nassl_X509_STORE_CTX_dealloc(nassl_X509_STORE_CTX_Object *self)
{
 	if (self->x509storeCtx != NULL)
 	{
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
        // TODO: Memory mgmt / free
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
    STACK_OF(X509) *trustedCerts = parseCertificateList(args);
    if (trustedCerts == NULL)
    {
        return NULL;
    }
    X509_STORE_CTX_set0_trusted_stack(self->x509storeCtx, trustedCerts);
    Py_RETURN_NONE;
}


static PyObject* nassl_X509_STORE_CTX_set0_untrusted(nassl_X509_STORE_CTX_Object *self, PyObject *args)
{
    STACK_OF(X509) *untrustedCerts = parseCertificateList(args);
    if (untrustedCerts == NULL)
    {
        return NULL;
    }
    X509_STORE_CTX_set0_untrusted(self->x509storeCtx, untrustedCerts);
    Py_RETURN_NONE;
}


static PyObject* nassl_X509_STORE_CTX_set_cert(nassl_X509_STORE_CTX_Object *self, PyObject *args)
{
    nassl_X509_Object* x509Object;
    if (!PyArg_ParseTuple(args, "O!", &nassl_X509_Type, &x509Object))
    {
        return NULL;
    }
       // TODO: Memory mgmt / free
    X509_STORE_CTX_set_cert(self->x509storeCtx, x509Object->x509);
    Py_RETURN_NONE;
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
