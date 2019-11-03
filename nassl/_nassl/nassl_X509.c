
#include <Python.h>

// Fix symbol clashing on Windows
// https://bugs.launchpad.net/pyopenssl/+bug/570101
#ifdef _WIN32
#include "winsock.h"
#endif

#include <openssl/ssl.h>
#include <openssl/evp.h>


#include "nassl_errors.h"
#include "nassl_X509.h"
#include "openssl_utils.h"

#ifndef LEGACY_OPENSSL
#include "nassl_X509_STORE_CTX.h"
#endif


// nassl.X509.new()
static PyObject* nassl_X509_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    nassl_X509_Object *self;
    char *pemCertificate;
	BIO *bio;
	
    self = (nassl_X509_Object *)type->tp_alloc(type, 0);
    if (self == NULL)
    {
    	return NULL;
    }

    // Read the certificate as PEM and create an X509 object
    if (!PyArg_ParseTuple(args, "s", &pemCertificate))
    {
        return NULL;
    }

    bio = BIO_new(BIO_s_mem());
    BIO_puts(bio, pemCertificate);

    self->x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_vfree(bio);

    if (self->x509 == NULL)
    {
        PyErr_SetString(PyExc_ValueError, "Could not parse the supplied PEM certificate");
        return NULL;
    }
    return (PyObject *)self;
}


static void nassl_X509_dealloc(nassl_X509_Object *self)
{
 	if (self->x509 != NULL)
 	{
  		X509_free(self->x509);
  		self->x509 = NULL;
  	}
    Py_TYPE(self)->tp_free((PyObject*)self);
}


static PyObject* nassl_X509_as_text(nassl_X509_Object *self, PyObject *args)
{
    return generic_print_to_string((int (*)(BIO *, const void *)) &X509_print, self->x509);
}


static PyObject* nassl_X509_as_pem(nassl_X509_Object *self, PyObject *args)
{
    return generic_print_to_string((int (*)(BIO *, const void *)) &PEM_write_bio_X509, self->x509);
}


static PyObject* nassl_X509_verify_cert_error_string(PyObject *nullPtr, PyObject *args)
{
    const char *errorString = NULL;
    long verifyError = 0;
    if (!PyArg_ParseTuple(args, "l", &verifyError))
    {
        return NULL;
    }

    errorString = X509_verify_cert_error_string(verifyError);
    return PyUnicode_FromString(errorString);
}


#ifndef LEGACY_OPENSSL
static PyObject* nassl_X509_verify_cert(PyObject *nullPtr, PyObject *args)
{
    int verifyReturnValue = 0;
    nassl_X509_STORE_CTX_Object *x509storeCtx_PyObject = NULL;
    if (!PyArg_ParseTuple(args, "O!", &nassl_X509_STORE_CTX_Type, &x509storeCtx_PyObject))
    {
        return NULL;
    }

    verifyReturnValue = X509_verify_cert(x509storeCtx_PyObject->x509storeCtx);
    return Py_BuildValue("I", verifyReturnValue);
}
#endif


static PyMethodDef nassl_X509_Object_methods[] =
{
    {"as_text", (PyCFunction)nassl_X509_as_text, METH_NOARGS,
     "Returns a string containing the result of OpenSSL's X509_print()."
    },
    {"as_pem", (PyCFunction)nassl_X509_as_pem, METH_NOARGS,
     "OpenSSL's PEM_write_bio_X509()."
    },
    {"verify_cert_error_string", (PyCFunction)nassl_X509_verify_cert_error_string, METH_VARARGS | METH_STATIC,
     "OpenSSL's X509_verify_cert_error_string()."
    },
#ifndef LEGACY_OPENSSL
    {"verify_cert", (PyCFunction)nassl_X509_verify_cert, METH_VARARGS | METH_STATIC,
     "OpenSSL's X509_verify_cert()."
    },
#endif

    {NULL}  // Sentinel
};


PyTypeObject nassl_X509_Type =
{
    PyVarObject_HEAD_INIT(NULL, 0)
    "_nassl.X509",             /*tp_name*/
    sizeof(nassl_X509_Object),             /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)nassl_X509_dealloc, /*tp_dealloc*/
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
    "X509 objects",           /* tp_doc */
    0,                     /* tp_traverse */
    0,                     /* tp_clear */
    0,                     /* tp_richcompare */
    0,                     /* tp_weaklistoffset */
    0,                     /* tp_iter */
    0,                     /* tp_iternext */
    nassl_X509_Object_methods,             /* tp_methods */
    0,             /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    0,      /* tp_init */
    0,                         /* tp_alloc */
    nassl_X509_new,                 /* tp_new */
};



void module_add_X509(PyObject* m)
{
	nassl_X509_Type.tp_new = nassl_X509_new;
	if (PyType_Ready(&nassl_X509_Type) < 0)
	{
    	return;
	}

    Py_INCREF(&nassl_X509_Type);
    PyModule_AddObject(m, "X509", (PyObject *)&nassl_X509_Type);

}

