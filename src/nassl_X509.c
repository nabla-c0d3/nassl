
#include <Python.h>

#include <openssl/ssl.h>

#include "nassl_errors.h"
#include "nassl_X509.h"




// nassl.X509.new()
static PyObject* nassl_X509_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
	nassl_X509_Object *self;

    self = (nassl_X509_Object *)type->tp_alloc(type, 0);
    if (self == NULL) 
    	return NULL;

	self->x509 = NULL;

    return (PyObject *)self;
} 



static void nassl_X509_dealloc(nassl_X509_Object *self) {
 	if (self->x509 != NULL) {
  		X509_free(self->x509);
  		self->x509 = NULL;
  	}

    self->ob_type->tp_free((PyObject*)self);
}


// Takes an XXX_print() function and a pointer to the structure to be printed
// Returns a Python string
static PyObject* generic_print_to_string(int (*openSslPrintFunction)(BIO *fp, const void *a), void *dataStruct) {
    BIO *memBio;
    char *dataTxtBuffer;
    int dataTxtSize;
    PyObject* res;

    memBio = BIO_new(BIO_s_mem());
    if (memBio == NULL) {
        raise_OpenSSL_error();
        return NULL;
    }

    openSslPrintFunction(memBio, dataStruct);
    dataTxtSize = BIO_pending(memBio);

    dataTxtBuffer = (char *) PyMem_Malloc(dataTxtSize);
    if (dataTxtBuffer == NULL)
        return PyErr_NoMemory();

    // Extract the text from the BIO
    BIO_read(memBio, dataTxtBuffer, dataTxtSize);
    res = PyString_FromString(dataTxtBuffer);
    PyMem_Free(dataTxtBuffer);
    return res;
}

static PyObject* nassl_X509_as_text(nassl_X509_Object *self, PyObject *args) {
    return generic_print_to_string((int (*)(BIO *, const void *)) &X509_print, self->x509);
}


static PyObject* nassl_X509_get_notBefore(nassl_X509_Object *self, PyObject *args) {
    ASN1_TIME *asn1Time = X509_get_notBefore(self->x509);
    return generic_print_to_string((int (*)(BIO *, const void *)) &ASN1_TIME_print, asn1Time);
}


static PyObject* nassl_X509_get_notAfter(nassl_X509_Object *self, PyObject *args) {
    ASN1_TIME *asn1Time = X509_get_notAfter(self->x509);
    return generic_print_to_string((int (*)(BIO *, const void *)) &ASN1_TIME_print, asn1Time);
}


static PyObject* nassl_X509_get_version(nassl_X509_Object *self, PyObject *args) {
    long version = X509_get_version(self->x509);
    return Py_BuildValue("I", version);
}


static PyObject* nassl_X509_get_serialNumber(nassl_X509_Object *self, PyObject *args) {
    ASN1_INTEGER *serialNum = X509_get_serialNumber(self->x509);
    return generic_print_to_string((int (*)(BIO *, const void *)) &i2a_ASN1_INTEGER, serialNum);
}








static PyMethodDef nassl_X509_Object_methods[] = {
    {"as_text", (PyCFunction)nassl_X509_as_text, METH_NOARGS,
     "OpenSSL's X509_print()."
    },
    {"get_version", (PyCFunction)nassl_X509_get_version, METH_NOARGS,
     "OpenSSL's X509_get_version()."
    },
    {"get_notBefore", (PyCFunction)nassl_X509_get_notBefore, METH_NOARGS,
     "OpenSSL's X509_get_notBefore()."
    },
    {"get_notAfter", (PyCFunction)nassl_X509_get_notAfter, METH_NOARGS,
     "OpenSSL's X509_get_notAfter()."
    },
    {"get_serialNumber", (PyCFunction)nassl_X509_get_serialNumber, METH_NOARGS,
     "OpenSSL's 509_get_serialNumber()."
    },

    {NULL}  // Sentinel
};


PyTypeObject nassl_X509_Type = {
    PyObject_HEAD_INIT(NULL)
    0,                         /*ob_size*/
    "nassl.X509",             /*tp_name*/
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



void module_add_X509(PyObject* m) {

	nassl_X509_Type.tp_new = nassl_X509_new;
	if (PyType_Ready(&nassl_X509_Type) < 0)
    	return;	
    
    Py_INCREF(&nassl_X509_Type);
    PyModule_AddObject(m, "X509", (PyObject *)&nassl_X509_Type);

}

