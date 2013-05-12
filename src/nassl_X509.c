
#include <Python.h>

#include <openssl/ssl.h>

#include "nassl_errors.h"
#include "nassl_X509.h"




// nassl.X509.new()
static PyObject* nassl_X509_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
	nassl_X509_Object *self;
	X509 *x509 = NULL;

    self = (nassl_X509_Object *)type->tp_alloc(type, 0);
    if (self == NULL) 
    	return NULL;

	if (!PyArg_ParseTuple(args, "I", &x509)) { // TODO Proper pointer type
		Py_DECREF(self);
    	return NULL;
    }


	if (x509 == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "Received a NULL X509 pointer.");
        Py_DECREF(self);
		return NULL;
	}

	self->x509 = x509;

    return (PyObject *)self;
} 



static void nassl_X509_dealloc(nassl_X509_Object *self) {
 	if (self->x509 != NULL) {
  		X509_free(self->x509);
  		self->x509 = NULL;
  	}

    self->ob_type->tp_free((PyObject*)self);
}


static PyObject* nassl_X509_as_text(nassl_X509_Object *self, PyObject *args) {
    BIO *memBio;
    char *certTxtBuffer;
    int certTxtSize;
    PyObject* res;

    memBio = BIO_new(BIO_s_mem());
    if (memBio == NULL) {
        raise_OpenSSL_error();
        return NULL;
    }

    X509_print(memBio, self->x509);
    certTxtSize = BIO_pending(memBio);

    certTxtBuffer = (char *) PyMem_Malloc(certTxtSize);
    if (certTxtBuffer == NULL)
        return PyErr_NoMemory();

    // Extract the text from the BIO
    BIO_read(memBio, certTxtBuffer, certTxtSize);
    res = PyString_FromString(certTxtBuffer);
    PyMem_Free(certTxtBuffer);
    return res;
}





static PyMethodDef nassl_X509_Object_methods[] = {
    {"as_text", (PyCFunction)nassl_X509_as_text, METH_NOARGS,
     "OpenSSL's X509_print()."
    },

    {NULL}  // Sentinel
};


static PyTypeObject nassl_X509_Type = {
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

