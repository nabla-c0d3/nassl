
#include <Python.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "nassl_errors.h"
#include "nassl_X509_EXTENSION.h"


// For simplicity, this class does not properly mirror OpenSSL's X509_EXTENSION_() functions

static PyObject* nassl_X509_EXTENSION_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {

    PyErr_SetString(PyExc_NotImplementedError, "Cannot directly create an X509_EXTENSION object. Get it from X509.get_extensions()");
    return NULL;
}


static void nassl_X509_EXTENSION_dealloc(nassl_X509_EXTENSION_Object *self) {
    if (self->x509ext != NULL) {
        X509_EXTENSION_free(self->x509ext);
        self->x509ext = NULL;
    }

    self->ob_type->tp_free((PyObject*)self);
}


static PyObject* nassl_X509_EXTENSION_get_object(nassl_X509_EXTENSION_Object *self) {
    ASN1_OBJECT *x509extObj;
    char *objTxtBuffer = NULL;
    unsigned int objTxtSize = 0;
    PyObject* res;

    x509extObj = X509_EXTENSION_get_object(self->x509ext);

    // Get the size of the text representation of the extension
    objTxtSize = OBJ_obj2txt(NULL, 0, x509extObj, 0) + 1;

    objTxtBuffer = (char *) PyMem_Malloc(objTxtSize);
    if (objTxtBuffer == NULL)
        return PyErr_NoMemory();

    // Extract the text representation
    OBJ_obj2txt(objTxtBuffer, objTxtSize, x509extObj, 0);
    res = PyString_FromStringAndSize(objTxtBuffer, objTxtSize - 1);
    PyMem_Free(objTxtBuffer);
    return res;
}


static PyObject* nassl_X509_EXTENSION_get_data(nassl_X509_EXTENSION_Object *self) {
    BIO *memBio;
    char *dataTxtBuffer;
    unsigned int dataTxtSize;
    PyObject* res;

    memBio = BIO_new(BIO_s_mem());
    if (memBio == NULL) {
        raise_OpenSSL_error();
        return NULL;
    }

    X509V3_EXT_print(memBio, self->x509ext, X509V3_EXT_ERROR_UNKNOWN, 0);

    dataTxtSize = BIO_pending(memBio);
    dataTxtBuffer = (char *) PyMem_Malloc(dataTxtSize);
    if (dataTxtBuffer == NULL)
        return PyErr_NoMemory();

    // Extract the text from the BIO
    BIO_read(memBio, dataTxtBuffer, dataTxtSize);
    res = PyString_FromStringAndSize(dataTxtBuffer, dataTxtSize);
    PyMem_Free(dataTxtBuffer);
    return res;
}


static PyObject* nassl_X509_EXTENSION_get_critical(nassl_X509_EXTENSION_Object *self) {
    if (X509_EXTENSION_get_critical(self->x509ext))
        Py_RETURN_TRUE;
    else
        Py_RETURN_FALSE;
}


static PyMethodDef nassl_X509_EXTENSION_Object_methods[] = {
    {"get_object", (PyCFunction)nassl_X509_EXTENSION_get_object, METH_NOARGS,
     "Returns a string containing the result of OpenSSL's X509_EXTENSION_get_object() and OBJ_obj2txt()."
    },
    {"get_data", (PyCFunction)nassl_X509_EXTENSION_get_data, METH_NOARGS,
     "Returns a string containing the result of OpenSSL's X509V3_EXT_print()."
    },
    {"get_critical", (PyCFunction)nassl_X509_EXTENSION_get_critical, METH_NOARGS,
     "OpenSSL's X509_EXTENSION_get_critical()."
    },

    {NULL}  // Sentinel
};


PyTypeObject nassl_X509_EXTENSION_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "_nassl.X509_EXTENSION",             /*tp_name*/
    sizeof(nassl_X509_EXTENSION_Object),             /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)nassl_X509_EXTENSION_dealloc, /*tp_dealloc*/
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
    "X509_EXTENSION objects",           /* tp_doc */
    0,                     /* tp_traverse */
    0,                     /* tp_clear */
    0,                     /* tp_richcompare */
    0,                     /* tp_weaklistoffset */
    0,                     /* tp_iter */
    0,                     /* tp_iternext */
    nassl_X509_EXTENSION_Object_methods,             /* tp_methods */
    0,             /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    0,      /* tp_init */
    0,                         /* tp_alloc */
    nassl_X509_EXTENSION_new,                 /* tp_new */
};



void module_add_X509_EXTENSION(PyObject* m) {

	nassl_X509_EXTENSION_Type.tp_new = nassl_X509_EXTENSION_new;
	if (PyType_Ready(&nassl_X509_EXTENSION_Type) < 0)
    	return;

    Py_INCREF(&nassl_X509_EXTENSION_Type);
    PyModule_AddObject(m, "X509_EXTENSION", (PyObject *)&nassl_X509_EXTENSION_Type);

}

