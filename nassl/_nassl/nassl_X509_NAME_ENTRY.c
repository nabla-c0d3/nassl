
#include <Python.h>

#include <openssl/x509.h>

#include "nassl_errors.h"
#include "nassl_X509_NAME_ENTRY.h"


static PyObject* nassl_X509_NAME_ENTRY_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {

    PyErr_SetString(PyExc_NotImplementedError, "Cannot directly create an X509_NAME_ENTRY object. Get it from X509.get_issuer_name_entries()");
    return NULL;
}


static void nassl_X509_NAME_ENTRY_dealloc(nassl_X509_NAME_ENTRY_Object *self) {
    if (self->x509NameEntry != NULL) {
        X509_NAME_ENTRY_free(self->x509NameEntry);
        self->x509NameEntry = NULL;
    }

    self->ob_type->tp_free((PyObject*)self);
}


static PyObject* nassl_X509_NAME_ENTRY_get_data(nassl_X509_NAME_ENTRY_Object *self) {
    unsigned int nameDataSize = 0, objectDataSize = 0, nameUtf8Size = 0;
    ASN1_STRING *nameData = NULL;
    ASN1_OBJECT *objectData = NULL;
    unsigned char *nameDataTxt = NULL;
    unsigned char *objectDataTxt = NULL;
    PyObject* res = NULL;

    nameData = X509_NAME_ENTRY_get_data(self->x509NameEntry);
    nameDataSize = ASN1_STRING_length(nameData);


    // Extract the text representation of the field's name
    objectData = X509_NAME_ENTRY_get_object(self->x509NameEntry);
    objectDataSize = OBJ_obj2txt(NULL, 0, objectData, 0) + 1;

    objectDataTxt = PyMem_Malloc(objectDataSize);
    if (objectDataTxt == NULL)
        return PyErr_NoMemory();

    OBJ_obj2txt((char *)objectDataTxt, objectDataSize, objectData, 0);
    nameUtf8Size = ASN1_STRING_to_UTF8(&nameDataTxt, nameData);


    // Are we extracting the Common Name ?
    if (strncmp((char *)objectDataTxt, "commonName", strlen("commonName")) == 0)
    {
        if (nameDataSize != nameUtf8Size)
        {
            // TODO: Unit test for that
            // Embedded null character in the Common Name ? Get out
            PyMem_Free(objectDataTxt);
            PyErr_SetString(PyExc_NotImplementedError, "ASN1 string length does not match C string length. Embedded null character ?");
            return NULL;
        }
    }
    PyMem_Free(objectDataTxt);
    res = PyString_FromStringAndSize((const char*) nameDataTxt, nameDataSize);
    return res;
}




static PyObject* nassl_X509_NAME_ENTRY_get_object(nassl_X509_NAME_ENTRY_Object *self) {
    unsigned int objectDataSize = 0;
    ASN1_OBJECT *objectData = NULL;
    char *objectDataTxt = NULL;
    PyObject* res = NULL;

    objectData = X509_NAME_ENTRY_get_object(self->x509NameEntry);
    objectDataSize = OBJ_obj2txt(NULL, 0, objectData, 0) + 1;

    objectDataTxt = (char *) PyMem_Malloc(objectDataSize);
    if (objectDataTxt == NULL)
        return PyErr_NoMemory();

    // Extract the text representation
    OBJ_obj2txt(objectDataTxt, objectDataSize, objectData, 0);
    res = PyString_FromStringAndSize(objectDataTxt, objectDataSize - 1);
    PyMem_Free(objectDataTxt);
    return res;
}




static PyMethodDef nassl_X509_NAME_ENTRY_Object_methods[] = {
    {"get_object", (PyCFunction)nassl_X509_NAME_ENTRY_get_object, METH_NOARGS,
     "Returns a string containing the result of OpenSSL's X509_NAME_get_object() and OBJ_obj2txt()."
    },
    {"get_data", (PyCFunction)nassl_X509_NAME_ENTRY_get_data, METH_NOARGS,
     "Returns a string containing the result of OpenSSL's X509_NAME_ENTRY_get_data() and ASN1_STRING_to_UTF8()."
    },

    {NULL}  // Sentinel
};


PyTypeObject nassl_X509_NAME_ENTRY_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "_nassl.X509_NAME_ENTRY",             /*tp_name*/
    sizeof(nassl_X509_NAME_ENTRY_Object),             /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)nassl_X509_NAME_ENTRY_dealloc, /*tp_dealloc*/
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
    "X509_NAME_ENTRY objects",           /* tp_doc */
    0,                     /* tp_traverse */
    0,                     /* tp_clear */
    0,                     /* tp_richcompare */
    0,                     /* tp_weaklistoffset */
    0,                     /* tp_iter */
    0,                     /* tp_iternext */
    nassl_X509_NAME_ENTRY_Object_methods,             /* tp_methods */
    0,             /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    0,      /* tp_init */
    0,                         /* tp_alloc */
    nassl_X509_NAME_ENTRY_new,                 /* tp_new */
};



void module_add_X509_NAME_ENTRY(PyObject* m) {

	nassl_X509_NAME_ENTRY_Type.tp_new = nassl_X509_NAME_ENTRY_new;
	if (PyType_Ready(&nassl_X509_NAME_ENTRY_Type) < 0)
    	return;

    Py_INCREF(&nassl_X509_NAME_ENTRY_Type);
    PyModule_AddObject(m, "X509_NAME_ENTRY", (PyObject *)&nassl_X509_NAME_ENTRY_Type);
}

