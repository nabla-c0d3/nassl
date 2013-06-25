
#include <Python.h>

#include <openssl/ssl.h>
#include <openssl/evp.h>

#include "nassl_errors.h"
#include "nassl_X509.h"
#include "nassl_X509_EXTENSION.h"



// nassl.X509.new()
static PyObject* nassl_X509_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {

    // For now X509.new() is not supposed to be called directly
    PyErr_SetString(PyExc_NotImplementedError, "Cannot directly create an X509 object. Get it from SSL.get_peer_certificate()");
    return NULL;

    /*
    nassl_X509_Object *self;
    self = (nassl_X509_Object *)type->tp_alloc(type, 0);
    if (self == NULL) 
    	return NULL;

	self->x509 = NULL;

    return (PyObject *)self;
    */
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
static PyObject* generic_print_to_string(int (*openSslPrintFunction)(BIO *fp, const void *a), const void *dataStruct) {
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
    res = PyString_FromStringAndSize(dataTxtBuffer, dataTxtSize);
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


static PyObject* nassl_X509_digest(nassl_X509_Object *self, PyObject *args) {
    unsigned char *readBuffer;
    unsigned int digestLen;
    PyObject *res = NULL;

    readBuffer = (unsigned char *) PyMem_Malloc(EVP_MAX_MD_SIZE);
    if (readBuffer == NULL)
        return PyErr_NoMemory();

    // Only support SHA1 for now
    if (X509_digest(self->x509, EVP_sha1(), readBuffer, &digestLen) == 1) { // Read OK
        res = PyString_FromStringAndSize((char *)readBuffer, digestLen);
    }
    else {
        PyErr_SetString(nassl_OpenSSLError_Exception, "X509_digest() failed.");
    }    

    PyMem_Free(readBuffer);
    return res;
}


static PyObject* nassl_X509_as_pem(nassl_X509_Object *self, PyObject *args) {
    return generic_print_to_string((int (*)(BIO *, const void *)) &PEM_write_bio_X509, self->x509);
}


static PyObject* nassl_X509_get_ext_count(nassl_X509_Object *self, PyObject *args) {
    return Py_BuildValue("I", X509_get_ext_count(self->x509));
}


static PyObject* nassl_X509_get_ext(nassl_X509_Object *self, PyObject *args) {
    int location;
    X509_EXTENSION *x509ext = NULL;

    if (!PyArg_ParseTuple(args, "I", &location)) {
        return NULL;
    }

    x509ext = X509_get_ext(self->x509, location);
    if (x509ext == NULL)
        Py_RETURN_NONE;
    else {
        // Return an nassl.X509_EXTENSION object
        nassl_X509_EXTENSION_Object *x509ext_Object;
        x509ext_Object = (nassl_X509_EXTENSION_Object *)nassl_X509_EXTENSION_Type.tp_alloc(&nassl_X509_EXTENSION_Type, 0);
        if (x509ext_Object == NULL) 
            return PyErr_NoMemory();

        // We need a copy of the X509_EXTENSION OpenSSL structure, 
        // otherwise the X509 object might get garbage collected 
        // (resulting in a call to X509_free()) while we're still 
        // using the X509_EXTENSION, resulting in a seg fault
        x509ext_Object->x509ext = X509_EXTENSION_dup(x509ext);
        return (PyObject *) x509ext_Object;
    }
}




static PyMethodDef nassl_X509_Object_methods[] = {
    {"as_text", (PyCFunction)nassl_X509_as_text, METH_NOARGS,
     "Returns a string containing the result of OpenSSL's X509_print()."
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
     "OpenSSL's x509_get_serialNumber()."
    },
    {"digest", (PyCFunction)nassl_X509_digest, METH_NOARGS,
     "OpenSSL's X509_digest() with SHA1 hardcoded."
    },
    {"as_pem", (PyCFunction)nassl_X509_as_pem, METH_NOARGS,
     "OpenSSL's PEM_write_bio_X509()."
    },
    {"get_ext_count", (PyCFunction)nassl_X509_get_ext_count, METH_NOARGS,
     "OpenSSL's X509_get_ext_count()."
    },
    {"get_ext", (PyCFunction)nassl_X509_get_ext, METH_VARARGS,
     "OpenSSL's X509_get_ext(). Returns an X509_EXTENSION object."
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

