
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
#include "nassl_X509_EXTENSION.h"
#include "nassl_X509_NAME_ENTRY.h"
#include "openssl_utils.h"


// nassl.X509.new()
static PyObject* nassl_X509_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {

    nassl_X509_Object *self;
    char *pemCertificate;
	BIO *bio;
	
    self = (nassl_X509_Object *)type->tp_alloc(type, 0);
    if (self == NULL)
    	return NULL;

    // Read the certificate as PEM and create an X509 object
    if (!PyArg_ParseTuple(args, "s", &pemCertificate)) {
        return NULL;
    }

    bio = BIO_new(BIO_s_mem());
    BIO_puts(bio, pemCertificate);

    self->x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (self->x509 == NULL) {
        PyErr_SetString(PyExc_ValueError, "Could not parse the supplied PEM certificate");
        return NULL;
    }
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
    {
        return PyErr_NoMemory();
    }

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


static PyObject* nassl_X509_get_extensions(nassl_X509_Object *self, PyObject *args) {
    PyObject* extensionsPyList = NULL;
    unsigned int i=0;
    unsigned int extCount = X509_get_ext_count(self->x509);


   // We'll return a Python list containing each extension
    extensionsPyList = PyList_New(extCount);
    if (extensionsPyList == NULL)
        return PyErr_NoMemory();


    // Return a list of X509_EXTENSION Python objects
    for (i=0;i<extCount;i++) {
        nassl_X509_EXTENSION_Object *x509ext_Object;
        X509_EXTENSION *x509ext = X509_get_ext(self->x509, i);
        if (x509ext == NULL) {
            PyErr_SetString(PyExc_ValueError, "Could not extract a X509_EXTENSION from the certificate. Exotic certificate ?");
            return NULL;
        }

        x509ext_Object = (nassl_X509_EXTENSION_Object *)nassl_X509_EXTENSION_Type.tp_alloc(&nassl_X509_EXTENSION_Type, 0);
        if (x509ext_Object == NULL)
            return PyErr_NoMemory();

        // We need a copy of the X509_EXTENSION OpenSSL structure,
        // otherwise the X509 Python object might get garbage collected
        // (resulting in a call to X509_free()) while we're still
        // using the X509_EXTENSION Python object, resulting in a seg fault
        x509ext_Object->x509ext = X509_EXTENSION_dup(x509ext);
        PyList_SET_ITEM(extensionsPyList, i, (PyObject *) x509ext_Object);
    }

    return extensionsPyList;
}


// Generic function to extract the list of X509_NAME_ENTRY from an X509_NAME.
// Used to get the subject name entries and the issuer name entries. Returns a Python list
static PyObject* generic_get_name_entries(X509_NAME * (*X509GetNameFunc)(X509 *a), nassl_X509_Object *self) {
    int i=0;
    X509_NAME * x509Name = NULL;
    unsigned int nameEntryCount = 0;
    PyObject* nameEntriesPyList = NULL;

    // Extract the name field
    x509Name = X509GetNameFunc(self->x509);
    if (x509Name == NULL) {
        PyErr_SetString(PyExc_ValueError, "Could not extract a X509_NAME from the certificate. Exotic certificate ?");
        return NULL;
    }
    nameEntryCount = X509_NAME_entry_count(x509Name);

   // We'll return a Python list containing each name entry
    nameEntriesPyList = PyList_New(nameEntryCount);
    if (nameEntriesPyList == NULL)
        return PyErr_NoMemory();

    // Extract each name entry and create a Python object
    for (i=0;i<nameEntryCount;i++) {
        nassl_X509_NAME_ENTRY_Object *nameEntry_Object;
        X509_NAME_ENTRY *nameEntry = X509_NAME_get_entry(x509Name, i);
        if (nameEntry == NULL) {
            PyErr_SetString(PyExc_ValueError, "Could not extract a X509_NAME_ENTRY from the certificate. Exotic certificate ?");
            return NULL;
        }

        nameEntry_Object = (nassl_X509_NAME_ENTRY_Object *)nassl_X509_NAME_ENTRY_Type.tp_alloc(&nassl_X509_NAME_ENTRY_Type, 0);
        if (nameEntry_Object == NULL)
            return PyErr_NoMemory();

        nameEntry_Object->x509NameEntry = X509_NAME_ENTRY_dup(nameEntry);
        PyList_SET_ITEM(nameEntriesPyList, i, (PyObject *) nameEntry_Object);
    }

    return nameEntriesPyList;
}


static PyObject* nassl_X509_get_issuer_name_entries(nassl_X509_Object *self, PyObject *args) {
    return generic_get_name_entries(&X509_get_issuer_name, self);
}


static PyObject* nassl_X509_get_subject_name_entries(nassl_X509_Object *self, PyObject *args) {
    return generic_get_name_entries(&X509_get_subject_name, self);
}


static PyObject* nassl_X509_verify_cert_error_string(PyObject *nullPtr, PyObject *args) {
    const char *errorString = NULL;
    long verifyError = 0;

    if (!PyArg_ParseTuple(args, "l", &verifyError)) {
        return NULL;
    }

    errorString = X509_verify_cert_error_string(verifyError);
    return PyString_FromString(errorString);
}

static PyObject* nassl_X509_get_spki_bytes(nassl_X509_Object *self, PyObject *args)
{
    int spkiLen = 0;
    unsigned char *spkiBufferEnd = NULL;
    unsigned char *spkiBufferStart = NULL;
    PyObject* spkiBytes = NULL;

    X509_PUBKEY *spki = X509_get_X509_PUBKEY(self->x509);
    spkiLen = i2d_X509_PUBKEY(spki, NULL);
    if (spkiLen < 0)
    {
        PyErr_SetString(PyExc_ValueError, "Could not extract SPKI bytes");
        return NULL;
    }

    spkiBufferStart = PyMem_Malloc(spkiLen);
    spkiBufferEnd = spkiBufferStart;
    if (spkiBufferStart == NULL)
    {
        return PyErr_NoMemory();
    }

    i2d_X509_PUBKEY(spki, &spkiBufferEnd);
    if (spkiBufferEnd - spkiBufferStart != spkiLen)
    {
        // Should never happen
        PyErr_SetString(PyExc_ValueError, "Could not extract SPKI bytes");
    }
    else
    {
        spkiBytes = PyString_FromStringAndSize((char *)spkiBufferStart, spkiLen);
    }
    PyMem_Free(spkiBufferStart);
    return spkiBytes;
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
    {"get_extensions", (PyCFunction)nassl_X509_get_extensions, METH_NOARGS,
     "Returns a list of X509_EXTENSION objects using OpenSSL's X509_get_ext()."
    },
    {"get_issuer_name_entries", (PyCFunction)nassl_X509_get_issuer_name_entries, METH_NOARGS,
     "Returns a list of X509_NAME_ENTRY objects extracted from the issuer name using OpenSSL's X509_get_issuer_name() and X509_NAME_get_entry()."
    },
    {"get_subject_name_entries", (PyCFunction)nassl_X509_get_subject_name_entries, METH_NOARGS,
     "Returns a list of X509_NAME_ENTRY objects extracted from the subject name using OpenSSL's X509_get_subject_name() and X509_NAME_get_entry()."
    },
    {"verify_cert_error_string", (PyCFunction)nassl_X509_verify_cert_error_string, METH_VARARGS | METH_STATIC,
     "OpenSSL's X509_verify_cert_error_string()."
    },
    {"get_spki_bytes", (PyCFunction)nassl_X509_get_spki_bytes, METH_NOARGS,
     "Returns the Subject Public Key Info bytes using OpenSSL's X509_get_X509_PUBKEY() and i2d_X509_PUBKEY()."
    },

    {NULL}  // Sentinel
};


PyTypeObject nassl_X509_Type = {
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



void module_add_X509(PyObject* m) {

	nassl_X509_Type.tp_new = nassl_X509_new;
	if (PyType_Ready(&nassl_X509_Type) < 0)
    	return;

    Py_INCREF(&nassl_X509_Type);
    PyModule_AddObject(m, "X509", (PyObject *)&nassl_X509_Type);

}

