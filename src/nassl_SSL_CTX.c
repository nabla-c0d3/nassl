
#include <Python.h>

#include <openssl/ssl.h>

#include "nassl_errors.h"
#include "nassl_SSL_CTX.h"


typedef enum {
	sslv23,
	sslv2,
	sslv3,
	tlsv1,
	tlsv1_1,
	tlsv1_2
} SslProtocolVersion;


// nassl.SSL_CTX.new()
static PyObject* nassl_SSL_CTX_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
	nassl_SSL_CTX_Object *self;
	int sslVersion;
	SSL_CTX *sslCtx;

    self = (nassl_SSL_CTX_Object *)type->tp_alloc(type, 0);
    if (self == NULL) 
    	return NULL;

	if (!PyArg_ParseTuple(args, "I", &sslVersion)) {
		Py_DECREF(self);
    	return NULL;
    }

    switch (sslVersion) {
		case sslv23:
			sslCtx = SSL_CTX_new(SSLv23_method());
			break;
		case sslv2:
			sslCtx = SSL_CTX_new(SSLv2_method());
			break;
		case sslv3:
			sslCtx = SSL_CTX_new(SSLv3_method());
			break;
		case tlsv1:
			sslCtx = SSL_CTX_new(TLSv1_method());
			break;
		case tlsv1_1:
			sslCtx = SSL_CTX_new(TLSv1_1_method());
			break;
		case tlsv1_2:
			sslCtx = SSL_CTX_new(TLSv1_2_method());
			break;
		default:
        	PyErr_SetString(PyExc_ValueError, "Invalid value for ssl version");
        	Py_DECREF(self);
			return NULL;
	}
	if (sslCtx == NULL) {
        raise_OpenSSL_error();
        Py_DECREF(self);
		return NULL;
	}

	self->sslCtx = sslCtx;

    return (PyObject *)self;
} 



static void nassl_SSL_CTX_dealloc(nassl_SSL_CTX_Object *self) {
 	if (self->sslCtx != NULL) {
  		SSL_CTX_free(self->sslCtx);
  		self->sslCtx = NULL;
  	}

    self->ob_type->tp_free((PyObject*)self);
}


static PyObject* nassl_SSL_CTX_set_verify(nassl_SSL_CTX_Object *self, PyObject *args) {
	int verifyMode;

	if (!PyArg_ParseTuple(args, "I", &verifyMode)) {
    	return NULL;
    }

    switch (verifyMode) {
        case SSL_VERIFY_NONE:
        case SSL_VERIFY_PEER:
        case SSL_VERIFY_FAIL_IF_NO_PEER_CERT:
        case SSL_VERIFY_CLIENT_ONCE:
            SSL_CTX_set_verify(self->sslCtx, verifyMode, NULL);
            break;
        default:
            PyErr_SetString(PyExc_ValueError, "Invalid value for verification mode");
            return NULL;
    }
	
	Py_RETURN_NONE;
}


static PyObject* nassl_SSL_CTX_set_cipher_list(nassl_SSL_CTX_Object *self, PyObject *args) {
    int cipherListSize;
    char *cipherList;

    if (!PyArg_ParseTuple(args, "t#", &cipherList, &cipherListSize)) {
        return NULL;
    }

    if (!SSL_CTX_set_cipher_list(self->sslCtx, cipherList)) { 
        raise_OpenSSL_error();
        return NULL;
    }

    Py_RETURN_NONE;
}


static PyObject* nassl_SSL_CTX_load_verify_locations(nassl_SSL_CTX_Object *self, PyObject *args) {
    int caFileSize;
    char *caFile;

    if (!PyArg_ParseTuple(args, "t#", &caFile, &caFileSize)) {
        return NULL;
    }

    if (!SSL_CTX_load_verify_locations(self->sslCtx, caFile, NULL)) { 
        raise_OpenSSL_error();
        return NULL;
    }

    Py_RETURN_NONE;
}





static PyMethodDef nassl_SSL_CTX_Object_methods[] = {
    {"set_verify", (PyCFunction)nassl_SSL_CTX_set_verify, METH_VARARGS,
     "OpenSSL's SSL_CTX_set_verify() with a NULL verify_callback."
    },
    {"set_cipher_list", (PyCFunction)nassl_SSL_CTX_set_cipher_list, METH_VARARGS,
     "OpenSSL's SSL_CTX_set_cipher_list()."
    },
    {"load_verify_locations", (PyCFunction)nassl_SSL_CTX_load_verify_locations, METH_VARARGS,
     "OpenSSL's SSL_CTX_load_verify_locations() with a NULL CAPath."
    },
    {NULL}  // Sentinel
};
/*

static PyMemberDef nassl_SSL_CTX_Object_members[] = {
    {NULL}  // Sentinel
};
*/

PyTypeObject nassl_SSL_CTX_Type = {
    PyObject_HEAD_INIT(NULL)
    0,                         /*ob_size*/
    "nassl.SSL_CTX",             /*tp_name*/
    sizeof(nassl_SSL_CTX_Object),             /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)nassl_SSL_CTX_dealloc, /*tp_dealloc*/
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
    "SSL_CTX objects",           /* tp_doc */
    0,                     /* tp_traverse */
    0,                     /* tp_clear */
    0,                     /* tp_richcompare */
    0,                     /* tp_weaklistoffset */
    0,                     /* tp_iter */
    0,                     /* tp_iternext */
    nassl_SSL_CTX_Object_methods,             /* tp_methods */
    0,             /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    0,      /* tp_init */
    0,                         /* tp_alloc */
    nassl_SSL_CTX_new,                 /* tp_new */
};



void module_add_SSL_CTX(PyObject* m) {

	nassl_SSL_CTX_Type.tp_new = nassl_SSL_CTX_new;
	if (PyType_Ready(&nassl_SSL_CTX_Type) < 0)
    	return;	
    
    Py_INCREF(&nassl_SSL_CTX_Type);
    PyModule_AddObject(m, "SSL_CTX", (PyObject *)&nassl_SSL_CTX_Type);

    // Verify constants
    PyModule_AddIntConstant(m, "SSL_VERIFY_NONE", SSL_VERIFY_NONE);
    PyModule_AddIntConstant(m, "SSL_VERIFY_PEER", SSL_VERIFY_PEER);
    PyModule_AddIntConstant(m, "SSL_VERIFY_FAIL_IF_NO_PEER_CERT", SSL_VERIFY_FAIL_IF_NO_PEER_CERT);
    PyModule_AddIntConstant(m, "SSL_VERIFY_CLIENT_ONCE", SSL_VERIFY_CLIENT_ONCE);

    // SSL version constants
    PyModule_AddIntConstant(m, "SSLV23", sslv23);
    PyModule_AddIntConstant(m, "SSLV2", sslv2);
    PyModule_AddIntConstant(m, "SSLV3", sslv3);
    PyModule_AddIntConstant(m, "TLSV1", tlsv1);
    PyModule_AddIntConstant(m, "TLSV1_1", tlsv1_1);
    PyModule_AddIntConstant(m, "TLSV1_2", tlsv1_2);

}

