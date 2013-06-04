
#include <Python.h>

#include <openssl/ssl.h>

#include "nassl_errors.h"
#include "nassl_SSL.h"
#include "nassl_BIO.h"
#include "nassl_X509.h"

extern PyObject *nassl_OpenSSLError_Exception;


// nassl.SSL.new()
static PyObject* nassl_SSL_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
	nassl_SSL_Object *self;
    nassl_SSL_CTX_Object *sslCtx_Object;
	SSL *ssl;

    self = (nassl_SSL_Object *)type->tp_alloc(type, 0);
    if (self == NULL) 
    	return NULL;
    
    self->ssl = NULL;
    self->sslCtx_Object = NULL;
    self->bio_Object = NULL;

    // Recover and store the corresponding ssl_ctx
	if (!PyArg_ParseTuple(args, "O!", &nassl_SSL_CTX_Type, &sslCtx_Object)) {
		Py_DECREF(self);
    	return NULL;
    }

	if (sslCtx_Object == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "Received a NULL SSL_CTX object");
        Py_DECREF(self);
		return NULL;
	}
    Py_INCREF(sslCtx_Object);

    ssl = SSL_new(sslCtx_Object->sslCtx);
    if (ssl == NULL) {
        Py_DECREF(self);
        return raise_OpenSSL_error();
    }

	self->sslCtx_Object = sslCtx_Object; 
    self->ssl = ssl;
    self->bio_Object = NULL;

    return (PyObject *)self;
} 


static void nassl_SSL_dealloc(nassl_SSL_Object *self) {
 	if (self->ssl != NULL) {
  		SSL_free(self->ssl);
        self->ssl = NULL;
        if (self->bio_Object != NULL) {
            // BIO is implicitely freed by SSL_free()
            self->bio_Object->bio = NULL;
  	    }
    }

    if (self->sslCtx_Object != NULL) {
        Py_DECREF(self->sslCtx_Object);
    }
    self->ob_type->tp_free((PyObject*)self);
}


static PyObject* nassl_SSL_set_bio(nassl_SSL_Object *self, PyObject *args) {
    nassl_BIO_Object* bioObject;

    if (!PyArg_ParseTuple(args, "O!", &nassl_BIO_Type, &bioObject)) {
        return NULL;
    }

    self->bio_Object = bioObject;
    SSL_set_bio(self->ssl, bioObject->bio, bioObject->bio);
    Py_RETURN_NONE;
}


static PyObject* nassl_SSL_set_connect_state(nassl_SSL_Object *self, PyObject *args) {
    SSL_set_connect_state(self->ssl);
    Py_RETURN_NONE;
}


static PyObject* nassl_SSL_do_handshake(nassl_SSL_Object *self, PyObject *args) {
    int result = SSL_do_handshake(self->ssl);
    if (result != 1) {
        return raise_OpenSSL_ssl_error(self->ssl, result);
    }

    return Py_BuildValue("I", result);
}


static PyObject* nassl_SSL_read(nassl_SSL_Object *self, PyObject *args) {
    int returnValue, readSize;
    char *readBuffer;
    PyObject *res = NULL;

    if (!PyArg_ParseTuple(args, "I", &readSize)) {
        return NULL;
    }

    readBuffer = (char *) PyMem_Malloc(readSize);
    if (readBuffer == NULL)
        return PyErr_NoMemory();

    returnValue = SSL_read(self->ssl, readBuffer, readSize);
    if (returnValue > 0) { // Read OK
        res = PyString_FromStringAndSize(readBuffer, readSize);
    }
    else {  // Read failed
        raise_OpenSSL_ssl_error(self->ssl, returnValue);
    }    

    PyMem_Free(readBuffer);
    return res;
}


static PyObject* nassl_SSL_write(nassl_SSL_Object *self, PyObject *args) {
    int returnValue, writeSize;
    char *writeBuffer;
    PyObject *res = NULL;

    if (!PyArg_ParseTuple(args, "t#", &writeBuffer, &writeSize)) {
        return NULL;
    }

    returnValue = SSL_write(self->ssl, writeBuffer, writeSize);
    if (returnValue > 0) { // Write OK
        res = Py_BuildValue("I", returnValue);
    }
    else { // Write failed
        raise_OpenSSL_ssl_error(self->ssl, returnValue);
    }    

    return res;
}


static PyObject* nassl_SSL_pending(nassl_SSL_Object *self, PyObject *args) {
    int returnValue;

    returnValue = SSL_pending(self->ssl);
    return Py_BuildValue("I", returnValue);
}


static PyObject* nassl_SSL_get_secure_renegotiation_support(nassl_SSL_Object *self, PyObject *args) {
 
    if (SSL_get_secure_renegotiation_support(self->ssl))
        Py_RETURN_TRUE;
    else
        Py_RETURN_FALSE;
}


static PyObject* nassl_SSL_get_current_compression_name(nassl_SSL_Object *self, PyObject *args) {
    const COMP_METHOD *compMethod;

    compMethod = SSL_get_current_compression(self->ssl); // TODO: test it
    if (compMethod == NULL)
        Py_RETURN_NONE;

    return PyString_FromString(compMethod->name);
}



static PyObject* nassl_SSL_set_verify(nassl_SSL_Object *self, PyObject *args) {
    int verifyMode;

    if (!PyArg_ParseTuple(args, "I", &verifyMode)) {
        return NULL;
    }

    switch (verifyMode) {
        case SSL_VERIFY_NONE:
        case SSL_VERIFY_PEER:
        case SSL_VERIFY_FAIL_IF_NO_PEER_CERT:
        case SSL_VERIFY_CLIENT_ONCE:
            SSL_set_verify(self->ssl, verifyMode, NULL);
            break;
        default:
            PyErr_SetString(PyExc_ValueError, "Invalid value for verification mode");
            return NULL;
    }
    
    Py_RETURN_NONE;
}




static PyObject* nassl_SSL_set_tlsext_host_name(nassl_SSL_Object *self, PyObject *args) {
    int nameIndicationSize;
    char *nameIndication;

    if (!PyArg_ParseTuple(args, "t#", &nameIndication, &nameIndicationSize)) {
        return NULL;
    }

    if (!SSL_set_tlsext_host_name(self->ssl, nameIndication))
        {
            raise_OpenSSL_error();
            return NULL;
        }  

    Py_RETURN_NONE;
}


static PyObject* nassl_SSL_get_peer_certificate(nassl_SSL_Object *self, PyObject *args) {
    X509 *cert;

    cert = SSL_get_peer_certificate(self->ssl);
    if (cert == NULL) // Anonymous cipher suite ?
        Py_RETURN_NONE;
    else {
        // Return an nassl.X509 object
        nassl_X509_Object *x509_Object;
        x509_Object = (nassl_X509_Object *)nassl_X509_Type.tp_alloc(&nassl_X509_Type, 0);
        if (x509_Object == NULL) 
            return PyErr_NoMemory();

        x509_Object->x509 = cert;
        return (PyObject *) x509_Object;
    }
}


static PyObject* nassl_SSL_set_cipher_list(nassl_SSL_Object *self, PyObject *args) {
    int cipherListSize;
    char *cipherList;

    if (!PyArg_ParseTuple(args, "t#", &cipherList, &cipherListSize)) {
        return NULL;
    }

    if (!SSL_set_cipher_list(self->ssl, cipherList)) { 
        raise_OpenSSL_error();
        return NULL;
    }

    Py_RETURN_NONE;
}



static PyMethodDef nassl_SSL_Object_methods[] = {
    {"set_bio", (PyCFunction)nassl_SSL_set_bio, METH_VARARGS,
     "OpenSSL's SSL_set_bio() on the internal BIO of an nassl.BIO_Pair object."
    },
    {"do_handshake", (PyCFunction)nassl_SSL_do_handshake, METH_NOARGS,
     "OpenSSL's SSL_do_handshake()."
    },
    {"set_connect_state", (PyCFunction)nassl_SSL_set_connect_state, METH_NOARGS,
     "OpenSSL's SSL_set_connect_state()."
    },
    {"read", (PyCFunction)nassl_SSL_read, METH_VARARGS,
     "OpenSSL's SSL_read()."
    },
    {"write", (PyCFunction)nassl_SSL_write, METH_VARARGS,
     "OpenSSL's SSL_write()."
    },
    {"pending", (PyCFunction)nassl_SSL_pending, METH_NOARGS,
     "OpenSSL's SSL_pending()."
    },
    {"get_secure_renegotiation_support", (PyCFunction)nassl_SSL_get_secure_renegotiation_support, METH_NOARGS,
     "OpenSSL's SSL_get_secure_renegotiation_support()."
    },
    {"get_current_compression_name", (PyCFunction)nassl_SSL_get_current_compression_name, METH_NOARGS,
     "Recovers the name of the compression method being used by calling SSL_get_current_compression()."
    },
    {"set_verify", (PyCFunction)nassl_SSL_set_verify, METH_VARARGS,
     "OpenSSL's SSL_set_verify() with a NULL verify_callback."
    },
    {"set_tlsext_host_name", (PyCFunction)nassl_SSL_set_tlsext_host_name, METH_VARARGS,
     "OpenSSL's SSL_set_tlsext_host_name()."
    },
    {"get_peer_certificate", (PyCFunction)nassl_SSL_get_peer_certificate, METH_NOARGS,
     "OpenSSL's SSL_get_peer_certificate(). Returns an nassl.X509 object."
    },
    {"set_cipher_list", (PyCFunction)nassl_SSL_set_cipher_list, METH_VARARGS,
     "OpenSSL's SSL_set_cipher_list()."
    },
    {NULL}  // Sentinel
};
/*

static PyMemberDef nassl_SSL_Object_members[] = {
    {NULL}  // Sentinel
};
*/

static PyTypeObject nassl_SSL_Type = {
    PyObject_HEAD_INIT(NULL)
    0,                         /*ob_size*/
    "nassl.SSL",             /*tp_name*/
    sizeof(nassl_SSL_Object),             /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)nassl_SSL_dealloc, /*tp_dealloc*/
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
    "SSL objects",           /* tp_doc */
    0,                     /* tp_traverse */
    0,                     /* tp_clear */
    0,                     /* tp_richcompare */
    0,                     /* tp_weaklistoffset */
    0,                     /* tp_iter */
    0,                     /* tp_iternext */
    nassl_SSL_Object_methods,             /* tp_methods */
    0,             /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    0,      /* tp_init */
    0,                         /* tp_alloc */
    nassl_SSL_new,                 /* tp_new */
};



void module_add_SSL(PyObject* m) {

	nassl_SSL_Type.tp_new = nassl_SSL_new;
	if (PyType_Ready(&nassl_SSL_Type) < 0)
    	return;	
    
    Py_INCREF(&nassl_SSL_Type);
    PyModule_AddObject(m, "SSL", (PyObject *)&nassl_SSL_Type);

    // TODO: Add constants
}

