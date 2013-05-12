
#include <Python.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/errno.h>

#include "nassl_errors.h"
#include "nassl_SSL.h"

extern PyObject *nassl_OpenSSLError_Exception;


// nassl.SSL.new()
static PyObject* nassl_SSL_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
	nassl_SSL_Object *self;
    nassl_SSL_CTX_Object *sslCtx_Object;
	SSL *ssl;
    BIO *socketBio;

    self = (nassl_SSL_Object *)type->tp_alloc(type, 0);
    if (self == NULL) 
    	return NULL;


    // Recover and store the corresponding ssl_ctx
	if (!PyArg_ParseTuple(args, "O", &sslCtx_Object)) {
		Py_DECREF(self);
    	return NULL;
    }

	if (sslCtx_Object == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "Received a NULL SSL_CTX object");
        Py_DECREF(self);
		return NULL;
	}

    Py_INCREF(sslCtx_Object);
	self->sslCtx_Object = sslCtx_Object; 


    // Create the socket BIO to be used for data transmission
    socketBio = BIO_new_ssl_connect(self->sslCtx_Object->sslCtx);
    BIO_get_ssl(socketBio, &ssl); 
    if(ssl == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "BIO_get_ssl() returned a NULL ssl reference");
        Py_DECREF(self);
        return NULL;
    }
    self->socketBio = socketBio;
    self->ssl = ssl;

    return (PyObject *)self;
} 



static void nassl_SSL_dealloc(nassl_SSL_Object *self) {
 	if (self->socketBio != NULL) {
  		BIO_free_all(self->socketBio); // this will free the ssl structure as well
        self->socketBio = NULL;
  		self->ssl = NULL;
  	}

    Py_DECREF(self->sslCtx_Object);
    self->ob_type->tp_free((PyObject*)self);
}



static int error_handler(SSL *ssl, int returnValue) {
    // TODO: Better error handling
    int sslError = SSL_get_error(ssl, returnValue);

    switch(sslError) {
        unsigned long openSslError;
        char *errorString;

        case SSL_ERROR_NONE:
            break;

        case SSL_ERROR_SSL:
            openSslError = ERR_get_error();
            errorString = ERR_error_string(openSslError, NULL);
            PyErr_SetString(PyExc_IOError, errorString);
            return -1;
        
        case SSL_ERROR_SYSCALL:
            openSslError = ERR_get_error();
            
            if (openSslError == 0) {
                if (returnValue == 0) {
                    PyErr_SetString(PyExc_IOError, "An EOF was observed that violates the protocol");
                    return -1;
                }
                else if (returnValue == -1) {
                    // TODO: Windows
                    PyErr_SetFromErrno(PyExc_IOError);
                    return -1;
                }
                else {
                    PyErr_SetString(PyExc_IOError, "SSL_ERROR_SYSCALL");
                    return -1;
                }
            } 
            else {
                errorString = ERR_error_string(openSslError, NULL);
                PyErr_SetString(PyExc_IOError, errorString);
                return -1;
            }

        case SSL_ERROR_ZERO_RETURN:
            PyErr_SetString(PyExc_IOError, "Connection was shut down by peer");
            return -1;

        default:
            PyErr_SetString(PyExc_IOError, "TODO: Better error handling");
            return -1;
    }
    
    return 0;
}


static PyObject* nassl_SSL_do_handshake(nassl_SSL_Object *self, PyObject *args) {
    int result;

    // TODO: Add a BIO class
    BIO_set_conn_hostname(self->socketBio, "localhost:8444");

    result = SSL_do_handshake(self->ssl);
    switch (result) {

        case 1: // Handshake successful
            break;

        case 0: // Handshake failed - protocol error
        default: // Handshake failed - fatal error
            if (error_handler(self->ssl, result) != 0) 
                return NULL;
    }
    
    Py_RETURN_NONE;
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
        res = PyString_FromString(readBuffer);
    }
    else if (returnValue == 0) { // Read failed
        error_handler(self->ssl, returnValue);
    }
    else {  // Read failed
        error_handler(self->ssl, returnValue);
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
    else if (returnValue == 0) { // Write failed
        error_handler(self->ssl, returnValue);
    }
    else { // Write failed
        error_handler(self->ssl, returnValue);
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
            PyErr_SetString(PyExc_IndexError, "Invalid value for verification mode");
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

    Py_RETURN_TRUE;
}


static PyObject* nassl_SSL_get_peer_certificate(nassl_SSL_Object *self, PyObject *args) {
    X509 *cert;

    cert = SSL_get_peer_certificate(self->ssl);
    if (cert == NULL) // Anonymous cipher suite ?
        Py_RETURN_NONE;
    else
        return Py_BuildValue("I", (int) cert); // TODO: Directly create the X509 object
}



static PyMethodDef nassl_SSL_Object_methods[] = {
    {"do_handshake", (PyCFunction)nassl_SSL_do_handshake, METH_NOARGS,
     "OpenSSL's SSL_do_handshake()."
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

