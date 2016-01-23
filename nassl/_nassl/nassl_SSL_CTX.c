
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


static int client_cert_cb(SSL *ssl, X509 **x509, EVP_PKEY **pkey) {
    // This callback is here so we can detect when the server wants a client cert
    // It will trigger an SSL_ERROR_WANT_X509_LOOKUP error during the handshake
    // if the server expected a client certificate and we didn't provide one
    return -1;
}


// nassl.SSL_CTX.new()
static PyObject* nassl_SSL_CTX_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
	nassl_SSL_CTX_Object *self;
	int sslVersion;
	SSL_CTX *sslCtx;

    self = (nassl_SSL_CTX_Object *)type->tp_alloc(type, 0);
    if (self == NULL)
    	return NULL;

    self->sslCtx = NULL;
    self->pkeyPasswordBuf = NULL;

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

    // Set the default client certificate callback
    SSL_CTX_set_client_cert_cb(sslCtx, client_cert_cb);

    self->sslCtx = sslCtx;
    return (PyObject *)self;
}



static void nassl_SSL_CTX_dealloc(nassl_SSL_CTX_Object *self) {
 	if (self->sslCtx != NULL) {
  		SSL_CTX_free(self->sslCtx);
  		self->sslCtx = NULL;
  	}

    if (self->pkeyPasswordBuf != NULL) {
        PyMem_Free(self->pkeyPasswordBuf);
        self->pkeyPasswordBuf = NULL;
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



static PyObject* nassl_SSL_CTX_load_verify_locations(nassl_SSL_CTX_Object *self, PyObject *args) {
    char *caFile = NULL;

    if (!PyArg_ParseTuple(args, "s", &caFile)) {
        return NULL;
    }

    if (!SSL_CTX_load_verify_locations(self->sslCtx, caFile, NULL)) {
        return raise_OpenSSL_error();
    }

    Py_RETURN_NONE;
}


static PyObject* nassl_SSL_CTX_use_certificate_chain_file(nassl_SSL_CTX_Object *self, PyObject *args) {
    const char *filePath = NULL;

    if (!PyArg_ParseTuple(args, "s", &filePath)) {
        return NULL;
    }

    if (SSL_CTX_use_certificate_chain_file(self->sslCtx, filePath) != 1 ){
        return raise_OpenSSL_error();
    }

    Py_RETURN_NONE;
}


static PyObject* nassl_SSL_CTX_use_PrivateKey_file(nassl_SSL_CTX_Object *self, PyObject *args) {
    const char *filePath = NULL;
    int certType = 0;

    if (!PyArg_ParseTuple(args, "sI", &filePath, &certType)) {
        return NULL;
    }

    if (SSL_CTX_use_PrivateKey_file(self->sslCtx, filePath, certType) != 1) {
        return raise_OpenSSL_error();
    }

    Py_RETURN_NONE;
}


static PyObject* nassl_SSL_CTX_check_private_key(nassl_SSL_CTX_Object *self, PyObject *args) {
    if (SSL_CTX_check_private_key(self->sslCtx) != 1){
        return raise_OpenSSL_error();
    }

    Py_RETURN_NONE;
}


// passwd callback for encrypted PEM file handling
static int pem_passwd_cb(char *buf, int size, int rwflag, void *userdata) {
    // This is a hack to allow callers to provide the password to unlock
    // a PEM private key whenever they want instead of when the SSL_CTX
    // object gets created (which would be less hacky and convenient)
    // The pointer to the buffer containing the user's password is at userdata
    size_t passwordSize = 0;
    char *passwordBuf = (char *)userdata;

    if ((userdata == NULL) || (buf == NULL)) {
        return 0;
    }

    // NUL-terminated string as it will come from Python
    passwordSize = strlen(passwordBuf) + 1;
    if (passwordSize > size){  // Not enough space in OpenSSL's buffer
        return 0;
    }

    strncpy(buf, passwordBuf, passwordSize);
    // OpenSSL wants the size of the password
    return (int) strlen(passwordBuf);
}


static PyObject* nassl_SSL_CTX_set_private_key_password(nassl_SSL_CTX_Object *self, PyObject *args) {
    size_t passwordSize = 0;
    char *passwordStr = NULL;

    if (!PyArg_ParseTuple(args, "s", &passwordStr)) {
        return NULL;
    }

    // Store the password; Python gives us a NUL-terminated string
    passwordSize = strlen(passwordStr) + 1;
    self->pkeyPasswordBuf = (char *) PyMem_Malloc(passwordSize);
    if (self->pkeyPasswordBuf == NULL)
        return PyErr_NoMemory();

    strncpy(self->pkeyPasswordBuf, passwordStr, passwordSize);

    // Set up the OpenSSL callbacks
    SSL_CTX_set_default_passwd_cb(self->sslCtx, &pem_passwd_cb);
    SSL_CTX_set_default_passwd_cb_userdata(self->sslCtx, self->pkeyPasswordBuf);

    Py_RETURN_NONE;
}

static PyObject* nassl_SSL_CTX_set_client_cert_cb_NULL(nassl_SSL_CTX_Object *self, PyObject *args) {
    SSL_CTX_set_client_cert_cb(self->sslCtx, NULL);
    Py_RETURN_NONE;
}


static PyMethodDef nassl_SSL_CTX_Object_methods[] = {
    {"set_verify", (PyCFunction)nassl_SSL_CTX_set_verify, METH_VARARGS,
     "OpenSSL's SSL_CTX_set_verify() with a NULL verify_callback."
    },
    {"load_verify_locations", (PyCFunction)nassl_SSL_CTX_load_verify_locations, METH_VARARGS,
     "OpenSSL's SSL_CTX_load_verify_locations() with a NULL CAPath."
    },
    {"use_certificate_chain_file", (PyCFunction)nassl_SSL_CTX_use_certificate_chain_file, METH_VARARGS,
     "OpenSSL's SSL_CTX_use_certificate_chain_file()."
    },
    {"use_PrivateKey_file", (PyCFunction)nassl_SSL_CTX_use_PrivateKey_file, METH_VARARGS,
     "OpenSSL's SSL_CTX_use_PrivateKey_file()."
    },
    {"check_private_key", (PyCFunction)nassl_SSL_CTX_check_private_key, METH_NOARGS,
     "OpenSSL's SSL_CTX_check_private_key()."
    },
    {"set_private_key_password", (PyCFunction)nassl_SSL_CTX_set_private_key_password, METH_VARARGS,
     "Sets up a default callback for encrypted PEM file handling using OpenSSL's SSL_CTX_set_default_passwd_cb() with a hardcoded callback, and then stores the supplied password to be used for subsequent PEM decryption operations."
    },
    {"set_client_cert_cb_NULL", (PyCFunction)nassl_SSL_CTX_set_client_cert_cb_NULL, METH_NOARGS,
     "Configure a NULL client certificate callback in order to ignore client certificate requests from the server and continue even if no certificate was provided."
    },
    {NULL}  // Sentinel
};
/*

static PyMemberDef nassl_SSL_CTX_Object_members[] = {
    {NULL}  // Sentinel
};
*/

PyTypeObject nassl_SSL_CTX_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "_nassl.SSL_CTX",             /*tp_name*/
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
}

