
#include <Python.h>

// Fix symbol clashing on Windows
// https://bugs.launchpad.net/pyopenssl/+bug/570101
#ifdef _WIN32
#include "winsock.h"
#endif

#include <openssl/ssl.h>
#include <openssl/ocsp.h>
#include <openssl/ossl_typ.h>
#include <openssl/ec.h>

#include "nassl_errors.h"
#include "nassl_SSL.h"
#include "nassl_BIO.h"
#include "nassl_X509.h"
#include "nassl_SSL_SESSION.h"
#include "nassl_OCSP_RESPONSE.h"
#include "openssl_utils.h"


// nassl.SSL.new()
static PyObject* nassl_SSL_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    nassl_SSL_Object *self;
    nassl_SSL_CTX_Object *sslCtx_Object;
    SSL *ssl;

    self = (nassl_SSL_Object *)type->tp_alloc(type, 0);
    if (self == NULL)
    {
        return NULL;
    }

    self->ssl = NULL;
    self->sslCtx_Object = NULL;
    self->networkBio_Object = NULL;

    // Recover and store the corresponding ssl_ctx
    if (!PyArg_ParseTuple(args, "O!", &nassl_SSL_CTX_Type, &sslCtx_Object))
    {
        Py_DECREF(self);
        return NULL;
    }

    if (sslCtx_Object == NULL)
    {
        PyErr_SetString(PyExc_RuntimeError, "Received a NULL SSL_CTX object");
        Py_DECREF(self);
        return NULL;
    }
    Py_INCREF(sslCtx_Object);

    ssl = SSL_new(sslCtx_Object->sslCtx);
    if (ssl == NULL)
    {
        Py_DECREF(self);
        return raise_OpenSSL_error();
    }

    self->sslCtx_Object = sslCtx_Object;
    self->ssl = ssl;

    return (PyObject *)self;
}


static void nassl_SSL_dealloc(nassl_SSL_Object *self)
{
    if (self->networkBio_Object != NULL)
    {
        if (self->networkBio_Object->bio != NULL)
        {
            // Manually free the network BIO; it's the only place where we know that it is not needed anymore
            // If a reference to the BIO Python object is kept, the object will not be usable
            BIO_vfree(self->networkBio_Object->bio);
            self->networkBio_Object->bio = NULL;
        }
        Py_DECREF(self->networkBio_Object);
        self->networkBio_Object = NULL;
    }

    if (self->ssl != NULL)
    {
        // This will also free the internal BIO
        SSL_free(self->ssl);
        self->ssl = NULL;
    }

    if (self->sslCtx_Object != NULL)
    {
        Py_DECREF(self->sslCtx_Object);
    }
    Py_TYPE(self)->tp_free((PyObject*)self);
}


static PyObject* nassl_SSL_set_bio(nassl_SSL_Object *self, PyObject *args)
{
    nassl_BIO_Object* internalBioObject;
    if (!PyArg_ParseTuple(args, "O!", &nassl_BIO_Type, &internalBioObject))
    {
        return NULL;
    }
    SSL_set_bio(self->ssl, internalBioObject->bio, internalBioObject->bio);
    Py_RETURN_NONE;
}


static PyObject* nassl_SSL_set_network_bio_to_free_when_dealloc(nassl_SSL_Object *self, PyObject *args)
{
    // The network BIO is only needed here so we properly free it when the SSL object gets freed
    // Other than that it's never used
    nassl_BIO_Object* networkBioObject;

    if (!PyArg_ParseTuple(args, "O!", &nassl_BIO_Type, &networkBioObject))
    {
        return NULL;
    }
    Py_INCREF(networkBioObject);
    self->networkBio_Object = networkBioObject;
    Py_RETURN_NONE;
}


static PyObject* nassl_SSL_set_connect_state(nassl_SSL_Object *self, PyObject *args)
{
    SSL_set_connect_state(self->ssl);
    Py_RETURN_NONE;
}


static PyObject* nassl_SSL_set_mode(nassl_SSL_Object *self, PyObject *args)
{
    long mode;
    if (!PyArg_ParseTuple(args, "l", &mode))
    {
        return NULL;
    }

    SSL_set_mode(self->ssl, mode);
    Py_RETURN_NONE;
}


static PyObject* nassl_SSL_do_handshake(nassl_SSL_Object *self, PyObject *args)
{
    int result = SSL_do_handshake(self->ssl);
    if (result != 1)
    {
        return raise_OpenSSL_ssl_error(self->ssl, result);
    }
    Py_RETURN_NONE;
}


static PyObject* nassl_SSL_read(nassl_SSL_Object *self, PyObject *args)
{
    int returnValue, readSize;
    char *readBuffer;
    PyObject *res = NULL;

    if (!PyArg_ParseTuple(args, "I", &readSize))
    {
        return NULL;
    }

    readBuffer = (char *) PyMem_Malloc(readSize);
    if (readBuffer == NULL)
    {
        return PyErr_NoMemory();
    }

    returnValue = SSL_read(self->ssl, readBuffer, readSize);
    if (returnValue > 0)
    {
        // Read OK
        res = PyBytes_FromStringAndSize(readBuffer, returnValue);
    }
    else
    {
        // Read failed
        raise_OpenSSL_ssl_error(self->ssl, returnValue);
    }

    PyMem_Free(readBuffer);
    return res;
}


static PyObject* nassl_SSL_write(nassl_SSL_Object *self, PyObject *args)
{
    int returnValue, writeSize;
    char *writeBuffer;
    PyObject *res = NULL;

    if (!PyArg_ParseTuple(args, "s#", &writeBuffer, &writeSize))
    {
        return NULL;
    }

    returnValue = SSL_write(self->ssl, writeBuffer, writeSize);
    if (returnValue > 0)
    {
        // Write OK
        res = Py_BuildValue("I", returnValue);
    }
    else
    {
        // Write failed
        raise_OpenSSL_ssl_error(self->ssl, returnValue);
    }
    return res;
}

#ifndef LEGACY_OPENSSL
static PyObject* nassl_SSL_write_early_data(nassl_SSL_Object *self, PyObject *args)
{
    int returnValue, writeSize;
    size_t writtenDataSize;
    char *writeBuffer;
    PyObject *res = NULL;

    if (!PyArg_ParseTuple(args, "s#", &writeBuffer, &writeSize))
    {
        return NULL;
    }

    returnValue = SSL_write_early_data(self->ssl, writeBuffer, writeSize, &writtenDataSize);
    if (returnValue > 0)
    {
        // Write OK
        res = Py_BuildValue("I", writtenDataSize);
    }
    else
    {
        // Write failed
        raise_OpenSSL_ssl_error(self->ssl, returnValue);
    }
    return res;
}

static PyObject* nassl_SSL_get_early_data_status(nassl_SSL_Object *self, PyObject *args)
{
    int returnValue = SSL_get_early_data_status(self->ssl);

    return Py_BuildValue("I", returnValue);
}

static PyObject* nassl_SSL_get_max_early_data(nassl_SSL_Object *self, PyObject *args)
{
    int returnValue = SSL_get_max_early_data(self->ssl);

    return Py_BuildValue("I", returnValue);
}

static PyObject* nassl_SSL_set1_groups_list(nassl_SSL_CTX_Object *self, PyObject *args)
{
    char *supportedGroups = NULL;
    if (PyArg_ParseTuple(args, "s", &supportedGroups) == NULL)
    {
        return NULL;
    }

    if (SSL_set1_groups_list(self->sslCtx, supportedGroups) != 1)
    {
        return raise_OpenSSL_error();
    }

    Py_RETURN_NONE;
}
#endif

static PyObject* nassl_SSL_shutdown(nassl_SSL_Object *self, PyObject *args)
{
    int returnValue = SSL_shutdown(self->ssl);
    PyObject *res = NULL;

    if (returnValue >= 0)
    {
        res = Py_BuildValue("I", returnValue);
    }
    else
    {
        raise_OpenSSL_ssl_error(self->ssl, returnValue);
    }
    return res;
}


static PyObject* nassl_SSL_pending(nassl_SSL_Object *self, PyObject *args)
{
    int returnValue = SSL_pending(self->ssl);
    return Py_BuildValue("I", returnValue);
}


static PyObject* nassl_SSL_get_secure_renegotiation_support(nassl_SSL_Object *self, PyObject *args)
{
    if (SSL_get_secure_renegotiation_support(self->ssl))
    {
        Py_RETURN_TRUE;
    }
    else
    {
        Py_RETURN_FALSE;
    }
}

static PyObject* nassl_SSL_get_available_compression_methods(nassl_SSL_Object *self, PyObject *args)
{
    PyObject* compMethodPyList = NULL;
    int i, compMethodsCount = 0;
    STACK_OF(SSL_COMP) *compMethods = SSL_COMP_get_compression_methods();

    // We'll return a Python list containing the name of each compression method
    compMethodsCount = sk_SSL_COMP_num(compMethods);
    compMethodPyList = PyList_New(compMethodsCount);
    if (compMethodPyList == NULL)
    {
        return PyErr_NoMemory();
    }

    for (i=0;i<compMethodsCount;i++)
    {
        PyObject *methodPyString = NULL;

        const SSL_COMP *method = sk_SSL_COMP_value(compMethods, i);
        if (method == NULL)
        {
            Py_DECREF(compMethodPyList);
            PyErr_SetString(PyExc_ValueError, "Could not extract a compression method. Should not happen ?");
            return NULL;
        }

#ifdef LEGACY_OPENSSL
        methodPyString = PyUnicode_FromString(method->name);
#else
        methodPyString = PyUnicode_FromString(SSL_COMP_get0_name(method));
#endif
        if (methodPyString == NULL)
        {
            Py_DECREF(compMethodPyList);
            return PyErr_NoMemory();
        }

        PyList_SET_ITEM(compMethodPyList, i,  methodPyString);
    }

    return compMethodPyList;
}


static PyObject* nassl_SSL_get_current_compression_method(nassl_SSL_Object *self, PyObject *args)
{
    const COMP_METHOD *compMethod;
    compMethod = SSL_get_current_compression(self->ssl);
    if (compMethod == NULL)
    {
        Py_RETURN_NONE;
    }
    return PyUnicode_FromString(SSL_COMP_get_name(compMethod));
}


static PyObject* nassl_SSL_set_verify(nassl_SSL_Object *self, PyObject *args)
{
    int verifyMode;
    if (!PyArg_ParseTuple(args, "I", &verifyMode))
    {
        return NULL;
    }

    switch (verifyMode)
    {
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


static PyObject* nassl_SSL_set_tlsext_host_name(nassl_SSL_Object *self, PyObject *args)
{
    char *nameIndication;
    if (!PyArg_ParseTuple(args, "s", &nameIndication))
    {
        return NULL;
    }

    if (!SSL_set_tlsext_host_name(self->ssl, nameIndication))
    {
        PyErr_SetString(PyExc_ValueError, "Error setting the SNI extension. Using SSL 2 ?");
        return NULL;
    }

    Py_RETURN_NONE;
}


static PyObject* nassl_SSL_set_cipher_list(nassl_SSL_Object *self, PyObject *args)
{
    char *cipherList;
    if (!PyArg_ParseTuple(args, "s", &cipherList))
    {
        return NULL;
    }

    if (!SSL_set_cipher_list(self->ssl, cipherList))
    {
        return raise_OpenSSL_error();
    }

    Py_RETURN_NONE;
}


static PyObject* nassl_SSL_get_cipher_list(nassl_SSL_Object *self, PyObject *args)
{
    unsigned int priority = 0;
    PyObject* ciphersPyList = NULL;
    if (SSL_get_cipher_list(self->ssl, 0) == NULL)
    {
        Py_RETURN_NONE;
    }

    // Return a list of cipher strings
    ciphersPyList = PyList_New(0);
    if (ciphersPyList == NULL)
    {
        return PyErr_NoMemory();
    }

   do
   {
        // Extract each cipher name
        PyObject *cipherPyString = NULL;
        const char *cipherName = SSL_get_cipher_list(self->ssl, priority);

        cipherPyString = PyUnicode_FromString(cipherName);
        if (cipherPyString == NULL)
        {
            Py_DECREF(ciphersPyList);
            return PyErr_NoMemory();
        }

        if (PyList_Append(ciphersPyList, cipherPyString) == -1)
        {
            Py_DECREF(ciphersPyList);
            Py_DECREF(cipherPyString);
            return NULL; // PyList_Append() sets an exception
        }
        Py_DECREF(cipherPyString);

        priority++;
    } while (SSL_get_cipher_list(self->ssl, priority) != NULL) ;

    return ciphersPyList;
}


// Used to retrieve the cipher earlier in the connection
// https://github.com/nabla-c0d3/nassl/pull/15
static const SSL_CIPHER* get_tmp_new_cipher(nassl_SSL_Object *self)
{
#ifdef LEGACY_OPENSSL
    // TODO: Rewrite this without accessing private members (for example, use get_cipher())
    if (self->ssl == NULL || self->ssl->s3 == NULL)
    {
        return NULL;
    }
    return self->ssl->s3->tmp.new_cipher;
#else
    return NULL;
#endif
}


static PyObject* nassl_SSL_get_cipher_bits(nassl_SSL_Object *self, PyObject *args)
{
    const SSL_CIPHER *cipher = get_tmp_new_cipher(self);
    int returnValue = cipher ? SSL_CIPHER_get_bits(cipher, NULL) : SSL_get_cipher_bits(self->ssl, NULL);

    return Py_BuildValue("I", returnValue);
}


static PyObject* nassl_SSL_get_cipher_name(nassl_SSL_Object *self, PyObject *args)
{
    const SSL_CIPHER *cipher = get_tmp_new_cipher(self);
    const char *cipherName = cipher ? SSL_CIPHER_get_name(cipher) : SSL_get_cipher_name(self->ssl);

    if (strcmp(cipherName, "(NONE)") == 0)
    {
        Py_RETURN_NONE;
    }

    return PyUnicode_FromString(cipherName);
}


static PyObject* nassl_SSL_get_client_CA_list(nassl_SSL_Object *self, PyObject *args)
{
    PyObject* namesPyList = NULL;
    int x509NamesNum = 0;
    int i = 0;
    STACK_OF(X509_NAME) *x509Names = NULL;

    // Return a list of X509 names
    namesPyList = PyList_New(0);
    if (namesPyList == NULL)
    {
        return PyErr_NoMemory();
    }

    x509Names = SSL_get_client_CA_list(self->ssl); // freed by SSL_free()
    x509NamesNum = sk_X509_NAME_num(x509Names);

    // Extract each X509_NAME and store their string representation
    for (i=0; i<x509NamesNum; i++)
    {
        char *nameStr = NULL;
        PyObject *namePyString = NULL;

        X509_NAME *name = sk_X509_NAME_pop(x509Names);
        if (name == NULL)
        {
            Py_DECREF(namesPyList);
            PyErr_SetString(PyExc_ValueError, "Could not extract an X509_NAME from the client CA list. Should not happen ?");
            return NULL;
        }

        // The use of X509_NAME_oneline is "is strongly discouraged in new applications"
        // But that's all we need for now
        nameStr = X509_NAME_oneline(name, NULL, 0);
        namePyString = PyUnicode_FromString(nameStr);
        if (namePyString == NULL)
        {
            Py_DECREF(namesPyList);
            return PyErr_NoMemory();
        }

        if (PyList_Append(namesPyList, namePyString) == -1)
        {
            Py_DECREF(namesPyList);
            Py_DECREF(namePyString);
            return NULL; // PyList_Append() sets an exception
        }
        Py_DECREF(namePyString);
    }
    return namesPyList;
}


static PyObject* nassl_SSL_get_verify_result(nassl_SSL_Object *self, PyObject *args)
{
    long returnValue = SSL_get_verify_result(self->ssl);
    return Py_BuildValue("l", returnValue);
}


static PyObject* nassl_SSL_renegotiate(nassl_SSL_Object *self, PyObject *args)
{
    SSL_renegotiate(self->ssl);
    Py_RETURN_NONE;
}


static PyObject* nassl_SSL_get_session(nassl_SSL_Object *self, PyObject *args)
{
    SSL_SESSION *sslSession = SSL_get1_session(self->ssl);
    if (sslSession == NULL)
    {
        Py_RETURN_NONE;
    }
    else
    {
        // Return an _nassl.SSL_SESSION object
        nassl_SSL_SESSION_Object *sslSession_PyObject;
        sslSession_PyObject = (nassl_SSL_SESSION_Object *)nassl_SSL_SESSION_Type.tp_alloc(&nassl_SSL_SESSION_Type, 0);
        if (sslSession_PyObject == NULL)
        {
            return PyErr_NoMemory();
        }

        sslSession_PyObject->sslSession = sslSession;
        return (PyObject *) sslSession_PyObject;
    }
}


static PyObject* nassl_SSL_set_session(nassl_SSL_Object *self, PyObject *args)
{
    nassl_SSL_SESSION_Object *sslSession_PyObject = NULL;
    if (!PyArg_ParseTuple(args, "O!", &nassl_SSL_SESSION_Type, &sslSession_PyObject))
    {
        return NULL;
    }

    if (SSL_set_session(self->ssl, sslSession_PyObject->sslSession) == 0)
    {
        return raise_OpenSSL_error();
    }

    Py_RETURN_NONE;
}


static PyObject* nassl_SSL_set_options(nassl_SSL_Object *self, PyObject *args)
{
    long sslOption = 0;
    if (!PyArg_ParseTuple(args, "l", &sslOption))
    {
        return NULL;
    }
    return Py_BuildValue("I", SSL_set_options(self->ssl, sslOption));
}


static PyObject* nassl_SSL_set_tlsext_status_type(nassl_SSL_Object *self, PyObject *args)
{
    int statusType = 0;
    if (!PyArg_ParseTuple(args, "I", &statusType)) {
        return NULL;
    }

    SSL_set_tlsext_status_type(self->ssl, statusType);
    Py_RETURN_NONE;
}


static PyObject* nassl_SSL_get_tlsext_status_ocsp_resp(nassl_SSL_Object *self, PyObject *args)
{
    OCSP_RESPONSE *ocspResp = NULL;
    nassl_OCSP_RESPONSE_Object *ocspResp_PyObject;
    long ocspRespLen = 0;
    const unsigned char *ocspBuf = NULL;
    STACK_OF(X509) *certChain = NULL, *certChainCpy = NULL;

    // Get the OCSP response
    ocspRespLen = SSL_get_tlsext_status_ocsp_resp(self->ssl, &ocspBuf);
    if (ocspBuf == NULL)
    {
        Py_RETURN_NONE;
    }

    // Try to parse it
    ocspResp = d2i_OCSP_RESPONSE(NULL, &ocspBuf, ocspRespLen);
    if (ocspResp == NULL)
    {
        PyErr_SetString(PyExc_ValueError, "Error parsing the OCSP response. Should not happen ?");
        return NULL;
    }

    // Get the peer's certificate chain
    certChain = SSL_get_peer_cert_chain(self->ssl); // automatically freed
    if (certChain == NULL)
    {
        PyErr_SetString(PyExc_ValueError, "Error getting the peer's certificate chain.");
        return NULL;
    }

    { // Copy each cert of the chain
        int i = 0, certNum = 0;

        certChainCpy = sk_X509_new_null();
        if (certChainCpy == NULL)
        {
            return raise_OpenSSL_error();
        }

        certNum = sk_X509_num(certChain);
        for(i=0; i<certNum; i++)
        {
            X509 *cert = sk_X509_value(certChain, i);
            sk_X509_push(certChainCpy, X509_dup(cert));
        }
    }

    // Return an _nassl.OCSP_RESPONSE object
    ocspResp_PyObject = (nassl_OCSP_RESPONSE_Object *)nassl_OCSP_RESPONSE_Type.tp_alloc(&nassl_OCSP_RESPONSE_Type, 0);
    if (ocspResp_PyObject == NULL)
    {
        return PyErr_NoMemory();
    }

    ocspResp_PyObject->ocspResp = ocspResp;
    ocspResp_PyObject->peerCertChain = certChainCpy;
    return (PyObject *) ocspResp_PyObject;
}


#ifdef LEGACY_OPENSSL
static PyObject* nassl_SSL_state_string_long(nassl_SSL_Object *self, PyObject *args)
{
    // This is only used for fixing SSLv2 connections when connecting to IIS7 (like in the 90s)
    // See SslClient.py for more information
    const char *stateString = SSL_state_string_long(self->ssl);
    return PyUnicode_FromString(stateString);
}
#endif

static PyObject* nassl_SSL_get_peer_cert_chain(nassl_SSL_Object *self, PyObject *args)
{
    STACK_OF(X509) *certChain = NULL;
    PyObject* certChainPyList = NULL;
    int certChainCount = 0, i = 0;

    // Get the peer's certificate chain
    certChain = SSL_get_peer_cert_chain(self->ssl); // automatically freed
    if (certChain == NULL)
    {
        PyErr_SetString(PyExc_ValueError, "Error getting the peer's certificate chain.");
        return NULL;
    }

    // We'll return a Python list containing each certificate
    certChainCount = sk_X509_num(certChain);
    certChainPyList = PyList_New(certChainCount);
    if (certChainPyList == NULL)
    {
        return PyErr_NoMemory();
    }

    for (i=0; i<certChainCount; i++)
    {
        nassl_X509_Object *x509_Object = NULL;
        // Copy the certificate as the cert chain is freed automatically
        X509 *cert = X509_dup(sk_X509_value(certChain, i));
        if (cert == NULL)
        {
            Py_DECREF(certChainPyList);
            PyErr_SetString(PyExc_ValueError, "Could not extract a certificate. Should not happen ?");
            return NULL;
        }

        // Store the cert in an _nassl.X509 object
        x509_Object = (nassl_X509_Object *)nassl_X509_Type.tp_alloc(&nassl_X509_Type, 0);
        if (x509_Object == NULL)
        {
            Py_DECREF(certChainPyList);
            return PyErr_NoMemory();
        }
        x509_Object->x509 = cert;

        // Add the X509 object to the final list
        PyList_SET_ITEM(certChainPyList, i,  (PyObject *)x509_Object);
    }

    return certChainPyList;
}


#ifndef LEGACY_OPENSSL
// SSL_set_ciphersuites() is only available in OpenSSL 1.1.1
static PyObject* nassl_SSL_set_ciphersuites(nassl_SSL_Object *self, PyObject *args)
{
    char *cipherList;
    if (!PyArg_ParseTuple(args, "s", &cipherList))
    {
        return NULL;
    }

    if (!SSL_set_ciphersuites(self->ssl, cipherList))
    {
        return raise_OpenSSL_error();
    }

    Py_RETURN_NONE;
}


static PyObject* nassl_SSL_get0_verified_chain(nassl_SSL_Object *self, PyObject *args)
{
    STACK_OF(X509) *verifiedCertChain = NULL;
    PyObject* certChainPyList = NULL;

    // Get the peer's certificate chain
    verifiedCertChain = SSL_get0_verified_chain(self->ssl); // automatically freed
    if (verifiedCertChain == NULL)
    {
        PyErr_SetString(PyExc_ValueError, "Error getting the peer's verified certificate chain.");
        return NULL;
    }

    // We'll return a Python list containing each certificate
    certChainPyList = stackOfX509ToPyList(verifiedCertChain);
    if (certChainPyList == NULL)
    {
        return NULL;
    }
    return certChainPyList;
}
#endif


static PyObject *nassl_SSL_get_dh_info(nassl_SSL_Object *self)
{
    // Try to get the ECDH/DH key from the connection 
    EVP_PKEY *key;
    if (!SSL_get_server_tmp_key(self->ssl, &key))
    {
        PyErr_SetString(PyExc_TypeError, "Unable to get server temporary key");
        return NULL;
    }

    int key_id = EVP_PKEY_id(key);
    if (key_id == EVP_PKEY_DH)
    {
        // If the connection uses DH

        // Common variables to store the parameters
        const BIGNUM *p, *g, *pub_key;

#ifdef LEGACY_OPENSSL
        // Get the DH params from the pkey directly in legacy OpenSSL
        DH *dh = key->pkey.dh;
        p = dh->p;
        g = dh->g;
        pub_key = dh->pub_key;
#else
        // Use the newer API for modern OpenSSL
        DH *dh = EVP_PKEY_get0_DH(key);
        DH_get0_pqg(dh, &p, NULL, &g);
        DH_get0_key(dh, &pub_key, NULL);
#endif

        // Allocate a buffer for the prime
        size_t p_buf_size = BN_num_bytes(p);
        unsigned char* p_buf = (unsigned char*) PyMem_Malloc(p_buf_size);
        if(p == NULL){
            EVP_PKEY_free(key);
            return PyErr_NoMemory();
        }

        // Allocate a buffer for the generator
        size_t g_buf_size = BN_num_bytes(g);
        unsigned char* g_buf = (unsigned char*) PyMem_Malloc(g_buf_size);
        if(g == NULL){
            PyMem_Free(p_buf);
            EVP_PKEY_free(key);
            return PyErr_NoMemory();
        }

        // Allocate a buffer for the public_key
        size_t pub_key_buf_size = BN_num_bytes(pub_key);
        unsigned char* pub_key_buf = (unsigned char*) PyMem_Malloc(pub_key_buf_size);
        if(pub_key == NULL){
            PyMem_Free(g_buf);
            PyMem_Free(p_buf);
            EVP_PKEY_free(key);
            return PyErr_NoMemory();
        }

        // Convert the prime, generator and public key from OpenSSL BIGNUM to an array of bytes 
        p_buf_size = BN_bn2bin(p, p_buf);
        g_buf_size = BN_bn2bin(g, g_buf);
        pub_key_buf_size = BN_bn2bin(pub_key, pub_key_buf);

        // Format the relevant params into a dictionary
        PyObject *return_dict = PyDict_New();
        PyDict_SetItemString(return_dict, "key_type", Py_BuildValue("I", key_id));
        PyDict_SetItemString(return_dict, "key_size", Py_BuildValue("I", EVP_PKEY_bits(key)));
        PyDict_SetItemString(return_dict, "public_key", PyByteArray_FromStringAndSize((char*) pub_key_buf, pub_key_buf_size));
        PyDict_SetItemString(return_dict, "prime", PyByteArray_FromStringAndSize((char*) p_buf, p_buf_size));
        PyDict_SetItemString(return_dict, "generator", PyByteArray_FromStringAndSize((char*) g_buf, g_buf_size));
        
        PyMem_Free(pub_key_buf);
        PyMem_Free(g_buf);
        PyMem_Free(p_buf);
        EVP_PKEY_free(key);
        return return_dict;
    }
    else if (key_id == EVP_PKEY_EC)
    {
        // If the connection uses ECDH

        // Get the EC key
        EC_KEY *ec = EVP_PKEY_get1_EC_KEY(key);
        if(ec == NULL){
            EVP_PKEY_free(key);
            PyErr_SetString(PyExc_TypeError, "Unable to get server EC key");
            return NULL;
        }

        // Get the group from the key
        const EC_GROUP *ec_group = EC_KEY_get0_group(ec);

        // Get the curve numeric ID from the group
        int nid = EC_GROUP_get_curve_name(ec_group);

        // Get the public point from the key and extract the x and y coords
        const EC_POINT *point = EC_KEY_get0_public_key(ec);

        BN_CTX *ctx = BN_CTX_new();
        if(ctx == NULL){
            EC_KEY_free(ec);
            EVP_PKEY_free(key);
            return PyErr_NoMemory();
        }

        // Allocate a buffer for the public point
        size_t pub_key_buf_size = EC_POINT_point2oct(ec_group, point, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
        unsigned char* pub_key_buf = (unsigned char*) PyMem_Malloc(pub_key_buf_size);
        if(pub_key_buf == NULL){
            BN_CTX_free(ctx);
            EC_KEY_free(ec);
            EVP_PKEY_free(key);
            return PyErr_NoMemory();
        }

        // Convert the point to an array of bytes
        pub_key_buf_size = EC_POINT_point2oct(ec_group, point, POINT_CONVERSION_UNCOMPRESSED, pub_key_buf, pub_key_buf_size, ctx);
        BN_CTX_free(ctx);
        
        BIGNUM *x = BN_new();
        BIGNUM *y = BN_new();

        if(x == NULL){
            PyMem_Free(pub_key_buf);
            EC_KEY_free(ec);
            EVP_PKEY_free(key);
            return PyErr_NoMemory();
        }

        if(y == NULL){
            BN_free(x);
            PyMem_Free(pub_key_buf);
            EC_KEY_free(ec);
            EVP_PKEY_free(key);
            return PyErr_NoMemory();
        }
        
        if(!EC_POINT_get_affine_coordinates_GFp(ec_group, point, x, y, NULL)){
            BN_free(y);
            BN_free(x);
            PyMem_Free(pub_key_buf);
            EC_KEY_free(ec);
            EVP_PKEY_free(key);
            PyErr_SetString(PyExc_TypeError, "Unable to get server public key coordinates");
            return NULL;
        };
        
        // Allocate a buffer for the x coordinate
        size_t x_buf_size = BN_num_bytes(x);
        unsigned char* x_buf = (unsigned char*) PyMem_Malloc(x_buf_size);
        if(x_buf == NULL){
            BN_free(y);
            BN_free(x);
            PyMem_Free(pub_key_buf);
            EC_KEY_free(ec);
            EVP_PKEY_free(key);
            return PyErr_NoMemory();
        }

        // Allocate a buffer for the y coordinate
        size_t y_buf_size = BN_num_bytes(y);
        unsigned char* y_buf = (unsigned char*) PyMem_Malloc(y_buf_size);
        if(y_buf == NULL){
            PyMem_Free(x_buf);
            BN_free(y);
            BN_free(x);
            PyMem_Free(pub_key_buf);
            EC_KEY_free(ec);
            EVP_PKEY_free(key);
            return PyErr_NoMemory();
        }

        // Convert the x and y coords to a byte array
        x_buf_size = BN_bn2bin(x, x_buf);
        y_buf_size = BN_bn2bin(y, y_buf);

        // Free resources that can be freed according to OpenSSL docs
        BN_free(y);
        BN_free(x);
        EC_KEY_free(ec);

        // Return a dictionary of relevant parameters
        PyObject *return_dict = PyDict_New();
        PyDict_SetItemString(return_dict, "key_type", Py_BuildValue("I", key_id));
        PyDict_SetItemString(return_dict, "key_size", Py_BuildValue("I", EVP_PKEY_bits(key)));
        PyDict_SetItemString(return_dict, "public_key", PyByteArray_FromStringAndSize((char*) pub_key_buf, pub_key_buf_size));
        PyDict_SetItemString(return_dict, "curve", Py_BuildValue("I", nid));
        PyDict_SetItemString(return_dict, "x", PyByteArray_FromStringAndSize((char*) x_buf, x_buf_size));
        PyDict_SetItemString(return_dict, "y", PyByteArray_FromStringAndSize((char*) y_buf, y_buf_size));

        PyMem_Free(pub_key_buf);
        PyMem_Free(x_buf);
        PyMem_Free(y_buf);
        EVP_PKEY_free(key);
        return return_dict;
    }
#ifndef LEGACY_OPENSSL
    else if(key_id == EVP_PKEY_X25519 || key_id == EVP_PKEY_X448){
        
        // If the connection uses X25519 or X448

        unsigned char* pub_key_buf = NULL;
        size_t pub_key_buf_size;

        // Get the length of the public key
        if(EVP_PKEY_get_raw_public_key(key, pub_key_buf, &pub_key_buf_size) < 0){
            EVP_PKEY_free(key);
            PyErr_SetString(PyExc_TypeError, "Unable to determine public key size");
            return NULL;
        }

        // Allocate a buffer for the public key
        pub_key_buf = (unsigned char*) PyMem_Malloc(pub_key_buf_size);
        if(pub_key_buf == NULL){
            EVP_PKEY_free(key);
            return PyErr_NoMemory();
        }

        // Get the public key
        if(EVP_PKEY_get_raw_public_key(key, pub_key_buf, &pub_key_buf_size) < 0){
            PyMem_Free(pub_key_buf);
            EVP_PKEY_free(key);
            PyErr_SetString(PyExc_TypeError, "Unable to get public key");
            return NULL;
        }

        // Return a dictionary of relevant parameters
        PyObject *return_dict = PyDict_New();
        PyDict_SetItemString(return_dict, "key_type", Py_BuildValue("I", key_id));
        PyDict_SetItemString(return_dict, "key_size", Py_BuildValue("I", EVP_PKEY_bits(key)));
        PyDict_SetItemString(return_dict, "public_key", PyByteArray_FromStringAndSize((char*) pub_key_buf, pub_key_buf_size));
        PyDict_SetItemString(return_dict, "curve", Py_BuildValue("I", key_id));

        PyMem_Free(pub_key_buf);
        EVP_PKEY_free(key);
        return return_dict;        
    }
#endif
    else
    {
        // Otherwise, raise an exception
        EVP_PKEY_free(key);
        PyErr_SetString(PyExc_TypeError, "Unsupported key exchange type");
        return NULL;
    }
}

static PyMethodDef nassl_SSL_Object_methods[] =
{
    {"set_bio", (PyCFunction)nassl_SSL_set_bio, METH_VARARGS,
     "OpenSSL's SSL_set_bio() on the internal BIO of an _nassl.BIO_Pair object."
    },
    {"set_network_bio_to_free_when_dealloc", (PyCFunction)nassl_SSL_set_network_bio_to_free_when_dealloc, METH_VARARGS,
     "Supply the network BIO paired with the internal BIO in order to have it freed when it's not needed anymore and to avoid memory leaks."
    },
    {"do_handshake", (PyCFunction)nassl_SSL_do_handshake, METH_NOARGS,
     "OpenSSL's SSL_do_handshake()."
    },
    {"set_connect_state", (PyCFunction)nassl_SSL_set_connect_state, METH_NOARGS,
     "OpenSSL's SSL_set_connect_state()."
    },
    {"set_mode", (PyCFunction)nassl_SSL_set_mode, METH_VARARGS,
     "OpenSSL's SSL_set_mode()."
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
    {"shutdown", (PyCFunction)nassl_SSL_shutdown, METH_NOARGS,
     "OpenSSL's SSL_shutdown()."
    },
    {"get_secure_renegotiation_support", (PyCFunction)nassl_SSL_get_secure_renegotiation_support, METH_NOARGS,
     "OpenSSL's SSL_get_secure_renegotiation_support()."
    },
    {"get_available_compression_methods", (PyCFunction)nassl_SSL_get_available_compression_methods, METH_NOARGS | METH_STATIC,
     "Recovers the list of all available compression methods by calling SSL_get_compression_methods()."
    },
    {"get_current_compression_method", (PyCFunction)nassl_SSL_get_current_compression_method, METH_NOARGS,
     "Recovers the name of the compression method being used by calling SSL_get_current_compression()."
    },
    {"set_verify", (PyCFunction)nassl_SSL_set_verify, METH_VARARGS,
     "OpenSSL's SSL_set_verify() with a NULL verify_callback."
    },
    {"set_tlsext_host_name", (PyCFunction)nassl_SSL_set_tlsext_host_name, METH_VARARGS,
     "OpenSSL's SSL_set_tlsext_host_name()."
    },
    {"set_cipher_list", (PyCFunction)nassl_SSL_set_cipher_list, METH_VARARGS,
     "OpenSSL's SSL_set_cipher_list()."
    },
    {"get_cipher_list", (PyCFunction)nassl_SSL_get_cipher_list, METH_NOARGS,
     "Returns a list of cipher strings using OpenSSL's SSL_get_cipher_list()."
    },
    {"get_cipher_bits", (PyCFunction)nassl_SSL_get_cipher_bits, METH_NOARGS,
     "OpenSSL's SSL_get_cipher_bits()."
    },
    {"get_cipher_name", (PyCFunction)nassl_SSL_get_cipher_name, METH_NOARGS,
     "OpenSSL's SSL_get_cipher_name()."
    },
    {"get_client_CA_list", (PyCFunction)nassl_SSL_get_client_CA_list, METH_NOARGS,
     "Returns a list of name strings using OpenSSL's SSL_get_client_CA_list() and X509_NAME_oneline()."
    },
    {"get_verify_result", (PyCFunction)nassl_SSL_get_verify_result, METH_NOARGS,
     "OpenSSL's SSL_get_verify_result()."
    },
    {"renegotiate", (PyCFunction)nassl_SSL_renegotiate, METH_NOARGS,
     "OpenSSL's SSL_renegotiate()."
    },
    {"get_session", (PyCFunction)nassl_SSL_get_session, METH_NOARGS,
     "OpenSSL's SSL_get_session(). Returns an _nassl.SSL_SESSION object."
    },
    {"set_session", (PyCFunction)nassl_SSL_set_session, METH_VARARGS,
     "OpenSSL's SSL_set_session(). Argument is an _nassl.SSL_SESSION object."
    },
    {"set_options", (PyCFunction)nassl_SSL_set_options, METH_VARARGS,
     "OpenSSL's SSL_set_options()."
    },
    {"set_tlsext_status_type", (PyCFunction)nassl_SSL_set_tlsext_status_type, METH_VARARGS,
     "OpenSSL's SSL_set_tlsext_status_type()."
    },
    {"get_tlsext_status_ocsp_resp", (PyCFunction)nassl_SSL_get_tlsext_status_ocsp_resp, METH_NOARGS,
     "OpenSSL's SSL_get_tlsext_status_ocsp_resp(). Returns an _nassl.OCSP_RESPONSE object."
    },
#ifdef LEGACY_OPENSSL
    {"state_string_long", (PyCFunction)nassl_SSL_state_string_long, METH_NOARGS,
     "OpenSSL's SSL_state_string_long()."
    },
#else
    {"write_early_data", (PyCFunction)nassl_SSL_write_early_data, METH_VARARGS,
     "OpenSSL's SSL_write_early_data()."
    },
    {"get_early_data_status", (PyCFunction)nassl_SSL_get_early_data_status, METH_VARARGS,
     "OpenSSL's SSL_get_early_data_status()."
    },
    {"get_max_early_data", (PyCFunction)nassl_SSL_get_max_early_data, METH_VARARGS,
     "OpenSSL's SSL_get_max_early_data()."
    },
    {"set_ciphersuites", (PyCFunction)nassl_SSL_set_ciphersuites, METH_VARARGS,
     "OpenSSL's SSL_set_ciphersuites()."
    },
    {"get0_verified_chain", (PyCFunction)nassl_SSL_get0_verified_chain, METH_NOARGS,
     "OpenSSL's SSL_get0_verified_chain(). Returns an array of _nassl.X509 objects."
    },
    {"set1_groups_list", (PyCFunction)nassl_SSL_set1_groups_list, METH_VARARGS,
    "OpenSSL's SSL_set1_groups_list()"
    },
#endif
    {"get_peer_cert_chain", (PyCFunction)nassl_SSL_get_peer_cert_chain, METH_NOARGS,
     "OpenSSL's SSL_get_peer_cert_chain(). Returns an array of _nassl.X509 objects."
    },
    {"get_dh_info", (PyCFunction)nassl_SSL_get_dh_info, METH_NOARGS,
     "Returns Diffie-Hellman / Elliptic curve Diffie-Hellman parameters as a dictionary."
    },
    {NULL}  // Sentinel
};
/*

static PyMemberDef nassl_SSL_Object_members[] = {
    {NULL}  // Sentinel
};
*/

static PyTypeObject nassl_SSL_Type =
{
    PyVarObject_HEAD_INIT(NULL, 0)
    "_nassl.SSL",             /*tp_name*/
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



void module_add_SSL(PyObject* m)
{
    nassl_SSL_Type.tp_new = nassl_SSL_new;
    if (PyType_Ready(&nassl_SSL_Type) < 0)
    {
        return;
    }

    Py_INCREF(&nassl_SSL_Type);
    PyModule_AddObject(m, "SSL", (PyObject *)&nassl_SSL_Type);

    // TODO: Add constants
}
