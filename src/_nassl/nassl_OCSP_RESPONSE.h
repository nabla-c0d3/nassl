#pragma once

typedef struct {
    PyObject_HEAD
    OCSP_RESPONSE *ocspResp; // OpenSSL OCSP_RESPONSE C struct
    STACK_OF(X509) *peerCertChain; // Certificate chain to help verify
} nassl_OCSP_RESPONSE_Object;

// Type needs to be accessible to nassl_SSL.c
extern PyTypeObject nassl_OCSP_RESPONSE_Type;

void module_add_OCSP_RESPONSE(PyObject* m);
