
#include "openssl_utils.h"


PyObject* generic_print_to_string(int (*openSslPrintFunction)(BIO *fp, const void *a), const void *dataStruct) {
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
