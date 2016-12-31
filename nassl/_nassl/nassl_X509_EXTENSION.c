
#include <Python.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "nassl_errors.h"
#include "nassl_X509_EXTENSION.h"
#include "openssl_utils.h"


// For simplicity, this class does not properly mirror OpenSSL's X509_EXTENSION_() functions

static PyObject* nassl_X509_EXTENSION_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    PyErr_SetString(PyExc_NotImplementedError, "Cannot directly create an X509_EXTENSION object. Get it from X509.get_extensions()");
    return NULL;
}


static void nassl_X509_EXTENSION_dealloc(nassl_X509_EXTENSION_Object *self)
{
    if (self->x509ext != NULL)
    {
        X509_EXTENSION_free(self->x509ext);
        self->x509ext = NULL;
    }

    self->ob_type->tp_free((PyObject*)self);
}


static PyObject* nassl_X509_EXTENSION_get_object(nassl_X509_EXTENSION_Object *self)
{
    ASN1_OBJECT *x509extObj;
    char *objTxtBuffer = NULL;
    unsigned int objTxtSize = 0;
    PyObject* res;

    x509extObj = X509_EXTENSION_get_object(self->x509ext);

    // Get the size of the text representation of the extension
    objTxtSize = OBJ_obj2txt(NULL, 0, x509extObj, 0) + 1;

    objTxtBuffer = (char *) PyMem_Malloc(objTxtSize);
    if (objTxtBuffer == NULL)
    {
        return PyErr_NoMemory();
    }

    // Extract the text representation
    OBJ_obj2txt(objTxtBuffer, objTxtSize, x509extObj, 0);
    res = PyString_FromStringAndSize(objTxtBuffer, objTxtSize - 1);
    PyMem_Free(objTxtBuffer);
    return res;
}


static PyObject* nassl_X509_EXTENSION_get_data(nassl_X509_EXTENSION_Object *self)
{
    BIO *memBio = BIO_new(BIO_s_mem());
    if (memBio == NULL)
    {
        raise_OpenSSL_error();
        return NULL;
    }

    X509V3_EXT_print(memBio, self->x509ext, X509V3_EXT_ERROR_UNKNOWN, 0);
    return bioToPyString(memBio);
}


static PyObject* nassl_X509_EXTENSION_parse_subject_alt_name(nassl_X509_EXTENSION_Object *self)
{
    PyObject *resultDict = NULL;
    int san_names_nb = 0;
    int i = 0;

    // Try to extract the names within the SAN extension
    STACK_OF(GENERAL_NAME) *san_names = X509V3_EXT_d2i(self->x509ext);
    if (san_names == NULL)
    {
        PyErr_SetString(PyExc_ValueError, "Could not extract GENERAL_NAMEs from the extension.");
        return NULL;
    }

    resultDict = PyDict_New();
    if (resultDict == NULL)
    {
        sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
        return PyErr_NoMemory();
    }

    // Extract each name within the extension
    san_names_nb = sk_GENERAL_NAME_num(san_names);
    for (i=0; i<san_names_nb; i++)
    {
        const GENERAL_NAME *gen = sk_GENERAL_NAME_value(san_names, i);
        const char *nameTypeStr = "unknown";
        PyObject *nameDataPyStr = NULL;
        PyObject* nameList = NULL;
        const char *defaultDataStr = "<unsupported>";

        // Heavily inspired from https://github.com/openssl/openssl/blob/master/crypto/x509v3/v3_alt.c
        switch (gen->type)
        {
            case GEN_OTHERNAME:
                nameTypeStr = "othername";
                nameDataPyStr = PyString_FromString(defaultDataStr);
                break;

            case GEN_X400:
                nameTypeStr = "X400Name";
                nameDataPyStr = PyString_FromString(defaultDataStr);
                break;

            case GEN_EDIPARTY:
                nameTypeStr = "EdiPartyName";
                nameDataPyStr = PyString_FromString(defaultDataStr);
                break;

            case GEN_EMAIL:
                nameTypeStr = "email";
                nameDataPyStr = PyString_FromStringAndSize((char *) gen->d.ia5->data, gen->d.ia5->length);
                break;

            case GEN_DNS:
                nameTypeStr = "DNS";
                nameDataPyStr = PyString_FromStringAndSize((char *) gen->d.ia5->data, gen->d.ia5->length);
                break;

            case GEN_URI:
                nameTypeStr = "URI";
                nameDataPyStr = PyString_FromStringAndSize((char *) gen->d.ia5->data, gen->d.ia5->length);
                break;

            case GEN_DIRNAME:
                nameTypeStr = "DirName";
                {
                    BIO *bio = BIO_new(BIO_s_mem());
                    if (bio == NULL)
                    {
                        sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
                        raise_OpenSSL_error();
                        return NULL;
                    }

                    X509_NAME_print_ex(bio, gen->d.dirn, 0, XN_FLAG_ONELINE);
                    nameDataPyStr = bioToPyString(bio);
                    BIO_free(bio);
                }
                break;

            case GEN_IPADD:
                nameTypeStr = "IP Address";
                {
                    unsigned char *p = gen->d.ip->data;
                    if (gen->d.ip->length == 4)
                    {
                        nameDataPyStr = PyString_FromFormat("%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
                    }
                    else if (gen->d.ip->length == 16)
                    {
                        int j = 0;
                        BIO *bio = BIO_new(BIO_s_mem());
                        if (bio == NULL)
                        {
                            sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
                            raise_OpenSSL_error();
                            return NULL;
                        }

                        for (j=0; j<8; j++)
                        {
                            BIO_printf(bio, ":%X", p[0] << 8 | p[1]);
                            p += 2;
                        }
                        nameDataPyStr = bioToPyString(bio);
                        BIO_free(bio);
                    }
                    else
                    {
                        nameDataPyStr = PyString_FromString("<invalid>");
                    }
                }
                break;

            case GEN_RID:
                nameTypeStr = "Registered ID";
                {
                    BIO *bio = BIO_new(BIO_s_mem());
                    if (bio == NULL)
                    {
                        sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
                        raise_OpenSSL_error();
                        return NULL;
                    }
                    i2a_ASN1_OBJECT(bio, gen->d.rid);
                    nameDataPyStr = bioToPyString(bio);
                    BIO_free(bio);

                }
                break;
        }
        // Store the entry in our result dict
        nameList = PyDict_GetItemString(resultDict, nameTypeStr);
        if (nameList == NULL)
        {
            // New entry for this type of name
            nameList = PyList_New(1);
            if (nameList == NULL)
            {
                sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
                return PyErr_NoMemory();
            }

            if ((PyList_SetItem(nameList, 0, nameDataPyStr) != 0) || (PyDict_SetItemString(resultDict, nameTypeStr, nameList) != 0))
            {
                sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
                PyErr_SetString(PyExc_RuntimeError, "Could not create name.");
                return NULL;
            }

        }
        else
        {
            // Extra entry
            if (PyList_Append(nameList, nameDataPyStr) != 0)
            {
                sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
                PyErr_SetString(PyExc_RuntimeError, "Could not append name.");
                return NULL;
            }
        }
    }
    sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
    return resultDict;
}


static PyObject* nassl_X509_EXTENSION_get_critical(nassl_X509_EXTENSION_Object *self)
{
    if (X509_EXTENSION_get_critical(self->x509ext))
    {
        Py_RETURN_TRUE;
    }
    else
    {
        Py_RETURN_FALSE;
    }
}


static PyMethodDef nassl_X509_EXTENSION_Object_methods[] =
{
        {"get_object", (PyCFunction)nassl_X509_EXTENSION_get_object, METH_NOARGS,
                "Returns a string containing the result of OpenSSL's X509_EXTENSION_get_object() and OBJ_obj2txt()."
        },
        {"get_data", (PyCFunction)nassl_X509_EXTENSION_get_data, METH_NOARGS,
                "Returns a string containing the result of OpenSSL's X509V3_EXT_print()."
        },
        {"get_critical", (PyCFunction)nassl_X509_EXTENSION_get_critical, METH_NOARGS,
                "OpenSSL's X509_EXTENSION_get_critical()."
        },
        {"parse_subject_alt_name", (PyCFunction)nassl_X509_EXTENSION_parse_subject_alt_name, METH_NOARGS,
                "Returns a dictionary with the content of the extension if it is a Subject Alternative Name extension."
        },

        {NULL}  // Sentinel
};


PyTypeObject nassl_X509_EXTENSION_Type =
{
        PyVarObject_HEAD_INIT(NULL, 0)
        "_nassl.X509_EXTENSION",             /*tp_name*/
        sizeof(nassl_X509_EXTENSION_Object),             /*tp_basicsize*/
        0,                         /*tp_itemsize*/
        (destructor)nassl_X509_EXTENSION_dealloc, /*tp_dealloc*/
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
        "X509_EXTENSION objects",           /* tp_doc */
        0,                     /* tp_traverse */
        0,                     /* tp_clear */
        0,                     /* tp_richcompare */
        0,                     /* tp_weaklistoffset */
        0,                     /* tp_iter */
        0,                     /* tp_iternext */
        nassl_X509_EXTENSION_Object_methods,             /* tp_methods */
        0,             /* tp_members */
        0,                         /* tp_getset */
        0,                         /* tp_base */
        0,                         /* tp_dict */
        0,                         /* tp_descr_get */
        0,                         /* tp_descr_set */
        0,                         /* tp_dictoffset */
        0,      /* tp_init */
        0,                         /* tp_alloc */
        nassl_X509_EXTENSION_new,                 /* tp_new */
};



void module_add_X509_EXTENSION(PyObject* m)
{
    nassl_X509_EXTENSION_Type.tp_new = nassl_X509_EXTENSION_new;
    if (PyType_Ready(&nassl_X509_EXTENSION_Type) < 0)
    {
        return;
    }

    Py_INCREF(&nassl_X509_EXTENSION_Type);
    PyModule_AddObject(m, "X509_EXTENSION", (PyObject *)&nassl_X509_EXTENSION_Type);

}

