
#include <Python.h>

#include <openssl/ssl.h>

#include "nassl_BIO.h"
#include "nassl_errors.h"


static PyObject* nassl_BIO_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    nassl_BIO_Object *self;
    BIO *sBio;

    self = (nassl_BIO_Object *)type->tp_alloc(type, 0);
    if (self == NULL)
    {
        return NULL;
    }
    self->bio = NULL;

    if (!PyArg_ParseTuple(args, ""))
    {
        Py_DECREF(self);
        return NULL;
    }
    // Only support for BIO pairs for now
    sBio = BIO_new(BIO_s_bio());
    if (sBio == NULL)
    {
        raise_OpenSSL_error();
        Py_DECREF(self);
        return NULL;
    }

    self->bio = sBio;
    return (PyObject *)self;
}


static void nassl_BIO_dealloc(nassl_BIO_Object *self)
{
    if (self->bio != NULL)
    {
        BIO_free(self->bio);
        self->bio = NULL;
    }
    self->ob_type->tp_free((PyObject*)self);
}


static PyObject* nassl_BIO_make_bio_pair(PyObject *nullPtr, PyObject *args)
{
    nassl_BIO_Object *bio1_Object, *bio2_Object = NULL;
    if (!PyArg_ParseTuple(args, "O!O!", &nassl_BIO_Type, &bio1_Object, &nassl_BIO_Type, &bio2_Object))
    {
        return NULL;
    }
    (void)BIO_make_bio_pair(bio1_Object->bio, bio2_Object->bio);
    Py_RETURN_NONE;
}


static PyObject* nassl_BIO_read(nassl_BIO_Object *self, PyObject *args)
{
    char *readBuffer;
    PyObject *res = NULL;

    unsigned int readSize;
    if (!PyArg_ParseTuple(args, "I", &readSize))
    {
        return NULL;
    }

    readBuffer = (char *) PyMem_Malloc(readSize);
    if (readBuffer == NULL)
    {
        return PyErr_NoMemory();
    }

    if (BIO_read(self->bio, readBuffer, readSize) > 0)
    {
        res = PyString_FromStringAndSize(readBuffer, readSize);
    }
    else
    {
        PyErr_SetString(PyExc_IOError, "BIO_read() failed.");
        return NULL;
    }

    PyMem_Free(readBuffer);
    return res;
}


static PyObject* nassl_BIO_pending(nassl_BIO_Object *self, PyObject *args)
{
    size_t returnValue = BIO_ctrl_pending(self->bio);
    return Py_BuildValue("I", returnValue);
}


static PyObject* nassl_BIO_write(nassl_BIO_Object *self, PyObject *args)
{
    PyObject *res = NULL;
    unsigned int writeSize;
    int returnValue;
    char *writeBuffer;
    if (!PyArg_ParseTuple(args, "t#", &writeBuffer, &writeSize))
    {
        return NULL;
    }

    returnValue = BIO_write(self->bio, writeBuffer, writeSize);
    if (returnValue > 0)
    {
        // Write OK
        res = Py_BuildValue("I", returnValue);
    }
    else
    {
        // Write failed
        // TODO: Error handling
        PyErr_SetString(PyExc_IOError, "BIO_write() failed");
        return NULL;
    }
    return res;
}


static PyMethodDef nassl_BIO_Object_methods[] =
{
    {"read", (PyCFunction)nassl_BIO_read, METH_VARARGS,
     "OpenSSL's BIO_read()."
    },
    {"pending", (PyCFunction)nassl_BIO_pending, METH_NOARGS,
     "OpenSSL's BIO_ctrl_pending()."
    },
    {"write", (PyCFunction)nassl_BIO_write, METH_VARARGS,
     "OpenSSL's BIO_write()."
    },
    {"make_bio_pair", (PyCFunction)nassl_BIO_make_bio_pair, METH_VARARGS | METH_STATIC,
     "OpenSSL's BIO_make_bio_pair()."
    },
    {NULL}  // Sentinel
};


PyTypeObject nassl_BIO_Type =
{
    PyVarObject_HEAD_INIT(NULL, 0)
    "_nassl.BIO",             /*tp_name*/
    sizeof(nassl_BIO_Object),             /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)nassl_BIO_dealloc, /*tp_dealloc*/
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
    "BIO objects",           /* tp_doc */
    0,                     /* tp_traverse */
    0,                     /* tp_clear */
    0,                     /* tp_richcompare */
    0,                     /* tp_weaklistoffset */
    0,                     /* tp_iter */
    0,                     /* tp_iternext */
    nassl_BIO_Object_methods,             /* tp_methods */
    0,             /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    0,      /* tp_init */
    0,                         /* tp_alloc */
    nassl_BIO_new,                 /* tp_new */
};



void module_add_BIO(PyObject* m)
{
	nassl_BIO_Type.tp_new = nassl_BIO_new;
	if (PyType_Ready(&nassl_BIO_Type) < 0)
    	return;

    Py_INCREF(&nassl_BIO_Type);
    PyModule_AddObject(m, "BIO", (PyObject *)&nassl_BIO_Type);
}

