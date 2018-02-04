
#include <Python.h>

#include <openssl/ssl.h>

#include "nassl_errors.h"
#include "nassl_SSL_SESSION.h"
#include "openssl_utils.h"


static PyObject* nassl_SSL_SESSION_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    PyErr_SetString(PyExc_NotImplementedError, "Cannot directly create an SSL_SESSION object. Get it from SSL.get_session()");
    return NULL;
}


static void nassl_SSL_SESSION_dealloc(nassl_SSL_SESSION_Object *self)
{
 	if (self->sslSession != NULL)
 	{
  		SSL_SESSION_free(self->sslSession);
  		self->sslSession = NULL;
  	}
    Py_TYPE(self)->tp_free((PyObject*)self);
}


static PyObject* nassl_SSL_SESSION_as_text(nassl_SSL_SESSION_Object *self)
{
    return generic_print_to_string((int (*)(BIO *, const void *)) &SSL_SESSION_print, self->sslSession);
}

#ifndef LEGACY_OPENSSL
static PyObject* nassl_SSL_SESSION_set_max_early_data(nassl_SSL_SESSION_Object *self, PyObject *args)
{
    int max_early_data = 0;

    if (!PyArg_ParseTuple(args, "I", &max_early_data))
    {
        return NULL;
    }

    if (self->sslSession != NULL) {
        SSL_SESSION_set_max_early_data(self->sslSession, max_early_data);
    }

    return Py_BuildValue("I", max_early_data);
}

static PyObject* nassl_SSL_SESSION_get_max_early_data(nassl_SSL_SESSION_Object *self, PyObject *args)
{
    int returnValue = 0;

    if (self->sslSession != NULL) {
        returnValue = SSL_SESSION_get_max_early_data(self->sslSession);
    }

    return Py_BuildValue("I", returnValue);
}
#endif

static PyMethodDef nassl_SSL_SESSION_Object_methods[] =
{
    {"as_text", (PyCFunction)nassl_SSL_SESSION_as_text, METH_NOARGS,
     "OpenSSL's SSL_SESSION_print()."
    },
#ifndef LEGACY_OPENSSL
    {"set_max_early_data", (PyCFunction)nassl_SSL_SESSION_set_max_early_data, METH_VARARGS,
     "OpenSSL's SSL_SESSION_set_max_early_data()."
    },
    {"get_max_early_data", (PyCFunction)nassl_SSL_SESSION_get_max_early_data, METH_NOARGS,
     "OpenSSL's SSL_SESSION_get_max_early_data()."
    },
#endif
    {NULL}  // Sentinel
};
/*

static PyMemberDef nassl_SSL_SESSION_Object_members[] = {
    {NULL}  // Sentinel
};
*/

PyTypeObject nassl_SSL_SESSION_Type =
{
    PyVarObject_HEAD_INIT(NULL, 0)
    "_nassl.SSL_SESSION",             /*tp_name*/
    sizeof(nassl_SSL_SESSION_Object),             /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)nassl_SSL_SESSION_dealloc, /*tp_dealloc*/
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
    "SSL_SESSION objects",           /* tp_doc */
    0,                     /* tp_traverse */
    0,                     /* tp_clear */
    0,                     /* tp_richcompare */
    0,                     /* tp_weaklistoffset */
    0,                     /* tp_iter */
    0,                     /* tp_iternext */
    nassl_SSL_SESSION_Object_methods,             /* tp_methods */
    0,             /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    0,      /* tp_init */
    0,                         /* tp_alloc */
    nassl_SSL_SESSION_new,                 /* tp_new */
};



void module_add_SSL_SESSION(PyObject* m)
{
	nassl_SSL_SESSION_Type.tp_new = nassl_SSL_SESSION_new;
	if (PyType_Ready(&nassl_SSL_SESSION_Type) < 0)
	{
    	return;
	}

    Py_INCREF(&nassl_SSL_SESSION_Type);
    PyModule_AddObject(m, "SSL_SESSION", (PyObject *)&nassl_SSL_SESSION_Type);
}

