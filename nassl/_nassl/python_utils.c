#define PY_SSIZE_T_CLEAN
#include <Python.h>

// Utility function to parse a file path the right way
void *PyArg_ParseFilePath(PyObject *args, char **filePathOut)
{
    PyObject *pyFilePath = NULL;
    if (!PyArg_ParseTuple(args, "O&", PyUnicode_FSConverter, &pyFilePath))
    {
        return NULL;
    }
    *filePathOut = PyBytes_AsString(pyFilePath);
    if (filePathOut == NULL)
    {
        PyErr_SetString(PyExc_ValueError, "Could not extract the file path");
        return NULL;
    }
    return filePathOut;
}