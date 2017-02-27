
#include <Python.h>

// Utility function to parse a file path the right way
void *PyArg_ParseFilePath(PyObject *args, char **filePathOut)
{
#if PY_MAJOR_VERSION >= 3
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
#else
    if (!PyArg_ParseTuple(args, "s", filePathOut))
    {
        return NULL;
    }
#endif
    return filePathOut;
}