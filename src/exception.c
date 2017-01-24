// Copyright (c) 2017 Ryan Leckey
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include "common.h"
#include "exception.h"

#include <xmlsec/xmlsec.h>
#include <xmlsec/errors.h>

#include <pythread.h>

// default error class
PyObject* PyXmlSec_Error;
PyObject* PyXmlSec_InternalError;
PyObject* PyXmlSec_VerificationError;

static int PyXmlSec_LastErrorKey = 0;

// saves new error in TLS and returns previous
static PyObject* PyXmlSec_ExchangeLastError(PyObject* e) {
    if (!PyXmlSec_LastErrorKey) {
        return NULL;
    }

    void* v = PyThread_get_key_value(PyXmlSec_LastErrorKey);
    Py_XINCREF(e);
    PyThread_set_key_value(PyXmlSec_LastErrorKey, (void*)e);
    return (PyObject*)v;
}


// xmlsec library error callback
static void PyXmlSec_ErrorCallback(const char* file, int line, const char* func, const char* errorObject, const char* errorSubject, int reason, const char* msg) {
    if (!PyXmlSec_LastErrorKey) {
        return;
    }

    PYXMLSEC_DEBUG("new xmlsec error");
    PyObject* py_code = NULL;
    PyObject* py_msg = NULL;
    PyObject* py_file = NULL;
    PyObject* py_line = NULL;
    PyObject* py_func = NULL;
    PyObject* py_error_object = NULL;
    PyObject* py_error_subject = NULL;
    PyObject* exc = NULL;

    PyGILState_STATE gstate;
    gstate = PyGILState_Ensure();

    if ((py_code = PyLong_FromLong(reason)) == NULL) goto ON_FAIL;
    if ((py_msg = PyString_FromString(msg != NULL ? msg : "-")) == NULL) goto ON_FAIL;
    if ((py_file = PyString_FromString(file != NULL ? file : "-")) == NULL) goto ON_FAIL;
    if ((py_line = PyLong_FromLong(line)) == NULL) goto ON_FAIL;
    if ((py_func = PyString_FromString(func != NULL ? func : "-")) == NULL) goto ON_FAIL;
    if ((py_error_object = PyString_FromString(errorObject != NULL ? errorObject: "-")) == NULL) goto ON_FAIL;
    if ((py_error_subject = PyString_FromString(errorSubject != NULL ? errorSubject: "-")) == NULL) goto ON_FAIL;


    if ((exc = PyObject_CallFunctionObjArgs(PyXmlSec_Error, py_code, py_msg, NULL)) == NULL) goto ON_FAIL;

    PyObject_SetAttrString(exc, "code", py_code);
    PyObject_SetAttrString(exc, "message", py_msg);
    PyObject_SetAttrString(exc, "file", py_file);
    PyObject_SetAttrString(exc, "line", py_line);
    PyObject_SetAttrString(exc, "func", py_func);
    PyObject_SetAttrString(exc, "object", py_error_object);
    PyObject_SetAttrString(exc, "subject", py_error_subject);

    Py_XDECREF(PyXmlSec_ExchangeLastError(exc));
ON_FAIL:
    Py_XDECREF(py_code);
    Py_XDECREF(py_msg);
    Py_XDECREF(py_file);
    Py_XDECREF(py_error_object);
    Py_XDECREF(py_error_subject);
    Py_XDECREF(exc);
    PyGILState_Release(gstate);
}

// pops the last error which was occured in current thread
static PyObject* PyXmlSec_GetLastError(void) {
    return PyXmlSec_ExchangeLastError(NULL);
}

void PyXmlSec_SetLastError2(PyObject* type, const char* what) {
    PyObject* last = PyXmlSec_GetLastError();
    if (last == NULL) {
        PYXMLSEC_DEBUG("WARNING: no xmlsec error");
        last = PyObject_CallFunction(PyXmlSec_InternalError, "is", (int)-1, what);
        if (last == NULL) {
            return;
        }
    }
    PyObject* whatObj = PyString_FromString(what);
    if (whatObj != NULL) {
        PyObject_SetAttrString(last, "what", whatObj);
        Py_DECREF(whatObj);
    }
    PyErr_SetObject(type, last);
}

void PyXmlSec_SetLastError(const char* what) {
    PyXmlSec_SetLastError2(PyXmlSec_Error, what);
}

void PyXmlSec_ClearError(void) {
    Py_XDECREF(PyXmlSec_ExchangeLastError(NULL));
}

// initializes errors module
int PyXmlSec_ExceptionsModule_Init(PyObject* package) {
    PyXmlSec_Error = NULL;
    PyXmlSec_InternalError = NULL;
    PyXmlSec_VerificationError = NULL;

    if ((PyXmlSec_Error = PyErr_NewExceptionWithDoc(
            STRINGIFY(MODULE_NAME) ".Error",  "The common exception class.", PyExc_Exception, 0)) == NULL) goto ON_FAIL;

    if ((PyXmlSec_InternalError = PyErr_NewExceptionWithDoc(
            STRINGIFY(MODULE_NAME) ".InternalError",  "The internal exception class.", PyXmlSec_Error, 0)) == NULL) goto ON_FAIL;

    if ((PyXmlSec_VerificationError = PyErr_NewExceptionWithDoc(
            STRINGIFY(MODULE_NAME) ".VerificationError",  "The verification exception class.", PyXmlSec_Error, 0)) == NULL) goto ON_FAIL;

    if (PyModule_AddObject(package, "Error", PyXmlSec_Error) < 0) goto ON_FAIL;
    if (PyModule_AddObject(package, "InternalError", PyXmlSec_InternalError) < 0) goto ON_FAIL;
    if (PyModule_AddObject(package, "VerificationError", PyXmlSec_VerificationError) < 0) goto ON_FAIL;

    PyXmlSec_LastErrorKey = PyThread_create_key();
    xmlSecErrorsSetCallback(&PyXmlSec_ErrorCallback);

    return 0;

ON_FAIL:
    Py_XDECREF(PyXmlSec_Error);
    Py_XDECREF(PyXmlSec_InternalError);
    Py_XDECREF(PyXmlSec_VerificationError);
    return -1;
}
