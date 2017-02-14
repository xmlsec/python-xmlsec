// Copyright (c) 2017 Ryan Leckey
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef __PYXMLSEC_PLATFORM_H__
#define __PYXMLSEC_PLATFORM_H__

#define PY_SSIZE_T_CLEAN 1

#include <xmlsec/version.h>
#include <Python.h>

#ifdef MS_WIN32
#include <windows.h>
#endif /* MS_WIN32 */

#define XMLSEC_VERSION_HEX ((XMLSEC_VERSION_MAJOR << 8) | (XMLSEC_VERSION_MINOR << 4) | (XMLSEC_VERSION_SUBMINOR))

#define XSTR(c) (const xmlChar*)(c)

#if PY_VERSION_HEX < 0x02050000 && !defined(PY_SSIZE_T_MIN)
typedef int Py_ssize_t;
#define PY_SSIZE_T_MAX INT_MAX
#define PY_SSIZE_T_MIN INT_MIN
#endif

#if PY_MAJOR_VERSION >= 3
#define PY3K 1
#define PyString_FromStringAndSize PyUnicode_FromStringAndSize

#define PyString_FromString PyUnicode_FromString

#define PyString_AsString PyUnicode_AsUTF8
#define PyString_AsUtf8AndSize PyUnicode_AsUTF8AndSize

#define PyCreateDummyObject PyModule_New

#define PyString_FSConverter PyUnicode_FSConverter
#else // PY3K

#define PyBytes_Check PyString_Check
#define PyBytes_FromStringAndSize PyString_FromStringAndSize

#define PyBytes_AsString PyString_AsString
#define PyBytes_AsStringAndSize PyString_AsStringAndSize

static inline char* PyString_AsUtf8AndSize(PyObject *obj, Py_ssize_t* length) {
    char* buffer = NULL;
    return (PyString_AsStringAndSize(obj, &buffer, length) < 0) ? (char*)(0) : buffer;
}

static inline PyObject* PyCreateDummyObject(const char* name) {
    PyObject* tmp = Py_InitModule(name, NULL);
    Py_INCREF(tmp);
    return tmp;
}

static inline int PyString_FSConverter(PyObject* o, PyObject** p) {
    if (o == NULL) {
        return 0;
    }

    Py_INCREF(o);
    *p = o;
    return 1;
}

#endif // PYTHON3

static inline char* PyBytes_AsStringAndSize2(PyObject *obj, Py_ssize_t* length) {
    char* buffer = NULL;
    return ((PyBytes_AsStringAndSize(obj, &buffer, length) < 0) ? (char*)(0) : buffer);
}

#endif //__PYXMLSEC_PLATFORM_H__
