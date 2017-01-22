// Copyright (c) 2017 Ryan Leckey
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include "utils.h"

// get string from pyobject
const char* PyXmlSec_GetAsString(PyObject* s) {
    if (PyString_Check(s)) {
        return PyString_AsString(s);
    }

    if (PyBytes_Check(s)) {
        return PyBytes_AsString(s);
    }
    PyErr_SetString(PyExc_TypeError, "one of bytes or strings expected.");
    return NULL;
}

// get string and size from pyobject
const char* PyXmlSec_GetAsStringAndSize(PyObject* s, Py_ssize_t* size) {
    if PyString_Check(s) {
        return PyString_AsUtf8AndSize(s, size);
    }

    if (PyBytes_Check(s)) {
        return PyBytes_AsStringAndSize2(s, size);
    }

    PyErr_SetString(PyExc_TypeError, "one of bytes or strings expected.");
    return NULL;
}
