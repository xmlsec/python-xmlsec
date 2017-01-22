// Copyright (c) 2017 Ryan Leckey
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include "common.h"
#include "utils.h"
#include "lxml.h"

#include <xmlsec/xmltree.h>

#define PYXMLSEC_TREE_DOC "Common XML utility functions"

static char PyXmlSec_TreeFindChild__doc__[] = \
    "Searches a direct child of the parent node having given name and namespace href.\n";
static PyObject* PyXmlSec_TreeFindChild(PyObject* self, PyObject *args, PyObject *kwargs) {
    static char *kwlist[] = { "parent", "name", "namespace", NULL};

    PyXmlSec_LxmlElementPtr node = NULL;
    const char* name = NULL;
    const char* ns = (const char*)xmlSecDSigNs;

    PYXMLSEC_DEBUG("tree find_child - start");
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O&s|s:find_child", kwlist,
        PyXmlSec_LxmlElementConverter, &node, &name, &ns))
    {
        goto ON_FAIL;
    }
    xmlNodePtr res;
    Py_BEGIN_ALLOW_THREADS;
    res = xmlSecFindChild(node->_c_node, XSTR(name), XSTR(ns));
    Py_END_ALLOW_THREADS;

    PYXMLSEC_DEBUG("tree find_child - ok");
    if (res == NULL) {
        Py_RETURN_NONE;
    }
    return (PyObject*)PyXmlSec_elementFactory(node->_doc, res);

ON_FAIL:
    PYXMLSEC_DEBUG("tree find_child - fail");
    return NULL;
}

static char PyXmlSec_TreeFindParent__doc__[] = \
    "Searches the ancestors axis of the node having given name and namespace href.\n";
static PyObject* PyXmlSec_TreeFindParent(PyObject* self, PyObject *args, PyObject *kwargs) {
    static char *kwlist[] = { "node", "name", "namespace", NULL};

    PyXmlSec_LxmlElementPtr node = NULL;
    const char* name = NULL;
    const char* ns = (const char*)xmlSecDSigNs;

    PYXMLSEC_DEBUG("tree find_parent - start");
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O&s|s:find_parent", kwlist,
        PyXmlSec_LxmlElementConverter, &node, &name, &ns))
    {
        goto ON_FAIL;
    }
    xmlNodePtr res;
    Py_BEGIN_ALLOW_THREADS;
    res = xmlSecFindParent(node->_c_node, XSTR(name), XSTR(ns));
    Py_END_ALLOW_THREADS;

    PYXMLSEC_DEBUG("tree find_parent - ok");
    if (res == NULL) {
        Py_RETURN_NONE;
    }
    return (PyObject*)PyXmlSec_elementFactory(node->_doc, res);

ON_FAIL:
    PYXMLSEC_DEBUG("tree find_parent - fail");
    return NULL;
}

static char PyXmlSec_TreeFindNode__doc__[] = \
    "Searches all children of the parent node having given name and namespace href.\n";
static PyObject* PyXmlSec_TreeFindNode(PyObject* self, PyObject *args, PyObject *kwargs) {
    static char *kwlist[] = { "node", "name", "namespace", NULL};

    PyXmlSec_LxmlElementPtr node = NULL;
    const char* name = NULL;
    const char* ns = (const char*)xmlSecDSigNs;

    PYXMLSEC_DEBUG("tree find_node - start");
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O&s|s:find_node", kwlist,
        PyXmlSec_LxmlElementConverter, &node, &name, &ns))
    {
        goto ON_FAIL;
    }
    xmlNodePtr res;
    Py_BEGIN_ALLOW_THREADS;
    res = xmlSecFindNode(node->_c_node, XSTR(name), XSTR(ns));
    Py_END_ALLOW_THREADS;

    PYXMLSEC_DEBUG("tree find_node - ok");
    if (res == NULL) {
        Py_RETURN_NONE;
    }
    return (PyObject*)PyXmlSec_elementFactory(node->_doc, res);

ON_FAIL:
    PYXMLSEC_DEBUG("tree find_node - fail");
    return NULL;
}

static char PyXmlSec_TreeAddIds__doc__[] = \
    "Registers *ids* as ids used below *node*. *ids* is a sequence of attribute names\n"\
    "used as XML ids in the subtree rooted at *node*.\n"\
    "A call to `addIds` may be necessary to make known which attributes contain XML ids.\n"\
    "This is the case, if a transform references an id via `XPointer` or a self document uri and\n"
    "the id inkey_data_formation is not available by other means (e.g. an associated DTD or XML schema).\n";
static PyObject* PyXmlSec_TreeAddIds(PyObject* self, PyObject *args, PyObject *kwargs) {
    static char *kwlist[] = { "node", "ids", NULL};

    PyXmlSec_LxmlElementPtr node = NULL;
    PyObject* ids = NULL;

    const xmlChar** list = NULL;

    PYXMLSEC_DEBUG("tree add_ids - start");
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O&O:add_ids", kwlist, PyXmlSec_LxmlElementConverter, &node, &ids))
    {
        goto ON_FAIL;
    }
    Py_ssize_t n = PyObject_Length(ids);
    if (n < 0) goto ON_FAIL;

    list = (const xmlChar**)xmlMalloc(sizeof(xmlChar*) * (n + 1));
    if (list == NULL) {
        PyErr_SetString(PyExc_MemoryError, "no memory");
        goto ON_FAIL;
    }

    PyObject* tmp;
    PyObject* key;
    for (Py_ssize_t i = 0; i < n; ++i) {
        key = PyLong_FromSsize_t(i);
        if (key == NULL) goto ON_FAIL;
        tmp = PyObject_GetItem(ids, key);
        Py_DECREF(key);
        if (tmp == NULL) goto ON_FAIL;
        list[i] = XSTR(PyString_AsString(tmp));
        Py_DECREF(tmp);
        if (list[i] == NULL) goto ON_FAIL;
    }
    list[n] = NULL;

    Py_BEGIN_ALLOW_THREADS;
    xmlSecAddIDs(node->_doc->_c_doc, node->_c_node, list);
    Py_END_ALLOW_THREADS;

    PyMem_Free(list);

    PYXMLSEC_DEBUG("tree add_ids - ok");
    Py_RETURN_NONE;
ON_FAIL:
    PYXMLSEC_DEBUG("tree add_ids - fail");
    xmlFree(list);
    return NULL;
}

static PyMethodDef PyXmlSec_TreeMethods[] = {
    {
        "find_child",
        (PyCFunction)PyXmlSec_TreeFindChild,
        METH_VARARGS|METH_KEYWORDS,
        PyXmlSec_TreeFindChild__doc__,
    },
    {
        "find_parent",
        (PyCFunction)PyXmlSec_TreeFindParent,
        METH_VARARGS|METH_KEYWORDS,
        PyXmlSec_TreeFindParent__doc__,
    },
    {
        "find_node",
        (PyCFunction)PyXmlSec_TreeFindNode,
        METH_VARARGS|METH_KEYWORDS,
        PyXmlSec_TreeFindNode__doc__,
    },
    {
        "add_ids",
        (PyCFunction)PyXmlSec_TreeAddIds,
        METH_VARARGS|METH_KEYWORDS,
        PyXmlSec_TreeAddIds__doc__,
    },
    {NULL, NULL} /* sentinel */
};

#ifdef PY3K
static PyModuleDef PyXmlSec_TreeModule =
{
    PyModuleDef_HEAD_INIT,
    STRINGIFY(MODULE_NAME) ".tree",
    PYXMLSEC_TREE_DOC,
    -1,
    PyXmlSec_TreeMethods,     /* m_methods */
    NULL,                     /* m_slots */
    NULL,                     /* m_traverse */
    NULL,                     /* m_clear */
    NULL,                     /* m_free */
};
#endif  // PY3K


int PyXmlSec_TreeModule_Init(PyObject* package) {
#ifdef PY3K
    PyObject* tree = PyModule_Create(&PyXmlSec_TreeModule);
#else
    PyObject* tree = Py_InitModule3(STRINGIFY(MODULE_NAME) ".template", PyXmlSec_TreeMethods, PYXMLSEC_TREE_DOC);
    Py_XINCREF(tree);
#endif

    if (!tree) goto ON_FAIL;

    PYXMLSEC_DEBUGF("%", tree);
    if (PyModule_AddObject(package, "tree", tree) < 0) goto ON_FAIL;

    return 0;
ON_FAIL:
    Py_XDECREF(tree);
    return -1;
}
