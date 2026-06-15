// Copyright (c) 2017 Ryan Leckey
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include "common.h"
#include "lxml.h"
#include "exception.h"

#include <etree_defs.h>
#include <etree_api.h>

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/dict.h>

#define XMLSEC_EXTRACT_VERSION(x, y) ((x / (y)) % 100)

#define XMLSEC_EXTRACT_MAJOR(x) XMLSEC_EXTRACT_VERSION(x, 100 * 100)
#define XMLSEC_EXTRACT_MINOR(x) XMLSEC_EXTRACT_VERSION(x, 100)
#define XMLSEC_EXTRACT_PATCH(x) XMLSEC_EXTRACT_VERSION(x, 1)

static long PyXmlSec_GetLibXmlVersionLong() {
    return PyOS_strtol(xmlParserVersion, NULL, 10);
}
long PyXmlSec_GetLibXmlVersionMajor() {
    return XMLSEC_EXTRACT_MAJOR(PyXmlSec_GetLibXmlVersionLong());
}
long PyXmlSec_GetLibXmlVersionMinor() {
    return XMLSEC_EXTRACT_MINOR(PyXmlSec_GetLibXmlVersionLong());
}
long PyXmlSec_GetLibXmlVersionPatch() {
    return XMLSEC_EXTRACT_PATCH(PyXmlSec_GetLibXmlVersionLong());
}

long PyXmlSec_GetLibXmlCompiledVersionMajor() {
    return XMLSEC_EXTRACT_MAJOR(LIBXML_VERSION);
}
long PyXmlSec_GetLibXmlCompiledVersionMinor() {
    return XMLSEC_EXTRACT_MINOR(LIBXML_VERSION);
}
long PyXmlSec_GetLibXmlCompiledVersionPatch() {
    return XMLSEC_EXTRACT_PATCH(LIBXML_VERSION);
}

static int PyXmlSec_CheckLxmlLibraryVersion(void) {
    // Make sure that the version of libxml2 lxml is using is the same as the one we are using. Because
    // we pass trees between the two libraries, we need to make sure that they are using the same version
    // of libxml2, or we could run into difficult to debug segfaults.
    // See: https://github.com/xmlsec/python-xmlsec/issues/283

    PyObject* lxml = NULL;
    PyObject* version = NULL;

    // Default to failure
    int result = -1;

    lxml = PyImport_ImportModule("lxml.etree");
    if (lxml == NULL) {
        goto FINALIZE;
    }
    version = PyObject_GetAttrString(lxml, "LIBXML_VERSION");
    if (version == NULL) {
        goto FINALIZE;
    }
    if (!PyTuple_Check(version) || PyTuple_Size(version) < 2) {
        goto FINALIZE;
    }

    PyObject* major = PyTuple_GetItem(version, 0);
    if (major == NULL) {
        goto FINALIZE;
    }
    PyObject* minor = PyTuple_GetItem(version, 1);
    if (minor == NULL) {
        goto FINALIZE;
    }

    if (!PyLong_Check(major) || !PyLong_Check(minor)) {
        goto FINALIZE;
    }

    if (PyLong_AsLong(major) != PyXmlSec_GetLibXmlVersionMajor() || PyLong_AsLong(minor) != PyXmlSec_GetLibXmlVersionMinor()) {
        goto FINALIZE;
    }

    result = 0;

FINALIZE:
    // Clear any errors that may have occurred
    PyErr_Clear();

    // Cleanup our references, and return the result
    Py_XDECREF(lxml);
    Py_XDECREF(version);

    return result;
}

int PyXmlSec_InitLxmlModule(void) {
    // By default we refuse to import when lxml and xmlsec link different libxml2
    // versions, because passing raw nodes between the two libraries can segfault
    // (https://github.com/xmlsec/python-xmlsec/issues/283). Setting
    // PYXMLSEC_SKIP_VERSION_CHECK opts out of that guard: it is needed to exercise
    // the serialized, ABI-decoupled code paths (issue #356) under a mismatch, but
    // it is unsafe for any operation that still hands an lxml node to xmlsec.
    if (PyXmlSec_CheckLxmlLibraryVersion() < 0 && getenv("PYXMLSEC_SKIP_VERSION_CHECK") == NULL) {
        PyXmlSec_SetLastError("lxml & xmlsec libxml2 library version mismatch");
        return -1;
    }

    return import_lxml__etree();
}

int PyXmlSec_IsElement(xmlNodePtr xnode) {
    return _isElement(xnode);
}

PyXmlSec_LxmlElementPtr PyXmlSec_elementFactory(PyXmlSec_LxmlDocumentPtr doc, xmlNodePtr xnode) {
    return elementFactory(doc, xnode);
}


int PyXmlSec_LxmlElementConverter(PyObject* o, PyXmlSec_LxmlElementPtr* p) {
    PyXmlSec_LxmlElementPtr node = rootNodeOrRaise(o);
    if (node == NULL) {
        return 0;
    }
    *p = node;
    // rootNodeOrRaise - increments ref-count, so need to compensate this.
    Py_DECREF(node);
    return 1;
}

PyObject* PyXmlSec_LxmlElementToBytes(PyObject* element) {
    // Calls lxml.etree.tostring(element, with_tail=False).
    // Input:  `element` - an lxml _Element (borrowed reference).
    // Output: a new reference to a Python bytes object with the element's
    //         serialized XML, or NULL with an exception set on failure.
    // Example: an lxml element <Reference URI="#foo"/> returns the bytes
    //          b'<Reference URI="#foo"/>'.
    // Done entirely through lxml's Python API so that the tree is walked by the
    // same libxml2 that allocated it. `with_tail=False` keeps the output to the
    // element itself, which xmlsec's libxml2 then re-parses from bytes.
    PyObject* etree = PyImport_ImportModule("lxml.etree");
    if (etree == NULL) {
        return NULL;
    }
    PyObject* tostring = PyObject_GetAttrString(etree, "tostring");
    Py_DECREF(etree);
    if (tostring == NULL) {
        return NULL;
    }

    PyObject* result = NULL;
    PyObject* args = PyTuple_Pack(1, element);
    PyObject* kwargs = Py_BuildValue("{s:O}", "with_tail", Py_False);
    if (args != NULL && kwargs != NULL) {
        result = PyObject_Call(tostring, args, kwargs);
    }
    Py_XDECREF(args);
    Py_XDECREF(kwargs);
    Py_DECREF(tostring);
    return result;
}

PyObject* PyXmlSec_LxmlElementFromBytes(PyObject* data) {
    PyObject* etree = PyImport_ImportModule("lxml.etree");
    if (etree == NULL) {
        return NULL;
    }
    PyObject* result = PyObject_CallMethod(etree, "fromstring", "O", data);
    Py_DECREF(etree);
    return result;
}

// dsig templates never nest anywhere near this deep; the bound just keeps the
// path buffer on the stack and guards against a pathological tree.
#define PYXMLSEC_MAX_TEMPLATE_DEPTH 64

PyObject* PyXmlSec_LxmlAddChildViaXmlSec(
    PyXmlSec_LxmlElementPtr element, PyXmlSec_LxmlXmlSecOp op, void* ctx, const char* error) {

    PyObject* serialized = NULL;
    PyObject* result_bytes = NULL;
    PyObject* new_tree = NULL;
    PyObject* new_node = NULL;
    PyObject* parent = NULL;
    PyObject* appended = NULL;

    xmlDocPtr doc = NULL;
    xmlNodePtr res = NULL;
    xmlChar* dump = NULL;
    int dump_size = 0;

    char* xml_data = NULL;
    Py_ssize_t xml_size = 0;

    // Element-only child indices from the copy's root down to the node `op`
    // produced, stored root-first; `depth` is its length (>= 1 on success).
    int path[PYXMLSEC_MAX_TEMPLATE_DEPTH];
    int depth = 0;
    int overflow = 0;
    int i;

    serialized = PyXmlSec_LxmlElementToBytes((PyObject*)element);
    if (serialized == NULL || PyBytes_AsStringAndSize(serialized, &xml_data, &xml_size) < 0) {
        goto ON_FAIL;
    }

    Py_BEGIN_ALLOW_THREADS;
    doc = xmlReadMemory(xml_data, (int)xml_size, NULL, NULL, XML_PARSE_NONET);
    if (doc != NULL) {
        res = op(xmlDocGetRootElement(doc), ctx);
        if (res != NULL) {
            // Record res's element-index path up to the root: first measure the
            // depth, then walk again filling `path` from the back so it ends up
            // ordered root-first.
            xmlNodePtr cur = res;
            int d = 0;
            while (cur->parent != NULL && cur->parent->type == XML_ELEMENT_NODE) {
                ++d;
                cur = cur->parent;
            }
            if (d < 1 || d > PYXMLSEC_MAX_TEMPLATE_DEPTH) {
                overflow = 1;
            } else {
                depth = d;
                for (cur = res; d > 0; cur = cur->parent) {
                    int idx = 0;
                    xmlNodePtr s;
                    for (s = cur->prev; s != NULL; s = s->prev) {
                        if (s->type == XML_ELEMENT_NODE) { ++idx; }
                    }
                    path[--d] = idx;
                }
                // Dump the whole mutated document, not just res: the surrounding
                // context carries the new node's ancestor-declared namespace and
                // the formatting whitespace xmlsec appends after it, so lxml
                // reconstructs both on re-parse — no manual reconcile/tail fix-up.
                xmlDocDumpMemory(doc, &dump, &dump_size);
            }
        }
    }
    Py_END_ALLOW_THREADS;

    if (doc == NULL) {
        PyErr_SetString(PyXmlSec_InternalError, "cannot parse serialized template.");
        goto ON_FAIL;
    }
    if (res == NULL) {
        PyXmlSec_SetLastError(error);
        goto ON_FAIL;
    }
    if (overflow) {
        PyErr_SetString(PyXmlSec_InternalError, "unexpected template structure.");
        goto ON_FAIL;
    }
    if (dump == NULL || dump_size <= 0) {
        PyErr_SetString(PyXmlSec_InternalError, "cannot serialize result.");
        goto ON_FAIL;
    }

    // Re-parse the whole result with lxml so the nodes are lxml-owned.
    result_bytes = PyBytes_FromStringAndSize((const char*)dump, (Py_ssize_t)dump_size);
    if (result_bytes == NULL) {
        goto ON_FAIL;
    }
    new_tree = PyXmlSec_LxmlElementFromBytes(result_bytes);
    if (new_tree == NULL) {
        goto ON_FAIL;
    }

    // Locate the produced node in the re-parsed tree by walking the recorded path.
    new_node = new_tree;
    Py_INCREF(new_node);
    for (i = 0; i < depth; ++i) {
        PyObject* child = PySequence_GetItem(new_node, path[i]);
        Py_DECREF(new_node);
        new_node = child;
        if (new_node == NULL) {
            goto ON_FAIL;
        }
    }

    // Walk the same path (minus the final step) in the *original* tree to reach
    // the parent the new node belongs under, then graft it onto the live tree.
    parent = (PyObject*)element;
    Py_INCREF(parent);
    for (i = 0; i < depth - 1; ++i) {
        PyObject* child = PySequence_GetItem(parent, path[i]);
        Py_DECREF(parent);
        parent = child;
        if (parent == NULL) {
            goto ON_FAIL;
        }
    }
    appended = PyObject_CallMethod(parent, "append", "O", new_node);
    if (appended == NULL) {
        goto ON_FAIL;
    }

    xmlFreeDoc(doc);
    xmlFree(dump);
    Py_DECREF(serialized);
    Py_DECREF(result_bytes);
    Py_DECREF(new_tree);
    Py_DECREF(parent);
    Py_DECREF(appended);
    return new_node;

ON_FAIL:
    if (doc != NULL) { xmlFreeDoc(doc); }
    if (dump != NULL) { xmlFree(dump); }
    Py_XDECREF(serialized);
    Py_XDECREF(result_bytes);
    Py_XDECREF(new_tree);
    Py_XDECREF(new_node);
    Py_XDECREF(parent);
    Py_XDECREF(appended);
    return NULL;
}
