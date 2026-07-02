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
    // By default refuse to import when lxml and xmlsec link different libxml2
    // versions: passing raw nodes between the two libraries then corrupts
    // memory (https://github.com/xmlsec/python-xmlsec/issues/283). Setting
    // PYXMLSEC_SKIP_VERSION_CHECK bypasses the guard — needed to exercise the
    // shadow-copy paths (issue #356) under a mismatch, but unsafe for every
    // operation that still hands an lxml node to xmlsec.
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

// ----------------------------------------------------------------------------
// Shadow copies (issue #356) — see lxml.h for the contract.
//
// Both crossings go through serialized bytes: lxml's own etree.tostring /
// etree.fromstring on its side, xmlReadMemory / xmlDocDumpMemory on ours.
// End dumps the *whole* mutated copy, not just the new node: the surrounding
// markup carries the ancestor-declared namespaces and the "\n" formatting
// siblings xmlsec emits, so the reflected result stays byte-identical to the
// old raw-pointer code without any manual namespace or whitespace fix-up.
// ----------------------------------------------------------------------------

// etree.tostring(element, with_tail=False) — lxml's own libxml2 walks the
// tree; with_tail keeps the serialization to the element itself.
static PyObject* PyXmlSec_LxmlElementToBytes(PyObject* element) {
    PyObject* result = NULL;
    PyObject* args = NULL;
    PyObject* kwargs = NULL;
    PyObject* tostring = NULL;
    PyObject* etree = PyImport_ImportModule("lxml.etree");
    if (etree == NULL) {
        return NULL;
    }
    tostring = PyObject_GetAttrString(etree, "tostring");
    Py_DECREF(etree);
    if (tostring == NULL) {
        return NULL;
    }
    args = PyTuple_Pack(1, element);
    kwargs = Py_BuildValue("{s:O}", "with_tail", Py_False);
    if (args != NULL && kwargs != NULL) {
        result = PyObject_Call(tostring, args, kwargs);
    }
    Py_XDECREF(args);
    Py_XDECREF(kwargs);
    Py_DECREF(tostring);
    return result;
}

// etree.fromstring(data) — the parsed nodes are owned and managed by lxml.
static PyObject* PyXmlSec_LxmlElementFromBytes(PyObject* data) {
    PyObject* result;
    PyObject* etree = PyImport_ImportModule("lxml.etree");
    if (etree == NULL) {
        return NULL;
    }
    result = PyObject_CallMethod(etree, "fromstring", "O", data);
    Py_DECREF(etree);
    return result;
}

// Nodes that exist before the xmlsec call are tagged through the libxml2
// _private field (never serialized, never touched by the parser or xmlsec);
// whatever is untagged after the call is new.
static const char PyXmlSec_LxmlShadowMarker = 0;
#define PYXMLSEC_SHADOW_MARKED(n) ((n)->_private == (void*)&PyXmlSec_LxmlShadowMarker)

static void PyXmlSec_LxmlShadowMark(xmlNodePtr node) {
    for (; node != NULL; node = node->next) {
        node->_private = (void*)&PyXmlSec_LxmlShadowMarker;
        if (node->children != NULL) {
            PyXmlSec_LxmlShadowMark(node->children);
        }
    }
}

// dsig/enc structures never nest anywhere near this deep; the bound just keeps
// the path buffers on the stack and guards against a pathological tree.
#define PYXMLSEC_SHADOW_MAX_DEPTH 64

// Index of node among its preceding siblings, counting only the node types
// lxml exposes as children (elements, comments, PIs, entity refs), so indices
// computed here line up with lxml's __getitem__ / insert.
static int PyXmlSec_LxmlShadowChildIndex(xmlNodePtr node) {
    int idx = 0;
    xmlNodePtr s;
    for (s = node->prev; s != NULL; s = s->prev) {
        if (_isElement(s)) {
            ++idx;
        }
    }
    return idx;
}

// Records the child indices leading from `top` down to `node` into `path`
// (ordered top-first) and returns the number of steps, or -1 when node is not
// under top or lies too deep. Both trees involved are byte-for-byte copies of
// each other, so a path recorded in one resolves in the other.
static int PyXmlSec_LxmlShadowPathTo(xmlNodePtr node, xmlNodePtr top, int* path) {
    int depth = 0;
    int d;
    xmlNodePtr n = node;
    while (n != top) {
        if (n->parent == NULL || depth >= PYXMLSEC_SHADOW_MAX_DEPTH) {
            return -1;
        }
        ++depth;
        n = n->parent;
    }
    for (n = node, d = depth; d > 0; n = n->parent) {
        path[--d] = PyXmlSec_LxmlShadowChildIndex(n);
    }
    return depth;
}

// Walks `path` (child indices) down from `start`. Returns a new reference.
static PyObject* PyXmlSec_LxmlShadowWalk(PyObject* start, const int* path, int depth) {
    int i;
    PyObject* cur = start;
    Py_INCREF(cur);
    for (i = 0; i < depth; ++i) {
        PyObject* child = PySequence_GetItem(cur, path[i]);
        Py_DECREF(cur);
        if (child == NULL) {
            return NULL;
        }
        cur = child;
    }
    return cur;
}

// Copies the attributes of `src` (a node in the shadow copy) onto the live
// lxml element `dst`: find-or-create calls may set attributes (e.g. Id) on a
// node that already existed, and that is then the only change to reflect.
static int PyXmlSec_LxmlShadowSyncAttributes(xmlNodePtr src, PyObject* dst) {
    xmlAttrPtr attr;
    for (attr = src->properties; attr != NULL; attr = attr->next) {
        PyObject* r = NULL;
        xmlChar* value = xmlGetNsProp(src, attr->name, attr->ns != NULL ? attr->ns->href : NULL);
        if (value == NULL) {
            continue;
        }
        if (attr->ns != NULL && attr->ns->href != NULL) {
            // lxml takes namespaced attribute names in Clark notation.
            PyObject* key = PyUnicode_FromFormat("{%s}%s", (const char*)attr->ns->href, (const char*)attr->name);
            if (key != NULL) {
                r = PyObject_CallMethod(dst, "set", "Os", key, (const char*)value);
                Py_DECREF(key);
            }
        } else {
            r = PyObject_CallMethod(dst, "set", "ss", (const char*)attr->name, (const char*)value);
        }
        xmlFree(value);
        if (r == NULL) {
            return -1;
        }
        Py_DECREF(r);
    }
    return 0;
}

int PyXmlSec_LxmlShadowBegin(PyXmlSec_LxmlShadow* shadow, PyXmlSec_LxmlElementPtr element) {
    PyObject* bytes;
    char* data = NULL;
    Py_ssize_t size = 0;

    shadow->element = element;
    shadow->doc = NULL;
    shadow->root = NULL;

    bytes = PyXmlSec_LxmlElementToBytes((PyObject*)element);
    if (bytes == NULL || PyBytes_AsStringAndSize(bytes, &data, &size) < 0) {
        Py_XDECREF(bytes);
        return -1;
    }
    shadow->doc = xmlReadMemory(data, (int)size, NULL, NULL, XML_PARSE_NONET);
    Py_DECREF(bytes);
    if (shadow->doc == NULL || (shadow->root = xmlDocGetRootElement(shadow->doc)) == NULL) {
        if (shadow->doc != NULL) {
            xmlFreeDoc(shadow->doc);
            shadow->doc = NULL;
        }
        PyErr_SetString(PyXmlSec_InternalError, "cannot make a private copy of the element.");
        return -1;
    }
    PyXmlSec_LxmlShadowMark(shadow->doc->children);
    return 0;
}

PyObject* PyXmlSec_LxmlShadowEnd(PyXmlSec_LxmlShadow* shadow, xmlNodePtr res, const char* error) {
    PyObject* result = NULL;
    PyObject* bytes = NULL;
    PyObject* copy_root = NULL;
    PyObject* copy_parent = NULL;
    PyObject* live_parent = NULL;
    PyObject* new_node = NULL;
    PyObject* tmp = NULL;

    xmlNodePtr fresh = NULL;  // topmost node the xmlsec call created, if any
    xmlNodePtr n;
    xmlChar* dump = NULL;
    int dump_size = 0;

    int path[PYXMLSEC_SHADOW_MAX_DEPTH];
    int rel[PYXMLSEC_SHADOW_MAX_DEPTH];
    int depth, rel_depth, insert_idx;

    if (res == NULL) {
        PyXmlSec_SetLastError(error);
        goto DONE;
    }

    // Everything the xmlsec call created is unmarked; walk up from res to find
    // the topmost new node (stays NULL when res already existed before the call).
    for (n = res; n != shadow->root && !PYXMLSEC_SHADOW_MARKED(n); n = n->parent) {
        if (n->parent == NULL) {
            PyErr_SetString(PyXmlSec_InternalError, "unexpected result node.");
            goto DONE;
        }
        fresh = n;
    }

    if (fresh == NULL) {
        // Find-or-create found: the tree did not grow, so the result is the
        // live lxml element in the same position (plus any attributes set).
        depth = PyXmlSec_LxmlShadowPathTo(res, shadow->root, path);
        if (depth < 0) {
            PyErr_SetString(PyXmlSec_InternalError, "unexpected result node.");
            goto DONE;
        }
        result = PyXmlSec_LxmlShadowWalk((PyObject*)shadow->element, path, depth);
        if (result != NULL && PyXmlSec_LxmlShadowSyncAttributes(res, result) < 0) {
            Py_CLEAR(result);
        }
        goto DONE;
    }

    depth = PyXmlSec_LxmlShadowPathTo(fresh->parent, shadow->root, path);
    rel_depth = PyXmlSec_LxmlShadowPathTo(res, fresh, rel);
    if (depth < 0 || rel_depth < 0) {
        PyErr_SetString(PyXmlSec_InternalError, "unexpected result node.");
        goto DONE;
    }
    insert_idx = PyXmlSec_LxmlShadowChildIndex(fresh);

    xmlDocDumpMemory(shadow->doc, &dump, &dump_size);
    if (dump == NULL || dump_size <= 0) {
        PyErr_SetString(PyXmlSec_InternalError, "cannot serialize the mutated copy.");
        goto DONE;
    }
    bytes = PyBytes_FromStringAndSize((const char*)dump, (Py_ssize_t)dump_size);
    if (bytes == NULL) {
        goto DONE;
    }
    copy_root = PyXmlSec_LxmlElementFromBytes(bytes);
    if (copy_root == NULL) {
        goto DONE;
    }
    copy_parent = PyXmlSec_LxmlShadowWalk(copy_root, path, depth);
    live_parent = PyXmlSec_LxmlShadowWalk((PyObject*)shadow->element, path, depth);
    if (copy_parent == NULL || live_parent == NULL) {
        goto DONE;
    }
    new_node = PySequence_GetItem(copy_parent, insert_idx);
    if (new_node == NULL) {
        goto DONE;
    }

    // Move the new node into the live tree at the position the xmlsec call
    // chose; lxml carries the node's tail along and reconciles namespaces.
    tmp = PyObject_CallMethod(live_parent, "insert", "iO", insert_idx, new_node);
    if (tmp == NULL) {
        goto DONE;
    }
    Py_CLEAR(tmp);

    // xmlsec may also have put a "\n" *before* the new node — the parent's
    // text when it is the first child, the previous sibling's tail otherwise;
    // mirror that too (a no-op when nothing changed there).
    if (insert_idx == 0) {
        tmp = PyObject_GetAttrString(copy_parent, "text");
        if (tmp == NULL || PyObject_SetAttrString(live_parent, "text", tmp) < 0) {
            goto DONE;
        }
        Py_CLEAR(tmp);
    } else {
        PyObject* prev_tail = NULL;
        PyObject* copy_prev = PySequence_GetItem(copy_parent, insert_idx - 1);
        PyObject* live_prev = PySequence_GetItem(live_parent, insert_idx - 1);
        int failed = (copy_prev == NULL || live_prev == NULL
            || (prev_tail = PyObject_GetAttrString(copy_prev, "tail")) == NULL
            || PyObject_SetAttrString(live_prev, "tail", prev_tail) < 0);
        Py_XDECREF(copy_prev);
        Py_XDECREF(live_prev);
        Py_XDECREF(prev_tail);
        if (failed) {
            goto DONE;
        }
    }

    // res may sit below the topmost new node (e.g. the new <Transform> inside
    // a freshly created <Transforms>); descend to it in the grafted subtree.
    result = PyXmlSec_LxmlShadowWalk(new_node, rel, rel_depth);

DONE:
    if (shadow->doc != NULL) {
        xmlFreeDoc(shadow->doc);
        shadow->doc = NULL;
        shadow->root = NULL;
    }
    if (dump != NULL) {
        xmlFree(dump);
    }
    Py_XDECREF(bytes);
    Py_XDECREF(copy_root);
    Py_XDECREF(copy_parent);
    Py_XDECREF(live_parent);
    Py_XDECREF(new_node);
    Py_XDECREF(tmp);
    return result;
}
