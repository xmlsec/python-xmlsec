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

// Non-zero when converted functions must run their xmlsec call on a shadow
// copy instead of directly on lxml's nodes; decided once at import, below.
static int PyXmlSec_LxmlShadowActive = 1;

// The two lxml.etree callables the shadow crossings use, resolved once at
// import and kept for the lifetime of the process.
static PyObject* PyXmlSec_LxmlEtreeToString;
static PyObject* PyXmlSec_LxmlEtreeFromString;

// Shadow-mode ID registry: maps the identity of an lxml document to the list
// of id-attribute specs registered for it (see PyXmlSec_LxmlShadowRecordId).
static PyObject* PyXmlSec_LxmlShadowIdRegistry;

int PyXmlSec_LxmlShadowIsActive(void) {
    return PyXmlSec_LxmlShadowActive;
}

int PyXmlSec_InitLxmlModule(void) {
    // By default refuse to import when lxml and xmlsec link different libxml2
    // versions: passing raw nodes between the two libraries then corrupts
    // memory (https://github.com/xmlsec/python-xmlsec/issues/283). Setting
    // PYXMLSEC_SKIP_VERSION_CHECK bypasses the guard — needed to exercise the
    // shadow-copy paths (issue #356) under a mismatch, but unsafe for every
    // operation that still hands an lxml node to xmlsec.
    int mismatch = PyXmlSec_CheckLxmlLibraryVersion() < 0;
    if (mismatch && getenv("PYXMLSEC_SKIP_VERSION_CHECK") == NULL) {
        PyXmlSec_SetLastError("lxml & xmlsec libxml2 library version mismatch");
        return -1;
    }

    // Matched versions are the long-standing status quo: xmlsec may mutate
    // lxml's nodes directly, so converted functions skip the copy (the
    // Begin/End fast path). Shadows turn on under a mismatch — or always with
    // PYXMLSEC_FORCE_SHADOW, the knob CI uses to exercise the shadow path on
    // matched libraries.
    PyXmlSec_LxmlShadowActive = mismatch || getenv("PYXMLSEC_FORCE_SHADOW") != NULL;

    PyObject* etree = PyImport_ImportModule("lxml.etree");
    if (etree == NULL) {
        return -1;
    }
    PyXmlSec_LxmlEtreeToString = PyObject_GetAttrString(etree, "tostring");
    PyXmlSec_LxmlEtreeFromString = PyObject_GetAttrString(etree, "fromstring");
    Py_DECREF(etree);
    if (PyXmlSec_LxmlEtreeToString == NULL || PyXmlSec_LxmlEtreeFromString == NULL) {
        return -1;
    }

    PyXmlSec_LxmlShadowIdRegistry = PyDict_New();
    if (PyXmlSec_LxmlShadowIdRegistry == NULL) {
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
    PyObject* args = PyTuple_Pack(1, element);
    PyObject* kwargs = Py_BuildValue("{s:O}", "with_tail", Py_False);
    if (args != NULL && kwargs != NULL) {
        result = PyObject_Call(PyXmlSec_LxmlEtreeToString, args, kwargs);
    }
    Py_XDECREF(args);
    Py_XDECREF(kwargs);
    return result;
}

// etree.fromstring(data) — the parsed nodes are owned and managed by lxml.
static PyObject* PyXmlSec_LxmlElementFromBytes(PyObject* data) {
    return PyObject_CallFunctionObjArgs(PyXmlSec_LxmlEtreeFromString, data, NULL);
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

// Paths now span whole user documents (BeginDoc), not just dsig/enc
// structures; the bound keeps the path buffers on the stack and guards
// against a pathological tree.
#define PYXMLSEC_SHADOW_MAX_DEPTH 128

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
    shadow->owned = NULL;
    shadow->doc = NULL;
    shadow->root = NULL;

    // Fast path: lxml links the same libxml2 (the import guard passed), so
    // xmlsec can mutate lxml's nodes directly and no copy is needed; End sees
    // doc == NULL and just wraps the result node.
    if (!PyXmlSec_LxmlShadowActive) {
        shadow->root = element->_c_node;
        return 0;
    }

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

    // Fast path (no copy was made): res is a node in the live lxml tree.
    if (shadow->doc == NULL) {
        if (res == NULL) {
            PyXmlSec_SetLastError(error);
            return NULL;
        }
        return (PyObject*)PyXmlSec_elementFactory(shadow->element->_doc, res);
    }

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
    PyXmlSec_LxmlShadowDiscard(shadow);
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

void PyXmlSec_LxmlShadowDiscard(PyXmlSec_LxmlShadow* shadow) {
    if (shadow->doc != NULL) {
        xmlFreeDoc(shadow->doc);
        shadow->doc = NULL;
        shadow->root = NULL;
    }
    Py_CLEAR(shadow->owned);
}

// ----------------------------------------------------------------------------
// Doc-level shadows and multi-site reflection — the rollout of the shadow
// pattern beyond templates (sign/verify, encrypt/decrypt, tree finders).
// Contracts in lxml.h.
// ----------------------------------------------------------------------------

// Walks `path` (child indices, top-first) down from `start` on a raw copy,
// counting children exactly like PyXmlSec_LxmlShadowChildIndex.
static xmlNodePtr PyXmlSec_LxmlShadowWalkNode(xmlNodePtr start, const int* path, int depth) {
    int i;
    xmlNodePtr n = start;
    for (i = 0; i < depth; ++i) {
        int idx = path[i];
        xmlNodePtr c;
        for (c = n->children; c != NULL; c = c->next) {
            if (_isElement(c) && idx-- == 0) {
                break;
            }
        }
        if (c == NULL) {
            return NULL;
        }
        n = c;
    }
    return n;
}

int PyXmlSec_LxmlShadowBeginDoc(PyXmlSec_LxmlShadow* shadow, PyXmlSec_LxmlElementPtr element, xmlNodePtr* target) {
    PyObject* cur = NULL;
    PyObject* tree = NULL;
    PyObject* bytes = NULL;
    char* data = NULL;
    Py_ssize_t size = 0;
    int path[PYXMLSEC_SHADOW_MAX_DEPTH];
    int depth = 0;
    int i;

    shadow->element = element;
    shadow->owned = NULL;
    shadow->doc = NULL;
    shadow->root = NULL;
    *target = NULL;

    if (!PyXmlSec_LxmlShadowActive) {
        shadow->root = element->_c_node;
        *target = element->_c_node;
        return 0;
    }

    // Record the element's position in its tree through lxml's own API (the
    // shadow path never walks lxml's raw nodes), ascending to the top; `cur`
    // ends as the live root element and `path` (reversed below) leads back
    // down to `element`.
    cur = (PyObject*)element;
    Py_INCREF(cur);
    for (;;) {
        PyObject* parent = PyObject_CallMethod(cur, "getparent", NULL);
        PyObject* index;
        long idx;
        if (parent == NULL) {
            goto ON_FAIL;
        }
        if (parent == Py_None) {
            Py_DECREF(parent);
            break;
        }
        index = PyObject_CallMethod(parent, "index", "O", cur);
        if (index == NULL) {
            Py_DECREF(parent);
            goto ON_FAIL;
        }
        idx = PyLong_AsLong(index);
        Py_DECREF(index);
        if (idx < 0 || depth >= PYXMLSEC_SHADOW_MAX_DEPTH) {
            Py_DECREF(parent);
            if (!PyErr_Occurred()) {
                PyErr_SetString(PyXmlSec_InternalError, "the document is nested too deeply.");
            }
            goto ON_FAIL;
        }
        path[depth++] = (int)idx;
        Py_DECREF(cur);
        cur = parent;
    }
    for (i = 0; i < depth / 2; ++i) {   // collected bottom-up; reverse
        int t = path[i];
        path[i] = path[depth - 1 - i];
        path[depth - 1 - i] = t;
    }

    // Serialize the whole tree, not just the root element, so comments/PIs
    // outside the root and the internal DTD subset (declared IDs) survive
    // into the copy.
    tree = PyObject_CallMethod(cur, "getroottree", NULL);
    if (tree == NULL) {
        goto ON_FAIL;
    }
    bytes = PyObject_CallFunctionObjArgs(PyXmlSec_LxmlEtreeToString, tree, NULL);
    Py_CLEAR(tree);
    if (bytes == NULL || PyBytes_AsStringAndSize(bytes, &data, &size) < 0) {
        goto ON_FAIL;
    }
    shadow->doc = xmlReadMemory(data, (int)size, NULL, NULL, XML_PARSE_NONET);
    Py_CLEAR(bytes);
    if (shadow->doc == NULL || (shadow->root = xmlDocGetRootElement(shadow->doc)) == NULL) {
        PyErr_SetString(PyXmlSec_InternalError, "cannot make a private copy of the document.");
        goto ON_FAIL;
    }
    PyXmlSec_LxmlShadowMark(shadow->doc->children);

    *target = PyXmlSec_LxmlShadowWalkNode(shadow->root, path, depth);
    if (*target == NULL) {
        PyErr_SetString(PyXmlSec_InternalError, "cannot locate the element in the private copy.");
        goto ON_FAIL;
    }

    // The reflect helpers map paths from the copy root, so the live element
    // they start from must be the live root.
    shadow->element = (PyXmlSec_LxmlElementPtr)cur;
    shadow->owned = cur;
    return 0;

ON_FAIL:
    Py_XDECREF(cur);
    Py_XDECREF(tree);
    Py_XDECREF(bytes);
    if (shadow->doc != NULL) {
        xmlFreeDoc(shadow->doc);
        shadow->doc = NULL;
        shadow->root = NULL;
    }
    return -1;
}

xmlDocPtr PyXmlSec_LxmlShadowBeginNewDoc(PyXmlSec_LxmlShadow* shadow, PyXmlSec_LxmlElementPtr element) {
    shadow->element = element;
    shadow->owned = NULL;
    shadow->doc = NULL;
    shadow->root = NULL;

    // Fast path: allocate the detached subtree straight in the element's own
    // document, as the raw code always did.
    if (!PyXmlSec_LxmlShadowActive) {
        return element->_doc->_c_doc;
    }
    shadow->doc = xmlNewDoc((const xmlChar*)"1.0");
    if (shadow->doc == NULL) {
        PyErr_SetString(PyXmlSec_InternalError, "cannot create a private document.");
        return NULL;
    }
    return shadow->doc;
}

PyObject* PyXmlSec_LxmlShadowEndNewDoc(PyXmlSec_LxmlShadow* shadow, xmlNodePtr res, const char* error) {
    PyObject* result = NULL;
    PyObject* bytes = NULL;
    xmlChar* dump = NULL;
    int dump_size = 0;

    if (shadow->doc == NULL) {  // fast path
        if (res == NULL) {
            PyXmlSec_SetLastError(error);
            return NULL;
        }
        return (PyObject*)PyXmlSec_elementFactory(shadow->element->_doc, res);
    }

    if (res == NULL) {
        PyXmlSec_SetLastError(error);
        goto DONE;
    }
    // The call left `res` detached inside our private doc; root it there so
    // the whole subtree serializes (and gets freed with the doc), then hand
    // the bytes to lxml. The result is a new detached element — lxml gives it
    // a document of its own, and moves it when the caller grafts it into a
    // tree, just like the raw code's detached node.
    xmlDocSetRootElement(shadow->doc, res);
    xmlDocDumpMemory(shadow->doc, &dump, &dump_size);
    if (dump == NULL || dump_size <= 0) {
        PyErr_SetString(PyXmlSec_InternalError, "cannot serialize the created node.");
        goto DONE;
    }
    bytes = PyBytes_FromStringAndSize((const char*)dump, (Py_ssize_t)dump_size);
    if (bytes != NULL) {
        result = PyXmlSec_LxmlElementFromBytes(bytes);
    }

DONE:
    PyXmlSec_LxmlShadowDiscard(shadow);
    if (dump != NULL) {
        xmlFree(dump);
    }
    Py_XDECREF(bytes);
    return result;
}

PyObject* PyXmlSec_LxmlShadowEndFind(PyXmlSec_LxmlShadow* shadow, xmlNodePtr res) {
    PyObject* result;
    int path[PYXMLSEC_SHADOW_MAX_DEPTH];
    int depth;

    if (shadow->doc == NULL) {  // fast path: res is a live node
        if (res == NULL) {
            Py_RETURN_NONE;
        }
        return (PyObject*)PyXmlSec_elementFactory(shadow->element->_doc, res);
    }
    if (res == NULL) {
        PyXmlSec_LxmlShadowDiscard(shadow);
        Py_RETURN_NONE;
    }
    depth = PyXmlSec_LxmlShadowPathTo(res, shadow->root, path);
    if (depth < 0) {
        PyErr_SetString(PyXmlSec_InternalError, "unexpected result node.");
        PyXmlSec_LxmlShadowDiscard(shadow);
        return NULL;
    }
    result = PyXmlSec_LxmlShadowWalk((PyObject*)shadow->element, path, depth);
    PyXmlSec_LxmlShadowDiscard(shadow);
    return result;
}

PyObject* PyXmlSec_LxmlShadowEndReplace(PyXmlSec_LxmlShadow* shadow, xmlNodePtr res, const char* error) {
    PyObject* copy_root = NULL;
    PyObject* copy_parent = NULL;
    PyObject* live_parent = NULL;
    PyObject* live_old = NULL;
    PyObject* new_node = NULL;
    PyObject* tmp = NULL;
    PyObject* result = NULL;
    int path[PYXMLSEC_SHADOW_MAX_DEPTH];
    int depth;
    int idx;

    // Everything except "shadow copy in play and res pre-existed, below the
    // root" is exactly the general End: the fast path mutates live nodes in
    // place, a fresh res reflects through the graft, errors raise, and for
    // res == root there is no live parent to graft into (only attributes can
    // change there, which End's sync covers).
    if (shadow->doc == NULL || res == NULL || !PYXMLSEC_SHADOW_MARKED(res) || res == shadow->root) {
        return PyXmlSec_LxmlShadowEnd(shadow, res, error);
    }

    depth = PyXmlSec_LxmlShadowPathTo(res->parent, shadow->root, path);
    if (depth < 0) {
        PyErr_SetString(PyXmlSec_InternalError, "unexpected result node.");
        goto DONE;
    }
    idx = PyXmlSec_LxmlShadowChildIndex(res);

    copy_root = PyXmlSec_LxmlShadowDumpCopy(shadow);
    if (copy_root == NULL) {
        goto DONE;
    }
    copy_parent = PyXmlSec_LxmlShadowWalk(copy_root, path, depth);
    live_parent = PyXmlSec_LxmlShadowWalk((PyObject*)shadow->element, path, depth);
    if (copy_parent == NULL || live_parent == NULL) {
        goto DONE;
    }
    new_node = PySequence_GetItem(copy_parent, idx);
    live_old = PySequence_GetItem(live_parent, idx);
    if (new_node == NULL || live_old == NULL) {
        goto DONE;
    }
    // Swap the live element for the copy's version; the tail travels with the
    // inserted node (same content — the call does not touch it).
    tmp = PyObject_CallMethod(live_parent, "remove", "O", live_old);
    if (tmp == NULL) {
        goto DONE;
    }
    Py_CLEAR(tmp);
    tmp = PyObject_CallMethod(live_parent, "insert", "iO", idx, new_node);
    if (tmp == NULL) {
        goto DONE;
    }
    Py_CLEAR(tmp);
    result = PySequence_GetItem(live_parent, idx);

DONE:
    PyXmlSec_LxmlShadowDiscard(shadow);
    Py_XDECREF(copy_root);
    Py_XDECREF(copy_parent);
    Py_XDECREF(live_parent);
    Py_XDECREF(live_old);
    Py_XDECREF(new_node);
    Py_XDECREF(tmp);
    return result;
}

xmlNodePtr PyXmlSec_LxmlShadowFindFresh(PyXmlSec_LxmlShadow* shadow) {
    xmlNodePtr n;

    if (shadow->doc == NULL) {  // fast path: End just wraps the node
        return shadow->root;
    }
    n = shadow->root->children;
    while (n != NULL) {
        if (!PYXMLSEC_SHADOW_MARKED(n)) {
            if (_isElement(n)) {
                return n;
            }
            n = n->next;  // fresh formatting text; the element follows it
            continue;
        }
        if (n->children != NULL) {
            n = n->children;
            continue;
        }
        while (n != shadow->root && n->next == NULL) {
            n = n->parent;
        }
        n = (n == shadow->root) ? NULL : n->next;
    }
    return shadow->root;  // nothing created; End takes its find-or-create path
}

PyObject* PyXmlSec_LxmlShadowDumpCopy(PyXmlSec_LxmlShadow* shadow) {
    PyObject* bytes = NULL;
    PyObject* result = NULL;
    xmlChar* dump = NULL;
    int dump_size = 0;

    xmlDocDumpMemory(shadow->doc, &dump, &dump_size);
    if (dump == NULL || dump_size <= 0) {
        PyErr_SetString(PyXmlSec_InternalError, "cannot serialize the mutated copy.");
        goto DONE;
    }
    bytes = PyBytes_FromStringAndSize((const char*)dump, (Py_ssize_t)dump_size);
    if (bytes != NULL) {
        result = PyXmlSec_LxmlElementFromBytes(bytes);
    }
DONE:
    if (dump != NULL) {
        xmlFree(dump);
    }
    Py_XDECREF(bytes);
    return result;
}

xmlNodePtr PyXmlSec_LxmlShadowImportElement(PyXmlSec_LxmlShadow* shadow, PyXmlSec_LxmlElementPtr element) {
    PyObject* bytes;
    char* data = NULL;
    Py_ssize_t size = 0;
    xmlDocPtr tdoc;
    xmlNodePtr troot;
    xmlNodePtr result = NULL;

    bytes = PyXmlSec_LxmlElementToBytes((PyObject*)element);
    if (bytes == NULL || PyBytes_AsStringAndSize(bytes, &data, &size) < 0) {
        Py_XDECREF(bytes);
        return NULL;
    }
    tdoc = xmlReadMemory(data, (int)size, NULL, NULL, XML_PARSE_NONET);
    Py_DECREF(bytes);
    if (tdoc == NULL || (troot = xmlDocGetRootElement(tdoc)) == NULL) {
        if (tdoc != NULL) {
            xmlFreeDoc(tdoc);
        }
        PyErr_SetString(PyXmlSec_InternalError, "cannot make a private copy of the element.");
        return NULL;
    }
    // Copy into the shadow doc (both trees are ours). The copy stays
    // untagged: from the reflection's point of view whatever the xmlsec call
    // grafts of it is a node "the call created".
    result = xmlDocCopyNode(troot, shadow->doc, 1);
    xmlFreeDoc(tdoc);
    if (result == NULL) {
        PyErr_SetString(PyXmlSec_InternalError, "cannot make a private copy of the element.");
    }
    return result;
}

// A mutation site found in the copy: either a fresh node to graft (elements,
// comments, PIs) or a text slot whose value changed. The reflection is
// two-phase — first every site's payload is fetched from the re-parsed copy
// while it is still in its final, untouched state, then everything is applied
// to the live tree in document order (each graft moves a node out of the
// re-parsed copy, which would invalidate later fetches, and each live insert
// makes the later, larger indices valid).
typedef struct {
    int depth;
    int path[PYXMLSEC_SHADOW_MAX_DEPTH];  // to the site's parent, from the copy root
    int idx;         // element-index of the site among its siblings
    int is_element;  // grafts `node`; otherwise the site is a text slot only
    int mirror;      // reflect the text slot before/at idx
    PyObject* node;  // phase 1: the node to graft, from the re-parsed copy
    PyObject* slot;  // phase 1: the slot's new value (str or None)
} PyXmlSec_LxmlShadowSite;

typedef struct {
    PyXmlSec_LxmlShadowSite* items;
    int count;
    int capacity;
    xmlNodePtr top;  // the copy's root element — origin of all paths
} PyXmlSec_LxmlShadowSiteList;

static int PyXmlSec_LxmlShadowSiteAppend(PyXmlSec_LxmlShadowSiteList* list, xmlNodePtr node, int is_element, int prev_elem_fresh) {
    PyXmlSec_LxmlShadowSite* site;

    if (list->count == list->capacity) {
        int capacity = list->capacity == 0 ? 8 : list->capacity * 2;
        PyXmlSec_LxmlShadowSite* items = (PyXmlSec_LxmlShadowSite*)PyMem_Realloc(list->items, capacity * sizeof(*items));
        if (items == NULL) {
            PyErr_NoMemory();
            return -1;
        }
        list->items = items;
        list->capacity = capacity;
    }
    site = &list->items[list->count];
    site->depth = PyXmlSec_LxmlShadowPathTo(node->parent, list->top, site->path);
    if (site->depth < 0) {
        PyErr_SetString(PyXmlSec_InternalError, "unexpected mutation site.");
        return -1;
    }
    site->idx = PyXmlSec_LxmlShadowChildIndex(node);
    site->is_element = is_element;
    // The slot before a fresh element travels with the preceding fresh
    // element's graft (it is that element's tail) — mirror it only otherwise.
    site->mirror = site->idx == 0 || !prev_elem_fresh;
    site->node = NULL;
    site->slot = NULL;
    ++list->count;
    return 0;
}

// Walks the pre-existing (marked) structure of the copy in document order,
// recording every fresh site. Fresh subtrees are grafted wholesale, so the
// scan does not descend into them.
static int PyXmlSec_LxmlShadowCollectSites(PyXmlSec_LxmlShadowSiteList* list, xmlNodePtr parent) {
    xmlNodePtr n;
    int last_elem_fresh = 0;

    for (n = parent->children; n != NULL; n = n->next) {
        if (PYXMLSEC_SHADOW_MARKED(n)) {
            if (_isElement(n)) {
                last_elem_fresh = 0;
                if (n->type == XML_ELEMENT_NODE && n->children != NULL
                    && PyXmlSec_LxmlShadowCollectSites(list, n) < 0) {
                    return -1;
                }
            }
            continue;
        }
        if (_isElement(n)) {
            if (PyXmlSec_LxmlShadowSiteAppend(list, n, 1, last_elem_fresh) < 0) {
                return -1;
            }
            last_elem_fresh = 1;
        } else if (n->type == XML_TEXT_NODE || n->type == XML_CDATA_SECTION_NODE) {
            // A fresh text after a fresh element is that element's tail
            // (travels with the graft); adjacent fresh texts share one slot.
            if (!last_elem_fresh
                && !(n->prev != NULL && !PYXMLSEC_SHADOW_MARKED(n->prev)
                     && (n->prev->type == XML_TEXT_NODE || n->prev->type == XML_CDATA_SECTION_NODE))
                && PyXmlSec_LxmlShadowSiteAppend(list, n, 0, 0) < 0) {
                return -1;
            }
        }
    }
    return 0;
}

int PyXmlSec_LxmlShadowReflectAll(PyXmlSec_LxmlShadow* shadow) {
    PyXmlSec_LxmlShadowSiteList list = {NULL, 0, 0, NULL};
    PyObject* copy_root = NULL;
    int i;
    int rv = -1;

    if (shadow->doc == NULL) {  // fast path: xmlsec already mutated the live tree
        Py_CLEAR(shadow->owned);
        return 0;
    }

    // Re-fetch the root: replacement operations may have swapped nodes at the
    // top. A fresh root means the call replaced the root itself — the callers
    // covering that (enc.c) reflect it explicitly and never get here.
    list.top = xmlDocGetRootElement(shadow->doc);
    if (list.top == NULL || !PYXMLSEC_SHADOW_MARKED(list.top)) {
        PyErr_SetString(PyXmlSec_InternalError, "unexpected mutation site.");
        goto DONE;
    }
    if (PyXmlSec_LxmlShadowCollectSites(&list, list.top) < 0) {
        goto DONE;
    }
    if (list.count == 0) {
        rv = 0;
        goto DONE;
    }
    copy_root = PyXmlSec_LxmlShadowDumpCopy(shadow);
    if (copy_root == NULL) {
        goto DONE;
    }

    // Phase 1: fetch every payload from the re-parsed copy (still final state).
    for (i = 0; i < list.count; ++i) {
        PyXmlSec_LxmlShadowSite* site = &list.items[i];
        PyObject* copy_parent = PyXmlSec_LxmlShadowWalk(copy_root, site->path, site->depth);
        if (copy_parent == NULL) {
            goto DONE;
        }
        if (site->is_element) {
            site->node = PySequence_GetItem(copy_parent, site->idx);
        }
        if (site->mirror) {
            if (site->idx == 0) {
                site->slot = PyObject_GetAttrString(copy_parent, "text");
            } else {
                PyObject* prev = PySequence_GetItem(copy_parent, site->idx - 1);
                if (prev != NULL) {
                    site->slot = PyObject_GetAttrString(prev, "tail");
                    Py_DECREF(prev);
                }
            }
        }
        Py_DECREF(copy_parent);
        if ((site->is_element && site->node == NULL) || (site->mirror && site->slot == NULL)) {
            goto DONE;
        }
    }

    // Phase 2: apply to the live tree in document order.
    for (i = 0; i < list.count; ++i) {
        PyXmlSec_LxmlShadowSite* site = &list.items[i];
        int failed = 0;
        PyObject* live_parent = PyXmlSec_LxmlShadowWalk((PyObject*)shadow->element, site->path, site->depth);
        if (live_parent == NULL) {
            goto DONE;
        }
        if (site->mirror) {
            if (site->idx == 0) {
                failed = PyObject_SetAttrString(live_parent, "text", site->slot) < 0;
            } else {
                PyObject* live_prev = PySequence_GetItem(live_parent, site->idx - 1);
                failed = live_prev == NULL || PyObject_SetAttrString(live_prev, "tail", site->slot) < 0;
                Py_XDECREF(live_prev);
            }
        }
        if (!failed && site->is_element) {
            PyObject* tmp = PyObject_CallMethod(live_parent, "insert", "iO", site->idx, site->node);
            failed = tmp == NULL;
            Py_XDECREF(tmp);
        }
        Py_DECREF(live_parent);
        if (failed) {
            goto DONE;
        }
    }
    rv = 0;

DONE:
    for (i = 0; i < list.count; ++i) {
        Py_XDECREF(list.items[i].node);
        Py_XDECREF(list.items[i].slot);
    }
    PyMem_Free(list.items);
    Py_XDECREF(copy_root);
    PyXmlSec_LxmlShadowDiscard(shadow);
    return rv;
}

// ----------------------------------------------------------------------------
// Shadow-mode ID registry.
//
// register_id / add_ids used to write straight into lxml's document (its ID
// hash) with our libxml2 — exactly the cross-library access the shadow
// forbids. Under the shadow they record the id-attribute specs here instead,
// and every whole-document Begin replays them onto the private copy so that
// #id references resolve during sign/verify/decrypt.
//
// The registry cannot hold strong references to lxml documents (that would
// pin whole trees forever) and lxml's classes refuse weak references, so
// entries are keyed by the _Document object's address with the underlying
// xmlDoc pointer stored alongside as a staleness check: an entry is trusted
// only while both addresses match, and is replaced when the address has been
// reused by a different document. A size cap bounds growth from dead
// documents whose addresses never get reused.
// ----------------------------------------------------------------------------

#define PYXMLSEC_SHADOW_ID_REGISTRY_CAP 4096

int PyXmlSec_LxmlShadowRecordId(PyXmlSec_LxmlElementPtr element, const char* name, const char* ns) {
    PyObject* key = NULL;
    PyObject* cdoc = NULL;
    PyObject* created = NULL;
    PyObject* spec = NULL;
    PyObject* entry;
    PyObject* specs;
    int contains;
    int result = -1;

    key = PyLong_FromVoidPtr((void*)element->_doc);
    cdoc = PyLong_FromVoidPtr((void*)element->_doc->_c_doc);
    if (key == NULL || cdoc == NULL) {
        goto DONE;
    }

    entry = PyDict_GetItem(PyXmlSec_LxmlShadowIdRegistry, key);  // borrowed
    if (entry != NULL) {
        int eq = PyObject_RichCompareBool(PyTuple_GET_ITEM(entry, 0), cdoc, Py_EQ);
        if (eq < 0) {
            goto DONE;
        }
        if (!eq) {
            entry = NULL;  // the address was reused by another document
        }
    }
    if (entry == NULL) {
        if (PyDict_Size(PyXmlSec_LxmlShadowIdRegistry) >= PYXMLSEC_SHADOW_ID_REGISTRY_CAP) {
            PyObject* k;
            PyObject* v;
            Py_ssize_t pos = 0;
            if (PyDict_Next(PyXmlSec_LxmlShadowIdRegistry, &pos, &k, &v)
                && PyDict_DelItem(PyXmlSec_LxmlShadowIdRegistry, k) < 0) {
                goto DONE;
            }
        }
        specs = PyList_New(0);
        if (specs == NULL) {
            goto DONE;
        }
        created = PyTuple_Pack(2, cdoc, specs);
        Py_DECREF(specs);
        if (created == NULL || PyDict_SetItem(PyXmlSec_LxmlShadowIdRegistry, key, created) < 0) {
            goto DONE;
        }
        entry = created;
    }

    spec = Py_BuildValue("(sz)", name, ns);
    if (spec == NULL) {
        goto DONE;
    }
    specs = PyTuple_GET_ITEM(entry, 1);
    contains = PySequence_Contains(specs, spec);
    if (contains < 0 || (!contains && PyList_Append(specs, spec) < 0)) {
        goto DONE;
    }
    result = 0;

DONE:
    Py_XDECREF(key);
    Py_XDECREF(cdoc);
    Py_XDECREF(created);
    Py_XDECREF(spec);
    return result;
}

// Registers every attribute named `name` (under `ns` when given) in the copy
// as an XML ID — a superset of the fast path's registrations (single node for
// register_id, subtree for add_ids), which is the safe direction: it mirrors
// what xmlSecAddIDs does from the root.
static void PyXmlSec_LxmlShadowApplyIdSpec(xmlDocPtr doc, xmlNodePtr n, const xmlChar* name, const xmlChar* ns) {
    for (; n != NULL; n = n->next) {
        if (n->type == XML_ELEMENT_NODE) {
            xmlAttrPtr attr = ns != NULL ? xmlHasNsProp(n, name, ns) : xmlHasProp(n, name);
            if (attr != NULL && attr->children != NULL) {
                xmlChar* value = xmlNodeListGetString(doc, attr->children, 1);
                if (value != NULL) {
                    if (xmlGetID(doc, value) == NULL) {
                        xmlAddID(NULL, doc, value, attr);
                    }
                    xmlFree(value);
                }
            }
            if (n->children != NULL) {
                PyXmlSec_LxmlShadowApplyIdSpec(doc, n->children, name, ns);
            }
        }
    }
}

int PyXmlSec_LxmlShadowReplayIds(PyXmlSec_LxmlShadow* shadow) {
    PyObject* key;
    PyObject* cdoc;
    PyObject* entry;
    PyObject* specs;
    Py_ssize_t i, n;
    int eq;

    if (shadow->doc == NULL) {  // fast path: the live document carries its own IDs
        return 0;
    }
    key = PyLong_FromVoidPtr((void*)shadow->element->_doc);
    if (key == NULL) {
        return -1;
    }
    entry = PyDict_GetItem(PyXmlSec_LxmlShadowIdRegistry, key);  // borrowed
    Py_DECREF(key);
    if (entry == NULL) {
        return 0;
    }
    cdoc = PyLong_FromVoidPtr((void*)shadow->element->_doc->_c_doc);
    if (cdoc == NULL) {
        return -1;
    }
    eq = PyObject_RichCompareBool(PyTuple_GET_ITEM(entry, 0), cdoc, Py_EQ);
    Py_DECREF(cdoc);
    if (eq < 0) {
        return -1;
    }
    if (!eq) {
        return 0;  // stale entry from a dead document at the same address
    }

    specs = PyTuple_GET_ITEM(entry, 1);
    n = PyList_GET_SIZE(specs);
    for (i = 0; i < n; ++i) {
        PyObject* spec = PyList_GET_ITEM(specs, i);
        const char* name = PyUnicode_AsUTF8(PyTuple_GET_ITEM(spec, 0));
        const char* ns = PyTuple_GET_ITEM(spec, 1) == Py_None ? NULL : PyUnicode_AsUTF8(PyTuple_GET_ITEM(spec, 1));
        if (name == NULL || (ns == NULL && PyErr_Occurred())) {
            return -1;
        }
        PyXmlSec_LxmlShadowApplyIdSpec(shadow->doc, shadow->doc->children, (const xmlChar*)name, (const xmlChar*)ns);
    }
    return 0;
}
