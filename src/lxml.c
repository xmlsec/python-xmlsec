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

// The lxml.etree callables the shadow crossings use, resolved once at import
// and kept for the lifetime of the process.
static PyObject* PyXmlSec_LxmlEtreeToString;
static PyObject* PyXmlSec_LxmlEtreeFromString;
static PyObject* PyXmlSec_LxmlEtreeParser;

// Shadow-mode ID registry: maps the identity of an lxml document to the list
// of id-attribute specs registered for it (see PyXmlSec_LxmlShadowRecordId).
static PyObject* PyXmlSec_LxmlShadowIdRegistry;

int PyXmlSec_LxmlShadowIsActive(void) {
    return PyXmlSec_LxmlShadowActive;
}

// etree.XMLParser(huge_tree=True), the parser for lxml's side of the reflect
// crossing. huge_tree lifts libxml2's 10 MB text-node limit, which lxml's
// default parser keeps, so a CipherValue above it (large encrypt_binary
// payloads) or a document the user parsed with huge_tree still reflects. It
// is safe here: what gets parsed is this extension's own dump of a tree lxml
// has already parsed.
static PyObject* PyXmlSec_LxmlNewParser(PyObject* etree) {
    PyObject* result = NULL;
    PyObject* cls = PyObject_GetAttrString(etree, "XMLParser");
    PyObject* args = PyTuple_New(0);
    PyObject* kwargs = Py_BuildValue("{s:O}", "huge_tree", Py_True);
    if (cls != NULL && args != NULL && kwargs != NULL) {
        result = PyObject_Call(cls, args, kwargs);
    }
    Py_XDECREF(cls);
    Py_XDECREF(args);
    Py_XDECREF(kwargs);
    return result;
}

int PyXmlSec_InitLxmlModule(void) {
    // By default refuse to import when lxml and xmlsec link different libxml2
    // versions: passing raw nodes between the two libraries then corrupts
    // memory (https://github.com/xmlsec/python-xmlsec/issues/283). Setting
    // PYXMLSEC_SKIP_VERSION_CHECK bypasses the guard — needed to exercise the
    // shadow-copy paths (issue #356) under a mismatch.
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
    PyXmlSec_LxmlEtreeParser = PyXmlSec_LxmlNewParser(etree);
    Py_DECREF(etree);
    if (PyXmlSec_LxmlEtreeToString == NULL || PyXmlSec_LxmlEtreeFromString == NULL || PyXmlSec_LxmlEtreeParser == NULL) {
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
// Begin tags every node of the copy through the libxml2 _private field, so
// that after the xmlsec call whatever is untagged is what the call created;
// the reflection then grafts exactly those nodes (and the text slots the
// call filled) into the live lxml tree, addressed by child-index paths that
// resolve identically in both trees.
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

// etree.fromstring(data, parser) — the parsed nodes are owned and managed by lxml.
static PyObject* PyXmlSec_LxmlElementFromBytes(PyObject* data) {
    return PyObject_CallFunctionObjArgs(PyXmlSec_LxmlEtreeFromString, data, PyXmlSec_LxmlEtreeParser, NULL);
}

// Our side of the crossing. NONET as always; HUGE lifts the 10 MB text-node
// and nesting limits so that nothing lxml accepted — or a CipherValue xmlsec
// is about to produce — is refused here. The bytes are lxml's own dump of an
// already-parsed tree, so the relaxed limits add no attack surface.
#define PYXMLSEC_SHADOW_PARSE_OPTIONS (XML_PARSE_NONET | XML_PARSE_HUGE)

// Parses `bytes` into a private document with a root element, or returns
// NULL with an exception set (`error` for parse failures).
static xmlDocPtr PyXmlSec_LxmlShadowParse(PyObject* bytes, const char* error) {
    char* data = NULL;
    Py_ssize_t size = 0;
    xmlDocPtr doc;

    if (PyBytes_AsStringAndSize(bytes, &data, &size) < 0) {
        return NULL;
    }
    doc = xmlReadMemory(data, (int)size, NULL, NULL, PYXMLSEC_SHADOW_PARSE_OPTIONS);
    if (doc == NULL || xmlDocGetRootElement(doc) == NULL) {
        if (doc != NULL) {
            xmlFreeDoc(doc);
        }
        PyErr_SetString(PyXmlSec_InternalError, error);
        return NULL;
    }
    return doc;
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

// Paths span whole user documents (BeginDoc). 256 is libxml2's default
// nesting limit, so any tree a default lxml parser accepted fits; deeper
// (huge_tree) documents fail cleanly instead of overrunning the buffers.
#define PYXMLSEC_SHADOW_MAX_DEPTH 256

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

// Walks `path` (child indices) down from `start`, an lxml element. Returns a
// new reference.
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

// The same walk on a raw copy, counting children exactly like ChildIndex.
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

// Serializes the copy in its current state and re-parses it with lxml,
// returning the root element of that detached parse (new reference). The
// *whole* copy is dumped, not just the changed nodes: the surrounding markup
// carries the ancestor-declared namespaces and the "\n" formatting siblings
// xmlsec emits, so whatever gets grafted from the re-parse stays
// byte-identical to the raw-pointer code without any manual namespace or
// whitespace fix-up.
static PyObject* PyXmlSec_LxmlShadowDumpCopy(PyXmlSec_LxmlShadow* shadow) {
    PyObject* bytes = NULL;
    PyObject* result = NULL;
    xmlChar* dump = NULL;
    int dump_size = 0;

    xmlDocDumpMemory(shadow->doc, &dump, &dump_size);
    if (dump == NULL || dump_size <= 0) {
        PyErr_SetString(PyXmlSec_InternalError, "cannot serialize the private copy.");
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

// Copies the attributes of `src` (a node in the copy) onto the live lxml
// element `dst`, touching only the ones that differ: find-or-create calls may
// set attributes (e.g. Id) on a node that already existed.
static int PyXmlSec_LxmlShadowSyncAttributes(xmlNodePtr src, PyObject* dst) {
    xmlAttrPtr attr;
    for (attr = src->properties; attr != NULL; attr = attr->next) {
        PyObject* key = NULL;
        PyObject* val = NULL;
        PyObject* cur = NULL;
        int same = -1;
        xmlChar* value = xmlGetNsProp(src, attr->name, attr->ns != NULL ? attr->ns->href : NULL);
        if (value == NULL) {
            continue;
        }
        if (attr->ns != NULL && attr->ns->href != NULL) {
            // lxml takes namespaced attribute names in Clark notation.
            key = PyUnicode_FromFormat("{%s}%s", (const char*)attr->ns->href, (const char*)attr->name);
        } else {
            key = PyUnicode_FromString((const char*)attr->name);
        }
        val = PyUnicode_FromString((const char*)value);
        xmlFree(value);
        if (key != NULL && val != NULL) {
            cur = PyObject_CallMethod(dst, "get", "O", key);
            if (cur != NULL) {
                same = PyObject_RichCompareBool(cur, val, Py_EQ);
            }
        }
        if (same == 0) {
            PyObject* r = PyObject_CallMethod(dst, "set", "OO", key, val);
            same = r != NULL ? 1 : -1;
            Py_XDECREF(r);
        }
        Py_XDECREF(key);
        Py_XDECREF(val);
        Py_XDECREF(cur);
        if (same < 0) {
            return -1;
        }
    }
    return 0;
}

int PyXmlSec_LxmlShadowBegin(PyXmlSec_LxmlShadow* shadow, PyXmlSec_LxmlElementPtr element) {
    PyObject* bytes;

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
    if (bytes == NULL) {
        return -1;
    }
    shadow->doc = PyXmlSec_LxmlShadowParse(bytes, "cannot make a private copy of the element.");
    Py_DECREF(bytes);
    if (shadow->doc == NULL) {
        return -1;
    }
    shadow->root = xmlDocGetRootElement(shadow->doc);
    PyXmlSec_LxmlShadowMark(shadow->doc->children);
    return 0;
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

void PyXmlSec_LxmlShadowDiscard(PyXmlSec_LxmlShadow* shadow) {
    if (shadow->doc != NULL) {
        xmlFreeDoc(shadow->doc);
        shadow->doc = NULL;
        shadow->root = NULL;
    }
    Py_CLEAR(shadow->owned);
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

// Replays the specs recorded for the shadow's live document onto the copy.
static int PyXmlSec_LxmlShadowReplayIds(PyXmlSec_LxmlShadow* shadow) {
    PyObject* key;
    PyObject* cdoc;
    PyObject* entry;
    PyObject* specs;
    Py_ssize_t i, n;
    int eq;

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

int PyXmlSec_LxmlShadowBeginDoc(PyXmlSec_LxmlShadow* shadow, PyXmlSec_LxmlElementPtr element, xmlNodePtr* target) {
    PyObject* cur = NULL;
    PyObject* tree = NULL;
    PyObject* bytes = NULL;
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
    if (bytes == NULL) {
        goto ON_FAIL;
    }
    shadow->doc = PyXmlSec_LxmlShadowParse(bytes, "cannot make a private copy of the document.");
    Py_CLEAR(bytes);
    if (shadow->doc == NULL) {
        goto ON_FAIL;
    }
    shadow->root = xmlDocGetRootElement(shadow->doc);
    PyXmlSec_LxmlShadowMark(shadow->doc->children);

    *target = PyXmlSec_LxmlShadowWalkNode(shadow->root, path, depth);
    if (*target == NULL) {
        PyErr_SetString(PyXmlSec_InternalError, "cannot locate the element in the private copy.");
        goto ON_FAIL;
    }

    // The End functions map paths from the copy root, so the live element
    // they start from must be the live root.
    shadow->element = (PyXmlSec_LxmlElementPtr)cur;
    shadow->owned = cur;
    cur = NULL;

    // The registered IDs live in lxml's document, which the copy knows
    // nothing about; replay them so that #id references resolve.
    if (PyXmlSec_LxmlShadowReplayIds(shadow) < 0) {
        goto ON_FAIL;
    }
    return 0;

ON_FAIL:
    Py_XDECREF(cur);
    Py_XDECREF(tree);
    Py_XDECREF(bytes);
    PyXmlSec_LxmlShadowDiscard(shadow);
    *target = NULL;
    return -1;
}

// ----------------------------------------------------------------------------
// The reflection: everything the xmlsec call did to the copy, applied to the
// live tree through lxml's Python API.
//
// Two kinds of site are recorded while walking the pre-existing (marked)
// structure of the copy in document order:
//
//   graft — a fresh node (element, comment, PI) to insert at its child
//           index. Fresh subtrees are grafted wholesale; the scan never
//           descends into them.
//   sync  — a marked parent that gained any fresh node (element or text)
//           gets its text slots (its .text and each child's .tail) copied
//           over from the re-parsed copy. That covers everything xmlsec does
//           to text: the "\n" formatting around a new node, values filled
//           into empty elements (DigestValue), and content it removed
//           (encrypt Type=Content) — a removal leaves no fresh node behind,
//           so only a wholesale sync can see it.
//
// The reflection is two-phase: first every site's payload is fetched from
// the re-parsed copy while it is still in its final, untouched state, then
// everything is applied to the live tree in document order (each graft moves
// a node out of the re-parsed copy, which would invalidate later fetches,
// and each live insert makes the later, larger indices valid; a parent's
// sync is recorded after its grafts, so it runs once they are in place).
// ----------------------------------------------------------------------------

enum { PYXMLSEC_SHADOW_SITE_GRAFT, PYXMLSEC_SHADOW_SITE_SYNC };

typedef struct {
    int kind;
    int depth;
    int path[PYXMLSEC_SHADOW_MAX_DEPTH];  // graft: to the fresh node's parent; sync: to the parent itself
    int idx;                              // graft: child index of the fresh node
    PyObject* value;                      // phase 1: the node to graft, or the [text, tail, ...] list to sync
} PyXmlSec_LxmlShadowSite;

typedef struct {
    PyXmlSec_LxmlShadowSite* items;
    int count;
    int capacity;
    xmlNodePtr top;  // the copy's root element — origin of all paths
} PyXmlSec_LxmlShadowSiteList;

static int PyXmlSec_LxmlShadowSiteAppend(PyXmlSec_LxmlShadowSiteList* list, xmlNodePtr node, int kind) {
    PyXmlSec_LxmlShadowSite* site;
    int graft = kind == PYXMLSEC_SHADOW_SITE_GRAFT;

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
    site->kind = kind;
    site->depth = PyXmlSec_LxmlShadowPathTo(graft ? node->parent : node, list->top, site->path);
    if (site->depth < 0) {
        PyErr_SetString(PyXmlSec_InternalError, "unexpected mutation site.");
        return -1;
    }
    site->idx = graft ? PyXmlSec_LxmlShadowChildIndex(node) : 0;
    site->value = NULL;
    ++list->count;
    return 0;
}

// Walks the marked structure of the copy in document order, recording a
// graft for every fresh node and, after them, a sync for their parent.
static int PyXmlSec_LxmlShadowCollectSites(PyXmlSec_LxmlShadowSiteList* list, xmlNodePtr parent) {
    xmlNodePtr n;
    int fresh = 0;

    for (n = parent->children; n != NULL; n = n->next) {
        if (PYXMLSEC_SHADOW_MARKED(n)) {
            if (n->type == XML_ELEMENT_NODE && n->children != NULL
                && PyXmlSec_LxmlShadowCollectSites(list, n) < 0) {
                return -1;
            }
            continue;
        }
        fresh = 1;
        if (_isElement(n) && PyXmlSec_LxmlShadowSiteAppend(list, n, PYXMLSEC_SHADOW_SITE_GRAFT) < 0) {
            return -1;
        }
    }
    if (fresh && PyXmlSec_LxmlShadowSiteAppend(list, parent, PYXMLSEC_SHADOW_SITE_SYNC) < 0) {
        return -1;
    }
    return 0;
}

// The text slots of an lxml element as the list [text, tail of child 0,
// tail of child 1, ...] (new reference).
static PyObject* PyXmlSec_LxmlShadowGetTextSlots(PyObject* parent) {
    PyObject* slots = PyList_New(0);
    PyObject* item;
    Py_ssize_t i, n;
    int failed;

    if (slots == NULL) {
        return NULL;
    }
    item = PyObject_GetAttrString(parent, "text");
    failed = item == NULL || PyList_Append(slots, item) < 0;
    Py_XDECREF(item);
    n = failed ? -1 : PyObject_Length(parent);
    for (i = 0; i < n; ++i) {
        PyObject* child = PySequence_GetItem(parent, i);
        item = child != NULL ? PyObject_GetAttrString(child, "tail") : NULL;
        failed = item == NULL || PyList_Append(slots, item) < 0;
        Py_XDECREF(child);
        Py_XDECREF(item);
        if (failed) {
            break;
        }
    }
    if (failed || n < 0) {
        Py_DECREF(slots);
        return NULL;
    }
    return slots;
}

// Applies a slot list to an lxml element whose children already mirror the
// copy's (the grafts under it have been applied).
static int PyXmlSec_LxmlShadowSetTextSlots(PyObject* parent, PyObject* slots) {
    Py_ssize_t i;
    Py_ssize_t n = PyObject_Length(parent);

    if (n < 0) {
        return -1;
    }
    if (n + 1 != PyList_GET_SIZE(slots)) {
        PyErr_SetString(PyXmlSec_InternalError, "unexpected mutation site.");
        return -1;
    }
    if (PyObject_SetAttrString(parent, "text", PyList_GET_ITEM(slots, 0)) < 0) {
        return -1;
    }
    for (i = 0; i < n; ++i) {
        PyObject* child = PySequence_GetItem(parent, i);
        int failed = child == NULL || PyObject_SetAttrString(child, "tail", PyList_GET_ITEM(slots, i + 1)) < 0;
        Py_XDECREF(child);
        if (failed) {
            return -1;
        }
    }
    return 0;
}

// Applies every change in the copy to the live tree. Does not release the
// copy. Returns 0, or -1 with an exception set.
static int PyXmlSec_LxmlShadowReflectSites(PyXmlSec_LxmlShadow* shadow) {
    PyXmlSec_LxmlShadowSiteList list = {NULL, 0, 0, NULL};
    PyObject* copy_root = NULL;
    int i;
    int rv = -1;

    // Re-fetch the root: replacement operations may swap nodes at the top. A
    // fresh root means the call replaced the root itself, which cannot be
    // reflected (lxml cannot swap a document's root); the callers that can
    // hit that (enc.c) check for it before getting here.
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
        if (site->kind == PYXMLSEC_SHADOW_SITE_GRAFT) {
            site->value = PySequence_GetItem(copy_parent, site->idx);
        } else {
            site->value = PyXmlSec_LxmlShadowGetTextSlots(copy_parent);
        }
        Py_DECREF(copy_parent);
        if (site->value == NULL) {
            goto DONE;
        }
    }

    // Phase 2: apply to the live tree in document order.
    for (i = 0; i < list.count; ++i) {
        PyXmlSec_LxmlShadowSite* site = &list.items[i];
        PyObject* live_parent = PyXmlSec_LxmlShadowWalk((PyObject*)shadow->element, site->path, site->depth);
        int failed;
        if (live_parent == NULL) {
            goto DONE;
        }
        if (site->kind == PYXMLSEC_SHADOW_SITE_GRAFT) {
            // lxml carries the node's tail along and reconciles namespaces.
            PyObject* tmp = PyObject_CallMethod(live_parent, "insert", "iO", site->idx, site->value);
            failed = tmp == NULL;
            Py_XDECREF(tmp);
        } else {
            failed = PyXmlSec_LxmlShadowSetTextSlots(live_parent, site->value) < 0;
        }
        Py_DECREF(live_parent);
        if (failed) {
            goto DONE;
        }
    }
    rv = 0;

DONE:
    for (i = 0; i < list.count; ++i) {
        Py_XDECREF(list.items[i].value);
    }
    PyMem_Free(list.items);
    Py_XDECREF(copy_root);
    return rv;
}

// Create shape (BeginNewDoc): the call left `res` detached inside the
// private document. Root it there so the whole subtree serializes (and is
// freed with the doc) and hand the bytes to lxml: the result is a new
// detached element in a document of its own — lxml moves it when the caller
// grafts it into a tree, just like the raw path's detached node.
static PyObject* PyXmlSec_LxmlShadowEndDetached(PyXmlSec_LxmlShadow* shadow, xmlNodePtr res) {
    PyObject* result;
    xmlDocSetRootElement(shadow->doc, res);
    result = PyXmlSec_LxmlShadowDumpCopy(shadow);
    PyXmlSec_LxmlShadowDiscard(shadow);
    return result;
}

// Swaps the live element at `path` for the copy's version of it (the tail
// travels with the inserted node; the call does not touch it). Returns the
// new live element (new reference).
static PyObject* PyXmlSec_LxmlShadowSwapLive(PyXmlSec_LxmlShadow* shadow, const int* path, int depth) {
    PyObject* copy_root = NULL;
    PyObject* copy_parent = NULL;
    PyObject* live_parent = NULL;
    PyObject* live_old = NULL;
    PyObject* new_node = NULL;
    PyObject* tmp = NULL;
    PyObject* result = NULL;
    int idx = path[depth - 1];

    copy_root = PyXmlSec_LxmlShadowDumpCopy(shadow);
    if (copy_root == NULL) {
        goto DONE;
    }
    copy_parent = PyXmlSec_LxmlShadowWalk(copy_root, path, depth - 1);
    live_parent = PyXmlSec_LxmlShadowWalk((PyObject*)shadow->element, path, depth - 1);
    if (copy_parent == NULL || live_parent == NULL) {
        goto DONE;
    }
    new_node = PySequence_GetItem(copy_parent, idx);
    live_old = PySequence_GetItem(live_parent, idx);
    if (new_node == NULL || live_old == NULL) {
        goto DONE;
    }
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
    Py_XDECREF(copy_root);
    Py_XDECREF(copy_parent);
    Py_XDECREF(live_parent);
    Py_XDECREF(live_old);
    Py_XDECREF(new_node);
    Py_XDECREF(tmp);
    return result;
}

// Find-or-create found an existing node: the tree did not grow there, so the
// result is the live element at the same path, plus whatever the call changed
// on it. Attributes (Id) are synced in place. A renamed namespace prefix
// (encrypted_data_ensure_key_info(ns=...)) has no lxml API, so the live
// element is swapped for the copy's version and the caller gets a new proxy
// object — except for the shadow root, which has no live parent to swap
// under (only attributes can change there).
static PyObject* PyXmlSec_LxmlShadowEndFound(PyXmlSec_LxmlShadow* shadow, xmlNodePtr res, const int* path, int depth) {
    PyObject* live = NULL;
    PyObject* live_prefix = NULL;
    PyObject* copy_prefix = NULL;
    PyObject* result = NULL;
    int same;

    live = PyXmlSec_LxmlShadowWalk((PyObject*)shadow->element, path, depth);
    if (live == NULL) {
        return NULL;
    }
    live_prefix = PyObject_GetAttrString(live, "prefix");
    if (live_prefix == NULL) {
        goto DONE;
    }
    if (res->ns != NULL && res->ns->prefix != NULL) {
        copy_prefix = PyUnicode_FromString((const char*)res->ns->prefix);
    } else {
        copy_prefix = Py_None;
        Py_INCREF(copy_prefix);
    }
    if (copy_prefix == NULL) {
        goto DONE;
    }
    same = PyObject_RichCompareBool(live_prefix, copy_prefix, Py_EQ);
    if (same < 0) {
        goto DONE;
    }
    if (same || depth == 0) {
        if (PyXmlSec_LxmlShadowSyncAttributes(res, live) == 0) {
            result = live;
            live = NULL;
        }
    } else {
        result = PyXmlSec_LxmlShadowSwapLive(shadow, path, depth);
    }

DONE:
    Py_XDECREF(live);
    Py_XDECREF(live_prefix);
    Py_XDECREF(copy_prefix);
    return result;
}

PyObject* PyXmlSec_LxmlShadowEnd(PyXmlSec_LxmlShadow* shadow, xmlNodePtr res, const char* error) {
    PyObject* result = NULL;
    int path[PYXMLSEC_SHADOW_MAX_DEPTH];
    int depth;

    if (res == NULL) {
        PyXmlSec_LxmlShadowDiscard(shadow);
        PyXmlSec_SetLastError(error);
        return NULL;
    }
    // Fast path (no copy was made): res is a node in the live lxml tree.
    if (shadow->doc == NULL) {
        PyXmlSec_LxmlShadowDiscard(shadow);
        return (PyObject*)PyXmlSec_elementFactory(shadow->element->_doc, res);
    }
    if (shadow->root == NULL) {
        return PyXmlSec_LxmlShadowEndDetached(shadow, res);
    }

    depth = PyXmlSec_LxmlShadowPathTo(res, shadow->root, path);
    if (depth < 0) {
        PyErr_SetString(PyXmlSec_InternalError, "unexpected result node.");
        goto DONE;
    }
    // Reflect first: the live tree then mirrors the copy's element structure,
    // so the path of `res` in the copy resolves to its live counterpart —
    // whether the call created it (now grafted) or found it.
    if (PyXmlSec_LxmlShadowReflectSites(shadow) < 0) {
        goto DONE;
    }
    if (PYXMLSEC_SHADOW_MARKED(res)) {
        result = PyXmlSec_LxmlShadowEndFound(shadow, res, path, depth);
    } else {
        result = PyXmlSec_LxmlShadowWalk((PyObject*)shadow->element, path, depth);
    }

DONE:
    PyXmlSec_LxmlShadowDiscard(shadow);
    return result;
}

PyObject* PyXmlSec_LxmlShadowEndFind(PyXmlSec_LxmlShadow* shadow, xmlNodePtr res) {
    PyObject* result = NULL;
    int path[PYXMLSEC_SHADOW_MAX_DEPTH];
    int depth;

    if (res == NULL) {
        PyXmlSec_LxmlShadowDiscard(shadow);
        Py_RETURN_NONE;
    }
    if (shadow->doc == NULL) {  // fast path: res is a live node
        PyXmlSec_LxmlShadowDiscard(shadow);
        return (PyObject*)PyXmlSec_elementFactory(shadow->element->_doc, res);
    }
    depth = PyXmlSec_LxmlShadowPathTo(res, shadow->root, path);
    if (depth < 0) {
        PyErr_SetString(PyXmlSec_InternalError, "unexpected result node.");
    } else {
        result = PyXmlSec_LxmlShadowWalk((PyObject*)shadow->element, path, depth);
    }
    PyXmlSec_LxmlShadowDiscard(shadow);
    return result;
}

int PyXmlSec_LxmlShadowReflect(PyXmlSec_LxmlShadow* shadow, int rv, const char* error) {
    if (rv < 0) {
        PyXmlSec_LxmlShadowDiscard(shadow);
        if (error != NULL) {
            PyXmlSec_SetLastError(error);
        }
        return -1;
    }
    rv = shadow->doc != NULL ? PyXmlSec_LxmlShadowReflectSites(shadow) : 0;
    PyXmlSec_LxmlShadowDiscard(shadow);
    return rv;
}

xmlNodePtr PyXmlSec_LxmlShadowImportElement(PyXmlSec_LxmlShadow* shadow, PyXmlSec_LxmlElementPtr element) {
    PyObject* bytes;
    xmlDocPtr tdoc;
    xmlNodePtr result;

    bytes = PyXmlSec_LxmlElementToBytes((PyObject*)element);
    if (bytes == NULL) {
        return NULL;
    }
    tdoc = PyXmlSec_LxmlShadowParse(bytes, "cannot make a private copy of the element.");
    Py_DECREF(bytes);
    if (tdoc == NULL) {
        return NULL;
    }
    // Copy into the shadow doc (both trees are ours). The copy stays
    // untagged: from the reflection's point of view whatever the xmlsec call
    // grafts of it is a node "the call created".
    result = xmlDocCopyNode(xmlDocGetRootElement(tdoc), shadow->doc, 1);
    xmlFreeDoc(tdoc);
    if (result == NULL) {
        PyErr_SetString(PyXmlSec_InternalError, "cannot make a private copy of the element.");
    }
    return result;
}
