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

#include <stdint.h>

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
static PyObject* PyXmlSec_LxmlEtreeCleanupNamespaces;
static PyObject* PyXmlSec_LxmlEtreeParser;

// Shadow-mode ID registry: maps the identity of an lxml document to the list
// of id-attribute specs registered for it (see PyXmlSec_LxmlShadowRecordId).
static PyObject* PyXmlSec_LxmlShadowIdRegistry;

int PyXmlSec_LxmlShadowIsActive(void) {
    return PyXmlSec_LxmlShadowActive;
}

// etree.XMLParser(huge_tree=True, resolve_entities=False), the parser for
// lxml's side of the reflect crossing.
//
// huge_tree lifts libxml2's 10 MB text-node limit, which lxml's default
// parser keeps, so a CipherValue above it (large encrypt_binary payloads) or
// a document the user parsed with huge_tree still reflects.
//
// resolve_entities=False keeps the entity references of a tree the caller
// parsed that way (lxml's `_Entity` children) as references: our own parse of
// the copy leaves them unexpanded too, so expanding them here would give the
// re-parse a different child structure than the copy the sites were collected
// from, and the child-index paths would address the wrong nodes. A tree whose
// entities were already resolved carries none to keep.
//
// Both are safe here: what gets parsed is this extension's own dump of a tree
// lxml has already parsed.
static PyObject* PyXmlSec_LxmlNewParser(PyObject* etree) {
    PyObject* result = NULL;
    PyObject* cls = PyObject_GetAttrString(etree, "XMLParser");
    PyObject* args = PyTuple_New(0);
    PyObject* kwargs = Py_BuildValue("{s:O,s:O}", "huge_tree", Py_True, "resolve_entities", Py_False);
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
    PyXmlSec_LxmlEtreeCleanupNamespaces = PyObject_GetAttrString(etree, "cleanup_namespaces");
    PyXmlSec_LxmlEtreeParser = PyXmlSec_LxmlNewParser(etree);
    Py_DECREF(etree);
    if (PyXmlSec_LxmlEtreeToString == NULL || PyXmlSec_LxmlEtreeFromString == NULL
            || PyXmlSec_LxmlEtreeCleanupNamespaces == NULL || PyXmlSec_LxmlEtreeParser == NULL) {
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
// NULL with an exception set (`error` for parse failures). `url` is the base
// URI the copy gets (see PyXmlSec_LxmlDocumentUrl); NULL when there is none.
static xmlDocPtr PyXmlSec_LxmlShadowParse(PyObject* bytes, const char* url, const char* error) {
    char* data = NULL;
    Py_ssize_t size = 0;
    xmlDocPtr doc;

    if (PyBytes_AsStringAndSize(bytes, &data, &size) < 0) {
        return NULL;
    }
    doc = xmlReadMemory(data, (int)size, url, NULL, PYXMLSEC_SHADOW_PARSE_OPTIONS);
    if (doc == NULL || xmlDocGetRootElement(doc) == NULL) {
        if (doc != NULL) {
            xmlFreeDoc(doc);
        }
        PyErr_SetString(PyXmlSec_InternalError, error);
        return NULL;
    }
    return doc;
}

// The URL of the document `tree` belongs to (lxml's `docinfo.URL`), so that
// the private copy carries the same base URI as the document it copies —
// what libxml2 resolves relative references against (an XSLT transform's
// document()/import, an xml:base, a DTD or entity system id). A copy parsed
// without one would resolve them against the process' working directory
// instead. Stores a new reference to the owning string in *holder (NULL when
// the document has no URL) and its UTF-8 in *url; returns 0, or -1 with an
// exception set.
static int PyXmlSec_LxmlDocumentUrl(PyObject* tree, PyObject** holder, const char** url) {
    PyObject* info;
    PyObject* value;

    *holder = NULL;
    *url = NULL;
    info = PyObject_GetAttrString(tree, "docinfo");
    if (info == NULL) {
        return -1;
    }
    value = PyObject_GetAttrString(info, "URL");
    Py_DECREF(info);
    if (value == NULL) {
        return -1;
    }
    if (!PyUnicode_Check(value)) {   // None for a document parsed from memory
        Py_DECREF(value);
        return 0;
    }
    *url = PyUnicode_AsUTF8(value);
    if (*url == NULL) {
        Py_DECREF(value);
        return -1;
    }
    *holder = value;
    return 0;
}

// Whether `tree` carries an internal DTD subset — the only place a document
// lxml parsed can declare the entities its `&name;` references name, and so
// what decides whether a subtree may be serialized on its own (see Begin).
static int PyXmlSec_LxmlDocumentHasInternalDtd(PyObject* tree, int* dtd) {
    PyObject* info = PyObject_GetAttrString(tree, "docinfo");
    PyObject* value;

    *dtd = 0;
    if (info == NULL) {
        return -1;
    }
    value = PyObject_GetAttrString(info, "internalDTD");
    Py_DECREF(info);
    if (value == NULL) {
        return -1;
    }
    *dtd = value != Py_None;
    Py_DECREF(value);
    return 0;
}

// Nodes that exist before the xmlsec call are tagged through the libxml2
// _private field (never serialized, never touched by the parser or xmlsec):
// it is pointed at the shadow's own tag array, so whatever is untagged after
// the call is what the call created. Each tag also records the child count
// the node had, which is what makes a *removal* visible — a call can delete a
// node and leave nothing fresh behind (an <EncryptedData/> that decrypts to
// empty content), and only the changed count shows it happened. A tag
// pointer is compared against the array bounds, never dereferenced blindly:
// a foreign _private (lxml's own proxy, when both libraries are the same
// libxml2) simply falls outside.
#define PYXMLSEC_SHADOW_TAGGED(shadow, n) \
    ((uintptr_t)(n)->_private >= (uintptr_t)(shadow)->tags \
     && (uintptr_t)(n)->_private < (uintptr_t)((shadow)->tags + (shadow)->ntags))
#define PYXMLSEC_SHADOW_TAG(shadow, n) \
    (PYXMLSEC_SHADOW_TAGGED(shadow, n) ? (PyXmlSec_LxmlShadowTag*)(n)->_private : NULL)

static int PyXmlSec_LxmlShadowCountNodes(xmlNodePtr node) {
    int count = 0;
    for (; node != NULL; node = node->next) {
        count += 1 + PyXmlSec_LxmlShadowCountNodes(node->children);
    }
    return count;
}

// Hands out `shadow->tags` in document order; returns the next free slot.
static int PyXmlSec_LxmlShadowTagNodes(PyXmlSec_LxmlShadow* shadow, xmlNodePtr node, int next) {
    for (; node != NULL; node = node->next) {
        PyXmlSec_LxmlShadowTag* tag = &shadow->tags[next++];
        xmlNodePtr child;
        tag->children = 0;
        for (child = node->children; child != NULL; child = child->next) {
            ++tag->children;
        }
        node->_private = (void*)tag;
        next = PyXmlSec_LxmlShadowTagNodes(shadow, node->children, next);
    }
    return next;
}

// Tags every node of the freshly parsed copy. Returns 0, or -1 with an
// exception set.
static int PyXmlSec_LxmlShadowMark(PyXmlSec_LxmlShadow* shadow) {
    int count = PyXmlSec_LxmlShadowCountNodes(shadow->doc->children);

    shadow->tags = (PyXmlSec_LxmlShadowTag*)PyMem_Malloc((count > 0 ? count : 1) * sizeof(*shadow->tags));
    if (shadow->tags == NULL) {
        PyErr_NoMemory();
        return -1;
    }
    shadow->ntags = count;
    PyXmlSec_LxmlShadowTagNodes(shadow, shadow->doc->children, 0);
    return 0;
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

// Records the child indices leading from the top of `node`'s live tree down
// to `node` into `path` (ordered top-first), through lxml's own API — the
// shadow path never walks lxml's raw nodes. Returns the depth and stores the
// top element in *top (new reference), or -1 with an exception set.
static int PyXmlSec_LxmlLivePathTo(PyObject* node, int* path, PyObject** top) {
    PyObject* cur = node;
    int depth = 0;
    int i;

    *top = NULL;
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
    *top = cur;
    return depth;

ON_FAIL:
    Py_DECREF(cur);
    return -1;
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

// Makes the copy's counterpart of the element at `path` the copy's root and
// drops the rest of the document, keeping its internal subset. Used when the
// document declares entities: the subtree cannot be serialized on its own
// then (its `&name;` references would be undefined), so the whole document is
// copied and cut down here. The node is copied before it is re-rooted, which
// is what makes the cut safe — libxml2 redeclares on the copy the namespaces
// it inherited from the ancestors that are about to go, and rebinds its
// entity references to the copy's own declarations. Returns 0, or -1 with an
// exception set.
static int PyXmlSec_LxmlShadowReroot(PyXmlSec_LxmlShadow* shadow, const int* path, int depth) {
    xmlNodePtr target = PyXmlSec_LxmlShadowWalkNode(xmlDocGetRootElement(shadow->doc), path, depth);
    xmlNodePtr copy;
    xmlNodePtr old;

    if (target == NULL) {
        PyErr_SetString(PyXmlSec_InternalError, "cannot locate the element in the private copy.");
        return -1;
    }
    if (depth == 0) {   // the element is the document root already
        return 0;
    }
    copy = xmlDocCopyNode(target, shadow->doc, 1);
    if (copy == NULL) {
        PyErr_SetString(PyXmlSec_InternalError, "cannot make a private copy of the element.");
        return -1;
    }
    old = xmlDocSetRootElement(shadow->doc, copy);
    if (old != NULL) {
        xmlFreeNode(old);
    }
    return 0;
}

int PyXmlSec_LxmlShadowBegin(PyXmlSec_LxmlShadow* shadow, PyXmlSec_LxmlElementPtr element) {
    PyObject* tree = NULL;
    PyObject* bytes = NULL;
    PyObject* url_holder = NULL;
    const char* url = NULL;
    int path[PYXMLSEC_SHADOW_MAX_DEPTH];
    int depth = 0;
    int dtd = 0;

    shadow->element = element;
    shadow->owned = NULL;
    shadow->doc = NULL;
    shadow->root = NULL;
    shadow->tags = NULL;
    shadow->ntags = 0;

    // Fast path: lxml links the same libxml2 (the import guard passed), so
    // xmlsec can mutate lxml's nodes directly and no copy is needed; End sees
    // doc == NULL and just wraps the result node.
    if (!PyXmlSec_LxmlShadowActive) {
        shadow->root = element->_c_node;
        return 0;
    }

    tree = PyObject_CallMethod((PyObject*)element, "getroottree", NULL);
    if (tree == NULL) {
        goto ON_FAIL;
    }
    if (PyXmlSec_LxmlDocumentUrl(tree, &url_holder, &url) < 0
            || PyXmlSec_LxmlDocumentHasInternalDtd(tree, &dtd) < 0) {
        goto ON_FAIL;
    }

    if (dtd) {
        // The subtree may hold entity references, and their declarations live
        // in the document's internal subset — serializing the element alone
        // would leave them undefined and the parse would fail. Copy the whole
        // document, declarations included, and cut it back to the element.
        PyObject* live_top = NULL;
        depth = PyXmlSec_LxmlLivePathTo((PyObject*)element, path, &live_top);
        Py_XDECREF(live_top);
        if (depth < 0) {
            goto ON_FAIL;
        }
        bytes = PyObject_CallFunctionObjArgs(PyXmlSec_LxmlEtreeToString, tree, NULL);
    } else {
        bytes = PyXmlSec_LxmlElementToBytes((PyObject*)element);
    }
    Py_CLEAR(tree);
    if (bytes == NULL) {
        goto ON_FAIL;
    }
    shadow->doc = PyXmlSec_LxmlShadowParse(bytes, url, "cannot make a private copy of the element.");
    Py_CLEAR(bytes);
    Py_CLEAR(url_holder);
    if (shadow->doc == NULL) {
        goto ON_FAIL;
    }
    if (dtd && PyXmlSec_LxmlShadowReroot(shadow, path, depth) < 0) {
        goto ON_FAIL;
    }
    shadow->root = xmlDocGetRootElement(shadow->doc);
    if (PyXmlSec_LxmlShadowMark(shadow) < 0) {
        goto ON_FAIL;
    }
    return 0;

ON_FAIL:
    Py_XDECREF(tree);
    Py_XDECREF(bytes);
    Py_XDECREF(url_holder);
    PyXmlSec_LxmlShadowDiscard(shadow);
    return -1;
}

xmlDocPtr PyXmlSec_LxmlShadowBeginNewDoc(PyXmlSec_LxmlShadow* shadow, PyXmlSec_LxmlElementPtr element) {
    shadow->element = element;
    shadow->owned = NULL;
    shadow->doc = NULL;
    shadow->root = NULL;
    shadow->tags = NULL;
    shadow->ntags = 0;

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
    PyMem_Free(shadow->tags);
    shadow->tags = NULL;
    shadow->ntags = 0;
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
// An entry is the tuple (document, nodes, specs), keyed by the _Document
// object's address: `nodes` holds the registered elements themselves and
// `specs` the (attribute name, namespace, node index, subtree) records. The
// entry keeps a strong reference to the document and to every registered
// element, so the key can never go stale — the address cannot be reused while
// the entry keeps the object alive.
//
// Keeping the elements is also what makes the replay faithful: a spec is
// applied to the very node it was registered for (and, for add_ids, that
// node's subtree), never to every same-named attribute in the document.
// Registering the whole document would let an unrelated element sharing the
// id value claim it first, so a `#id` reference — the URI a signature covers
// — could resolve to content the caller never registered.
//
// Those references also make liveness decidable without weak references
// (lxml's classes refuse those): every element proxy holds a reference to the
// document it hangs in, so when the document's reference count is exactly
// what the registry itself holds (the entry plus one per registered element
// still in it) and no registered element is referenced anywhere else, nothing
// can hand that document to a binding again — the entry is dead and is
// dropped. Pruning runs before every new registration, which bounds the
// registry — and the documents it pins — by the documents still in use. No
// live registration is ever evicted.
//
// An element need not stay in the document it was registered for: lxml lets
// one be adopted into another tree, and its proxy then references that other
// document. The count is therefore taken from each proxy's *current* owner,
// and re-registering an adopted node vacates its slot in the entry it came
// from (ForgetIdNode), so a node is never held by two entries at once and a
// reference count of one still means "the registry alone".
// ----------------------------------------------------------------------------

enum { PYXMLSEC_ID_ENTRY_DOC, PYXMLSEC_ID_ENTRY_NODES, PYXMLSEC_ID_ENTRY_SPECS };

// Non-zero when nothing outside the registry can reach the entry's document.
static int PyXmlSec_LxmlShadowIdEntryIsDead(PyObject* entry) {
    PyObject* doc = PyTuple_GET_ITEM(entry, PYXMLSEC_ID_ENTRY_DOC);
    PyObject* nodes = PyTuple_GET_ITEM(entry, PYXMLSEC_ID_ENTRY_NODES);
    Py_ssize_t n = PyList_GET_SIZE(nodes);
    Py_ssize_t held = 1;   // the entry's own reference
    Py_ssize_t i;

    for (i = 0; i < n; ++i) {
        PyObject* node = PyList_GET_ITEM(nodes, i);
        if (node == Py_None) {   // vacated slot: the node was registered elsewhere
            continue;
        }
        if (Py_REFCNT(node) != 1) {
            return 0;
        }
        if ((PyObject*)((PyXmlSec_LxmlElementPtr)node)->_doc == doc) {
            ++held;
        }
    }
    return Py_REFCNT(doc) == held;
}

// Drops `element` from every entry but `keep`. A node registered again after
// being adopted into another document is no longer part of the tree its old
// entry stands for, and its slot there must stop holding it: the liveness
// test above counts on a registered proxy being held by one entry only. The
// slot is vacated rather than removed, so the indices the surviving specs
// carry stay valid; the specs that pointed at it go. Best effort — a failure
// only leaves an entry alive longer than needed.
static void PyXmlSec_LxmlShadowForgetIdNode(PyObject* keep, PyObject* element) {
    PyObject* key;
    PyObject* entry;
    Py_ssize_t pos = 0;

    while (PyDict_Next(PyXmlSec_LxmlShadowIdRegistry, &pos, &key, &entry)) {
        PyObject* nodes;
        PyObject* specs;
        Py_ssize_t i;
        if (entry == keep) {
            continue;
        }
        nodes = PyTuple_GET_ITEM(entry, PYXMLSEC_ID_ENTRY_NODES);
        specs = PyTuple_GET_ITEM(entry, PYXMLSEC_ID_ENTRY_SPECS);
        for (i = 0; i < PyList_GET_SIZE(nodes); ++i) {
            Py_ssize_t j;
            if (PyList_GET_ITEM(nodes, i) != element) {
                continue;
            }
            for (j = PyList_GET_SIZE(specs) - 1; j >= 0; --j) {
                PyObject* spec = PyList_GET_ITEM(specs, j);
                if (PyLong_AsSsize_t(PyTuple_GET_ITEM(spec, 2)) == i && PyList_SetSlice(specs, j, j + 1, NULL) < 0) {
                    PyErr_Clear();
                }
            }
            Py_INCREF(Py_None);
            PyList_SetItem(nodes, i, Py_None);   // steals the reference, releases the node
        }
    }
}

// Drops the entries of documents nobody but the registry still references.
// Best effort: on an allocation failure the entries simply survive until the
// next registration prunes them.
static void PyXmlSec_LxmlShadowPruneIdRegistry(void) {
    PyObject* dead;
    PyObject* key;
    PyObject* entry;
    Py_ssize_t pos = 0;
    Py_ssize_t i;

    dead = PyList_New(0);
    if (dead == NULL) {
        PyErr_Clear();
        return;
    }
    // The dict cannot be mutated while iterating it, so collect first.
    while (PyDict_Next(PyXmlSec_LxmlShadowIdRegistry, &pos, &key, &entry)) {
        if (PyXmlSec_LxmlShadowIdEntryIsDead(entry) && PyList_Append(dead, key) < 0) {
            PyErr_Clear();
            break;
        }
    }
    for (i = 0; i < PyList_GET_SIZE(dead); ++i) {
        if (PyDict_DelItem(PyXmlSec_LxmlShadowIdRegistry, PyList_GET_ITEM(dead, i)) < 0) {
            PyErr_Clear();
        }
    }
    Py_DECREF(dead);
}

int PyXmlSec_LxmlShadowRecordIds(PyXmlSec_LxmlElementPtr element, PyObject* names, const char* ns, int subtree) {
    PyObject* key = NULL;
    PyObject* created = NULL;
    PyObject* spec = NULL;
    PyObject* entry = NULL;
    PyObject* nodes;
    PyObject* specs;
    Py_ssize_t nnodes = 0;
    Py_ssize_t nspecs = 0;
    Py_ssize_t idx;
    Py_ssize_t i;
    int contains;
    int fresh = 0;
    int result = -1;

    key = PyLong_FromVoidPtr((void*)element->_doc);
    if (key == NULL) {
        goto DONE;
    }

    entry = PyDict_GetItem(PyXmlSec_LxmlShadowIdRegistry, key);  // borrowed
    if (entry == NULL) {
        PyXmlSec_LxmlShadowPruneIdRegistry();
        nodes = PyList_New(0);
        specs = PyList_New(0);
        if (nodes != NULL && specs != NULL) {
            created = PyTuple_Pack(3, (PyObject*)element->_doc, nodes, specs);
        }
        Py_XDECREF(nodes);
        Py_XDECREF(specs);
        if (created == NULL || PyDict_SetItem(PyXmlSec_LxmlShadowIdRegistry, key, created) < 0) {
            goto DONE;
        }
        entry = created;
        fresh = 1;
    }

    // One reference per registered element, so that the liveness test can
    // account for exactly the references the registry itself holds.
    nodes = PyTuple_GET_ITEM(entry, PYXMLSEC_ID_ENTRY_NODES);
    specs = PyTuple_GET_ITEM(entry, PYXMLSEC_ID_ENTRY_SPECS);
    nnodes = PyList_GET_SIZE(nodes);
    nspecs = PyList_GET_SIZE(specs);
    idx = -1;
    for (i = 0; i < nnodes; ++i) {
        if (PyList_GET_ITEM(nodes, i) == (PyObject*)element) {
            idx = i;
            break;
        }
    }
    if (idx < 0) {
        if (PyList_Append(nodes, (PyObject*)element) < 0) {
            goto DONE;
        }
        idx = nnodes;
        PyXmlSec_LxmlShadowForgetIdNode(entry, (PyObject*)element);
    }

    for (i = 0; i < PyList_GET_SIZE(names); ++i) {
        spec = Py_BuildValue("(Ozni)", PyList_GET_ITEM(names, i), ns, idx, subtree);
        if (spec == NULL) {
            goto DONE;
        }
        contains = PySequence_Contains(specs, spec);
        if (contains < 0 || (!contains && PyList_Append(specs, spec) < 0)) {
            goto DONE;
        }
        Py_CLEAR(spec);
    }
    result = 0;

DONE:
    // All of the call's names are recorded or none of them are: a caller that
    // hands over a bad list must not find part of it registered. Rolling back
    // must not clobber the failure that caused it, hence the fetch/restore.
    if (result < 0 && entry != NULL) {
        PyObject* type;
        PyObject* value;
        PyObject* tb;
        PyErr_Fetch(&type, &value, &tb);
        if (fresh ? PyDict_DelItem(PyXmlSec_LxmlShadowIdRegistry, key) < 0
                  : (PyList_SetSlice(PyTuple_GET_ITEM(entry, PYXMLSEC_ID_ENTRY_SPECS), nspecs, PY_SSIZE_T_MAX, NULL) < 0
                     || PyList_SetSlice(PyTuple_GET_ITEM(entry, PYXMLSEC_ID_ENTRY_NODES), nnodes, PY_SSIZE_T_MAX, NULL) < 0)) {
            PyErr_Clear();
        }
        PyErr_Restore(type, value, tb);
    }
    Py_XDECREF(key);
    Py_XDECREF(created);
    Py_XDECREF(spec);
    return result;
}

int PyXmlSec_LxmlShadowRecordId(PyXmlSec_LxmlElementPtr element, const char* name, const char* ns, int subtree) {
    PyObject* names = Py_BuildValue("[s]", name);
    int rv;

    if (names == NULL) {
        return -1;
    }
    rv = PyXmlSec_LxmlShadowRecordIds(element, names, ns, subtree);
    Py_DECREF(names);
    return rv;
}

// Registers `node`'s `name` attribute (in `ns` when given) as an XML ID, the
// way xmlSecAddIDs does: the first registration of a value wins.
static void PyXmlSec_LxmlShadowAddId(xmlDocPtr doc, xmlNodePtr node, const xmlChar* name, const xmlChar* ns) {
    xmlAttrPtr attr = ns != NULL ? xmlHasNsProp(node, name, ns) : xmlHasProp(node, name);
    xmlChar* value;

    if (attr == NULL || attr->children == NULL) {
        return;
    }
    value = xmlNodeListGetString(doc, attr->children, 1);
    if (value == NULL) {
        return;
    }
    if (xmlGetID(doc, value) == NULL) {
        xmlAddID(NULL, doc, value, attr);
    }
    xmlFree(value);
}

// `node`, its siblings and their descendants.
static void PyXmlSec_LxmlShadowAddIdsBelow(xmlDocPtr doc, xmlNodePtr node, const xmlChar* name, const xmlChar* ns) {
    for (; node != NULL; node = node->next) {
        if (node->type == XML_ELEMENT_NODE) {
            PyXmlSec_LxmlShadowAddId(doc, node, name, ns);
            PyXmlSec_LxmlShadowAddIdsBelow(doc, node->children, name, ns);
        }
    }
}

// Applies one recorded spec to `node`, the copy's counterpart of the element
// it was registered for: that node alone (register_id), or the subtree rooted
// at it (add_ids, which is the scope xmlSecAddIDs walks).
static void PyXmlSec_LxmlShadowApplyIdSpec(xmlDocPtr doc, xmlNodePtr node, const xmlChar* name, const xmlChar* ns, int subtree) {
    if (node == NULL || node->type != XML_ELEMENT_NODE) {
        return;
    }
    PyXmlSec_LxmlShadowAddId(doc, node, name, ns);
    if (subtree) {
        PyXmlSec_LxmlShadowAddIdsBelow(doc, node->children, name, ns);
    }
}

// Replays the specs recorded for the shadow's live document onto the copy,
// each at the copy's counterpart of the element it was registered for.
static int PyXmlSec_LxmlShadowReplayIds(PyXmlSec_LxmlShadow* shadow) {
    PyObject* key;
    PyObject* entry;
    PyObject* nodes;
    PyObject* specs;
    int path[PYXMLSEC_SHADOW_MAX_DEPTH];
    Py_ssize_t i, n;

    key = PyLong_FromVoidPtr((void*)shadow->element->_doc);
    if (key == NULL) {
        return -1;
    }
    // The entry, if any, belongs to this very document: the registry's own
    // reference keeps the address from being reused by another one.
    entry = PyDict_GetItem(PyXmlSec_LxmlShadowIdRegistry, key);  // borrowed
    Py_DECREF(key);
    if (entry == NULL) {
        return 0;
    }

    nodes = PyTuple_GET_ITEM(entry, PYXMLSEC_ID_ENTRY_NODES);
    specs = PyTuple_GET_ITEM(entry, PYXMLSEC_ID_ENTRY_SPECS);
    n = PyList_GET_SIZE(specs);
    for (i = 0; i < n; ++i) {
        PyObject* spec = PyList_GET_ITEM(specs, i);  // (name, ns, node index, subtree)
        PyObject* node = PyList_GET_ITEM(nodes, PyLong_AsSsize_t(PyTuple_GET_ITEM(spec, 2)));
        PyObject* top = NULL;
        const char* name = PyUnicode_AsUTF8(PyTuple_GET_ITEM(spec, 0));
        const char* ns = PyTuple_GET_ITEM(spec, 1) == Py_None ? NULL : PyUnicode_AsUTF8(PyTuple_GET_ITEM(spec, 1));
        int subtree = PyObject_IsTrue(PyTuple_GET_ITEM(spec, 3));
        int depth;

        if (name == NULL || (ns == NULL && PyErr_Occurred())) {
            return -1;
        }
        if (node == Py_None) {   // vacated slot: the node is registered elsewhere now
            continue;
        }
        depth = PyXmlSec_LxmlLivePathTo(node, path, &top);
        if (depth < 0) {
            return -1;
        }
        // lxml hands out one proxy per node, so identity settles whether the
        // element still hangs under the root being copied; a registration for
        // an element that has since left this tree applies to nothing here.
        if (top == (PyObject*)shadow->element) {
            PyXmlSec_LxmlShadowApplyIdSpec(shadow->doc, PyXmlSec_LxmlShadowWalkNode(shadow->root, path, depth),
                                           (const xmlChar*)name, (const xmlChar*)ns, subtree);
        }
        Py_DECREF(top);
    }
    return 0;
}

int PyXmlSec_LxmlShadowBeginDoc(PyXmlSec_LxmlShadow* shadow, PyXmlSec_LxmlElementPtr element, xmlNodePtr* target) {
    PyObject* cur = NULL;
    PyObject* tree = NULL;
    PyObject* bytes = NULL;
    PyObject* url_holder = NULL;
    const char* url = NULL;
    int path[PYXMLSEC_SHADOW_MAX_DEPTH];
    int depth;

    shadow->element = element;
    shadow->owned = NULL;
    shadow->doc = NULL;
    shadow->root = NULL;
    shadow->tags = NULL;
    shadow->ntags = 0;
    *target = NULL;

    if (!PyXmlSec_LxmlShadowActive) {
        shadow->root = element->_c_node;
        *target = element->_c_node;
        return 0;
    }

    // `cur` ends as the live root element and `path` leads back down to
    // `element`.
    depth = PyXmlSec_LxmlLivePathTo((PyObject*)element, path, &cur);
    if (depth < 0) {
        goto ON_FAIL;
    }

    // Serialize the whole tree, not just the root element, so comments/PIs
    // outside the root and the internal DTD subset (declared IDs) survive
    // into the copy.
    tree = PyObject_CallMethod(cur, "getroottree", NULL);
    if (tree == NULL) {
        goto ON_FAIL;
    }
    bytes = PyObject_CallFunctionObjArgs(PyXmlSec_LxmlEtreeToString, tree, NULL);
    if (bytes == NULL || PyXmlSec_LxmlDocumentUrl(tree, &url_holder, &url) < 0) {
        goto ON_FAIL;
    }
    Py_CLEAR(tree);
    shadow->doc = PyXmlSec_LxmlShadowParse(bytes, url, "cannot make a private copy of the document.");
    Py_CLEAR(bytes);
    Py_CLEAR(url_holder);
    if (shadow->doc == NULL) {
        goto ON_FAIL;
    }
    shadow->root = xmlDocGetRootElement(shadow->doc);
    if (PyXmlSec_LxmlShadowMark(shadow) < 0) {
        goto ON_FAIL;
    }

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
    Py_XDECREF(url_holder);
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
//   sync  — a tagged parent whose children changed — it gained a fresh node
//           (element or text), or lost a tagged one — gets its text slots
//           (its .text and each child's .tail) copied over from the re-parsed
//           copy. That covers everything xmlsec does to text: the "\n"
//           formatting around a new node, values filled into empty elements
//           (DigestValue), and content it removed (encrypt Type=Content) —
//           a removal leaves no fresh node behind, so only the tagged child
//           count shows that it happened, and only a wholesale sync can carry
//           it across.
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
    xmlNodePtr top;                // the copy's root element — origin of all paths
    PyXmlSec_LxmlShadow* shadow;   // borrowed; owns the tags the walk reads
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

// Walks the tagged structure of the copy in document order, recording a
// graft for every fresh node and, after them, a sync for their parent — and
// for a parent that no longer holds the children it was tagged with, whose
// text slots are the only trace the removal left.
static int PyXmlSec_LxmlShadowCollectSites(PyXmlSec_LxmlShadowSiteList* list, xmlNodePtr parent) {
    PyXmlSec_LxmlShadowTag* tag = PYXMLSEC_SHADOW_TAG(list->shadow, parent);
    xmlNodePtr n;
    int fresh = 0;
    int tagged = 0;

    for (n = parent->children; n != NULL; n = n->next) {
        if (PYXMLSEC_SHADOW_TAGGED(list->shadow, n)) {
            ++tagged;
            if (n->type == XML_ELEMENT_NODE && PyXmlSec_LxmlShadowCollectSites(list, n) < 0) {
                return -1;
            }
            continue;
        }
        fresh = 1;
        if (_isElement(n) && PyXmlSec_LxmlShadowSiteAppend(list, n, PYXMLSEC_SHADOW_SITE_GRAFT) < 0) {
            return -1;
        }
    }
    if ((fresh || (tag != NULL && tag->children != tagged))
        && PyXmlSec_LxmlShadowSiteAppend(list, parent, PYXMLSEC_SHADOW_SITE_SYNC) < 0) {
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

// etree.cleanup_namespaces(element, top_nsmap=..., keep_ns_prefixes=...);
// either keyword may be NULL to leave it out.
static int PyXmlSec_LxmlCleanupNamespaces(PyObject* element, PyObject* top_nsmap, PyObject* keep) {
    PyObject* args = PyTuple_Pack(1, element);
    PyObject* kwargs = PyDict_New();
    PyObject* result = NULL;

    if (args != NULL && kwargs != NULL
            && (top_nsmap == NULL || PyDict_SetItemString(kwargs, "top_nsmap", top_nsmap) == 0)
            && (keep == NULL || PyDict_SetItemString(kwargs, "keep_ns_prefixes", keep) == 0)) {
        result = PyObject_Call(PyXmlSec_LxmlEtreeCleanupNamespaces, args, kwargs);
    }
    Py_XDECREF(args);
    Py_XDECREF(kwargs);
    Py_XDECREF(result);
    return result != NULL ? 0 : -1;
}

// The call replaced the copy's root element itself — encrypt_xml with
// Type=Element on the document root, decrypt of a root <EncryptedData/>.
// lxml offers no way to swap a document's root element (_ElementTree._setroot
// only rebinds that one Python object; the document keeps its root), so the
// live element is morphed in place into `fresh`, the re-parsed replacement,
// through lxml's public API: emptied and stripped of every namespace
// declaration, given exactly the declarations of `fresh` (a temporary child
// pins the default namespace, which cleanup_namespaces would otherwise drop
// as unused before the tag can use it — the tag setter itself never declares
// a default namespace), then renamed and refilled. The children go through
// lxml's usual namespace reconciliation, like every graft. The live proxy
// thus *becomes* the replacement, where the raw path leaves the caller's old
// root proxy (and any _ElementTree holding it) detached and stale.
static int PyXmlSec_LxmlShadowMorphRoot(PyObject* live, PyObject* fresh) {
    PyObject* tag = NULL;
    PyObject* tail = NULL;
    PyObject* nsmap = NULL;
    PyObject* keep = NULL;
    PyObject* pin = NULL;
    PyObject* attrib = NULL;
    PyObject* fresh_attrib = NULL;
    PyObject* text = NULL;
    PyObject* children = NULL;
    PyObject* tmp = NULL;
    PyObject* key;
    PyObject* href;
    Py_ssize_t pos = 0;
    const char* local;
    int rv = -1;

    // Empty the element and give it a namespace-free name (the tail is not
    // the call's to change), so that every old declaration is unused and
    // cleanup_namespaces drops it — a conflicting old prefix would otherwise
    // block the new declaration.
    tag = PyObject_GetAttrString(fresh, "tag");
    tail = PyObject_GetAttrString(live, "tail");
    if (tag == NULL || tail == NULL || (local = PyUnicode_AsUTF8(tag)) == NULL) {
        goto DONE;
    }
    if (strchr(local, '}') != NULL) {
        local = strchr(local, '}') + 1;
    }
    tmp = PyObject_CallMethod(live, "clear", NULL);
    if (tmp == NULL || PyObject_SetAttrString(live, "tail", tail) < 0) {
        goto DONE;
    }
    Py_CLEAR(tmp);
    tmp = PyUnicode_FromString(local);
    if (tmp == NULL || PyObject_SetAttrString(live, "tag", tmp) < 0) {
        goto DONE;
    }
    Py_CLEAR(tmp);
    if (PyXmlSec_LxmlCleanupNamespaces(live, NULL, NULL) < 0) {
        goto DONE;
    }

    // Declare exactly the replacement's namespaces.
    nsmap = PyObject_GetAttrString(fresh, "nsmap");
    keep = PyList_New(0);
    if (nsmap == NULL || keep == NULL) {
        goto DONE;
    }
    if (!PyDict_Check(nsmap)) {
        PyErr_SetString(PyXmlSec_InternalError, "unexpected nsmap.");
        goto DONE;
    }
    while (PyDict_Next(nsmap, &pos, &key, &href)) {
        if (key == Py_None) {
            tmp = PyUnicode_FromFormat("{%U}pin", href);
            pin = tmp != NULL ? PyObject_CallMethod(live, "makeelement", "O", tmp) : NULL;
            Py_CLEAR(tmp);
            tmp = pin != NULL ? PyObject_CallMethod(live, "append", "O", pin) : NULL;
            if (tmp == NULL) {
                goto DONE;
            }
            Py_CLEAR(tmp);
        } else if (PyList_Append(keep, key) < 0) {
            goto DONE;
        }
    }
    if (PyXmlSec_LxmlCleanupNamespaces(live, nsmap, keep) < 0) {
        goto DONE;
    }

    // Rename and refill.
    if (PyObject_SetAttrString(live, "tag", tag) < 0) {
        goto DONE;
    }
    attrib = PyObject_GetAttrString(live, "attrib");
    fresh_attrib = PyObject_GetAttrString(fresh, "attrib");
    tmp = attrib != NULL && fresh_attrib != NULL ? PyObject_CallMethod(attrib, "update", "O", fresh_attrib) : NULL;
    if (tmp == NULL) {
        goto DONE;
    }
    Py_CLEAR(tmp);
    if (pin != NULL) {
        tmp = PyObject_CallMethod(live, "remove", "O", pin);
        if (tmp == NULL) {
            goto DONE;
        }
        Py_CLEAR(tmp);
    }
    text = PyObject_GetAttrString(fresh, "text");
    if (text == NULL || PyObject_SetAttrString(live, "text", text) < 0) {
        goto DONE;
    }
    children = PySequence_List(fresh);
    tmp = children != NULL ? PyObject_CallMethod(live, "extend", "O", children) : NULL;
    if (tmp == NULL) {
        goto DONE;
    }
    rv = 0;

DONE:
    Py_XDECREF(tag);
    Py_XDECREF(tail);
    Py_XDECREF(nsmap);
    Py_XDECREF(keep);
    Py_XDECREF(pin);
    Py_XDECREF(attrib);
    Py_XDECREF(fresh_attrib);
    Py_XDECREF(text);
    Py_XDECREF(children);
    Py_XDECREF(tmp);
    return rv;
}

// Applies every change in the copy to the live tree. Does not release the
// copy. Returns 0, or -1 with an exception set.
static int PyXmlSec_LxmlShadowReflectSites(PyXmlSec_LxmlShadow* shadow) {
    PyXmlSec_LxmlShadowSiteList list = {NULL, 0, 0, NULL, shadow};
    PyObject* copy_root = NULL;
    int i;
    int rv = -1;

    // Re-fetch the root: replacement operations may swap nodes at the top.
    list.top = xmlDocGetRootElement(shadow->doc);
    if (list.top == NULL) {
        PyErr_SetString(PyXmlSec_InternalError, "unexpected mutation site.");
        goto DONE;
    }
    if (!PYXMLSEC_SHADOW_TAGGED(shadow, list.top)) {
        // A fresh root: the call replaced the root itself, so there are no
        // sites to graft — the live root is morphed into it wholesale. lxml
        // holds one element (plus comments and PIs) at document level, so a
        // root replaced by anything else (a Type=Content decryption of the
        // root) cannot be reflected.
        xmlNodePtr n;
        int elements = 0;
        int others = 0;
        for (n = shadow->doc->children; n != NULL; n = n->next) {
            if (n->type == XML_ELEMENT_NODE) {
                ++elements;
            } else if (n->type != XML_COMMENT_NODE && n->type != XML_PI_NODE && n->type != XML_DTD_NODE) {
                ++others;
            }
        }
        if (elements != 1 || others != 0) {
            PyErr_SetString(PyXmlSec_Error, "the document root was replaced by content that is not a single element");
            goto DONE;
        }
        copy_root = PyXmlSec_LxmlShadowDumpCopy(shadow);
        if (copy_root != NULL) {
            rv = PyXmlSec_LxmlShadowMorphRoot((PyObject*)shadow->element, copy_root);
        }
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
    if (PYXMLSEC_SHADOW_TAGGED(shadow, res)) {
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
    tdoc = PyXmlSec_LxmlShadowParse(bytes, NULL, "cannot make a private copy of the element.");
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
