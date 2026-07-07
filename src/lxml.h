// Copyright (c) 2017 Ryan Leckey
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef __PYXMLSEC_LXML_H__
#define __PYXMLSEC_LXML_H__

#include "platform.h"

#include <libxml/tree.h>
#include <libxml/valid.h>

#include <lxml-version.h>
#include <etree.h>

typedef struct LxmlElement* PyXmlSec_LxmlElementPtr;
typedef struct LxmlDocument* PyXmlSec_LxmlDocumentPtr;

// checks that xnode is Element
int PyXmlSec_IsElement(xmlNodePtr xnode);
// creates a new element
PyXmlSec_LxmlElementPtr PyXmlSec_elementFactory(PyXmlSec_LxmlDocumentPtr doc, xmlNodePtr node);

// converts o to PyObject, None object is not allowed, does not increment ref_counts
int PyXmlSec_LxmlElementConverter(PyObject* o, PyXmlSec_LxmlElementPtr* p);

// A "shadow" is a private copy of an lxml element, owned by the libxml2 this
// extension links, so that an xmlsec call never touches a node allocated by
// lxml's (possibly different) libxml2 — only serialized bytes cross between
// the two libraries (https://github.com/xmlsec/python-xmlsec/issues/356).
//
// Usage (see template.c):
//
//     PyXmlSec_LxmlShadow shadow;
//     if (PyXmlSec_LxmlShadowBegin(&shadow, node) < 0) goto ON_FAIL;
//     Py_BEGIN_ALLOW_THREADS;
//     res = xmlSecTmplSignatureAddReference(shadow.root, ...);
//     Py_END_ALLOW_THREADS;
//     result = PyXmlSec_LxmlShadowEnd(&shadow, res, "cannot add reference.");
//
// Begin serializes `element` with lxml's own libxml2 and re-parses the bytes
// with ours into `root`/`doc`. The caller then runs exactly one xmlsec call
// against `root` (nothing else; Python may not run between Begin and End) and
// hands the returned node to End, which reflects whatever the call did back
// into the live lxml tree and returns the lxml element corresponding to that
// node (a new reference), or NULL with an exception set (`error` is raised
// when the node is NULL). End must be called exactly once after a successful
// Begin; it always releases the copy.
//
// Fast path: when lxml links the same libxml2 as this extension (the
// import-time version check passed), no copy is needed — Begin aliases the
// live node into `root` (leaving `doc` NULL) and End just wraps the result,
// which is the long-standing direct behavior with zero overhead. Setting
// PYXMLSEC_FORCE_SHADOW in the environment forces the shadow path even on
// matched libraries; CI uses it to keep that path exercised.
//
// The reflection covers the whole xmlSecTmpl* family: a new subtree grafted at
// the position xmlsec chose (including intermediate nodes like <Transforms>
// and the "\n" formatting text around it), or — for find-or-create calls that
// added nothing — the already-existing element plus any attributes the call
// set on it. It assumes the call mutates at most one place in the tree;
// multi-site calls (sign, encrypt) use ReflectAll below instead.
typedef struct {
    PyXmlSec_LxmlElementPtr element;  // borrowed; the live lxml element (BeginDoc: the live root)
    PyObject* owned;                  // reference released when the shadow ends (BeginDoc's root proxy)
    xmlDocPtr doc;                    // the private copy; owned by the shadow
    xmlNodePtr root;                  // doc's root element (the copy of element)
} PyXmlSec_LxmlShadow;

int PyXmlSec_LxmlShadowBegin(PyXmlSec_LxmlShadow* shadow, PyXmlSec_LxmlElementPtr element);
PyObject* PyXmlSec_LxmlShadowEnd(PyXmlSec_LxmlShadow* shadow, xmlNodePtr res, const char* error);

// Non-zero when the shadow path is on (mismatched libxml2 or PYXMLSEC_FORCE_SHADOW).
// Only the few call sites whose *semantics* differ per mode (ID registration,
// encrypt/decrypt replacement) may branch on this; everything else goes through
// the Begin/End pairs, which encapsulate both paths.
int PyXmlSec_LxmlShadowIsActive(void);

// Whole-document shadow, for xmlsec calls that read or mutate beyond the
// element's subtree (sign/verify, encrypt/decrypt, find_parent). Serializes the
// element's whole tree (element.getroottree()), so ID references resolve and
// comments/PIs outside the root survive. `*target` receives the copy's node
// corresponding to `element` (the live node itself on the fast path);
// `shadow.element` becomes the live *root*, so the End/Reflect helpers map
// copy paths from the copy root onto it.
int PyXmlSec_LxmlShadowBeginDoc(PyXmlSec_LxmlShadow* shadow, PyXmlSec_LxmlElementPtr element, xmlNodePtr* target);

// Create-shape (template.create, encrypted_data_create): the xmlsec call only
// needs a document to allocate a *detached* subtree in. Begin returns that
// document — the element's own on the fast path, a private empty one on the
// shadow path — and End reflects the result as a new detached lxml element
// (no live-tree graft). NULL from Begin means an exception is set.
xmlDocPtr PyXmlSec_LxmlShadowBeginNewDoc(PyXmlSec_LxmlShadow* shadow, PyXmlSec_LxmlElementPtr element);
PyObject* PyXmlSec_LxmlShadowEndNewDoc(PyXmlSec_LxmlShadow* shadow, xmlNodePtr res, const char* error);

// End for read-only finders: maps `res` (a pre-existing node in the copy) back
// to the live lxml element; returns None when res is NULL (not found — no
// exception). Always releases the copy.
PyObject* PyXmlSec_LxmlShadowEndFind(PyXmlSec_LxmlShadow* shadow, xmlNodePtr res);

// End for find-or-create calls that may mutate the found node in ways the
// attribute sync cannot express (encrypted_data_ensure_key_info renames the
// namespace prefix): a fresh `res` behaves exactly like End; a pre-existing
// one is reflected by *replacing* the live element with the copy's version,
// so the returned element is a new object rather than the original proxy.
PyObject* PyXmlSec_LxmlShadowEndReplace(PyXmlSec_LxmlShadow* shadow, xmlNodePtr res, const char* error);

// First node the xmlsec call created (document order), for calls that return
// only a status int: pass the result to End. Falls back to shadow->root when
// the call created nothing (End then takes its find-or-create path).
xmlNodePtr PyXmlSec_LxmlShadowFindFresh(PyXmlSec_LxmlShadow* shadow);

// Multi-site End (sign, encrypt_binary/uri and the replacement reflects):
// scans the copy for *all* topmost nodes the xmlsec call created and grafts
// each back into the live tree — new subtrees via insert, new/changed text via
// the text slots. Returns 0, or -1 with an exception set. Like End, it always
// releases the copy; there is no result node (the call sites know what to
// return). No-op on the fast path.
int PyXmlSec_LxmlShadowReflectAll(PyXmlSec_LxmlShadow* shadow);

// Serializes the mutated copy and re-parses it with lxml, returning the root
// element of that detached parse (new reference). Used by the replacement
// reflects (enc.c) when the copy's root itself was replaced. Does not release
// the copy.
PyObject* PyXmlSec_LxmlShadowDumpCopy(PyXmlSec_LxmlShadow* shadow);

// Re-serializes `element` (a live lxml element) into the shadow's private copy
// as a fresh (untagged) detached subtree — encrypt_xml's template import.
// Shadow path only (shadow->doc != NULL).
xmlNodePtr PyXmlSec_LxmlShadowImportElement(PyXmlSec_LxmlShadow* shadow, PyXmlSec_LxmlElementPtr element);

// Releases the copy without reflecting anything (verify, error paths).
// Safe to call after any successful Begin*; End* call it internally.
void PyXmlSec_LxmlShadowDiscard(PyXmlSec_LxmlShadow* shadow);

// Shadow-mode ID registration (issue #356): register_id/add_ids cannot write
// lxml's ID hash with our libxml2, so they record the id-attribute specs per
// document here, and every whole-document Begin replays them onto the copy
// (ReplayIds) so that #id references resolve during sign/verify/decrypt.
// The registry is keyed by the lxml document's identity; replay scans the
// whole copy for the recorded attribute names (a superset of the single-node
// registration on the fast path — see lxml.c).
int PyXmlSec_LxmlShadowRecordId(PyXmlSec_LxmlElementPtr element, const char* name, const char* ns);
int PyXmlSec_LxmlShadowReplayIds(PyXmlSec_LxmlShadow* shadow);

// get version numbers for libxml2 both compiled and loaded
long PyXmlSec_GetLibXmlVersionMajor();
long PyXmlSec_GetLibXmlVersionMinor();
long PyXmlSec_GetLibXmlVersionPatch();

long PyXmlSec_GetLibXmlCompiledVersionMajor();
long PyXmlSec_GetLibXmlCompiledVersionMinor();
long PyXmlSec_GetLibXmlCompiledVersionPatch();

#endif // __PYXMLSEC_LXML_H__
