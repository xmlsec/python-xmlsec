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
// Every binding follows the same four lines (see template.c):
//
//     PyXmlSec_LxmlShadow shadow;
//     if (PyXmlSec_LxmlShadowBegin(&shadow, node) < 0) goto ON_FAIL;
//     Py_BEGIN_ALLOW_THREADS;
//     res = xmlSecTmplSignatureAddReference(shadow.root, ...);
//     Py_END_ALLOW_THREADS;
//     result = PyXmlSec_LxmlShadowEnd(&shadow, res, "cannot add reference.");
//
// Three Begin flavours make the copy: of the element's subtree (Begin), of
// its whole document (BeginDoc — for calls that follow references or walk
// upward), or of nothing (BeginNewDoc — for calls that only need a document
// to build a detached subtree in). The caller then runs exactly one xmlsec
// call against the copy (nothing else; Python may not run between Begin and
// End) and hands its result to one of the End functions, which reflect every
// change the call made back into the live lxml tree and always release the
// copy:
//
//   End      returns the lxml element for a result node (new reference):
//            grafted into the live tree if the call created it, or the
//            existing live element (with the attributes / prefix the call
//            changed) if it already existed. NULL raises `error`.
//   EndFind  the same for read-only finders; a NULL result is None, not an
//            error.
//   Reflect  for calls that return only a status: rv < 0 raises `error`,
//            otherwise the changes are reflected.
//   Discard  releases the copy without reflecting (read-only calls such as
//            verify, and error paths before End).
//
// Fast path: when lxml links the same libxml2 as this extension (the
// import-time version check passed), no copy is made — Begin aliases the
// live node into `root` (leaving `doc` NULL) and End just wraps the result,
// which is the long-standing direct behaviour with zero overhead. Setting
// PYXMLSEC_FORCE_SHADOW in the environment forces the shadow path even on
// matched libraries; CI uses it to keep that path exercised.
typedef struct {
    PyXmlSec_LxmlElementPtr element;  // borrowed; the live element copy paths start from (BeginDoc: the live root)
    PyObject* owned;                  // reference released when the shadow ends (BeginDoc's root proxy)
    xmlDocPtr doc;                    // the private copy, owned by the shadow; NULL on the fast path
    xmlNodePtr root;                  // doc's root element, the copy of `element`; NULL for BeginNewDoc
} PyXmlSec_LxmlShadow;

// Subtree copy: `shadow.root` is the copy of `element`.
int PyXmlSec_LxmlShadowBegin(PyXmlSec_LxmlShadow* shadow, PyXmlSec_LxmlElementPtr element);

// Whole-document copy, for calls that read or mutate beyond the element's
// subtree (sign/verify, encrypt/decrypt, find_parent). Serializes
// element.getroottree() — comments/PIs outside the root and the internal DTD
// subset survive — and replays the IDs registered for the document
// (RecordId) onto the copy so that #id references resolve. `*target`
// receives the copy's counterpart of `element` (the live node itself on the
// fast path); `shadow.root` / `shadow.element` become the copy root / the
// live root, which is what the End functions map paths between.
int PyXmlSec_LxmlShadowBeginDoc(PyXmlSec_LxmlShadow* shadow, PyXmlSec_LxmlElementPtr element, xmlNodePtr* target);

// Create shape (template.create, encrypted_data_create): the call only needs
// a document to build a *detached* subtree in. Returns that document — the
// element's own on the fast path, a private empty one on the shadow path —
// or NULL with an exception set. End then returns the result as a new
// detached lxml element (in a document of its own until it is grafted; the
// raw path's "detached node inside the source document" has no lxml
// equivalent).
xmlDocPtr PyXmlSec_LxmlShadowBeginNewDoc(PyXmlSec_LxmlShadow* shadow, PyXmlSec_LxmlElementPtr element);

// Reflects every change the call made and returns the lxml element for
// `res` (new reference), or NULL with an exception set (`error` is raised
// when res is NULL). Works after any Begin flavour.
PyObject* PyXmlSec_LxmlShadowEnd(PyXmlSec_LxmlShadow* shadow, xmlNodePtr res, const char* error);

// End for read-only finders: maps `res` (a pre-existing node in the copy)
// back to the live element; returns None when res is NULL (not found).
PyObject* PyXmlSec_LxmlShadowEndFind(PyXmlSec_LxmlShadow* shadow, xmlNodePtr res);

// End for calls that return only a status (sign, encrypt, ...): rv < 0
// raises `error` and returns -1; otherwise every change the call made is
// reflected. Returns 0, or -1 with an exception set. No-op on the fast path
// except for raising.
int PyXmlSec_LxmlShadowReflect(PyXmlSec_LxmlShadow* shadow, int rv, const char* error);

// Releases the copy without reflecting anything (verify, error paths before
// End). Safe to call after any successful Begin; the End functions call it.
void PyXmlSec_LxmlShadowDiscard(PyXmlSec_LxmlShadow* shadow);

// Non-zero when the shadow path is on (mismatched libxml2 or
// PYXMLSEC_FORCE_SHADOW). Only the few call sites whose *semantics* differ
// per mode (ID registration, encrypt/decrypt replacement) may branch on
// this; everything else goes through Begin/End, which encapsulate both paths.
int PyXmlSec_LxmlShadowIsActive(void);

// Re-serializes `element` (a live lxml element) into the shadow's private
// copy as a fresh (untagged) detached subtree — encrypt_xml's template
// import. Shadow path only (shadow->doc != NULL).
xmlNodePtr PyXmlSec_LxmlShadowImportElement(PyXmlSec_LxmlShadow* shadow, PyXmlSec_LxmlElementPtr element);

// Shadow-mode ID registration (issue #356): register_id/add_ids cannot write
// lxml's ID hash with our libxml2, so they record the id-attribute spec for
// the element's document here, and every BeginDoc replays the recorded specs
// onto its copy. The replay scans the whole copy for the recorded attribute
// names — a superset of the single-node registration on the fast path.
int PyXmlSec_LxmlShadowRecordId(PyXmlSec_LxmlElementPtr element, const char* name, const char* ns);

// get version numbers for libxml2 both compiled and loaded
long PyXmlSec_GetLibXmlVersionMajor();
long PyXmlSec_GetLibXmlVersionMinor();
long PyXmlSec_GetLibXmlVersionPatch();

long PyXmlSec_GetLibXmlCompiledVersionMajor();
long PyXmlSec_GetLibXmlCompiledVersionMinor();
long PyXmlSec_GetLibXmlCompiledVersionPatch();

#endif // __PYXMLSEC_LXML_H__
