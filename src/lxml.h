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
// The reflection covers the whole xmlSecTmpl* family: a new subtree grafted at
// the position xmlsec chose (including intermediate nodes like <Transforms>
// and the "\n" formatting text around it), or — for find-or-create calls that
// added nothing — the already-existing element plus any attributes the call
// set on it. It assumes the call mutates at most one place in the tree.
typedef struct {
    PyXmlSec_LxmlElementPtr element;  // borrowed; the live lxml element
    xmlDocPtr doc;                    // the private copy; owned by the shadow
    xmlNodePtr root;                  // doc's root element (the copy of element)
} PyXmlSec_LxmlShadow;

int PyXmlSec_LxmlShadowBegin(PyXmlSec_LxmlShadow* shadow, PyXmlSec_LxmlElementPtr element);
PyObject* PyXmlSec_LxmlShadowEnd(PyXmlSec_LxmlShadow* shadow, xmlNodePtr res, const char* error);

// get version numbers for libxml2 both compiled and loaded
long PyXmlSec_GetLibXmlVersionMajor();
long PyXmlSec_GetLibXmlVersionMinor();
long PyXmlSec_GetLibXmlVersionPatch();

long PyXmlSec_GetLibXmlCompiledVersionMajor();
long PyXmlSec_GetLibXmlCompiledVersionMinor();
long PyXmlSec_GetLibXmlCompiledVersionPatch();

#endif // __PYXMLSEC_LXML_H__
