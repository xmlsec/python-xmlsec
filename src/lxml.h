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

// Serializes an lxml element (and its subtree) to a bytes object using lxml's
// own libxml2. This is the ABI-safe way to read a tree owned by lxml: only the
// resulting bytes cross over to xmlsec's libxml2, never raw node pointers.
// Returns a new reference, or NULL (with an exception set) on failure.
PyObject* PyXmlSec_LxmlElementToBytes(PyObject* element);

// Parses bytes into a fresh lxml element using lxml's own libxml2, so the
// returned node is owned and managed by lxml. Returns a new reference, or NULL
// (with an exception set) on failure.
PyObject* PyXmlSec_LxmlElementFromBytes(PyObject* data);

// Performs the actual xmlsec mutation on a private, xmlsec-owned copy of an
// element. `root` is the copy's root element (the equivalent of the original
// `element->_c_node`); `ctx` carries the call's extra arguments. Must return the
// node it created, or NULL on failure (with the xmlsec error already recorded).
typedef xmlNodePtr (*PyXmlSec_LxmlXmlSecOp)(xmlNodePtr root, void* ctx);

// ABI-safe replacement for the "call an xmlSecTmpl*Add* function on `element`'s
// raw node, then wrap the returned node with elementFactory" pattern (see
// https://github.com/xmlsec/python-xmlsec/issues/356). Serializes `element`,
// runs `op` on a throwaway xmlsec-owned copy, then reflects the node `op`
// produced back into `element`'s live lxml tree and returns it as a new lxml
// _Element. Only bytes cross the lxml/xmlsec boundary, never raw pointers.
// Returns a new reference, or NULL with an exception set; `error` is the message
// raised when `op` returns NULL.
//
// Assumes `op` appends exactly one new node beneath a parent that already exists
// in `element` (true for the xmlSecTmpl*Add* family). Find-or-create ops
// (xmlSecTmpl*Ensure*) and ops that also create intermediate ancestors need
// extra handling — see CLAUDE.md.
PyObject* PyXmlSec_LxmlAddChildViaXmlSec(
    PyXmlSec_LxmlElementPtr element, PyXmlSec_LxmlXmlSecOp op, void* ctx, const char* error);

// get version numbers for libxml2 both compiled and loaded
long PyXmlSec_GetLibXmlVersionMajor();
long PyXmlSec_GetLibXmlVersionMinor();
long PyXmlSec_GetLibXmlVersionPatch();

long PyXmlSec_GetLibXmlCompiledVersionMajor();
long PyXmlSec_GetLibXmlCompiledVersionMinor();
long PyXmlSec_GetLibXmlCompiledVersionPatch();

#endif // __PYXMLSEC_LXML_H__
