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

// get version numbers for libxml2 both compiled and loaded
long PyXmlSec_GetLibXmlVersionMajor();
long PyXmlSec_GetLibXmlVersionMinor();
long PyXmlSec_GetLibXmlVersionPatch();

long PyXmlSec_GetLibXmlCompiledVersionMajor();
long PyXmlSec_GetLibXmlCompiledVersionMinor();
long PyXmlSec_GetLibXmlCompiledVersionPatch();

#endif // __PYXMLSEC_LXML_H__
