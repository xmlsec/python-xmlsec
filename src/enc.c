// Copyright (c) 2017 Ryan Leckey
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include "common.h"
#include "platform.h"
#include "exception.h"
#include "constants.h"
#include "keys.h"
#include "lxml.h"

#include <xmlsec/xmlenc.h>
#include <xmlsec/xmltree.h>

// Backwards compatibility with xmlsec 1.2
#ifndef XMLSEC_KEYINFO_FLAGS_LAX_KEY_SEARCH
#define XMLSEC_KEYINFO_FLAGS_LAX_KEY_SEARCH 0x00008000
#endif

typedef struct {
    PyObject_HEAD
    xmlSecEncCtxPtr handle;
    PyXmlSec_KeysManager* manager;
} PyXmlSec_EncryptionContext;

static PyObject* PyXmlSec_EncryptionContext__new__(PyTypeObject *type, PyObject *args, PyObject *kwargs) {
    PyXmlSec_EncryptionContext* ctx = (PyXmlSec_EncryptionContext*)PyType_GenericNew(type, args, kwargs);
    PYXMLSEC_DEBUGF("%p: new enc context", ctx);
    if (ctx != NULL) {
        ctx->handle = NULL;
        ctx->manager = NULL;
    }
    return (PyObject*)(ctx);
}

static int PyXmlSec_EncryptionContext__init__(PyObject* self, PyObject* args, PyObject* kwargs) {
    static char *kwlist[] = { "manager", NULL};

    PyXmlSec_KeysManager* manager = NULL;
    PyXmlSec_EncryptionContext* ctx = (PyXmlSec_EncryptionContext*)self;

    PYXMLSEC_DEBUGF("%p: init enc context", self);
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|O&:__init__", kwlist, PyXmlSec_KeysManagerConvert, &manager)) {
        goto ON_FAIL;
    }
    ctx->handle = xmlSecEncCtxCreate(manager != NULL ? manager->handle : NULL);
    if (ctx->handle == NULL) {
        PyXmlSec_SetLastError("failed to create the encryption context");
        goto ON_FAIL;
    }
    ctx->manager = manager;
    PYXMLSEC_DEBUGF("%p: init enc context - ok, manager - %p", self, manager);

    // xmlsec 1.3 changed the key search to strict mode, causing various examples
    // in the docs to fail. For backwards compatibility, this changes it back to
    // lax mode for now.
    ctx->handle->keyInfoReadCtx.flags = XMLSEC_KEYINFO_FLAGS_LAX_KEY_SEARCH;
    ctx->handle->keyInfoWriteCtx.flags = XMLSEC_KEYINFO_FLAGS_LAX_KEY_SEARCH;

    return 0;
ON_FAIL:
    PYXMLSEC_DEBUGF("%p: init enc context - failed", self);
    Py_XDECREF(manager);
    return -1;
}

static void PyXmlSec_EncryptionContext__del__(PyObject* self) {
    PyXmlSec_EncryptionContext* ctx = (PyXmlSec_EncryptionContext*)self;

    PYXMLSEC_DEBUGF("%p: delete enc context", self);

    if (ctx->handle != NULL) {
        xmlSecEncCtxDestroy(ctx->handle);
    }
    // release manager object
    Py_XDECREF(ctx->manager);
    Py_TYPE(self)->tp_free(self);
}

static const char PyXmlSec_EncryptionContextKey__doc__[] = "Encryption key.\n";
static PyObject* PyXmlSec_EncryptionContextKeyGet(PyObject* self, void* closure) {
    PyXmlSec_EncryptionContext* ctx = ((PyXmlSec_EncryptionContext*)self);
    PyXmlSec_Key* key;

    if (ctx->handle->encKey == NULL) {
        Py_RETURN_NONE;
    }

    key = PyXmlSec_NewKey();
    key->handle = ctx->handle->encKey;
    key->is_own = 0;
    return (PyObject*)key;
}

static int PyXmlSec_EncryptionContextKeySet(PyObject* self, PyObject* value, void* closure) {
    PyXmlSec_EncryptionContext* ctx = (PyXmlSec_EncryptionContext*)self;
    PyXmlSec_Key* key;

    PYXMLSEC_DEBUGF("%p, %p", self, value);

    if (value == NULL) {  // key deletion
        if (ctx->handle->encKey != NULL) {
            xmlSecKeyDestroy(ctx->handle->encKey);
            ctx->handle->encKey = NULL;
        }
        return 0;
    }

    if (!PyObject_IsInstance(value, (PyObject*)PyXmlSec_KeyType)) {
        PyErr_SetString(PyExc_TypeError, "instance of *xmlsec.Key* expected.");
        return -1;
    }

    key = (PyXmlSec_Key*)value;
    if (key->handle == NULL) {
        PyErr_SetString(PyExc_TypeError, "empty key.");
        return -1;
    }

    if (ctx->handle->encKey != NULL) {
        xmlSecKeyDestroy(ctx->handle->encKey);
    }

    ctx->handle->encKey = xmlSecKeyDuplicate(key->handle);
    if (ctx->handle->encKey == NULL) {
        PyXmlSec_SetLastError("failed to duplicate key");
        return -1;
    }
    return 0;
}

static const char PyXmlSec_EncryptionContextReset__doc__[] = \
    "reset() -> None\n"\
    "Reset this context, user settings are not touched.\n";
static PyObject* PyXmlSec_EncryptionContextReset(PyObject* self, PyObject* args, PyObject* kwargs) {
    PyXmlSec_EncryptionContext* ctx = (PyXmlSec_EncryptionContext*)self;

    PYXMLSEC_DEBUGF("%p: reset context - start", self);
    Py_BEGIN_ALLOW_THREADS;
    xmlSecEncCtxReset(ctx->handle);
    PYXMLSEC_DUMP(xmlSecEncCtxDebugDump, ctx->handle);
    Py_END_ALLOW_THREADS;
    PYXMLSEC_DEBUGF("%p: reset context - ok", self);
    Py_RETURN_NONE;
}

static const char PyXmlSec_EncryptionContextEncryptBinary__doc__[] = \
    "encrypt_binary(template, data) -> lxml.etree._Element\n"
    "Encrypts binary ``data`` according to ``EncryptedData`` template ``template``.\n\n"
    ".. note:: ``template`` is modified in place.\n\n"
    ":param template: the pointer to :xml:`<enc:EncryptedData/>` template node\n"
    ":type template: :class:`lxml.etree._Element`\n"
    ":param data: the data\n"
    ":type data: :class:`bytes`\n"
    ":return: the resulting :xml:`<enc:EncryptedData/>` subtree\n"
    ":rtype: :class:`lxml.etree._Element`";
static PyObject* PyXmlSec_EncryptionContextEncryptBinary(PyObject* self, PyObject* args, PyObject* kwargs) {
    static char *kwlist[] = { "template", "data", NULL};

    PyXmlSec_EncryptionContext* ctx = (PyXmlSec_EncryptionContext*)self;
    PyXmlSec_LxmlElementPtr template = NULL;
    const char* data = NULL;
    Py_ssize_t data_size = 0;
    PyXmlSec_LxmlShadow shadow;
    int rv;

    PYXMLSEC_DEBUGF("%p: encrypt_binary - start", self);
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O&s#:encrypt_binary", kwlist,
        PyXmlSec_LxmlElementConverter, &template, &data, &data_size))
    {
        goto ON_FAIL;
    }

    // The encryption fills several places inside the template subtree
    // (CipherValue, KeyInfo/EncryptedKey); the reflect carries them all back
    // (issue #356).
    if (PyXmlSec_LxmlShadowBegin(&shadow, template) < 0) {
        goto ON_FAIL;
    }
    Py_BEGIN_ALLOW_THREADS;
    rv = xmlSecEncCtxBinaryEncrypt(ctx->handle, shadow.root, (const xmlSecByte*)data, (xmlSecSize)data_size);
    PYXMLSEC_DUMP(xmlSecEncCtxDebugDump, ctx->handle);
    Py_END_ALLOW_THREADS;

    if (PyXmlSec_LxmlShadowReflect(&shadow, rv, "failed to encrypt binary") < 0) {
        goto ON_FAIL;
    }
    Py_INCREF(template);
    PYXMLSEC_DEBUGF("%p: encrypt_binary - ok", self);

    return (PyObject*)template;
ON_FAIL:
    PYXMLSEC_DEBUGF("%p: encrypt_binary - fail", self);
    return NULL;
}

// release the replaced nodes in a way safe for `lxml`
static void PyXmlSec_ClearReplacedNodes(xmlSecEncCtxPtr ctx, PyXmlSec_LxmlDocumentPtr doc) {
    PyXmlSec_LxmlElementPtr elem;
    // release the replaced nodes in a way safe for `lxml`
    xmlNodePtr n = ctx->replacedNodeList;
    xmlNodePtr nn;

    while (n != NULL) {
        PYXMLSEC_DEBUGF("clear replaced node %p", n);
        nn = n->next;
        // Sever the chain first: lxml releases an element together with the
        // text siblings that follow it, which would free the next node of
        // this list under our feet (Type=Content replaces text nodes too).
        n->next = NULL;
        n->prev = NULL;
        if (PyXmlSec_IsElement(n)) {
            // if n has references, it will not be deleted
            elem = (PyXmlSec_LxmlElementPtr)PyXmlSec_elementFactory(doc, n);
            if (NULL == elem)
                xmlFreeNode(n);
            else
                Py_DECREF(elem);
        } else {
            // text and CDATA nodes never have lxml proxies
            xmlFreeNode(n);
        }
        n = nn;
    }
    ctx->replacedNodeList = NULL;
}

// The raw path hands `xmlSecEncCtxXmlEncrypt` the template node itself
// whenever it belongs to the target's document, and xmlsec *moves* it into
// the target's place. The shadow path encrypts a copy of it instead, so
// without this the live tree would keep the original where it was and the
// document would end up with a second, empty <EncryptedData/> — a tree shape
// that depended on which libxml2 the extension is linked against. Unlink it
// once the reflection is done, leaving its tail text behind the way libxml2's
// `xmlReplaceNode` does, since lxml drops an element's tail together with the
// element. A detached template, or one in another document, is copied on both
// paths and stays where it is. Returns 0, or -1 with an exception set.
static int PyXmlSec_EncryptionContextDropMovedTemplate(PyXmlSec_LxmlElementPtr template, PyXmlSec_LxmlElementPtr node) {
    PyObject* parent = NULL;
    PyObject* tree = NULL;
    PyObject* root = NULL;
    PyObject* top = NULL;
    PyObject* tail = NULL;
    PyObject* prev = NULL;
    PyObject* slot = NULL;
    PyObject* tmp = NULL;
    const char* name = "tail";
    int rv = -1;

    parent = PyObject_CallMethod((PyObject*)template, "getparent", NULL);
    if (parent == NULL) {
        goto DONE;
    }
    if (parent == Py_None) {
        rv = 0;
        goto DONE;
    }

    // Only a template still hanging under the live document root is one the
    // raw path would have moved; one carried off inside the subtree the
    // encryption replaced, or one belonging to another document, is not.
    tree = PyObject_CallMethod((PyObject*)node, "getroottree", NULL);
    root = tree != NULL ? PyObject_CallMethod(tree, "getroot", NULL) : NULL;
    if (root == NULL) {
        goto DONE;
    }
    top = parent;
    Py_INCREF(top);
    for (;;) {
        tmp = PyObject_CallMethod(top, "getparent", NULL);
        if (tmp == NULL) {
            goto DONE;
        }
        if (tmp == Py_None) {
            Py_CLEAR(tmp);
            break;
        }
        Py_DECREF(top);
        top = tmp;
        tmp = NULL;
    }
    if (top != root) {
        rv = 0;
        goto DONE;
    }

    tail = PyObject_GetAttrString((PyObject*)template, "tail");
    if (tail == NULL) {
        goto DONE;
    }
    if (tail != Py_None) {
        prev = PyObject_CallMethod((PyObject*)template, "getprevious", NULL);
        if (prev == NULL) {
            goto DONE;
        }
        if (prev == Py_None) {
            // first child: the text libxml2 would leave behind belongs to the
            // parent's own text slot
            Py_DECREF(prev);
            Py_INCREF(parent);
            prev = parent;
            name = "text";
        }
        slot = PyObject_GetAttrString(prev, name);
        if (slot == NULL) {
            goto DONE;
        }
        if (slot != Py_None) {
            tmp = PyUnicode_Concat(slot, tail);
            if (tmp == NULL) {
                goto DONE;
            }
            Py_DECREF(tail);
            tail = tmp;
            tmp = NULL;
        }
        if (PyObject_SetAttrString(prev, name, tail) < 0) {
            goto DONE;
        }
    }
    tmp = PyObject_CallMethod(parent, "remove", "O", template);
    if (tmp == NULL) {
        goto DONE;
    }
    rv = 0;

DONE:
    Py_XDECREF(parent);
    Py_XDECREF(tree);
    Py_XDECREF(root);
    Py_XDECREF(top);
    Py_XDECREF(tail);
    Py_XDECREF(prev);
    Py_XDECREF(slot);
    Py_XDECREF(tmp);
    return rv;
}

// Shadow-path body of encrypt_xml (issue #356): the target document and the
// template are both re-parsed into one private copy, the encryption runs
// there, and the replacement is reflected back through lxml — the fresh
// <EncryptedData/> takes the target's place (`Type=Element`; the document
// root is morphed in place, as lxml cannot swap it) or its content
// (`Type=Content`). The live template is unlinked afterwards when the raw
// path would have moved it.
static PyObject* PyXmlSec_EncryptionContextEncryptXmlShadow(PyXmlSec_EncryptionContext* ctx, PyXmlSec_LxmlElementPtr template, PyXmlSec_LxmlElementPtr node) {
    PyXmlSec_LxmlShadow shadow;
    xmlNodePtr target = NULL;
    xmlNodePtr tmpl_copy;
    PyObject* type_value = NULL;
    PyObject* parent = NULL;
    PyObject* result = NULL;
    PyObject* tmp = NULL;
    const char* type_str;
    long idx = -1;
    int is_content = 0;
    int rv;

    type_value = PyObject_CallMethod((PyObject*)template, "get", "s", "Type");
    if (type_value == NULL) {
        return NULL;
    }
    type_str = type_value == Py_None ? NULL : PyUnicode_AsUTF8(type_value);
    if (type_str == NULL || !(strcmp(type_str, (const char*)xmlSecTypeEncElement) == 0
            || strcmp(type_str, (const char*)xmlSecTypeEncContent) == 0)) {
        PyErr_SetString(PyXmlSec_Error, "unsupported `Type`, it should be `element` or `content`");
        goto ON_FAIL;
    }
    is_content = strcmp(type_str, (const char*)xmlSecTypeEncContent) == 0;

    parent = PyObject_CallMethod((PyObject*)node, "getparent", NULL);
    if (parent == NULL) {
        goto ON_FAIL;
    }
    if (parent != Py_None) {
        tmp = PyObject_CallMethod(parent, "index", "O", node);
        if (tmp == NULL) {
            goto ON_FAIL;
        }
        idx = PyLong_AsLong(tmp);
        Py_CLEAR(tmp);
        if (idx < 0) {
            goto ON_FAIL;
        }
    }

    if (PyXmlSec_LxmlShadowBeginDoc(&shadow, node, &target) < 0) {
        goto ON_FAIL;
    }
    tmpl_copy = PyXmlSec_LxmlShadowImportElement(&shadow, template);
    if (tmpl_copy == NULL) {
        PyXmlSec_LxmlShadowDiscard(&shadow);
        goto ON_FAIL;
    }

    // The replaced nodes belong to the private copy: xmlsec must free them
    // itself (with our libxml2) rather than hand them back, because the copy
    // is discarded right after and nothing could release them later.
    ctx->handle->flags &= ~XMLSEC_ENC_RETURN_REPLACED_NODE;

    Py_BEGIN_ALLOW_THREADS;
    rv = xmlSecEncCtxXmlEncrypt(ctx->handle, tmpl_copy, target);
    PYXMLSEC_DUMP(xmlSecEncCtxDebugDump, ctx->handle);
    Py_END_ALLOW_THREADS;

    if (rv < 0) {
        // still detached means the encryption never consumed our template copy
        if (tmpl_copy->parent == NULL) {
            xmlFreeNode(tmpl_copy);
        }
        PyXmlSec_LxmlShadowDiscard(&shadow);
        PyXmlSec_SetLastError("failed to encrypt xml");
        goto ON_FAIL;
    }

    if (is_content) {
        // the node stays; its old content was consumed and replaced by the
        // fresh <EncryptedData/>, which the reflection grafts back in
        Py_ssize_t len = PyObject_Length((PyObject*)node);
        if (len < 0) {
            PyXmlSec_LxmlShadowDiscard(&shadow);
            goto ON_FAIL;
        }
        while (len-- > 0) {
            PyObject* child = PySequence_GetItem((PyObject*)node, 0);
            tmp = child != NULL ? PyObject_CallMethod((PyObject*)node, "remove", "O", child) : NULL;
            Py_XDECREF(child);
            if (tmp == NULL) {
                PyXmlSec_LxmlShadowDiscard(&shadow);
                goto ON_FAIL;
            }
            Py_CLEAR(tmp);
        }
        if (PyXmlSec_LxmlShadowReflect(&shadow, 0, NULL) < 0) {
            goto ON_FAIL;
        }
        result = PySequence_GetItem((PyObject*)node, 0);
        if (result == NULL) {
            goto ON_FAIL;
        }
    } else if (parent == Py_None) {
        // Type=Element on the document root: the reflection morphs the live
        // root in place into the fresh <EncryptedData/>, so the node itself
        // is the result — the new root, as on the raw path
        if (PyXmlSec_LxmlShadowReflect(&shadow, 0, NULL) < 0) {
            goto ON_FAIL;
        }
        result = (PyObject*)node;
        Py_INCREF(result);
    } else {
        // Type=Element: the node itself was consumed and replaced
        tmp = PyObject_CallMethod(parent, "remove", "O", node);
        if (tmp == NULL) {
            PyXmlSec_LxmlShadowDiscard(&shadow);
            goto ON_FAIL;
        }
        Py_CLEAR(tmp);
        if (PyXmlSec_LxmlShadowReflect(&shadow, 0, NULL) < 0) {
            goto ON_FAIL;
        }
        result = PySequence_GetItem(parent, (Py_ssize_t)idx);
        if (result == NULL) {
            goto ON_FAIL;
        }
    }

    if (PyXmlSec_EncryptionContextDropMovedTemplate(template, node) < 0) {
        goto ON_FAIL;
    }

    Py_DECREF(type_value);
    Py_XDECREF(parent);
    return result;

ON_FAIL:
    Py_XDECREF(type_value);
    Py_XDECREF(parent);
    Py_XDECREF(tmp);
    Py_XDECREF(result);
    return NULL;
}

static const char PyXmlSec_EncryptionContextEncryptXml__doc__[] = \
    "encrypt_xml(template, node) -> lxml.etree._Element\n"
    "Encrypts ``node`` using ``template``.\n\n"
    ".. note:: The ``\"Type\"`` attribute of ``template`` decides whether ``node`` itself "
    "(``http://www.w3.org/2001/04/xmlenc#Element``) or its content (``http://www.w3.org/2001/04/xmlenc#Content``) is encrypted.\n"
    "   It must have one of these two values (or an exception is raised).\n"
    "   The operation modifies the tree and removes replaced nodes.\n\n"
    ":param template: the pointer to :xml:`<enc:EncryptedData/>` template node\n\n"
    ":type template: :class:`lxml.etree._Element`\n"
    ":param node: the pointer to node for encryption\n\n"
    ":type node: :class:`lxml.etree._Element`\n"
    ":return: the pointer to newly created :xml:`<enc:EncryptedData/>` node\n"
    ":rtype: :class:`lxml.etree._Element`";
static PyObject* PyXmlSec_EncryptionContextEncryptXml(PyObject* self, PyObject* args, PyObject* kwargs) {
    static char *kwlist[] = { "template", "node", NULL};

    PyXmlSec_EncryptionContext* ctx = (PyXmlSec_EncryptionContext*)self;
    PyXmlSec_LxmlElementPtr template = NULL;
    PyXmlSec_LxmlElementPtr node = NULL;
    xmlNodePtr xnew_node = NULL;
    xmlChar* tmpType = NULL;
    int rv = 0;

    PYXMLSEC_DEBUGF("%p: encrypt_xml - start", self);
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O&O&:encrypt_xml", kwlist,
        PyXmlSec_LxmlElementConverter, &template, PyXmlSec_LxmlElementConverter, &node))
    {
        goto ON_FAIL;
    }

    if (PyXmlSec_LxmlShadowIsActive()) {
        PyObject* result = PyXmlSec_EncryptionContextEncryptXmlShadow(ctx, template, node);
        if (result == NULL) {
            goto ON_FAIL;
        }
        PYXMLSEC_DEBUGF("%p: encrypt_xml - ok", self);
        return result;
    }

    tmpType = xmlGetProp(template->_c_node, XSTR("Type"));
    if (tmpType == NULL || !(xmlStrEqual(tmpType, xmlSecTypeEncElement) || xmlStrEqual(tmpType, xmlSecTypeEncContent))) {
        PyErr_SetString(PyXmlSec_Error, "unsupported `Type`, it should be `element` or `content`");
        goto ON_FAIL;
    }

    // `xmlSecEncCtxXmlEncrypt` will replace the subtree rooted
    //  at `node._c_node` or its children by an extended subtree rooted at "c_node".
    //  We set `XMLSEC_ENC_RETURN_REPLACED_NODE` to prevent deallocation
    //  of the replaced node. This is important as `node` is still referencing it
    ctx->handle->flags = XMLSEC_ENC_RETURN_REPLACED_NODE;

    // try to do all actions whithin single python-free section
    // rv has the following codes, 1 - failed to copy node, -1 - op failed, 0 - success
    Py_BEGIN_ALLOW_THREADS;
    if (template->_doc->_c_doc != node->_doc->_c_doc) {
        // `xmlSecEncCtxEncrypt` expects *template* to belong to the document of *node*
        // if this is not the case, we copy the `libxml2` subtree there.
        xnew_node = xmlDocCopyNode(template->_c_node, node->_doc->_c_doc, 1); // recursive
        if (xnew_node == NULL) {
            rv = 1;
        }
    }
    if (rv == 0 && xmlSecEncCtxXmlEncrypt(ctx->handle, xnew_node != NULL ? xnew_node: template->_c_node, node->_c_node) < 0) {
        rv = -1;
        if (xnew_node != NULL) {
            xmlFreeNode(xnew_node);
            xnew_node = NULL;
        }
    }
    PYXMLSEC_DUMP(xmlSecEncCtxDebugDump, ctx->handle);
    Py_END_ALLOW_THREADS;

    PyXmlSec_ClearReplacedNodes(ctx->handle, node->_doc);
    if (NULL != PyErr_Occurred()) {
        goto ON_FAIL;
    }

    if (rv != 0) {
        if (rv > 0) {
            PyErr_SetString(PyXmlSec_InternalError, "could not copy template tree");
        } else {
            PyXmlSec_SetLastError("failed to encrypt xml");
        }
        goto ON_FAIL;
    }

    xmlFree(tmpType);

    PYXMLSEC_DEBUGF("%p: encrypt_xml - ok", self);
    return (PyObject*)PyXmlSec_elementFactory(node->_doc, xnew_node != NULL ? xnew_node : template->_c_node);
ON_FAIL:
    PYXMLSEC_DEBUGF("%p: encrypt_xml - fail", self);
    xmlFree(tmpType);
    return NULL;
}

static const char PyXmlSec_EncryptionContextEncryptUri__doc__[] = \
    "encrypt_uri(template, uri) -> lxml.etree._Element\n"
    "Encrypts binary data obtained from ``uri`` according to ``template``.\n\n"
    ".. note:: ``template`` is modified in place.\n\n"
    ":param template: the pointer to :xml:`<enc:EncryptedData/>` template node\n"
    ":type template: :class:`lxml.etree._Element`\n"
    ":param uri: the URI\n"
    ":type uri: :class:`str`\n"
    ":return: the resulting :xml:`<enc:EncryptedData/>` subtree\n"
    ":rtype: :class:`lxml.etree._Element`";
static PyObject* PyXmlSec_EncryptionContextEncryptUri(PyObject* self, PyObject* args, PyObject* kwargs) {
    static char *kwlist[] = { "template", "uri", NULL};

    PyXmlSec_EncryptionContext* ctx = (PyXmlSec_EncryptionContext*)self;
    PyXmlSec_LxmlElementPtr template = NULL;
    const char* uri = NULL;
    PyXmlSec_LxmlShadow shadow;
    int rv;

    PYXMLSEC_DEBUGF("%p: encrypt_uri - start", self);
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O&s:encrypt_uri", kwlist, PyXmlSec_LxmlElementConverter, &template, &uri)) {
        goto ON_FAIL;
    }

    if (PyXmlSec_LxmlShadowBegin(&shadow, template) < 0) {
        goto ON_FAIL;
    }
    Py_BEGIN_ALLOW_THREADS;
    rv = xmlSecEncCtxUriEncrypt(ctx->handle, shadow.root, (const xmlSecByte*)uri);
    PYXMLSEC_DUMP(xmlSecEncCtxDebugDump, ctx->handle);
    Py_END_ALLOW_THREADS;

    if (PyXmlSec_LxmlShadowReflect(&shadow, rv, "failed to encrypt URI") < 0) {
        goto ON_FAIL;
    }
    PYXMLSEC_DEBUGF("%p: encrypt_uri - ok", self);
    Py_INCREF(template);
    return (PyObject*)template;
ON_FAIL:
    PYXMLSEC_DEBUGF("%p: encrypt_uri - fail", self);
    return NULL;
}

// Shadow-path body of decrypt (issue #356): whole-document copy (with the
// registered IDs replayed, for RetrievalMethod references), decryption on the
// copy, then a replacement reflect — the decrypted subtree or content takes
// the <EncryptedData/>'s place in the live tree. Binary results need no
// reflection at all.
static PyObject* PyXmlSec_EncryptionContextDecryptShadow(PyXmlSec_EncryptionContext* ctx, PyXmlSec_LxmlElementPtr node) {
    PyXmlSec_LxmlShadow shadow;
    xmlNodePtr target = NULL;
    PyObject* parent = NULL;
    PyObject* result = NULL;
    PyObject* tmp = NULL;
    long idx = -1;
    xmlChar* ttype;
    int not_content;
    int rv;

    parent = PyObject_CallMethod((PyObject*)node, "getparent", NULL);
    if (parent == NULL) {
        return NULL;
    }
    if (parent != Py_None) {
        tmp = PyObject_CallMethod(parent, "index", "O", node);
        if (tmp == NULL) {
            goto ON_FAIL;
        }
        idx = PyLong_AsLong(tmp);
        Py_CLEAR(tmp);
        if (idx < 0) {
            goto ON_FAIL;
        }
    }

    if (PyXmlSec_LxmlShadowBeginDoc(&shadow, node, &target) < 0) {
        goto ON_FAIL;
    }

    // the Type decides the reflect shape; read it from the copy before the
    // decryption consumes the node
    ttype = xmlGetProp(target, XSTR("Type"));
    not_content = (ttype == NULL || !xmlStrEqual(ttype, xmlSecTypeEncContent));
    xmlFree(ttype);

    // The replaced node belongs to the private copy: xmlsec must free it
    // itself (with our libxml2) rather than hand it back, because the copy
    // is discarded right after and nothing could release it later.
    ctx->handle->flags &= ~XMLSEC_ENC_RETURN_REPLACED_NODE;

    Py_BEGIN_ALLOW_THREADS;
    ctx->handle->mode = xmlSecCheckNodeName(target, xmlSecNodeEncryptedKey, xmlSecEncNs) ? xmlEncCtxModeEncryptedKey : xmlEncCtxModeEncryptedData;
    PYXMLSEC_DEBUGF("mode: %d", ctx->handle->mode);
    rv = xmlSecEncCtxDecrypt(ctx->handle, target);
    PYXMLSEC_DUMP(xmlSecEncCtxDebugDump, ctx->handle);
    Py_END_ALLOW_THREADS;

    if (rv < 0) {
        PyXmlSec_LxmlShadowDiscard(&shadow);
        PyXmlSec_SetLastError("failed to decrypt");
        goto ON_FAIL;
    }

    if (!ctx->handle->resultReplaced) {
        PyXmlSec_LxmlShadowDiscard(&shadow);
        Py_DECREF(parent);
        PYXMLSEC_DEBUGF("%p: binary.decrypt - ok", ctx);
        return PyBytes_FromStringAndSize(
            (const char*)xmlSecBufferGetData(ctx->handle->result),
            (Py_ssize_t)xmlSecBufferGetSize(ctx->handle->result)
        );
    }

    // the node was consumed; the reflection grafts whatever replaced it — or,
    // for the document root (no parent to remove it from), morphs the node
    // itself into the replacement, which is then the new root: the raw path's
    // result too
    if (parent != Py_None) {
        tmp = PyObject_CallMethod(parent, "remove", "O", node);
        if (tmp == NULL) {
            PyXmlSec_LxmlShadowDiscard(&shadow);
            goto ON_FAIL;
        }
        Py_CLEAR(tmp);
    }
    if (PyXmlSec_LxmlShadowReflect(&shadow, 0, NULL) < 0) {
        goto ON_FAIL;
    }
    if (parent == Py_None) {
        result = (PyObject*)node;
        Py_INCREF(result);
    } else if (not_content) {
        result = PySequence_GetItem(parent, (Py_ssize_t)idx);
        if (result == NULL) {
            goto ON_FAIL;
        }
    } else {
        result = parent;
        Py_INCREF(result);
    }

    Py_DECREF(parent);
    return result;

ON_FAIL:
    Py_XDECREF(parent);
    Py_XDECREF(tmp);
    Py_XDECREF(result);
    return NULL;
}

static const char PyXmlSec_EncryptionContextDecrypt__doc__[] = \
    "decrypt(node)\n"
    "Decrypts ``node`` (an ``EncryptedData`` or ``EncryptedKey`` element) and returns the result. "
    "The decryption may result in binary data or an XML subtree. "
    "In the former case, the binary data is returned. In the latter case, "
    "the input tree is modified and a reference to the decrypted XML subtree is returned.\n"
    "If the operation modifies the tree, it removes replaced nodes.\n\n"
    ":param node: the pointer to :xml:`<enc:EncryptedData/>` or :xml:`<enc:EncryptedKey/>` node\n"
    ":type node: :class:`lxml.etree._Element`\n"
    ":return: depends on input parameters\n"
    ":rtype: :class:`lxml.etree._Element` or :class:`bytes`";
static PyObject* PyXmlSec_EncryptionContextDecrypt(PyObject* self, PyObject* args, PyObject* kwargs) {
    static char *kwlist[] = { "node", NULL};

    PyXmlSec_EncryptionContext* ctx = (PyXmlSec_EncryptionContext*)self;
    PyXmlSec_LxmlElementPtr node = NULL;

    PyObject* node_num = NULL;
    PyObject* parent = NULL;

    PyObject* tmp;
    xmlNodePtr root;
    xmlNodePtr xparent;
    int rv;
    xmlChar* ttype;
    int notContent;

    PYXMLSEC_DEBUGF("%p: decrypt - start", self);
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O&:decrypt", kwlist, PyXmlSec_LxmlElementConverter, &node)) {
        goto ON_FAIL;
    }

    if (PyXmlSec_LxmlShadowIsActive()) {
        PyObject* result = PyXmlSec_EncryptionContextDecryptShadow(ctx, node);
        if (result == NULL) {
            goto ON_FAIL;
        }
        PYXMLSEC_DEBUGF("%p: decrypt - ok", self);
        return result;
    }

    xparent = node->_c_node->parent;
    if (xparent != NULL && !PyXmlSec_IsElement(xparent)) {
        xparent = NULL;
    }

    if (xparent != NULL) {
        parent = (PyObject*)PyXmlSec_elementFactory(node->_doc, xparent);
        if (parent == NULL) {
            PyErr_SetString(PyXmlSec_InternalError, "failed to construct parent");
            goto ON_FAIL;
        }
        // get index of node
        node_num = PyObject_CallMethod(parent, "index", "O", node);
        PYXMLSEC_DEBUGF("parent: %p, %p", parent, node_num);
    }

    Py_BEGIN_ALLOW_THREADS;
    ctx->handle->flags = XMLSEC_ENC_RETURN_REPLACED_NODE;
    ctx->handle->mode = xmlSecCheckNodeName(node->_c_node, xmlSecNodeEncryptedKey, xmlSecEncNs) ? xmlEncCtxModeEncryptedKey : xmlEncCtxModeEncryptedData;
    PYXMLSEC_DEBUGF("mode: %d", ctx->handle->mode);
    rv = xmlSecEncCtxDecrypt(ctx->handle, node->_c_node);
    PYXMLSEC_DUMP(xmlSecEncCtxDebugDump, ctx->handle);
    Py_END_ALLOW_THREADS;

    PyXmlSec_ClearReplacedNodes(ctx->handle, node->_doc);

    if (rv < 0) {
        PyXmlSec_SetLastError("failed to decrypt");
        goto ON_FAIL;
    }

    if (!ctx->handle->resultReplaced) {
        Py_XDECREF(node_num);
        Py_XDECREF(parent);
        PYXMLSEC_DEBUGF("%p: binary.decrypt - ok", self);
        return PyBytes_FromStringAndSize(
            (const char*)xmlSecBufferGetData(ctx->handle->result),
            (Py_ssize_t)xmlSecBufferGetSize(ctx->handle->result)
        );
    }

    if (xparent != NULL) {
        ttype = xmlGetProp(node->_c_node, XSTR("Type"));
        notContent = (ttype == NULL || !xmlStrEqual(ttype, xmlSecTypeEncContent));
        xmlFree(ttype);

        if (notContent) {
            tmp = PyObject_GetItem(parent, node_num);
            if (tmp == NULL) goto ON_FAIL;
            Py_DECREF(parent);
            parent = tmp;
        }
        Py_DECREF(node_num);
        PYXMLSEC_DEBUGF("%p: parent.decrypt - ok", self);
        return parent;
    }

    // root has been replaced
    root = xmlDocGetRootElement(node->_doc->_c_doc);
    if (root == NULL) {
        PyErr_SetString(PyXmlSec_Error, "decryption resulted in a non well formed document");
        goto ON_FAIL;
    }

    Py_XDECREF(node_num);
    Py_XDECREF(parent);

    PYXMLSEC_DEBUGF("%p: decrypt - ok", self);
    return (PyObject*)PyXmlSec_elementFactory(node->_doc, root);

ON_FAIL:
    PYXMLSEC_DEBUGF("%p: decrypt - fail", self);
    Py_XDECREF(node_num);
    Py_XDECREF(parent);
    return NULL;
}

static PyGetSetDef PyXmlSec_EncryptionContextGetSet[] = {
    {
        "key",
        (getter)PyXmlSec_EncryptionContextKeyGet,
        (setter)PyXmlSec_EncryptionContextKeySet,
        (char*)PyXmlSec_EncryptionContextKey__doc__,
        NULL
    },
    {NULL} /* Sentinel */
};

static PyMethodDef PyXmlSec_EncryptionContextMethods[] = {
    {
        "reset",
        (PyCFunction)PyXmlSec_EncryptionContextReset,
        METH_NOARGS,
        PyXmlSec_EncryptionContextReset__doc__,
    },
    {
        "encrypt_binary",
        (PyCFunction)PyXmlSec_EncryptionContextEncryptBinary,
        METH_VARARGS|METH_KEYWORDS,
        PyXmlSec_EncryptionContextEncryptBinary__doc__,
    },
    {
        "encrypt_xml",
        (PyCFunction)PyXmlSec_EncryptionContextEncryptXml,
        METH_VARARGS|METH_KEYWORDS,
        PyXmlSec_EncryptionContextEncryptXml__doc__
    },
    {
        "encrypt_uri",
        (PyCFunction)PyXmlSec_EncryptionContextEncryptUri,
        METH_VARARGS|METH_KEYWORDS,
        PyXmlSec_EncryptionContextEncryptUri__doc__
    },
    {
        "decrypt",
        (PyCFunction)PyXmlSec_EncryptionContextDecrypt,
        METH_VARARGS|METH_KEYWORDS,
        PyXmlSec_EncryptionContextDecrypt__doc__
    },
    {NULL, NULL} /* sentinel */
};

static PyTypeObject _PyXmlSec_EncryptionContextType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    STRINGIFY(MODULE_NAME) ".EncryptionContext", /* tp_name */
    sizeof(PyXmlSec_EncryptionContext),          /* tp_basicsize */
    0,                                           /* tp_itemsize */
    PyXmlSec_EncryptionContext__del__,           /* tp_dealloc */
    0,                                           /* tp_print */
    0,                                           /* tp_getattr */
    0,                                           /* tp_setattr */
    0,                                           /* tp_reserved */
    0,                                           /* tp_repr */
    0,                                           /* tp_as_number */
    0,                                           /* tp_as_sequence */
    0,                                           /* tp_as_mapping */
    0,                                           /* tp_hash  */
    0,                                           /* tp_call */
    0,                                           /* tp_str */
    0,                                           /* tp_getattro */
    0,                                           /* tp_setattro */
    0,                                           /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,      /* tp_flags */
    "XML Encryption implementation",             /* tp_doc */
    0,                                           /* tp_traverse */
    0,                                           /* tp_clear */
    0,                                           /* tp_richcompare */
    0,                                           /* tp_weaklistoffset */
    0,                                           /* tp_iter */
    0,                                           /* tp_iternext */
    PyXmlSec_EncryptionContextMethods,           /* tp_methods */
    0,                                           /* tp_members */
    PyXmlSec_EncryptionContextGetSet,            /* tp_getset */
    0,                                           /* tp_base */
    0,                                           /* tp_dict */
    0,                                           /* tp_descr_get */
    0,                                           /* tp_descr_set */
    0,                                           /* tp_dictoffset */
    PyXmlSec_EncryptionContext__init__,          /* tp_init */
    0,                                           /* tp_alloc */
    PyXmlSec_EncryptionContext__new__,           /* tp_new */
    0                                            /* tp_free */
};

PyTypeObject* PyXmlSec_EncryptionContextType = &_PyXmlSec_EncryptionContextType;

int PyXmlSec_EncModule_Init(PyObject* package) {
    if (PyType_Ready(PyXmlSec_EncryptionContextType) < 0) goto ON_FAIL;

    PYXMLSEC_DEBUGF("%p", PyXmlSec_EncryptionContextType);
    // since objects is created as static objects, need to increase refcount to prevent deallocate
    Py_INCREF(PyXmlSec_EncryptionContextType);

    if (PyModule_AddObject(package, "EncryptionContext", (PyObject*)PyXmlSec_EncryptionContextType) < 0) goto ON_FAIL;
    return 0;
ON_FAIL:
    return -1;
}
