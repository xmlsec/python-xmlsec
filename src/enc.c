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

typedef struct {
    PyObject_HEAD
    xmlSecEncCtxPtr handle;
    PyXmlSec_KeysManager* manager;
} PyXmlSec_EncryptionContext;

static PyObject* PyXmlSec_EncryptionContext__new__(PyTypeObject *type, PyObject *args, PyObject *kwargs) {
    PyXmlSec_EncryptionContext* ctx = (PyXmlSec_EncryptionContext*)PyType_GenericNew(type, args, kwargs);
    PYXMLSEC_DEBUGF("%p: new sign context", ctx);
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
    PYXMLSEC_DEBUGF("%p: init sign context", self);
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|O&:__init__", kwlist, PyXmlSec_KeysManagerConvert, &manager)) {
        return -1;
    }

    PYXMLSEC_DEBUGF("%p", manager);
    ctx->handle = xmlSecEncCtxCreate(manager != NULL ? manager->handle : NULL);
    if (ctx->handle == NULL) {
        PyXmlSec_SetLastError("failed to create the digital signature context");
        return -1;
    }
    Py_XINCREF(manager);
    ctx->manager = manager;
    return 0;
}

static void PyXmlSec_EncryptionContext__del__(PyObject* self) {
    PYXMLSEC_DEBUGF("%p: delete sign context", self);
    PyXmlSec_EncryptionContext* ctx = (PyXmlSec_EncryptionContext*)self;
    if (ctx->handle != NULL) {
        xmlSecEncCtxDestroy(ctx->handle);
    }
    // release manager object
    Py_XDECREF(ctx->manager);
    Py_TYPE(self)->tp_free(self);
}

static const char PyXmlSec_EncryptionContextKey__doc__[] = "Encryption key.\n";
static PyObject* PyXmlSec_EncryptionContextKeyGet(PyObject* self, void* closure) {
    PyXmlSec_Key* key = PyXmlSec_NewKey();
    key->handle = ((PyXmlSec_EncryptionContext*)self)->handle->encKey;
    key->is_own = 0;
    return (PyObject*)key;
}

static int PyXmlSec_EncryptionContextKeySet(PyObject* self, PyObject* value, void* closure) {
    PYXMLSEC_DEBUGF("%p, %p", self, value);
    if (!PyObject_IsInstance(value, (PyObject*)PyXmlSec_KeyType)) {
        PyErr_SetString(PyExc_TypeError, "instance of *xmlsec.Key* expected.");
        return -1;
    }

    xmlSecKeyPtr keyHandle = ((PyXmlSec_Key*)value)->handle;
    if (keyHandle == NULL) {
        PyErr_SetString(PyExc_TypeError, "empty key.");
        return -1;
    }

    PyXmlSec_EncryptionContext* ctx = (PyXmlSec_EncryptionContext*)self;
    if (ctx->handle->encKey != NULL) {
        xmlSecKeyDestroy(ctx->handle->encKey);
    }

    ctx->handle->encKey = xmlSecKeyDuplicate(keyHandle);
    if (ctx->handle->encKey == NULL) {
        PyXmlSec_SetLastError("failed to duplicate key");
        return -1;
    }
    return 0;
}

static const char PyXmlSec_EncryptionContextEncryptBinary__doc__[] = \
    "Encrypts binary *data* according to `EncryptedData` template *template*\n"\
    "returns the resulting `EncryptedData` subtree.\n" \
    "Note: *template* is modified in place.\n";
static PyObject* PyXmlSec_EncryptionContextEncryptBinary(PyObject* self, PyObject* args, PyObject* kwargs) {
    static char *kwlist[] = { "template", "data", NULL};

    PyXmlSec_LxmlElementPtr template = NULL;
    const char* data = NULL;
    Py_ssize_t data_size = 0;

    PYXMLSEC_DEBUGF("%p: encrypt_binary - start", self);
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O&s#:encrypt_binary", kwlist,
        PyXmlSec_LxmlElementConverter, &template, &data, &data_size))
    {
        goto ON_FAIL;
    }
    xmlSecEncCtxPtr ctx = ((PyXmlSec_EncryptionContext*)self)->handle;
    int rv;
    Py_BEGIN_ALLOW_THREADS;
    rv = xmlSecEncCtxBinaryEncrypt(ctx, template->_c_node, (const xmlSecByte*)data, (xmlSecSize)data_size);
    Py_END_ALLOW_THREADS;

    if (rv < 0) {
        PyXmlSec_SetLastError("failed to encrypt binary");
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
    // release the replaced nodes in a way safe for `lxml`
    xmlNodePtr n = ctx->replacedNodeList;
    xmlNodePtr nn;
    while (n != NULL) {
        nn = n->next;
        // if n has references, it will not be deleted
        Py_XDECREF(PyXmlSec_elementFactory(doc, n));
        n = nn;
    }
    ctx->replacedNodeList = NULL;
}

static const char PyXmlSec_EncryptionContextEncryptXml__doc__[] = \
    "Encrpyts *node* using *template*.\n" \
    "Returns the resulting `EncryptedData` element.\n\n"\
    "Note: The `Type` attribute of *template* decides whether *node* itself is encrypted\n"\
    "(`http://www.w3.org/2001/04/xmlenc#Element`) or its content (`http://www.w3.org/2001/04/xmlenc#Content`).\n"\
    "It must have one of these two values (or an exception is raised).\n"\
    "The operation modifies the tree containing *node* in a way that\n"\
    "`lxml` references to or into this tree may see a surprising state.\n"\
    "You should no longer rely on them. Especially, you should use\n"\
    "`getroottree()` on the result to obtain the encrypted result tree.\n";
static PyObject* PyXmlSec_EncryptionContextEncryptXml(PyObject* self, PyObject* args, PyObject* kwargs) {
    static char *kwlist[] = { "template", "node", NULL};

    PyXmlSec_LxmlElementPtr template = NULL;
    PyXmlSec_LxmlElementPtr node = NULL;
    xmlNodePtr xnew_node = NULL;
    xmlChar* tmpType = NULL;

    PYXMLSEC_DEBUGF("%p: encrypt_xml - start", self);
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O&O&:encrypt_xml", kwlist,
        PyXmlSec_LxmlElementConverter, &template, PyXmlSec_LxmlElementConverter, &node))
    {
        goto ON_FAIL;
    }
    tmpType = xmlGetProp(template->_c_node, XSTR("Type"));
    if (tmpType == NULL || !(xmlStrEqual(tmpType, xmlSecTypeEncElement) || xmlStrEqual(tmpType, xmlSecTypeEncContent))) {
        PyErr_SetString(PyXmlSec_Error, "unsupported `Type`, it should be `element` or `content`)");
        goto ON_FAIL;
    }

    // `xmlSecEncCtxXmlEncrypt` will replace the subtree rooted
    //  at `node._c_node` or its children by an extended subtree rooted at "c_node".
    //  We set `XMLSEC_ENC_RETURN_REPLACED_NODE` to prevent deallocation
    //  of the replaced node. This is important as `node` is still referencing it
    xmlSecEncCtxPtr ctx = ((PyXmlSec_EncryptionContext*)self)->handle;
    ctx->flags = XMLSEC_ENC_RETURN_REPLACED_NODE;
    int rv = 0;

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
    if (rv == 0 && xmlSecEncCtxXmlEncrypt(ctx, xnew_node != NULL ? xnew_node: template->_c_node, node->_c_node) < 0) {
        rv = -1;
        if (xnew_node != NULL) {
            xmlFreeNode(xnew_node);
            xnew_node = NULL;
        }
    }
    Py_END_ALLOW_THREADS;

    PyXmlSec_ClearReplacedNodes(ctx, node->_doc);

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
    "Encrypts binary data obtained from *uri* according to *template*.\n";
static PyObject* PyXmlSec_EncryptionContextEncryptUri(PyObject* self, PyObject* args, PyObject* kwargs) {
    static char *kwlist[] = { "template", "uri", NULL};

    PyXmlSec_LxmlElementPtr template = NULL;
    const char* uri = NULL;

    PYXMLSEC_DEBUGF("%p: encrypt_uri - start", self);
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O&s:encrypt_uri", kwlist, PyXmlSec_LxmlElementConverter, &template, &uri)) {
        goto ON_FAIL;
    }

    xmlSecEncCtxPtr ctx = ((PyXmlSec_EncryptionContext*)self)->handle;
    int rv;
    Py_BEGIN_ALLOW_THREADS;
    rv = xmlSecEncCtxUriEncrypt(ctx, template->_c_node, (const xmlSecByte*)uri);
    Py_END_ALLOW_THREADS;

    if (rv < 0) {
        PyXmlSec_SetLastError("failed to encrypt URI");
        goto ON_FAIL;
    }
    PYXMLSEC_DEBUGF("%p: encrypt_uri - ok", self);
    Py_INCREF(template);
    return (PyObject*)template;
ON_FAIL:
    PYXMLSEC_DEBUGF("%p: encrypt_uri - fail", self);
    return NULL;
}

static const char PyXmlSec_EncryptionContextDecrypt__doc__[] = \
    "Decrypts *node* (an `EncryptedData` element) and return the result.\n"\
    "The decryption may result in binary data or an XML subtree.\n"\
    "In the former case, the binary data is returned. In the latter case,\n"\
    "the input tree is modified and a reference to the decrypted XML subtree is returned.\n"\
    "If the operation modifies the tree, `lxml` references to or into this tree may see a surprising state.\n"\
    "You should no longer rely on them. Especially, you should use `getroottree()` on the result\n"\
    "to obtain the decrypted result tree.\n";
static PyObject* PyXmlSec_EncryptionContextDecrypt(PyObject* self, PyObject* args, PyObject* kwargs) {
    static char *kwlist[] = { "node", NULL};

    PyXmlSec_LxmlElementPtr node = NULL;

    PyObject* node_num = NULL;
    PyObject* parent = NULL;


    PYXMLSEC_DEBUGF("%p: decrypt - start", self);
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O&:decrypt", kwlist, PyXmlSec_LxmlElementConverter, &node)) {
        goto ON_FAIL;
    }

    xmlNodePtr xparent = node->_c_node->parent;
    if (xparent != NULL && !_isElement(xparent)) {
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
        PYXMLSEC_DEBUGF("%p, %p", parent, node_num);
    }

    xmlSecEncCtxPtr ctx = ((PyXmlSec_EncryptionContext*)self)->handle;
    ctx->flags = XMLSEC_ENC_RETURN_REPLACED_NODE;
    int rv;

    Py_BEGIN_ALLOW_THREADS;
    rv = xmlSecEncCtxDecrypt(ctx, node->_c_node);
    Py_END_ALLOW_THREADS;

    PyXmlSec_ClearReplacedNodes(ctx, node->_doc);

    if (rv < 0) {
        PyXmlSec_SetLastError("failed to decrypt");
        goto ON_FAIL;
    }

    if (!ctx->resultReplaced) {
        Py_XDECREF(node_num);
        Py_XDECREF(parent);
        PYXMLSEC_DEBUGF("%p: decrypt - ok", self);
        return PyBytes_FromStringAndSize(
            (const char*)xmlSecBufferGetData(ctx->result), (Py_ssize_t)xmlSecBufferGetSize(ctx->result)
        );
    }

    if (xparent != NULL) {
        xmlChar* ttype = xmlGetProp(node->_c_node, XSTR("Type"));
        int notContent = (ttype == NULL || !xmlStrEqual(ttype, xmlSecTypeEncContent));
        xmlFree(ttype);

        if (notContent) {
            PyObject* tmp = PyObject_GetItem(parent, node_num);
            if (tmp == NULL) goto ON_FAIL;
            Py_DECREF(parent);
            parent = tmp;
        }
        Py_DECREF(node_num);
        PYXMLSEC_DEBUGF("%p: decrypt - ok", self);
        return parent;
    }

    // root has been replaced
    xmlNodePtr root = xmlDocGetRootElement(node->_doc->_c_doc);
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
    PyType_GenericAlloc,                         /* tp_alloc */
    PyXmlSec_EncryptionContext__new__,           /* tp_new */
    PyObject_Del                                 /* tp_free */
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
