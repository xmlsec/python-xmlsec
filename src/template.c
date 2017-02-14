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
#include "lxml.h"

#include <xmlsec/templates.h>

#define PYXMLSEC_TEMPLATES_DOC "Xml Templates processing"

static char PyXmlSec_TemplateCreate__doc__[] = \
    "Creates new <dsig:Signature/> node with the mandatory <dsig:SignedInfo/>, <dsig:CanonicalizationMethod/>,\n"
    "<dsig:SignatureMethod/> and <dsig:SignatureValue/> children and sub-children.\n";
static PyObject* PyXmlSec_TemplateCreate(PyObject* self, PyObject *args, PyObject *kwargs) {
    static char *kwlist[] = { "node", "c14n_method", "sign_method", "name", "ns", NULL};

    PyXmlSec_LxmlElementPtr node = NULL;
    PyXmlSec_Transform* c14n = NULL;
    PyXmlSec_Transform* sign = NULL;
    const char* name = NULL;
    const char* ns = NULL;

    PYXMLSEC_DEBUG("template create - start");
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O&O!O!|zz:create", kwlist,
        PyXmlSec_LxmlElementConverter, &node, PyXmlSec_TransformType, &c14n, PyXmlSec_TransformType, &sign, &name, &ns))
    {
        goto ON_FAIL;
    }

    xmlNodePtr res;
    Py_BEGIN_ALLOW_THREADS;
    res = xmlSecTmplSignatureCreateNsPref(node->_doc->_c_doc, c14n->id, sign->id, XSTR(name), XSTR(ns));
    Py_END_ALLOW_THREADS;
    if (res == NULL) {
        PyXmlSec_SetLastError("cannot create template.");
        goto ON_FAIL;
    }

    PYXMLSEC_DEBUG("template create - ok");
    return (PyObject*)PyXmlSec_elementFactory(node->_doc, res);

ON_FAIL:
    PYXMLSEC_DEBUG("template create - fail");
    return NULL;
}

static char PyXmlSec_TemplateAddReference__doc__[] = \
    "Adds <dsig:Reference/> node with given URI (uri ), Id (id ) and Type (type ) attributes and\n"
    "the required children <dsig:DigestMethod/> and <dsig:DigestValue/> to the <dsig:SignedInfo/> child of *node*.\n";
static PyObject* PyXmlSec_TemplateAddReference(PyObject* self, PyObject *args, PyObject *kwargs) {
    static char *kwlist[] = { "node", "digest_method", "id", "uri", "type", NULL};

    PyXmlSec_LxmlElementPtr node = NULL;
    PyXmlSec_Transform* digest = NULL;
    const char* id = NULL;
    const char* uri = NULL;
    const char* type = NULL;

    PYXMLSEC_DEBUG("template add_reference - start");
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O&O!|zzz:add_reference", kwlist,
        PyXmlSec_LxmlElementConverter, &node, PyXmlSec_TransformType, &digest, &id, &uri, &type))
    {
        goto ON_FAIL;
    }
    xmlNodePtr res;
    Py_BEGIN_ALLOW_THREADS;
    res = xmlSecTmplSignatureAddReference(node->_c_node, digest->id, XSTR(id), XSTR(uri), XSTR(type));
    Py_END_ALLOW_THREADS;
    if (res == NULL) {
        PyXmlSec_SetLastError("cannot add reference.");
        goto ON_FAIL;
    }

    PYXMLSEC_DEBUG("template add_reference - ok");
    return (PyObject*)PyXmlSec_elementFactory(node->_doc, res);

ON_FAIL:
    PYXMLSEC_DEBUG("template add_reference - fail");
    return NULL;
}

static char PyXmlSec_TemplateAddTransform__doc__[] = \
    "Adds <dsig:Transform/> node to the <dsig:Reference/> node of *node*.\n";
static PyObject* PyXmlSec_TemplateAddTransform(PyObject* self, PyObject *args, PyObject *kwargs) {
    static char *kwlist[] = { "node", "transform", NULL};

    PyXmlSec_LxmlElementPtr node = NULL;
    PyXmlSec_Transform* transform = NULL;

    PYXMLSEC_DEBUG("template add_transform - start");
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O&O!:add_transform", kwlist,
        PyXmlSec_LxmlElementConverter, &node, PyXmlSec_TransformType, &transform))
    {
        goto ON_FAIL;
    }
    xmlNodePtr res;
    Py_BEGIN_ALLOW_THREADS;
    res = xmlSecTmplReferenceAddTransform(node->_c_node, transform->id);
    Py_END_ALLOW_THREADS;
    if (res == NULL) {
        PyXmlSec_SetLastError("cannot add transform.");
        goto ON_FAIL;
    }

    PYXMLSEC_DEBUG("template add_transform - ok");
    return (PyObject*)PyXmlSec_elementFactory(node->_doc, res);

ON_FAIL:
    PYXMLSEC_DEBUG("template add_transform - fail");
    return NULL;
}

static char PyXmlSec_TemplateEnsureKeyInfo__doc__[] = \
    "Adds (if necessary) <dsig:KeyInfo/> node to the <dsig:Signature/> node of *node*.\n";
static PyObject* PyXmlSec_TemplateEnsureKeyInfo(PyObject* self, PyObject *args, PyObject *kwargs) {
    static char *kwlist[] = { "node", "id", NULL};

    PyXmlSec_LxmlElementPtr node = NULL;
    const char* id = NULL;

    PYXMLSEC_DEBUG("template ensure_key_info - start");
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O&|z:ensure_key_info", kwlist, PyXmlSec_LxmlElementConverter, &node, &id))
    {
        goto ON_FAIL;
    }
    xmlNodePtr res;
    Py_BEGIN_ALLOW_THREADS;
    res = xmlSecTmplSignatureEnsureKeyInfo(node->_c_node, XSTR(id));
    Py_END_ALLOW_THREADS;
    if (res == NULL) {
        PyXmlSec_SetLastError("cannot ensure key info.");
        goto ON_FAIL;
    }

    PYXMLSEC_DEBUG("template ensure_key_info - ok");
    return (PyObject*)PyXmlSec_elementFactory(node->_doc, res);

ON_FAIL:
    PYXMLSEC_DEBUG("template ensure_key_info - fail");
    return NULL;
}

static char PyXmlSec_TemplateAddKeyName__doc__[] = \
    "Adds <dsig:KeyName/> node to the <dsig:KeyInfo/> node of *node*.\n";
static PyObject* PyXmlSec_TemplateAddKeyName(PyObject* self, PyObject *args, PyObject *kwargs) {
    static char *kwlist[] = { "node", "name", NULL};

    PyXmlSec_LxmlElementPtr node = NULL;
    const char* name = NULL;

    PYXMLSEC_DEBUG("template add_key_name - start");
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O&|z:add_key_name", kwlist, PyXmlSec_LxmlElementConverter, &node, &name))
    {
        goto ON_FAIL;
    }

    xmlNodePtr res;
    Py_BEGIN_ALLOW_THREADS;
    res = xmlSecTmplKeyInfoAddKeyName(node->_c_node, XSTR(name));
    Py_END_ALLOW_THREADS;
    if (res == NULL) {
        PyXmlSec_SetLastError("cannot add key name.");
        goto ON_FAIL;
    }

    PYXMLSEC_DEBUG("template add_key_name - ok");
    return (PyObject*)PyXmlSec_elementFactory(node->_doc, res);

ON_FAIL:
    PYXMLSEC_DEBUG("template add_key_name - fail");
    return NULL;
}

static char PyXmlSec_TemplateAddKeyValue__doc__[] = \
    "Adds <dsig:KeyValue/> node to the <dsig:KeyInfo/> node of *node*.\n";
static PyObject* PyXmlSec_TemplateAddKeyValue(PyObject* self, PyObject *args, PyObject *kwargs) {
    static char *kwlist[] = { "node", NULL};

    PyXmlSec_LxmlElementPtr node = NULL;

    PYXMLSEC_DEBUG("template add_key_value - start");
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O&:add_key_value", kwlist, PyXmlSec_LxmlElementConverter, &node))
    {
        goto ON_FAIL;
    }

    xmlNodePtr res;
    Py_BEGIN_ALLOW_THREADS;
    res = xmlSecTmplKeyInfoAddKeyValue(node->_c_node);
    Py_END_ALLOW_THREADS;
    if (res == NULL) {
        PyXmlSec_SetLastError("cannot add key value.");
        goto ON_FAIL;
    }

    PYXMLSEC_DEBUG("template add_key_name - ok");
    return (PyObject*)PyXmlSec_elementFactory(node->_doc, res);

ON_FAIL:
    PYXMLSEC_DEBUG("template add_key_name - fail");
    return NULL;
}

static char PyXmlSec_TemplateAddX509Data__doc__[] = \
    "Adds <dsig:X509Data/> node to the <dsig:KeyInfo/> node of *node*.\n";
static PyObject* PyXmlSec_TemplateAddX509Data(PyObject* self, PyObject *args, PyObject *kwargs) {
    static char *kwlist[] = { "node", NULL};

    PyXmlSec_LxmlElementPtr node = NULL;

    PYXMLSEC_DEBUG("template add_x509_data - start");
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O&:add_x509_data", kwlist, PyXmlSec_LxmlElementConverter, &node))
    {
        goto ON_FAIL;
    }

    xmlNodePtr res;
    Py_BEGIN_ALLOW_THREADS;
    res = xmlSecTmplKeyInfoAddX509Data(node->_c_node);
    Py_END_ALLOW_THREADS;
    if (res == NULL) {
        PyXmlSec_SetLastError("cannot add x509 data.");
        goto ON_FAIL;
    }

    PYXMLSEC_DEBUG("template add_x509_data - ok");
    return (PyObject*)PyXmlSec_elementFactory(node->_doc, res);

ON_FAIL:
    PYXMLSEC_DEBUG("template add_x509_data - fail");
    return NULL;
}

static char PyXmlSec_TemplateAddX509DataAddIssuerSerial__doc__[] = \
    "Adds <dsig:X509IssuerSerial/> node to the given <dsig:X509Data/> node of *node*.\n";
static PyObject* PyXmlSec_TemplateAddX509DataAddIssuerSerial(PyObject* self, PyObject *args, PyObject *kwargs) {
    static char *kwlist[] = { "node", NULL};

    PyXmlSec_LxmlElementPtr node = NULL;

    PYXMLSEC_DEBUG("template x509_data_add_issuer_serial - start");
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O&:x509_data_add_issuer_serial", kwlist,
        PyXmlSec_LxmlElementConverter, &node))
    {
        goto ON_FAIL;
    }
    xmlNodePtr res;
    Py_BEGIN_ALLOW_THREADS;
    res = xmlSecTmplX509DataAddIssuerSerial(node->_c_node);
    Py_END_ALLOW_THREADS;
    if (res == NULL) {
        PyXmlSec_SetLastError("cannot add x509 issuer serial.");
        goto ON_FAIL;
    }

    PYXMLSEC_DEBUG("template x509_data_add_issuer_serial - ok");
    return (PyObject*)PyXmlSec_elementFactory(node->_doc, res);

ON_FAIL:
    PYXMLSEC_DEBUG("template x509_data_add_issuer_serial - fail");
    return NULL;
}

static char PyXmlSec_TemplateAddX509DataIssuerSerialAddIssuerName__doc__[] = \
    "Adds <dsig:X509IssuerName/> node to the <dsig:X509IssuerSerial/> node of *node*.\n";
static PyObject* PyXmlSec_TemplateAddX509DataIssuerSerialAddIssuerName(PyObject* self, PyObject *args, PyObject *kwargs) {
    static char *kwlist[] = { "node", "name", NULL};

    PyXmlSec_LxmlElementPtr node = NULL;
    const char* name = NULL;

    PYXMLSEC_DEBUG("template x509_issuer_serial_add_issuer_name - start");
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O&|z:x509_issuer_serial_add_issuer_name", kwlist,
        PyXmlSec_LxmlElementConverter, &node, &name))
    {
        goto ON_FAIL;
    }
    xmlNodePtr res;
    Py_BEGIN_ALLOW_THREADS;
    res = xmlSecTmplX509IssuerSerialAddIssuerName(node->_c_node, XSTR(name));
    Py_END_ALLOW_THREADS;
    if (res == NULL) {
        PyXmlSec_SetLastError("cannot add x509 issuer serial name.");
        goto ON_FAIL;
    }

    PYXMLSEC_DEBUG("template x509_issuer_serial_add_issuer_name - ok");
    return (PyObject*)PyXmlSec_elementFactory(node->_doc, res);

ON_FAIL:
    PYXMLSEC_DEBUG("template x509_issuer_serial_add_issuer_name - fail");
    return NULL;
}

static char PyXmlSec_TemplateAddX509DataIssuerSerialAddIssuerSerialNumber__doc__[] = \
    "Adds <dsig:X509SerialNumber/> node to the <dsig:X509IssuerSerial/> node of *node*.\n";
static PyObject* PyXmlSec_TemplateAddX509DataIssuerSerialAddIssuerSerialNumber(PyObject* self, PyObject *args, PyObject *kwargs) {
    static char *kwlist[] = { "node", "serial", NULL};

    PyXmlSec_LxmlElementPtr node = NULL;
    const char* serial = NULL;

    PYXMLSEC_DEBUG("template x509_issuer_serial_add_serial_number - start");
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O&|z:x509_issuer_serial_add_serial_number", kwlist,
        PyXmlSec_LxmlElementConverter, &node, &serial))
    {
        goto ON_FAIL;
    }
    xmlNodePtr res;
    Py_BEGIN_ALLOW_THREADS;
    res = xmlSecTmplX509IssuerSerialAddSerialNumber(node->_c_node, XSTR(serial));
    Py_END_ALLOW_THREADS;
    if (res == NULL) {
        PyXmlSec_SetLastError("cannot add x509 issuer serial number.");
        goto ON_FAIL;
    }

    PYXMLSEC_DEBUG("template x509_issuer_serial_add_serial_number - ok");
    return (PyObject*)PyXmlSec_elementFactory(node->_doc, res);

ON_FAIL:
    PYXMLSEC_DEBUG("template x509_issuer_serial_add_serial_number - fail");
    return NULL;
}

static char PyXmlSec_TemplateAddX509DataAddSubjectName__doc__[] = \
    "Adds <dsig:X509SubjectName/> node to the given <dsig:X509Data/> node of *node*.\n";
static PyObject* PyXmlSec_TemplateAddX509DataAddSubjectName(PyObject* self, PyObject *args, PyObject *kwargs) {
    static char *kwlist[] = { "node", NULL};

    PyXmlSec_LxmlElementPtr node = NULL;

    PYXMLSEC_DEBUG("template x509_data_add_subject_name - start");
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O&:x509_data_add_subject_name", kwlist,
        PyXmlSec_LxmlElementConverter, &node))
    {
        goto ON_FAIL;
    }
    xmlNodePtr res;
    Py_BEGIN_ALLOW_THREADS;
    res = xmlSecTmplX509DataAddSubjectName(node->_c_node);
    Py_END_ALLOW_THREADS;
    if (res == NULL) {
        PyXmlSec_SetLastError("cannot add x509 subject name.");
        goto ON_FAIL;
    }

    PYXMLSEC_DEBUG("template x509_data_add_subject_name - ok");
    return (PyObject*)PyXmlSec_elementFactory(node->_doc, res);

ON_FAIL:
    PYXMLSEC_DEBUG("template x509_data_add_subject_name - fail");
    return NULL;
}

static char PyXmlSec_TemplateAddX509DataAddSKI__doc__[] = \
    "Adds <dsig:X509SKI/> node to the given <dsig:X509Data/> node of *node*.\n";
static PyObject* PyXmlSec_TemplateAddX509DataAddSKI(PyObject* self, PyObject *args, PyObject *kwargs) {
    static char *kwlist[] = { "node", NULL};

    PyXmlSec_LxmlElementPtr node = NULL;

    PYXMLSEC_DEBUG("template x509_data_add_ski - start");
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O&:x509_data_add_ski", kwlist,
        PyXmlSec_LxmlElementConverter, &node))
    {
        goto ON_FAIL;
    }
    xmlNodePtr res;
    Py_BEGIN_ALLOW_THREADS;
    res = xmlSecTmplX509DataAddSKI(node->_c_node);
    Py_END_ALLOW_THREADS;
    if (res == NULL) {
        PyXmlSec_SetLastError("cannot add x509 SKI.");
        goto ON_FAIL;
    }

    PYXMLSEC_DEBUG("template x509_data_add_ski - ok");
    return (PyObject*)PyXmlSec_elementFactory(node->_doc, res);

ON_FAIL:
    PYXMLSEC_DEBUG("template x509_data_add_ski - fail");
    return NULL;
}

static char PyXmlSec_TemplateAddX509DataAddCertificate__doc__[] = \
    "Adds <dsig:X509Certificate/> node to the given <dsig:X509Data/> node of *node*.\n";
static PyObject* PyXmlSec_TemplateAddX509DataAddCertificate(PyObject* self, PyObject *args, PyObject *kwargs) {
    static char *kwlist[] = { "node", NULL};

    PyXmlSec_LxmlElementPtr node = NULL;

    PYXMLSEC_DEBUG("template x509_data_add_certificate - start");
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O&:x509_data_add_certificate", kwlist,
        PyXmlSec_LxmlElementConverter, &node))
    {
        goto ON_FAIL;
    }
    xmlNodePtr res;
    Py_BEGIN_ALLOW_THREADS;
    res = xmlSecTmplX509DataAddCertificate(node->_c_node);
    Py_END_ALLOW_THREADS;
    if (res == NULL) {
        PyXmlSec_SetLastError("cannot add x509 certificate.");
        goto ON_FAIL;
    }

    PYXMLSEC_DEBUG("template x509_data_add_certificate - ok");
    return (PyObject*)PyXmlSec_elementFactory(node->_doc, res);

ON_FAIL:
    PYXMLSEC_DEBUG("template x509_data_add_certificate - fail");
    return NULL;
}

static char PyXmlSec_TemplateAddX509DataAddCRL__doc__[] = \
    "Adds <dsig:X509CRL/> node to the given <dsig:X509Data/> node of *node*.\n";
static PyObject* PyXmlSec_TemplateAddX509DataAddCRL(PyObject* self, PyObject *args, PyObject *kwargs) {
    static char *kwlist[] = { "node", NULL};

    PyXmlSec_LxmlElementPtr node = NULL;

    PYXMLSEC_DEBUG("template x509_data_add_crl - start");
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O&:x509_data_add_crl", kwlist,
        PyXmlSec_LxmlElementConverter, &node))
    {
        goto ON_FAIL;
    }
    xmlNodePtr res;
    Py_BEGIN_ALLOW_THREADS;
    res = xmlSecTmplX509DataAddCRL(node->_c_node);
    Py_END_ALLOW_THREADS;
    if (res == NULL) {
        PyXmlSec_SetLastError("cannot add x509 CRL.");
        goto ON_FAIL;
    }

    PYXMLSEC_DEBUG("template x509_data_add_crl - ok");
    return (PyObject*)PyXmlSec_elementFactory(node->_doc, res);

ON_FAIL:
    PYXMLSEC_DEBUG("template x509_data_add_crl - fail");
    return NULL;
}

static char PyXmlSec_TemplateAddEncryptedKey__doc__[] = \
    "Adds <enc:EncryptedKey/> node with given attributes to the <dsig:KeyInfo/> node of *node*.\n";
static PyObject* PyXmlSec_TemplateAddEncryptedKey(PyObject* self, PyObject *args, PyObject *kwargs) {
    static char *kwlist[] = { "node", "method", "id", "type", "recipient", NULL};

    PyXmlSec_LxmlElementPtr node = NULL;
    PyXmlSec_Transform* method = NULL;
    const char* id = NULL;
    const char* type = NULL;
    const char* recipient = NULL;

    PYXMLSEC_DEBUG("template add_encrypted_key - start");
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O&O!|zzz:add_encrypted_key", kwlist,
        PyXmlSec_LxmlElementConverter, &node, PyXmlSec_TransformType, &method, &id, &type, &recipient))
    {
        goto ON_FAIL;
    }
    xmlNodePtr res;
    Py_BEGIN_ALLOW_THREADS;
    res = xmlSecTmplKeyInfoAddEncryptedKey(node->_c_node, method->id, XSTR(id), XSTR(type), XSTR(recipient));
    Py_END_ALLOW_THREADS;
    if (res == NULL) {
        PyXmlSec_SetLastError("cannot add encrypted key.");
        goto ON_FAIL;
    }

    PYXMLSEC_DEBUG("template add_encrypted_key - ok");
    return (PyObject*)PyXmlSec_elementFactory(node->_doc, res);

ON_FAIL:
    PYXMLSEC_DEBUG("template add_encrypted_key - fail");
    return NULL;
}

static char PyXmlSec_TemplateCreateEncryptedData__doc__[] = \
    "Creates new <{ns}:EncryptedData /> node for encryption template.\n";
static PyObject* PyXmlSec_TemplateCreateEncryptedData(PyObject* self, PyObject *args, PyObject *kwargs) {
    static char *kwlist[] = { "node", "method", "id", "type", "mime_type", "encoding", "ns", NULL};

    PyXmlSec_LxmlElementPtr node = NULL;
    PyXmlSec_Transform* method = NULL;
    const char* id = NULL;
    const char* type = NULL;
    const char* mime_type = NULL;
    const char* encoding = NULL;
    const char* ns = NULL;

    PYXMLSEC_DEBUG("template encrypted_data_create - start");
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O&O!|zzzzz:encrypted_data_create", kwlist,
        PyXmlSec_LxmlElementConverter, &node, PyXmlSec_TransformType, &method, &id, &type, &mime_type, &encoding, &ns))
    {
        goto ON_FAIL;
    }
    xmlNodePtr res;
    Py_BEGIN_ALLOW_THREADS;
    res = xmlSecTmplEncDataCreate(node->_doc->_c_doc, method->id, XSTR(id), XSTR(type), XSTR(mime_type), XSTR(encoding));
    Py_END_ALLOW_THREADS;
    if (res == NULL) {
        PyXmlSec_SetLastError("cannot create encrypted data.");
        goto ON_FAIL;
    }
    if (ns != NULL) {
        res->ns->prefix = xmlStrdup(XSTR(ns));
    }

    PYXMLSEC_DEBUG("template encrypted_data_create - ok");
    return (PyObject*)PyXmlSec_elementFactory(node->_doc, res);

ON_FAIL:
    PYXMLSEC_DEBUG("template encrypted_data_create - fail");
    return NULL;
}

static char PyXmlSec_TemplateEncryptedDataEnsureKeyInfo__doc__[] = \
    "Adds <{ns}:KeyInfo/> to the <enc:EncryptedData/> node of *node*.\n";
static PyObject* PyXmlSec_TemplateEncryptedDataEnsureKeyInfo(PyObject* self, PyObject *args, PyObject *kwargs) {
    static char *kwlist[] = { "node", "id", "ns", NULL};

    PyXmlSec_LxmlElementPtr node = NULL;
    const char* id = NULL;
    const char* ns = NULL;

    PYXMLSEC_DEBUG("template encrypted_data_ensure_key_info - start");
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O&|zz:encrypted_data_ensure_key_info", kwlist,
        PyXmlSec_LxmlElementConverter, &node, &id, &ns))
    {
        goto ON_FAIL;
    }
    xmlNodePtr res;
    Py_BEGIN_ALLOW_THREADS;
    res = xmlSecTmplEncDataEnsureKeyInfo(node->_c_node, XSTR(id));
    Py_END_ALLOW_THREADS;
    if (res == NULL) {
        PyXmlSec_SetLastError("cannot ensure key info for encrypted data.");
        goto ON_FAIL;
    }
    if (ns != NULL) {
        res->ns->prefix = xmlStrdup(XSTR(ns));
    }

    PYXMLSEC_DEBUG("template encrypted_data_ensure_key_info - ok");
    return (PyObject*)PyXmlSec_elementFactory(node->_doc, res);

ON_FAIL:
    PYXMLSEC_DEBUG("template encrypted_data_ensure_key_info - fail");
    return NULL;
}

static char PyXmlSec_TemplateEncryptedDataEnsureCipherValue__doc__[] = \
    "Adds <CipherValue/> to the <enc:EncryptedData/> node of *node*.\n";
static PyObject* PyXmlSec_TemplateEncryptedDataEnsureCipherValue(PyObject* self, PyObject *args, PyObject *kwargs) {
    static char *kwlist[] = { "node", NULL};

    PyXmlSec_LxmlElementPtr node = NULL;

    PYXMLSEC_DEBUG("template encrypted_data_ensure_cipher_value - start");
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O&:encrypted_data_ensure_cipher_value", kwlist,
        PyXmlSec_LxmlElementConverter, &node))
    {
        goto ON_FAIL;
    }
    xmlNodePtr res;
    Py_BEGIN_ALLOW_THREADS;
    res = xmlSecTmplEncDataEnsureCipherValue(node->_c_node);
    Py_END_ALLOW_THREADS;
    if (res == NULL) {
        PyXmlSec_SetLastError("cannot ensure cipher value for encrypted data.");
        goto ON_FAIL;
    }

    PYXMLSEC_DEBUG("template encrypted_data_ensure_cipher_value - ok");
    return (PyObject*)PyXmlSec_elementFactory(node->_doc, res);

ON_FAIL:
    PYXMLSEC_DEBUG("template encrypted_data_ensure_cipher_value - fail");
    return NULL;
}


static PyMethodDef PyXmlSec_TemplateMethods[] = {
    {
        "create",
        (PyCFunction)PyXmlSec_TemplateCreate,
        METH_VARARGS|METH_KEYWORDS,
        PyXmlSec_TemplateCreate__doc__
    },
    {
        "add_reference",
        (PyCFunction)PyXmlSec_TemplateAddReference,
        METH_VARARGS|METH_KEYWORDS,
        PyXmlSec_TemplateAddReference__doc__
    },
    {
        "add_transform",
        (PyCFunction)PyXmlSec_TemplateAddTransform,
        METH_VARARGS|METH_KEYWORDS,
        PyXmlSec_TemplateAddTransform__doc__
    },
    {
        "ensure_key_info",
        (PyCFunction)PyXmlSec_TemplateEnsureKeyInfo,
        METH_VARARGS|METH_KEYWORDS,
        PyXmlSec_TemplateEnsureKeyInfo__doc__
    },
    {
        "add_key_name",
        (PyCFunction)PyXmlSec_TemplateAddKeyName,
        METH_VARARGS|METH_KEYWORDS,
        PyXmlSec_TemplateAddKeyName__doc__
    },
    {
        "add_key_value",
        (PyCFunction)PyXmlSec_TemplateAddKeyValue,
        METH_VARARGS|METH_KEYWORDS,
        PyXmlSec_TemplateAddKeyValue__doc__
    },
    {
        "add_x509_data",
        (PyCFunction)PyXmlSec_TemplateAddX509Data,
        METH_VARARGS|METH_KEYWORDS,
        PyXmlSec_TemplateAddX509Data__doc__
    },
    {
        "x509_data_add_issuer_serial",
        (PyCFunction)PyXmlSec_TemplateAddX509DataAddIssuerSerial,
        METH_VARARGS|METH_KEYWORDS,
        PyXmlSec_TemplateAddX509DataAddIssuerSerial__doc__
    },
    {
        "x509_issuer_serial_add_issuer_name",
        (PyCFunction)PyXmlSec_TemplateAddX509DataIssuerSerialAddIssuerName,
        METH_VARARGS|METH_KEYWORDS,
        PyXmlSec_TemplateAddX509DataIssuerSerialAddIssuerName__doc__
    },
    {
        "x509_issuer_serial_add_serial_number",
        (PyCFunction)PyXmlSec_TemplateAddX509DataIssuerSerialAddIssuerSerialNumber,
        METH_VARARGS|METH_KEYWORDS,
        PyXmlSec_TemplateAddX509DataIssuerSerialAddIssuerSerialNumber__doc__
    },
    {
        "x509_data_add_subject_name",
        (PyCFunction)PyXmlSec_TemplateAddX509DataAddSubjectName,
        METH_VARARGS|METH_KEYWORDS,
        PyXmlSec_TemplateAddX509DataAddSubjectName__doc__
    },
    {
        "x509_data_add_ski",
        (PyCFunction)PyXmlSec_TemplateAddX509DataAddSKI,
        METH_VARARGS|METH_KEYWORDS,
        PyXmlSec_TemplateAddX509DataAddSKI__doc__
    },
    {
        "x509_data_add_certificate",
        (PyCFunction)PyXmlSec_TemplateAddX509DataAddCertificate,
        METH_VARARGS|METH_KEYWORDS,
        PyXmlSec_TemplateAddX509DataAddCertificate__doc__
    },
    {
        "x509_data_add_crl",
        (PyCFunction)PyXmlSec_TemplateAddX509DataAddCRL,
        METH_VARARGS|METH_KEYWORDS,
        PyXmlSec_TemplateAddX509DataAddCRL__doc__
    },
    {
        "add_encrypted_key",
        (PyCFunction)PyXmlSec_TemplateAddEncryptedKey,
        METH_VARARGS|METH_KEYWORDS,
        PyXmlSec_TemplateAddEncryptedKey__doc__
    },
    {
        "encrypted_data_create",
        (PyCFunction)PyXmlSec_TemplateCreateEncryptedData,
        METH_VARARGS|METH_KEYWORDS,
        PyXmlSec_TemplateCreateEncryptedData__doc__
    },
    {
        "encrypted_data_ensure_key_info",
        (PyCFunction)PyXmlSec_TemplateEncryptedDataEnsureKeyInfo,
        METH_VARARGS|METH_KEYWORDS,
        PyXmlSec_TemplateEncryptedDataEnsureKeyInfo__doc__
    },
    {
        "encrypted_data_ensure_cipher_value",
        (PyCFunction)PyXmlSec_TemplateEncryptedDataEnsureCipherValue,
        METH_VARARGS|METH_KEYWORDS,
        PyXmlSec_TemplateEncryptedDataEnsureCipherValue__doc__
    },
    {NULL, NULL} /* sentinel */
};

#ifdef PY3K
static PyModuleDef PyXmlSec_TemplateModule =
{
    PyModuleDef_HEAD_INIT,
    STRINGIFY(MODULE_NAME) ".template",
    PYXMLSEC_TEMPLATES_DOC,
    -1,
    PyXmlSec_TemplateMethods, /* m_methods */
    NULL,                     /* m_slots */
    NULL,                     /* m_traverse */
    NULL,                     /* m_clear */
    NULL,                     /* m_free */
};
#endif  // PY3K

int PyXmlSec_TemplateModule_Init(PyObject* package) {
#ifdef PY3K
    PyObject* template = PyModule_Create(&PyXmlSec_TemplateModule);
#else
    PyObject* template = Py_InitModule3(STRINGIFY(MODULE_NAME) ".template", PyXmlSec_TemplateMethods, PYXMLSEC_TEMPLATES_DOC);
    Py_XINCREF(template);
#endif

    if (!template) goto ON_FAIL;
    PYXMLSEC_DEBUGF("%p", template);

    if (PyModule_AddObject(package, "template", template) < 0) goto ON_FAIL;

    return 0;
ON_FAIL:
    Py_XDECREF(template);
    return -1;
}
