from lxml.includes.tree cimport const_xmlChar, xmlNode, xmlDoc
from .constants cimport xmlSecTransformId


cdef extern from "xmlsec.h":  # xmlsec/templates.h

    xmlNode* xmlSecTmplSignatureCreateNsPref(
        xmlDoc* document, xmlSecTransformId c14n, xmlSecTransformId sign,
        const_xmlChar* id, const_xmlChar* ns) nogil

    xmlNode* xmlSecTmplSignatureAddReference(
        xmlNode* node, xmlSecTransformId digest,
        const_xmlChar* id, const_xmlChar* uri, const_xmlChar* type) nogil

    xmlNode* xmlSecTmplReferenceAddTransform(
        xmlNode* node, xmlSecTransformId transform) nogil

    xmlNode* xmlSecTmplSignatureEnsureKeyInfo(
        xmlNode* node, const_xmlChar* id) nogil

    xmlNode* xmlSecTmplKeyInfoAddKeyName(xmlNode* node, const_xmlChar* name) nogil

    xmlNode* xmlSecTmplKeyInfoAddKeyValue(xmlNode* node) nogil

    xmlNode* xmlSecTmplKeyInfoAddX509Data(xmlNode* node) nogil

    xmlNode* xmlSecTmplX509DataAddIssuerSerial(xmlNode* node) nogil

    xmlNode* xmlSecTmplX509IssuerSerialAddIssuerName(xmlNode* node, const_xmlChar* name) nogil

    xmlNode* xmlSecTmplX509IssuerSerialAddSerialNumber(xmlNode* node, const_xmlChar* serial) nogil

    xmlNode* xmlSecTmplX509DataAddSubjectName(xmlNode* node) nogil

    xmlNode* xmlSecTmplX509DataAddSKI(xmlNode* node) nogil

    xmlNode* xmlSecTmplX509DataAddCertificate(xmlNode* node) nogil

    xmlNode* xmlSecTmplX509DataAddCRL(xmlNode* node) nogil

    xmlNode* xmlSecTmplKeyInfoAddEncryptedKey(
        xmlNode* keyInfoNode, xmlSecTransformId encMethodId,
        const_xmlChar *id, const_xmlChar *type, const_xmlChar *recipient) nogil

    xmlNode* xmlSecTmplEncDataCreate(
        xmlDoc* doc, xmlSecTransformId encMethodId, const_xmlChar *id,
        const_xmlChar *type, const_xmlChar *mimeType, const_xmlChar *encoding) nogil

    xmlNode* xmlSecTmplEncDataEnsureKeyInfo(xmlNode* encNode, const_xmlChar *id) nogil

    xmlNode* xmlSecTmplEncDataEnsureCipherValue(xmlNode* encNode) nogil
