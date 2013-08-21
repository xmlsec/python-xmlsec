from lxml.includes.tree cimport const_xmlChar, xmlNode, xmlDoc
from constants cimport xmlSecTransformId


cdef extern from "xmlsec.h":  # xmlsec/templates.h

    xmlNode* xmlSecTmplSignatureCreate(
        xmlDoc* document, xmlSecTransformId c14n, xmlSecTransformId sign,
        const_xmlChar* id)

    xmlNode* xmlSecTmplSignatureAddReference(
        xmlNode* node, xmlSecTransformId digest,
        const_xmlChar* id, const_xmlChar* uri, const_xmlChar* type)

    xmlNode* xmlSecTmplReferenceAddTransform(
        xmlNode* node, xmlSecTransformId transform)

    xmlNode* xmlSecTmplSignatureEnsureKeyInfo(
        xmlNode* node, const_xmlChar* id)

    xmlNode* xmlSecTmplKeyInfoAddKeyName(xmlNode* node, const_xmlChar* name)
