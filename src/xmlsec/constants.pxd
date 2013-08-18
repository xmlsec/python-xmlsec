from lxml.includes.tree cimport const_xmlChar


cdef extern from "xmlsec/strings.h":
    # Global namespaces.
    const_xmlChar* xmlSecNs
    const_xmlChar* xmlSecDSigNs
    const_xmlChar* xmlSecEncNs
    const_xmlChar* xmlSecXkmsNs
    const_xmlChar* xmlSecXPathNs
    const_xmlChar* xmlSecXPath2Ns
    const_xmlChar* xmlSecXPointerNs
    const_xmlChar* xmlSecSoap11Ns
    const_xmlChar* xmlSecSoap12Ns

    # Digital signature nodes.
    const_xmlChar* xmlSecNodeSignature
    const_xmlChar* xmlSecNodeSignedInfo
    const_xmlChar* xmlSecNodeCanonicalizationMethod
    const_xmlChar* xmlSecNodeSignatureMethod
    const_xmlChar* xmlSecNodeSignatureValue
    const_xmlChar* xmlSecNodeDigestMethod
    const_xmlChar* xmlSecNodeDigestValue
    const_xmlChar* xmlSecNodeObject
    const_xmlChar* xmlSecNodeManifest
    const_xmlChar* xmlSecNodeSignatureProperties
