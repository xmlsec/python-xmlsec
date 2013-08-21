from lxml.includes.tree cimport const_xmlChar


cdef extern from "xmlsec.h":  # xmlsec/strings.h
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

    # Transform ids
    cdef struct _xmlSecTransformKlass:
        const_xmlChar* name
        const_xmlChar* href

    ctypedef _xmlSecTransformKlass *xmlSecTransformId

    xmlSecTransformId xmlSecTransformInclC14NId
    xmlSecTransformId xmlSecTransformInclC14NWithCommentsId
    xmlSecTransformId xmlSecTransformInclC14N11Id
    xmlSecTransformId xmlSecTransformInclC14N11WithCommentsId
    xmlSecTransformId xmlSecTransformExclC14NId
    xmlSecTransformId xmlSecTransformExclC14NWithCommentsId
    xmlSecTransformId xmlSecTransformEnvelopedId
    xmlSecTransformId xmlSecTransformXPathId
    xmlSecTransformId xmlSecTransformXPath2Id
    xmlSecTransformId xmlSecTransformXPointerId
    xmlSecTransformId xmlSecTransformXsltId
    xmlSecTransformId xmlSecTransformRemoveXmlTagsC14NId
    xmlSecTransformId xmlSecTransformVisa3DHackId

    xmlSecTransformId xmlSecTransformAes128CbcId
    xmlSecTransformId xmlSecTransformAes192CbcId
    xmlSecTransformId xmlSecTransformAes256CbcId
    xmlSecTransformId xmlSecTransformKWAes128Id
    xmlSecTransformId xmlSecTransformKWAes192Id
    xmlSecTransformId xmlSecTransformKWAes256Id
    xmlSecTransformId xmlSecTransformDes3CbcId
    xmlSecTransformId xmlSecTransformKWDes3Id
    xmlSecTransformId xmlSecTransformDsaSha1Id
    xmlSecTransformId xmlSecTransformHmacMd5Id
    xmlSecTransformId xmlSecTransformHmacRipemd160Id
    xmlSecTransformId xmlSecTransformHmacSha1Id
    xmlSecTransformId xmlSecTransformHmacSha224Id
    xmlSecTransformId xmlSecTransformHmacSha256Id
    xmlSecTransformId xmlSecTransformHmacSha384Id
    xmlSecTransformId xmlSecTransformHmacSha512Id
    xmlSecTransformId xmlSecTransformMd5Id
    xmlSecTransformId xmlSecTransformRipemd160Id
    xmlSecTransformId xmlSecTransformRsaMd5Id
    xmlSecTransformId xmlSecTransformRsaRipemd160Id
    xmlSecTransformId xmlSecTransformRsaSha1Id
    xmlSecTransformId xmlSecTransformRsaSha224Id
    xmlSecTransformId xmlSecTransformRsaSha256Id
    xmlSecTransformId xmlSecTransformRsaSha384Id
    xmlSecTransformId xmlSecTransformRsaSha512Id
    xmlSecTransformId xmlSecTransformRsaPkcs1Id
    xmlSecTransformId xmlSecTransformRsaOaepId
    xmlSecTransformId xmlSecTransformSha1Id
    xmlSecTransformId xmlSecTransformSha224Id
    xmlSecTransformId xmlSecTransformSha256Id
    xmlSecTransformId xmlSecTransformSha384Id
    xmlSecTransformId xmlSecTransformSha512Id


cdef class _Transform(object):
    cdef xmlSecTransformId target
