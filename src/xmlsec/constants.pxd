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

    # Encypted nodes
    const_xmlChar* xmlSecNodeEncryptedData
    const_xmlChar* xmlSecNodeEncryptedKey
    const_xmlChar* xmlSecNodeEncryptionMethod
    const_xmlChar* xmlSecNodeEncryptionProperties
    const_xmlChar* xmlSecNodeEncryptionProperty
    const_xmlChar* xmlSecNodeCipherData
    const_xmlChar* xmlSecNodeCipherValue
    const_xmlChar* xmlSecNodeCipherReference
    const_xmlChar* xmlSecNodeReferenceList
    const_xmlChar* xmlSecNodeDataReference
    const_xmlChar* xmlSecNodeKeyReference
    const_xmlChar* xmlSecNodeKeyInfo


    # encryption types
    const_xmlChar* xmlSecTypeEncContent
    const_xmlChar* xmlSecTypeEncElement

    ctypedef unsigned int xmlSecTransformUsage
    cdef enum:
        xmlSecTransformUsageUnknown=0x0000
        xmlSecTransformUsageDSigTransform=0x0001
        xmlSecTransformUsageC14NMethod=0x0002
        xmlSecTransformUsageDigestMethod=0x0004
        xmlSecTransformUsageSignatureMethod=0x0008
        xmlSecTransformUsageEncryptionMethod=0x0010
        xmlSecTransformUsageAny=0xFFFF

    # Transform ids
    cdef struct _xmlSecTransformKlass:
        const_xmlChar* name
        const_xmlChar* href
        xmlSecTransformUsage usage

    ctypedef _xmlSecTransformKlass *xmlSecTransformId

    xmlSecTransformId xmlSecTransformInclC14NGetKlass()
    xmlSecTransformId xmlSecTransformInclC14NWithCommentsGetKlass()
    xmlSecTransformId xmlSecTransformInclC14N11GetKlass()
    xmlSecTransformId xmlSecTransformInclC14N11WithCommentsGetKlass()
    xmlSecTransformId xmlSecTransformExclC14NGetKlass()
    xmlSecTransformId xmlSecTransformExclC14NWithCommentsGetKlass()
    xmlSecTransformId xmlSecTransformEnvelopedGetKlass()
    xmlSecTransformId xmlSecTransformXPathGetKlass()
    xmlSecTransformId xmlSecTransformXPath2GetKlass()
    xmlSecTransformId xmlSecTransformXPointerGetKlass()
    xmlSecTransformId xmlSecTransformXsltGetKlass()
    xmlSecTransformId xmlSecTransformRemoveXmlTagsC14NGetKlass()
    xmlSecTransformId xmlSecTransformVisa3DHackGetKlass()

    xmlSecTransformId xmlSecTransformAes128CbcGetKlass()
    xmlSecTransformId xmlSecTransformAes192CbcGetKlass()
    xmlSecTransformId xmlSecTransformAes256CbcGetKlass()
    xmlSecTransformId xmlSecTransformKWAes128GetKlass()
    xmlSecTransformId xmlSecTransformKWAes192GetKlass()
    xmlSecTransformId xmlSecTransformKWAes256GetKlass()
    xmlSecTransformId xmlSecTransformDes3CbcGetKlass()
    xmlSecTransformId xmlSecTransformKWDes3GetKlass()
    xmlSecTransformId xmlSecTransformDsaSha1GetKlass()
    xmlSecTransformId xmlSecTransformEcdsaSha1GetKlass()
    xmlSecTransformId xmlSecTransformEcdsaSha224GetKlass()
    xmlSecTransformId xmlSecTransformEcdsaSha256GetKlass()
    xmlSecTransformId xmlSecTransformEcdsaSha384GetKlass()
    xmlSecTransformId xmlSecTransformEcdsaSha512GetKlass()
    xmlSecTransformId xmlSecTransformHmacMd5GetKlass()
    xmlSecTransformId xmlSecTransformHmacRipemd160GetKlass()
    xmlSecTransformId xmlSecTransformHmacSha1GetKlass()
    xmlSecTransformId xmlSecTransformHmacSha224GetKlass()
    xmlSecTransformId xmlSecTransformHmacSha256GetKlass()
    xmlSecTransformId xmlSecTransformHmacSha384GetKlass()
    xmlSecTransformId xmlSecTransformHmacSha512GetKlass()
    xmlSecTransformId xmlSecTransformMd5GetKlass()
    xmlSecTransformId xmlSecTransformRipemd160GetKlass()
    xmlSecTransformId xmlSecTransformRsaMd5GetKlass()
    xmlSecTransformId xmlSecTransformRsaRipemd160GetKlass()
    xmlSecTransformId xmlSecTransformRsaSha1GetKlass()
    xmlSecTransformId xmlSecTransformRsaSha224GetKlass()
    xmlSecTransformId xmlSecTransformRsaSha256GetKlass()
    xmlSecTransformId xmlSecTransformRsaSha384GetKlass()
    xmlSecTransformId xmlSecTransformRsaSha512GetKlass()
    xmlSecTransformId xmlSecTransformRsaPkcs1GetKlass()
    xmlSecTransformId xmlSecTransformRsaOaepGetKlass()
    xmlSecTransformId xmlSecTransformSha1GetKlass()
    xmlSecTransformId xmlSecTransformSha224GetKlass()
    xmlSecTransformId xmlSecTransformSha256GetKlass()
    xmlSecTransformId xmlSecTransformSha384GetKlass()
    xmlSecTransformId xmlSecTransformSha512GetKlass()


cdef class _Transform(object):
    cdef xmlSecTransformId target
