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

    # Transform ids  # xmlsec/app.h
    cdef struct _xmlSecTransformKlass:
        const_xmlChar* name
        const_xmlChar* href
        xmlSecTransformUsage usage

    ctypedef _xmlSecTransformKlass *xmlSecTransformId

    xmlSecTransformId xmlSecTransformInclC14NGetKlass() nogil
    xmlSecTransformId xmlSecTransformInclC14NWithCommentsGetKlass() nogil
    xmlSecTransformId xmlSecTransformInclC14N11GetKlass() nogil
    xmlSecTransformId xmlSecTransformInclC14N11WithCommentsGetKlass() nogil
    xmlSecTransformId xmlSecTransformExclC14NGetKlass() nogil
    xmlSecTransformId xmlSecTransformExclC14NWithCommentsGetKlass() nogil
    xmlSecTransformId xmlSecTransformEnvelopedGetKlass() nogil
    xmlSecTransformId xmlSecTransformXPathGetKlass() nogil
    xmlSecTransformId xmlSecTransformXPath2GetKlass() nogil
    xmlSecTransformId xmlSecTransformXPointerGetKlass() nogil
    xmlSecTransformId xmlSecTransformXsltGetKlass() nogil
    xmlSecTransformId xmlSecTransformRemoveXmlTagsC14NGetKlass() nogil
    xmlSecTransformId xmlSecTransformVisa3DHackGetKlass() nogil

    xmlSecTransformId xmlSecTransformAes128CbcGetKlass() nogil
    xmlSecTransformId xmlSecTransformAes192CbcGetKlass() nogil
    xmlSecTransformId xmlSecTransformAes256CbcGetKlass() nogil
    xmlSecTransformId xmlSecTransformKWAes128GetKlass() nogil
    xmlSecTransformId xmlSecTransformKWAes192GetKlass() nogil
    xmlSecTransformId xmlSecTransformKWAes256GetKlass() nogil
    xmlSecTransformId xmlSecTransformDes3CbcGetKlass() nogil
    xmlSecTransformId xmlSecTransformKWDes3GetKlass() nogil
    xmlSecTransformId xmlSecTransformDsaSha1GetKlass() nogil
    xmlSecTransformId xmlSecTransformEcdsaSha1GetKlass() nogil
    xmlSecTransformId xmlSecTransformEcdsaSha224GetKlass() nogil
    xmlSecTransformId xmlSecTransformEcdsaSha256GetKlass() nogil
    xmlSecTransformId xmlSecTransformEcdsaSha384GetKlass() nogil
    xmlSecTransformId xmlSecTransformEcdsaSha512GetKlass() nogil
    xmlSecTransformId xmlSecTransformHmacMd5GetKlass() nogil
    xmlSecTransformId xmlSecTransformHmacRipemd160GetKlass() nogil
    xmlSecTransformId xmlSecTransformHmacSha1GetKlass() nogil
    xmlSecTransformId xmlSecTransformHmacSha224GetKlass() nogil
    xmlSecTransformId xmlSecTransformHmacSha256GetKlass() nogil
    xmlSecTransformId xmlSecTransformHmacSha384GetKlass() nogil
    xmlSecTransformId xmlSecTransformHmacSha512GetKlass() nogil
    xmlSecTransformId xmlSecTransformMd5GetKlass() nogil
    xmlSecTransformId xmlSecTransformRipemd160GetKlass() nogil
    xmlSecTransformId xmlSecTransformRsaMd5GetKlass() nogil
    xmlSecTransformId xmlSecTransformRsaRipemd160GetKlass() nogil
    xmlSecTransformId xmlSecTransformRsaSha1GetKlass() nogil
    xmlSecTransformId xmlSecTransformRsaSha224GetKlass() nogil
    xmlSecTransformId xmlSecTransformRsaSha256GetKlass() nogil
    xmlSecTransformId xmlSecTransformRsaSha384GetKlass() nogil
    xmlSecTransformId xmlSecTransformRsaSha512GetKlass() nogil
    xmlSecTransformId xmlSecTransformRsaPkcs1GetKlass() nogil
    xmlSecTransformId xmlSecTransformRsaOaepGetKlass() nogil
    xmlSecTransformId xmlSecTransformSha1GetKlass() nogil
    xmlSecTransformId xmlSecTransformSha224GetKlass() nogil
    xmlSecTransformId xmlSecTransformSha256GetKlass() nogil
    xmlSecTransformId xmlSecTransformSha384GetKlass() nogil
    xmlSecTransformId xmlSecTransformSha512GetKlass() nogil


cdef class _Transform(object):
    cdef xmlSecTransformId target
