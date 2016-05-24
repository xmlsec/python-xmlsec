from lxml.includes.tree cimport const_xmlChar


cdef extern from "xmlsec.h":  # xmlsec/strings.h
    # Global namespaces.
    const_xmlChar* xmlSecNs
    const_xmlChar* xmlSecDSigNs
    const_xmlChar* xmlSecEncNs
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

    xmlSecTransformId xmlSecOpenSSLTransformAes128CbcGetKlass() nogil
    xmlSecTransformId xmlSecOpenSSLTransformAes192CbcGetKlass() nogil
    xmlSecTransformId xmlSecOpenSSLTransformAes256CbcGetKlass() nogil
    xmlSecTransformId xmlSecOpenSSLTransformKWAes128GetKlass() nogil
    xmlSecTransformId xmlSecOpenSSLTransformKWAes192GetKlass() nogil
    xmlSecTransformId xmlSecOpenSSLTransformKWAes256GetKlass() nogil
    xmlSecTransformId xmlSecOpenSSLTransformDes3CbcGetKlass() nogil
    xmlSecTransformId xmlSecOpenSSLTransformKWDes3GetKlass() nogil
    xmlSecTransformId xmlSecOpenSSLTransformDsaSha1GetKlass() nogil
    # xmlSecTransformId xmlSecOpenSSLTransformEcdsaSha1GetKlass() nogil
    # xmlSecTransformId xmlSecOpenSSLTransformEcdsaSha224GetKlass() nogil
    # xmlSecTransformId xmlSecOpenSSLTransformEcdsaSha256GetKlass() nogil
    # xmlSecTransformId xmlSecOpenSSLTransformEcdsaSha384GetKlass() nogil
    # xmlSecTransformId xmlSecOpenSSLTransformEcdsaSha512GetKlass() nogil
    xmlSecTransformId xmlSecOpenSSLTransformHmacMd5GetKlass() nogil
    xmlSecTransformId xmlSecOpenSSLTransformHmacRipemd160GetKlass() nogil
    xmlSecTransformId xmlSecOpenSSLTransformHmacSha1GetKlass() nogil
    xmlSecTransformId xmlSecOpenSSLTransformHmacSha224GetKlass() nogil
    xmlSecTransformId xmlSecOpenSSLTransformHmacSha256GetKlass() nogil
    xmlSecTransformId xmlSecOpenSSLTransformHmacSha384GetKlass() nogil
    xmlSecTransformId xmlSecOpenSSLTransformHmacSha512GetKlass() nogil
    xmlSecTransformId xmlSecOpenSSLTransformMd5GetKlass() nogil
    xmlSecTransformId xmlSecOpenSSLTransformRipemd160GetKlass() nogil
    xmlSecTransformId xmlSecOpenSSLTransformRsaMd5GetKlass() nogil
    xmlSecTransformId xmlSecOpenSSLTransformRsaRipemd160GetKlass() nogil
    xmlSecTransformId xmlSecOpenSSLTransformRsaSha1GetKlass() nogil
    xmlSecTransformId xmlSecOpenSSLTransformRsaSha224GetKlass() nogil
    xmlSecTransformId xmlSecOpenSSLTransformRsaSha256GetKlass() nogil
    xmlSecTransformId xmlSecOpenSSLTransformRsaSha384GetKlass() nogil
    xmlSecTransformId xmlSecOpenSSLTransformRsaSha512GetKlass() nogil
    xmlSecTransformId xmlSecOpenSSLTransformRsaPkcs1GetKlass() nogil
    xmlSecTransformId xmlSecOpenSSLTransformRsaOaepGetKlass() nogil
    xmlSecTransformId xmlSecOpenSSLTransformSha1GetKlass() nogil
    xmlSecTransformId xmlSecOpenSSLTransformSha224GetKlass() nogil
    xmlSecTransformId xmlSecOpenSSLTransformSha256GetKlass() nogil
    xmlSecTransformId xmlSecOpenSSLTransformSha384GetKlass() nogil
    xmlSecTransformId xmlSecOpenSSLTransformSha512GetKlass() nogil


cdef class _Transform(object):
    cdef xmlSecTransformId target
