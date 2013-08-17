
from tree cimport xmlNode, xmlDoc, xmlChar, const_xmlChar
from etreepublic cimport LXML_VERSION_STRING

cdef extern from "libxml/parser.h":
    cdef const_xmlChar* XML_DEFAULT_VERSION

cdef extern from "xmlsec.h":
    # [xmlsec.c]
    int xmlSecInit() nogil
    int xmlSecShutdown() nogil

    # [app.c]
    int xmlSecCryptoInit() nogil
    int xmlSecCryptoShutdown() nogil

    int xmlSecCryptoAppInit(char* name) nogil
    int xmlSecCryptoAppShutdown() nogil

    # [transforms.c]
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

    # [templates.c]
    xmlNode* xmlSecTmplSignatureCreate(
        xmlDoc* document,
        xmlSecTransformId c14n_method,
        xmlSecTransformId sign_method,
        const_xmlChar* id) nogil

    xmlNode* xmlSecTmplSignatureAddReference(
        xmlNode* node,
        xmlSecTransformId digest_method,
        const_xmlChar* id,
        const_xmlChar* uri,
        const_xmlChar* type) nogil

    xmlNode* xmlSecTmplReferenceAddTransform(
        xmlNode* node,
        xmlSecTransformId method) nogil

    xmlNode* xmlSecTmplSignatureEnsureKeyInfo(
        xmlNode* node,
        const_xmlChar* id) nogil

    xmlNode* xmlSecTmplKeyInfoAddKeyName(
        xmlNode* node,
        const_xmlChar* name) nogil

    xmlNode* xmlSecTmplKeyInfoAddX509Data(xmlNode* node) nogil

    # [xmldsig.c]
    ctypedef void* xmlSecKeysMngrPtr

    struct _xmlSecDSigCtx:
        pass
##                void * userData
##                unsigned int flags
##                unsigned int flags2
##                xmlSecKeyInfoCtx keyInfoReadCtx
##                xmlSecKeyInfoCtx keyInfoWriteCtx
##                xmlSecTransformCtx transformCtx
##                xmlSecTransformUriType enabledReferenceUris
##                xmlSecPtrListPtr enabledReferenceTransforms
##                xmlSecTransformCtxPreExecuteCallback referencePreExecuteCallback
##                xmlSecTransformId defSignMethodId
##                xmlSecTransformId defC14NMethodId
##                xmlSecTransformId defDigestMethodId
        # xmlSecKeyPtr signKey
##                xmlSecTransformOperation operation
##                xmlSecBufferPtr result
        # xmlSecDSigStatus status
##                xmlSecTransformPtr signMethod
##                xmlSecTransformPtr c14nMethod
##                xmlSecTransformPtr preSignMemBufMethod
##                xmlNodePtr signValueNode
##                xmlChar * id
##                xmlSecPtrList signedInfoReferences
##                xmlSecPtrList manifestReferences
##                void * reserved0
##                void * reserved1

    ctypedef _xmlSecDSigCtx* xmlSecDSigCtxPtr

    xmlSecDSigCtxPtr xmlSecDSigCtxCreate(xmlSecKeysMngrPtr manager) nogil

    void xmlSecDSigCtxDestroy(xmlSecDSigCtxPtr ctx) nogil
