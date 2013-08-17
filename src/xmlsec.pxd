from tree cimport xmlNode, xmlDoc, xmlChar, const_xmlChar


cdef extern from *:
    ctypedef char const_char "const char"
    ctypedef unsigned char const_unsigned_char "const unsigned char"


cdef extern from "xmlsec.h":  # xmlsec/xmlsec.h
    int xmlSecInit() nogil
    int xmlSecShutdown() nogil


cdef extern from "xmlsec.h":  # xmlsec/app.h
    int xmlSecCryptoInit() nogil
    int xmlSecCryptoShutdown() nogil

    int xmlSecCryptoAppInit(char* name) nogil
    int xmlSecCryptoAppShutdown() nogil


cdef extern from "xmlsec.h":  # xmlsec/transforms.h
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


cdef extern from "xmlsec.h":  # xmlsec/keys.h
    cdef struct _xmlSecKeyDataKlass:
        const_xmlChar* name
        const_xmlChar* href

    ctypedef _xmlSecKeyDataKlass* xmlSecKeyDataId

    xmlSecKeyDataId xmlSecKeyDataNameId
    xmlSecKeyDataId xmlSecKeyDataValueId
    xmlSecKeyDataId xmlSecKeyDataRetrievalMethodId
    xmlSecKeyDataId xmlSecKeyDataEncryptedKeyId
    xmlSecKeyDataId xmlSecKeyDataAesId
    xmlSecKeyDataId xmlSecKeyDataDesId
    xmlSecKeyDataId xmlSecKeyDataDsaId
    xmlSecKeyDataId xmlSecKeyDataHmacId
    xmlSecKeyDataId xmlSecKeyDataRsaId
    xmlSecKeyDataId xmlSecKeyDataX509Id
    xmlSecKeyDataId xmlSecKeyDataRawX509CertId

    ctypedef void* xmlSecKeyPtr

    ctypedef enum xmlSecKeyDataFormat:
        xmlSecKeyDataFormatUnknown = 0
        xmlSecKeyDataFormatBinary = 1
        xmlSecKeyDataFormatPem = 2
        xmlSecKeyDataFormatDer = 3
        xmlSecKeyDataFormatPkcs8Pem = 4
        xmlSecKeyDataFormatPkcs8Der = 5
        xmlSecKeyDataFormatPkcs12 = 6
        xmlSecKeyDataFormatCertPem = 7
        xmlSecKeyDataFormatCertDer = 8

    ctypedef unsigned int xmlSecKeyDataType

    cdef enum:
        xmlSecKeyDataTypeUnknown = 0x0000
        xmlSecKeyDataTypeNone = 0x0000
        xmlSecKeyDataTypePublic = 0x0001
        xmlSecKeyDataTypePrivate = 0x0002
        xmlSecKeyDataTypeSymmetric = 0x0004
        xmlSecKeyDataTypeSession = 0x0008
        xmlSecKeyDataTypePermanent = 0x0010
        xmlSecKeyDataTypeTrusted = 0x0100
        xmlSecKeyDataTypeAny = 0xFFFF

    void xmlSecKeyDestroy(xmlSecKeyPtr) nogil

    xmlSecKeyPtr xmlSecKeyDuplicate(xmlSecKeyPtr) nogil

    xmlSecKeyPtr xmlSecCryptoAppKeyLoad(
        const_char*, xmlSecKeyDataFormat, const_char*, void*, void*) nogil

    int xmlSecCryptoAppKeyCertLoad(
        xmlSecKeyPtr, const_char*, xmlSecKeyDataFormat) nogil

    xmlSecKeyPtr xmlSecCryptoAppKeyLoadMemory(
        const_unsigned_char*, int, xmlSecKeyDataFormat,
        const_char*, void*, void*) nogil

    xmlSecKeyPtr xmlSecKeyReadBinaryFile(
        xmlSecKeyDataId, const_char*) nogil

    xmlSecKeyPtr xmlSecKeyReadMemory(
        xmlSecKeyDataId, const_unsigned_char*, size_t) nogil

    xmlSecKeyPtr xmlSecKeyGenerate(
        xmlSecKeyDataId, size_t, xmlSecKeyDataType) nogil

    int xmlSecKeySetName(xmlSecKeyPtr, const_xmlChar*) nogil

    const_xmlChar* xmlSecKeyGetName(xmlSecKeyPtr) nogil


cdef extern from "xmlsec.h":  # xmlsec/keysmngr.h
    ctypedef void* xmlSecKeysMngrPtr

    xmlSecKeysMngrPtr xmlSecKeysMngrCreate() nogil

    void xmlSecKeysMngrDestroy(xmlSecKeysMngrPtr) nogil

    int xmlSecCryptoAppDefaultKeysMngrInit(xmlSecKeysMngrPtr) nogil

    int xmlSecCryptoAppDefaultKeysMngrAdoptKey(
        xmlSecKeysMngrPtr, xmlSecKeyPtr) nogil

    int xmlSecCryptoAppKeysMngrCertLoad(
        xmlSecKeysMngrPtr, char* filename,
        xmlSecKeyDataFormat, xmlSecKeyDataType) nogil

    int xmlSecCryptoAppKeysMngrCertLoadMemory(
        xmlSecKeysMngrPtr, const_unsigned_char*, size_t,
        xmlSecKeyDataFormat, xmlSecKeyDataType) nogil


cdef extern from "xmlsec.h":  # xmlsec/xmldsig.h
    ctypedef enum xmlSecDSigStatus:
        xmlSecDSigStatusUnknown = 0
        xmlSecDSigStatusSucceeded = 1
        xmlSecDSigStatusInvalid = 2

    struct _xmlSecDSigCtx:
        # These data user can set before performing the operation.
        # void* userData
        # int flags
        # int flags2
        # xmlSecKeyInfoCtx keyInfoReadCtx
        # xmlSecKeyInfoCtx keyInfoWriteCtx
        # xmlSecTransformCtx transformCtx
        # xmlSecTransformUriType enabledReferenceUris
        # xmlSecPtrListPtr enabledReferenceTransforms
        # xmlSecTransformCtxPreExecuteCallback referencePreExecuteCallback
        # xmlSecTransformId defSignMethodId
        # xmlSecTransformId defC14NMethodId
        # xmlSecTransformId defDigestMethodId

        # These data are returned.
        xmlSecKeyPtr signKey
        # xmlSecTransformOperation operation
        # xmlSecBufferPtr result
        xmlSecDSigStatus status
        # xmlSecTransformPtr signMethod
        # xmlSecTransformPtr c14nMethod
        # xmlSecTransformPtr preSignMemBufMethod
        # xmlNodePtr signValueNode
        # xmlChar* id
        # xmlSecPtrList signedInfoReferences
        # xmlSecPtrList  manifestReferences

        # Reserved for future.
        # void* reserved0
        # void* reserved1

    ctypedef _xmlSecDSigCtx* xmlSecDSigCtxPtr

    xmlSecDSigCtxPtr xmlSecDSigCtxCreate(xmlSecKeysMngrPtr manager) nogil

    void xmlSecDSigCtxDestroy(xmlSecDSigCtxPtr ctx) nogil

    int xmlSecDSigCtxSign(xmlSecDSigCtxPtr, xmlNodePtr) nogil

    int xmlSecDSigCtxVerify(xmlSecDSigCtxPtr, xmlNodePtr) nogil

    int xmlSecDSigCtxEnableReferenceTransform(
        xmlSecDSigCtxPtr, xmlSecTransformId) nogil

    int xmlSecDSigCtxEnableSignatureTransform(
        xmlSecDSigCtxPtr, xmlSecTransformId) nogil
