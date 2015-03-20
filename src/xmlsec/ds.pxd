from lxml.includes.tree cimport xmlNode
from lxml.includes.tree cimport const_xmlChar, xmlNode, xmlID, xmlDoc, xmlAttr
from lxml.includes.dtdvalid cimport xmlValidCtxt
from .key cimport xmlSecKeyPtr, xmlSecKeyReq, xmlSecKeyReqPtr, xmlSecKeysMngrPtr
from .constants cimport xmlSecTransformId


cdef extern from "xmlsec.h":  # xmlsec/keys.h

    ctypedef unsigned int xmlSecSize
    ctypedef unsigned char xmlSecByte
    ctypedef xmlSecByte const_xmlSecByte "const xmlSecByte"

    ctypedef void * xmlSecPtrList
    ctypedef xmlSecPtrList * xmlSecPtrListPtr
    ctypedef void * xmlSecPtr

    int xmlSecPtrListAdd(xmlSecPtrListPtr, xmlSecPtr) nogil

    int xmlSecPtrListEmpty(xmlSecPtrListPtr) nogil

    cdef struct _xmlSecBuffer:
        xmlSecByte* data
        size_t size
        # size_t maxSize
        # xmlSecAllocMode allocMode

    ctypedef _xmlSecBuffer *xmlSecBufferPtr

    # transforms and transform contexts (partial)
    ctypedef enum xmlSecTransformStatus:
        xmlSecTransformStatusNone = 0
        xmlSecTransformStatusWorking
        xmlSecTransformStatusFinished
        xmlSecTransformStatusOk
        xmlSecTransformStatusFail

    ctypedef enum xmlSecTransformOperation:
        xmlSecTransformOperationNone = 0
        xmlSecTransformOperationEncode
        xmlSecTransformOperationDecode
        xmlSecTransformOperationSign
        xmlSecTransformOperationVerify
        xmlSecTransformOperationEncrypt
        xmlSecTransformOperationDecrypt

    cdef struct _xmlSecTransform:
        xmlSecTransformOperation operation
        xmlSecTransformStatus status

    ctypedef _xmlSecTransform* xmlSecTransformPtr

    cdef struct _xmlSecTransformCtx:
        xmlSecBufferPtr result
        xmlSecTransformStatus status

    ctypedef _xmlSecTransformCtx xmlSecTransformCtx
    ctypedef _xmlSecTransformCtx* xmlSecTransformCtxPtr

    cdef struct xmlSecKeyInfoCtx:
        xmlSecPtrList enabledKeyData
        xmlSecKeyReq keyReq

    ctypedef enum xmlSecDSigStatus:
        xmlSecDSigStatusUnknown = 0
        xmlSecDSigStatusSucceeded = 1
        xmlSecDSigStatusInvalid = 2

    cdef struct _xmlSecDSigCtx:
        # void* userData
        # unsigned int flags
        # unsigned int flags2
        xmlSecKeyInfoCtx keyInfoReadCtx
        # xmlSecKeyInfoCtx keyInfoWriteCtx
        xmlSecTransformCtx transformCtx
        # xmlSecTransformUriType enabledReferenceUris
        # xmlSecPtrListPtr enabledReferenceTransforms
        # xmlSecTransformCtxPreExecuteCallback referencePreExecuteCallback
        # xmlSecTransformId defSignMethodId
        # xmlSecTransformId defC14NMethodId
        # xmlSecTransformId defDigestMethodId
        xmlSecKeyPtr signKey
        xmlSecTransformOperation operation
        # xmlSecBufferPtr result
        xmlSecDSigStatus status
        xmlSecTransformPtr signMethod
        # xmlSecTransformPtr c14nMethod
        # xmlSecTransformPtr preSignMemBufMethod
        # xmlNode* signValueNode
        # xmlChar* id
        # xmlSecPtrList signedInfoReferences
        # xmlSecPtrList manifestReferences
        # void* reserved0
        # void* reserved1

    ctypedef _xmlSecDSigCtx* xmlSecDSigCtxPtr


    xmlSecDSigCtxPtr xmlSecDSigCtxCreate(xmlSecKeysMngrPtr) nogil

    int xmlSecDSigCtxSign(xmlSecDSigCtxPtr, xmlNode*) nogil

    int xmlSecDSigCtxProcessSignatureNode(xmlSecDSigCtxPtr, xmlNode*) nogil

    int xmlSecDSigCtxVerify(xmlSecDSigCtxPtr, xmlNode*) nogil

    int xmlSecDSigCtxEnableReferenceTransform(
        xmlSecDSigCtxPtr, xmlSecTransformId) nogil

    int xmlSecDSigCtxEnableSignatureTransform(
        xmlSecDSigCtxPtr, xmlSecTransformId) nogil

    void xmlSecDSigCtxDestroy(xmlSecDSigCtxPtr) nogil

    xmlID* xmlAddID(xmlValidCtxt* ctx, xmlDoc* doc, const_xmlChar* value, xmlAttr* attr)

    xmlSecTransformPtr xmlSecTransformCtxCreateAndAppend(xmlSecTransformCtxPtr, xmlSecTransformId) nogil

    int xmlSecTransformSetKey(xmlSecTransformPtr, xmlSecKeyPtr) nogil

    int xmlSecTransformSetKeyReq(xmlSecTransformPtr, xmlSecKeyReqPtr) nogil

    int xmlSecTransformVerify(xmlSecTransformPtr, const_xmlSecByte*, xmlSecSize, xmlSecTransformCtxPtr) nogil

    int xmlSecTransformCtxBinaryExecute(xmlSecTransformCtxPtr, const_xmlSecByte*, xmlSecSize) nogil
