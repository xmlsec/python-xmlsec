from lxml.includes.tree cimport xmlNode
from xmlsec.key cimport xmlSecKeyPtr


cdef extern from "xmlsec.h":  # xmlsec/keys.h

    ctypedef enum xmlSecDSigStatus:
        xmlSecDSigStatusUnknown = 0
        xmlSecDSigStatusSucceeded = 1
        xmlSecDSigStatusInvalid = 2

    cdef struct _xmlSecDSigCtx:
        # void* userData
        # unsigned int flags
        # unsigned int flags2
        # xmlSecKeyInfoCtx keyInfoReadCtx
        # xmlSecKeyInfoCtx keyInfoWriteCtx
        # xmlSecTransformCtx transformCtx
        # xmlSecTransformUriType enabledReferenceUris
        # xmlSecPtrListPtr enabledReferenceTransforms
        # xmlSecTransformCtxPreExecuteCallback referencePreExecuteCallback
        # xmlSecTransformId defSignMethodId
        # xmlSecTransformId defC14NMethodId
        # xmlSecTransformId defDigestMethodId
        xmlSecKeyPtr signKey
        # xmlSecTransformOperation operation
        # xmlSecBufferPtr result
        xmlSecDSigStatus status
        # xmlSecTransformPtr signMethod
        # xmlSecTransformPtr c14nMethod
        # xmlSecTransformPtr preSignMemBufMethod
        # xmlNode* signValueNode
        # xmlChar* id
        # xmlSecPtrList signedInfoReferences
        # xmlSecPtrList manifestReferences
        # void* reserved0
        # void* reserved1

    ctypedef _xmlSecDSigCtx* xmlSecDSigCtxPtr

    ctypedef void* xmlSecKeysMngrPtr

    xmlSecDSigCtxPtr xmlSecDSigCtxCreate(xmlSecKeysMngrPtr) nogil

    int xmlSecDSigCtxSign(xmlSecDSigCtxPtr, xmlNode*) nogil

    int xmlSecDSigCtxProcessSignatureNode(xmlSecDSigCtxPtr, xmlNode*) nogil

    int xmlSecDSigCtxVerify(xmlSecDSigCtxPtr, xmlNode*) nogil

    # int xmlSecDSigCtxEnableReferenceTransform(
    #     xmlSecDSigCtxPtr, xmlSecTransformId) nogil

    # int xmlSecDSigCtxEnableSignatureTransform(
    #     xmlSecDSigCtxPtr, xmlSecTransformId) nogil

    void xmlSecDSigCtxDestroy(xmlSecDSigCtxPtr) nogil
