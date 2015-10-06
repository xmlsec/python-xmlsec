from lxml.includes.tree cimport xmlChar, const_xmlChar, xmlNode
from .key cimport xmlSecKeyPtr, xmlSecKeyReqPtr, xmlSecKeysMngrPtr
from .ds cimport const_xmlSecByte, xmlSecBufferPtr


cdef extern from "xmlsec.h":  # xmlsec/keys.h

    cdef enum: XMLSEC_ENC_RETURN_REPLACED_NODE

    cdef struct _xmlSecEncCtx:
        # void * userData
        unsigned int flags
        # unsigned int flags2
        # xmlEncCtxMode mode
        # xmlSecKeyInfoCtx keyInfoReadCtx
        # xmlSecKeyInfoCtx keyInfoWriteCtx
        # xmlSecTransformCtx transformCtx
        # xmlSecTransformId defEncMethodId
        xmlSecKeyPtr encKey
        # xmlSecTransformOperation operation
        xmlSecBufferPtr result
        # int resultBase64Encoded
        bint resultReplaced
        # xmlSecTransformPtr encMethod
        # xmlChar* id
        # xmlChar* type
        # xmlChar* mimeType
        # xmlChar* encoding
        # xmlChar* recipient
        # xmlChar* carriedKeyName
        # xmlNode* encDataNode
        # xmlNode* encMethodNode
        # xmlNode* keyInfoNode
        # xmlNode* cipherValueNode
        xmlNode* replacedNodeList
        # void* reserved1

    ctypedef _xmlSecEncCtx* xmlSecEncCtxPtr

    xmlSecEncCtxPtr xmlSecEncCtxCreate(xmlSecKeysMngrPtr) nogil
    int xmlSecEncCtxInitialize(xmlSecEncCtxPtr encCtx, xmlSecKeysMngrPtr keysMngr) nogil

    void xmlSecEncCtxFinalize(xmlSecEncCtxPtr) nogil
    void xmlSecEncCtxDestroy(xmlSecEncCtxPtr) nogil

    int xmlSecEncCtxBinaryEncrypt(
        xmlSecEncCtxPtr, xmlNode*, const_xmlSecByte*, size_t) nogil

    int xmlSecEncCtxXmlEncrypt(xmlSecEncCtxPtr, xmlNode*, xmlNode*) nogil

    int xmlSecEncCtxUriEncrypt(xmlSecEncCtxPtr, xmlNode*, const_xmlChar*) nogil

    int xmlSecEncCtxDecrypt(xmlSecEncCtxPtr, xmlNode*) nogil

    void xmlSecErrorsSetCallback(void *callback) nogil

    int xmlSecKeyMatch(xmlSecKeyPtr, const_xmlChar*, xmlSecKeyReqPtr)
