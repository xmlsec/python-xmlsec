from lxml.includes.tree cimport const_xmlChar


cdef extern from *:
    ctypedef char const_char "const char"
    ctypedef unsigned char const_unsigned_char "const unsigned char"


cdef extern from "xmlsec.h":  # xmlsec/keys.h

    # cdef struct _xmlSecKeyDataKlass:
    #     const_xmlChar* name
    #     const_xmlChar* href

    # ctypedef _xmlSecKeyDataKlass *xmlSecKeyDataId

    # xmlSecKeyDataId xmlSecKeyDataNameId
    # xmlSecKeyDataId xmlSecKeyDataValueId
    # xmlSecKeyDataId xmlSecKeyDataRetrievalMethodId
    # xmlSecKeyDataId xmlSecKeyDataEncryptedKeyId
    # xmlSecKeyDataId xmlSecKeyDataAesId
    # xmlSecKeyDataId xmlSecKeyDataDesId
    # xmlSecKeyDataId xmlSecKeyDataDsaId
    # xmlSecKeyDataId xmlSecKeyDataHmacId
    # xmlSecKeyDataId xmlSecKeyDataRsaId
    # xmlSecKeyDataId xmlSecKeyDataX509Id
    # xmlSecKeyDataId xmlSecKeyDataRawX509CertId

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

    # ctypedef unsigned int xmlSecKeyDataType

    # cdef enum:
    #     xmlSecKeyDataTypeUnknown = 0x0000
    #     xmlSecKeyDataTypeNone = 0x0000
    #     xmlSecKeyDataTypePublic = 0x0001
    #     xmlSecKeyDataTypePrivate = 0x0002
    #     xmlSecKeyDataTypeSymmetric = 0x0004
    #     xmlSecKeyDataTypeSession = 0x0008
    #     xmlSecKeyDataTypePermanent = 0x0010
    #     xmlSecKeyDataTypeTrusted = 0x0100
    #     xmlSecKeyDataTypeAny = 0xFFFF

    void xmlSecKeyDestroy(xmlSecKeyPtr) nogil

    xmlSecKeyPtr xmlSecKeyDuplicate(xmlSecKeyPtr) nogil

    xmlSecKeyPtr xmlSecCryptoAppKeyLoad(
        const_char*, xmlSecKeyDataFormat, const_char*, void*, void *) nogil

    xmlSecKeyPtr xmlSecCryptoAppKeyLoadMemory(
        const_unsigned_char*, int, xmlSecKeyDataFormat,
        const_char*, void*, void*) nogil

    # xmlSecKeyPtr xmlSecKeyReadBinaryFile(xmlSecKeyDataId, const_char*) nogil

    # xmlSecKeyPtr xmlSecKeyReadMemory(
    #     xmlSecKeyDataId, const_unsigned_char*, size_t) nogil

    int xmlSecCryptoAppKeyCertLoad(
        xmlSecKeyPtr, const_char*, xmlSecKeyDataFormat) nogil

    int xmlSecCryptoAppKeyCertLoadMemory(
        xmlSecKeyPtr, const_unsigned_char*, int, xmlSecKeyDataFormat) nogil

    # xmlSecKeyPtr xmlSecKeyGenerate(
    #     xmlSecKeyDataId, size_t, xmlSecKeyDataType) nogil

    int xmlSecKeySetName(xmlSecKeyPtr, const_xmlChar*) nogil

    const_xmlChar* xmlSecKeyGetName(xmlSecKeyPtr) nogil

cdef class Key(object):
    cdef xmlSecKeyPtr _handle
    cdef bint _owner
