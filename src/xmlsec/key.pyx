# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals, division

from .key cimport *
from .utils cimport _b, _u
from .error import *
from copy import copy

__all__ = [
    'KeyData',
    'KeyDataType',
    'KeyFormat',
    'Key',
    'KeysManager'
]


class KeyFormat:
    UNKNOWN = xmlSecKeyDataFormatUnknown
    BINARY = xmlSecKeyDataFormatBinary
    PEM = xmlSecKeyDataFormatPem
    DER = xmlSecKeyDataFormatDer
    PKCS8_PEM = xmlSecKeyDataFormatPkcs8Pem
    PKCS8_DER = xmlSecKeyDataFormatPkcs8Der
    PKCS12_PEM = xmlSecKeyDataFormatPkcs12
    CERT_PEM = xmlSecKeyDataFormatCertPem
    CERT_DER = xmlSecKeyDataFormatCertDer


cdef class _KeyData(object):
    property name:
        def __get__(self):
            return _u(<const_xmlChar*>self.id.name)

    property href:
        def __get__(self):
            return _u(<const_xmlChar*>self.id.href)


cdef _KeyData _mkkdi(xmlSecKeyDataId target):
    cdef _KeyData r = _KeyData.__new__(_KeyData)
    r.target = target
    return r


cdef class KeyData(object):
    NAME = _mkkdi(xmlSecKeyDataNameId)
    VALUE = _mkkdi(xmlSecKeyDataValueId)
    RETRIEVALMETHOD = _mkkdi(xmlSecKeyDataRetrievalMethodId)
    ENCRYPTEDKEY = _mkkdi(xmlSecKeyDataEncryptedKeyId)
    AES = _mkkdi(xmlSecKeyDataAesId)
    DES = _mkkdi(xmlSecKeyDataDesId)
    DSA = _mkkdi(xmlSecKeyDataDsaId)
    ECDSA = _mkkdi(xmlSecKeyDataEcdsaId)
    HMAC = _mkkdi(xmlSecKeyDataHmacId)
    RSA = _mkkdi(xmlSecKeyDataRsaId)
    X509 = _mkkdi(xmlSecKeyDataX509Id)
    RAWX509CERT = _mkkdi(xmlSecKeyDataRawX509CertId)



cdef class KeyDataType(object):
    UNKNOWN = xmlSecKeyDataTypeUnknown
    NONE = xmlSecKeyDataTypeNone
    PUBLIC = xmlSecKeyDataTypePublic
    PRIVATE = xmlSecKeyDataTypePrivate
    SYMMETRIC = xmlSecKeyDataTypeSymmetric
    SESSION = xmlSecKeyDataTypeSession
    PERMANENT = xmlSecKeyDataTypePermanent
    TRUSTED = xmlSecKeyDataTypeTrusted
    ANY = xmlSecKeyDataTypeAny


cdef class Key(object):

    def __dealloc__(self):
        if self._owner and self._handle != NULL:
            xmlSecKeyDestroy(self._handle)

    def __deepcopy__(self):
        return self.__copy__()

    def __copy__(self):
        cdef Key instance = type(self)()
        instance._handle = xmlSecKeyDuplicate(self._handle)
        if instance._handle == NULL:
            raise InternalError("failed to duplicate key", -1)

        return instance

    @classmethod
    def from_memory(cls, data, xmlSecKeyDataFormat format, password=None):
        """Load PKI key from memory.
        """

        cdef xmlSecKeyPtr handle
        cdef size_t c_size
        cdef const_unsigned_char *c_data
        cdef const_char* c_password = <const_char*>_b(password)
        cdef Key instance

        if hasattr(data, "read"):
            data = data.read()

        if isinstance(data, str):
            data = data.encode('utf8')

        c_size = len(data)
        c_data = <const_unsigned_char*><char*>data

        with nogil:
            handle = xmlSecCryptoAppKeyLoadMemory(
                c_data, c_size, format, c_password, NULL, NULL)

        if handle == NULL:
            raise ValueError("failed to load key")

        # Construct and return a new instance.
        instance = cls()
        instance._handle = handle
        return instance

    @classmethod
    def from_file(cls, filename, xmlSecKeyDataFormat format, password=None):
        """Load PKI key from a file.
        """

        cdef xmlSecKeyPtr handle
        cdef const_char* c_filename = <const_char*>_b(filename)
        cdef const_char* c_password = <const_char*>_b(password)
        cdef Key instance

        with nogil:
            handle = xmlSecCryptoAppKeyLoad(
                c_filename, format, c_password, NULL, NULL)

        if handle == NULL:
            raise ValueError("failed to load key from '%s'" % filename)

        # Construct and return a new instance.
        instance = cls()
        instance._handle = handle
        return instance

    @classmethod
    def generate(cls, _KeyData data, size_t size, xmlSecKeyDataType type):
        """Generate key of kind *data* with *size* and *type*.
        """

        cdef xmlSecKeyPtr handle
        cdef xmlSecKeyDataId data_id = data.target
        cdef Key instance

        with nogil:
           handle = xmlSecKeyGenerate(data_id, size, type)

        if handle == NULL:
           raise ValueError("failed to generate key")

        # Construct and return a new instance.
        instance = cls()
        instance._handle = handle
        return instance

    @classmethod
    def from_binary_file(cls, _KeyData data, filename):
        """load (symmetric) key from file.
        load key of kind *data* from *filename*
        """
        cdef xmlSecKeyPtr handle
        cdef const_char* c_filename = <const_char*>_b(filename)
        cdef xmlSecKeyDataId data_id = data.target
        cdef Key instance

        with nogil:
           handle = xmlSecKeyReadBinaryFile(data_id, c_filename)

        if handle == NULL:
           raise ValueError("failed to load from '%s'" % filename)

        # Construct and return a new instance.
        instance = cls()
        instance._handle = handle
        return instance


    def load_cert_from_memory(self, data, xmlSecKeyDataFormat format):
        cdef int rv
        cdef size_t c_size
        cdef const_unsigned_char *c_data

        if isinstance(data, str):
            data = data.encode('utf8')
        c_size = len(data)
        c_data = <const_unsigned_char*><char*>data

        with nogil:
            rv = xmlSecCryptoAppKeyCertLoadMemory(
                self._handle, c_data, c_size, format)

        if rv != 0:
            raise ValueError('Failed to load the certificate from the I/O stream.')

    def load_cert_from_file(self, filename, xmlSecKeyDataFormat format):
        cdef int rv
        cdef const_char* c_filename = <const_char*>_b(filename)
        cdef Key instance

        with nogil:
            rv = xmlSecCryptoAppKeyCertLoad(self._handle, c_filename, format)

        if rv != 0:
            raise ValueError('Failed to load the certificate from the file.')

    property name:
        def __get__(self):
            return _u(xmlSecKeyGetName(self._handle))

        def __set__(self, value):
            xmlSecKeySetName(self._handle, _b(value))


cdef class KeysManager(object):
    def __cinit__(self):
        cdef int rv
        cdef xmlSecKeysMngrPtr handle

        handle = xmlSecKeysMngrCreate()
        if handle == NULL:
            raise InternalError("failed to create keys manager", -1)

        rv = xmlSecCryptoAppDefaultKeysMngrInit(handle)
        if rv < 0:
            raise InternalError("failed to initialize keys manager", rv)
        self._handle = handle

    def __dealloc__(self):
        if self._handle != NULL:
            xmlSecKeysMngrDestroy(self._handle)

    def add_key(self, Key key):
        """add (a copy of) *key*."""

        cdef int rv
        cdef xmlSecKeyPtr key_handle = xmlSecKeyDuplicate(key._handle)
        if key_handle == NULL:
            raise InternalError("failed to copy key", -1)

        rv = xmlSecCryptoAppDefaultKeysMngrAdoptKey(self._handle, key_handle)
        if rv < 0:
            xmlSecKeyDestroy(key_handle)
            raise Error("failed to add key", rv)

    def load_cert(self, filename, xmlSecKeyDataFormat format, xmlSecKeyDataType type):
        """load certificate from *filename*.
        *format* specifies the key data format.
        *type* specifies the type and is an or of `KeyDataType*` constants.
        """
        cdef int rv
        cdef const_char* c_filename = <const_char*>_b(filename)

        with nogil:
            rv = xmlSecCryptoAppKeysMngrCertLoad(self._handle, c_filename, format, type)

        if rv != 0:
            raise Error("failed to load certificate from '%s'" % filename, rv)

    def load_cert_from_memory(self, data, xmlSecKeyDataFormat format, xmlSecKeyDataType type):
        """load certificate from *data* (a sequence of bytes).
        *format* specifies the key_data_format.
        *type* specifies the type and is an or of `KeyDataType*` constants.
        """
        cdef int rv
        cdef size_t c_size
        cdef const_unsigned_char *c_data

        if isinstance(data, str):
            data = data.encode('utf8')
        c_size = len(data)
        c_data = <const_unsigned_char*><char*>data

        with nogil:
            rv = xmlSecCryptoAppKeysMngrCertLoadMemory(self._handle, c_data, c_size, format, type)

        if rv != 0:
            raise Error("failed to load certificate from memory", rv)
