# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals, division

from xmlsec.key cimport *
from xmlsec.utils cimport *

__all__ = [
    'KeyFormat',
    'Key'
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


cdef class Key(object):

    def __dealloc__(self):
        if self._owner and self._handle != NULL:
            xmlSecKeyDestroy(self._handle)

    def __deepcopy__(self):
        return self.__copy__()

    def __copy__(self):
        cdef Key instance = Key.__new__(Key)
        instance._handle = xmlSecKeyDuplicate(self._handle)

        return instance

    @classmethod
    def from_memory(cls, stream, xmlSecKeyDataFormat format, password=None):
        """Load PKI key from memory.
        """

        cdef xmlSecKeyPtr handle
        cdef size_t c_size
        cdef const_unsigned_char *c_data
        cdef const_char* c_password = <const_char*>_b(password)
        cdef Key instance

        # Read in the stream.
        text = stream.read().encode('utf8')
        c_size = len(text)
        c_data = <const_unsigned_char*><char*>text

        with nogil:
            handle = xmlSecCryptoAppKeyLoadMemory(
                c_data, c_size, format, c_password, NULL, NULL)

        if handle != NULL:
            # Construct and return a new instance.
            instance = Key.__new__(Key)
            instance._handle = handle
            return instance

        # Failed to load the key; return nothing.

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

        if handle != NULL:
            # Construct and return a new instance.
            instance = Key.__new__(Key)
            instance._handle = handle
            return instance

        # Failed to load the key; return nothing.

    def load_cert_from_memory(self, stream, xmlSecKeyDataFormat format):
        cdef int rv
        cdef size_t c_size
        cdef const_unsigned_char *c_data

        text = stream.read().encode('utf8')
        c_size = len(text)
        c_data = <const_unsigned_char*><char*>text

        with nogil:
            rv = xmlSecCryptoAppKeyCertLoadMemory(
                self._handle, c_data, c_size, format)

        if rv != 0:
            raise RuntimeError(
                'Failed to load the certificate from the I/O stream.')

    def load_cert_from_file(self, filename, xmlSecKeyDataFormat format):
        cdef int rv
        cdef const_char* c_filename = <const_char*>_b(filename)
        cdef Key instance

        with nogil:
            rv = xmlSecCryptoAppKeyCertLoad(self._handle, c_filename, format)

        if rv != 0:
            raise RuntimeError(
                'Failed to load the certificate from the file.')

    property name:
        def __get__(self):
            return _u(xmlSecKeyGetName(self._handle))

        def __set__(self, value):
            xmlSecKeySetName(self._handle, _b(value))
