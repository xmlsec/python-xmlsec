from key cimport *
from utils cimport *

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


cdef class Key:
    def __dealloc__(self):
        if self._owner and self._handle != NULL:
            xmlSecKeyDestroy(self._handle)

    def __deepcopy__(self):
        return self.__copy__()

    def __copy__(self):
        cdef Key instance = Key.__new__(Key)
        instance._handle = xmlSecKeyDuplicate(self._handle)

        return instance

    def __init__(self, stream, format, password=None):
        """Load PKI key from memory.
        """

        cdef xmlSecKeyPtr handle
        cdef size_t c_size
        cdef const_unsigned_char *c_data
        cdef xmlSecKeyDataFormat c_format = format
        cdef const_char* c_password = <const_char*>_b(password)

        # Read in the stream.
        text = stream.read().encode('utf8')
        c_size = len(text)
        c_data = <const_unsigned_char*><char*>text

        with nogil:
            handle = xmlSecCryptoAppKeyLoadMemory(
                c_data, c_size, c_format, c_password, NULL, NULL)

        if handle == NULL:
            raise RuntimeError(
                'Failed to load the key from the I/O stream.')

        # Set the new handle.
        self._handle = handle

        # Failed to load the key; return nothing.

    @classmethod
    def from_file(cls, filename, format, password=None):
        """Load PKI key from a file.
        """

        cdef xmlSecKeyPtr handle
        cdef xmlSecKeyDataFormat c_format = format
        cdef const_char* c_filename = <const_char*>_b(filename)
        cdef const_char* c_password = <const_char*>_b(password)
        cdef Key instance

        with nogil:
            handle = xmlSecCryptoAppKeyLoad(
                c_filename, c_format, c_password, NULL, NULL)

        if handle != NULL:
            # Construct and return a new instance.
            instance = Key.__new__(Key)
            instance._handle = handle
            return instance

        # Failed to load the key; return nothing.

    property name:
        def __get__(self):
            return _u(xmlSecKeyGetName(self._handle))

        def __set__(self, value):
            xmlSecKeySetName(self._handle, _b(value))
