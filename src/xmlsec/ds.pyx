from lxml.includes.etreepublic cimport import_lxml__etree
import_lxml__etree()

from lxml.includes.etreepublic cimport _Element
from ds cimport *
from key cimport Key as _Key, xmlSecKeyDuplicate, xmlSecKeyDestroy

from copy import copy
from .key import Key

__all__ = [
    'SignatureContext'
]



cdef class SignatureContext:
    """Digital signature context.
    """

    cdef xmlSecDSigCtxPtr _handle

    def __cinit__(self):  # , KeysMngr manager=None):
        # cdef xmlSecKeysMngrPtr _mngr
        # _mngr = mngr.mngr if mngr is not None else NULL
        cdef xmlSecDSigCtxPtr handle
        handle = xmlSecDSigCtxCreate(NULL)
        if handle == NULL:
            raise RuntimeError(
                'Failed to create the digital signature context.')

        # Store the constructed context handle.
        self._handle = handle

    def __dealloc__(self):
        if self._handle != NULL:
            xmlSecDSigCtxDestroy(self._handle)

    property key:
        def __set__(self, _Key key):
            self._handle.signKey = key._handle

        def __get__(self):
            cdef _Key instance = Key.__new__(Key)
            instance._owner = False
            instance._handle = self._handle.signKey
            return instance

    def sign(self, _Element node not None):
        """Sign according to the signature template.
        """

        cdef int rv
        cdef xmlSecDSigCtxPtr handle = self._handle

        print('handle.signValueNode == NULL', handle.signValueNode is NULL)
        handle.signValueNode = NULL
        print('handle.signValueNode == NULL', <int>NULL)

        rv = xmlSecDSigCtxSign(handle, node._c_node)


        if rv != 0:
            raise RuntimeError('signing failed with return value %r' % rv)
