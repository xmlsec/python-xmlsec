# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals, division

from lxml.includes.tree cimport xmlHasProp, xmlHasNsProp, xmlAttr
from lxml.includes.etreepublic cimport import_lxml__etree
import_lxml__etree()

from lxml.includes.etreepublic cimport _Element

from .ds cimport *
from .constants cimport _Transform, xmlSecTransformUsageSignatureMethod
from .key cimport Key as _Key, KeysManager as _KeysManager, _KeyData, \
    xmlSecKeyDuplicate, xmlSecKeyMatch, xmlSecKeyDestroy
from .utils cimport _b
from .error import *


__all__ = [
    'SignatureContext'
]


cdef class SignatureContext(object):
    """Digital signature context.
    """

    cdef xmlSecDSigCtxPtr _handle

    def __cinit__(self, _KeysManager manager=None):
        cdef xmlSecKeysMngrPtr _manager = manager._handle if manager is not None else NULL
        cdef xmlSecDSigCtxPtr handle
        handle = xmlSecDSigCtxCreate(_manager)
        if handle == NULL:
            raise InternalError('Failed to create the digital signature context.', -1)

        # Store the constructed context handle.
        self._handle = handle

    def __dealloc__(self):
        if self._handle != NULL:
            xmlSecDSigCtxDestroy(self._handle)

    property key:
        def __set__(self, _Key key):
            if self._handle.signKey != NULL:
                xmlSecKeyDestroy(self._handle.signKey)

            self._handle.signKey = xmlSecKeyDuplicate(key._handle)
            if self._handle.signKey == NULL:
                raise InternalError("failed to duplicate key", -1)

        def __get__(self):
            cdef _Key instance = _Key.__new__(_Key)
            instance._owner = False
            instance._handle = self._handle.signKey
            return instance

    def register_id(self, _Element node not None, id_attr="ID", id_ns=None):
        cdef xmlAttr* attr

        if id_ns:
           attr = xmlHasNsProp(node._c_node, _b(id_attr), _b(id_ns))
           attrname = '{%s}%s' % (id_ns, id_attr)
        else:
           attr = xmlHasProp(node._c_node, _b(id_attr))
           attrname = id_attr
        value = node.attrib.get(attrname)

        xmlAddID(NULL, node._doc._c_doc, _b(value), attr)

    def sign(self, _Element node not None):
        """Sign according to the signature template.
        """

        cdef int rv

        rv = xmlSecDSigCtxSign(self._handle, node._c_node)
        if rv != 0:
            raise Error('sign failed with return value', rv)

    def verify(self, _Element node not None):
        """Verify according to the signature template.
        """

        cdef int rv

        rv = xmlSecDSigCtxVerify(self._handle, node._c_node)
        if rv != 0:
            raise Error('verify failed with return value', rv)

        if self._handle.status != xmlSecDSigStatusSucceeded:
            raise VerificationError('Signature verification failed', self._handle.status)

    def sign_binary(self, bytes data not None, _Transform algorithm not None):
        """sign binary data *data* with *algorithm* and return the signature.
        You must already have set the context's `signKey` (its value must
        be compatible with *algorithm* and signature creation).
        """

        cdef xmlSecDSigCtxPtr context = self._handle
        context.operation = xmlSecTransformOperationSign
        self._binary(context, data, algorithm)
        if context.transformCtx.status != xmlSecTransformStatusFinished:
            raise Error("signing failed with transform status", context.transformCtx.status)
        res = context.transformCtx.result
        return <bytes> (<char*>res.data)[:res.size]

    def verify_binary(self, bytes data not None, _Transform algorithm not None, bytes signature not None):
        """Verify *signature* for *data* with *algorithm*.
        You must already have set the context's `signKey` (its value must
        be compatible with *algorithm* and signature verification).
        """

        cdef int rv
        cdef xmlSecDSigCtxPtr context = self._handle
        context.operation = xmlSecTransformOperationVerify
        self._binary(context, data, algorithm)
        rv = xmlSecTransformVerify(context.signMethod,
                                   <const_xmlSecByte *><char *> signature,
                                   len(signature),
                                   &context.transformCtx)
        if rv != 0:
            raise Error("Verification failed with return value", rv)

        if context.signMethod.status != xmlSecTransformStatusOk:
            raise VerificationError("Signature verification failed", context.signMethod.status)

    cdef _binary(self, xmlSecDSigCtxPtr context, bytes data, _Transform algorithm):
        """common helper used for `sign_binary` and `verify_binary`."""

        cdef int rv
        cdef const_xmlSecByte* c_data = <const_xmlSecByte*>data
        cdef xmlSecSize c_size = <xmlSecSize>len(data)

        if not (algorithm.target.usage & xmlSecTransformUsageSignatureMethod):
            raise Error("improper signature algorithm")

        if context.signMethod != NULL:
            raise Error("Signature context already used; it is designed for one use only")

        context.signMethod = xmlSecTransformCtxCreateAndAppend(&(context.transformCtx), algorithm.target)

        if context.signMethod == NULL:
            raise Error("Could not create signature transform")

        context.signMethod.operation = context.operation
        if context.signKey == NULL:
            raise Error("signKey not yet set")

        xmlSecTransformSetKeyReq(context.signMethod, &(context.keyInfoReadCtx.keyReq))

        rv = xmlSecKeyMatch(context.signKey, NULL, &(context.keyInfoReadCtx.keyReq))
        if rv != 1:
            raise Error("inappropriate key type")

        rv = xmlSecTransformSetKey(context.signMethod, context.signKey)
        if rv != 0:
            raise Error("`xmlSecTransfromSetKey` failed", rv)

        context.transformCtx.result = NULL
        context.transformCtx.status = xmlSecTransformStatusNone

        rv = xmlSecTransformCtxBinaryExecute(&(context.transformCtx), c_data, c_size)

        if rv != 0:
            raise Error("transformation failed error value", rv)

        if context.transformCtx.status != xmlSecTransformStatusFinished:
            raise Error("transformation failed with status", context.transformCtx.status)

    def enable_reference_transform(self, _Transform transform):
        """enable use of *t* as reference transform.
        Note: by default, all transforms are enabled. The first call of
        `enableReferenceTransform` will switch to explicitely enabled transforms.
        """

        rv = xmlSecDSigCtxEnableReferenceTransform(self._handle, transform.target)
        if rv < 0:
            raise Error("enableReferenceTransform failed", rv)

    def enable_signature_transform(self, _Transform transform):
        """enable use of *t* as signature transform.
        Note: by default, all transforms are enabled. The first call of
        `enableSignatureTransform` will switch to explicitely enabled transforms.
        """

        rv = xmlSecDSigCtxEnableSignatureTransform(self._handle, transform.target)
        if rv < 0:
            raise Error("enableSignatureTransform failed", rv)

    def set_enabled_key_data(self, keydata_list):
        cdef _KeyData keydata
        cdef xmlSecPtrListPtr enabled_list = &(self._handle.keyInfoReadCtx.enabledKeyData)
        xmlSecPtrListEmpty(enabled_list)
        for keydata in keydata_list:
            rv = xmlSecPtrListAdd(enabled_list, <xmlSecPtr>keydata.target)
            if rv < 0:
                raise Error("setEnabledKeyData failed")
