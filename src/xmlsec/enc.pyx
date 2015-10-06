# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals, division

from lxml.includes.etreepublic cimport import_lxml__etree
import_lxml__etree()

from lxml.includes.etreepublic cimport _Document, _Element, elementFactory
from lxml.includes.tree cimport xmlDocCopyNode, xmlFreeNode, xmlDoc, xmlDocGetRootElement

from .enc cimport *
from .key cimport Key as _Key, KeysManager as _KeysManager, _KeyData, \
    xmlSecKeyDuplicate, xmlSecKeyMatch, xmlSecKeyDestroy
from .utils cimport _b

from .constants import EncryptionType
from .error import *
from copy import copy

__all__ = [
    'EncryptionContext'
]


# we let `lxml` get rid of the subtree by wrapping *c_node* into a
# proxy and then releasing it again.
# Note: if referenced by `lxml`, nodes inside the subtree may lack
# necessary namespace daclarations. Hopefully, I can
# convince the `lxml` maintainers to provide a really safe
# `lxml_safe_unlink` function

cdef inline int _lxml_safe_dealloc(_Document doc, xmlNode* c_node) except -1:
    elementFactory(doc, c_node)
    return 0



cdef class EncryptionContext:
    """Encryption context."""

    cdef xmlSecEncCtxPtr _handle

    def __cinit__(self, _KeysManager manager=None):
        cdef xmlSecKeysMngrPtr _manager = manager._handle if manager is not None else NULL
        cdef xmlSecEncCtxPtr handle = xmlSecEncCtxCreate(_manager)
        if handle == NULL:
            raise InternalError("failed to create encryption context")

        self._handle = handle

    def __dealloc__(self):
        if self._handle != NULL:
            xmlSecEncCtxDestroy(self._handle)

    property key:
        def __set__(self, _Key key):
                if self._handle.encKey != NULL:
                    xmlSecKeyDestroy(self._handle.encKey)

                self._handle.encKey = xmlSecKeyDuplicate(key._handle)
                if self._handle.encKey == NULL:
                    raise InternalError("failed to duplicate key", -1)

        def __get__(self):
            cdef _Key instance = _Key.__new__(_Key)
            instance._owner = False
            instance._handle = self._handle.encKey
            return instance

    def encrypt_binary(self, _Element template not None, data):
        """encrypt binary *data* according to `EncryptedData` template *template*
        and return the resulting `EncryptedData` subtree.
        Note: *template* is modified in place.
        """
        cdef int rv

        # Data to bytes
        cdef const_xmlSecByte* c_data = <const_xmlSecByte*>data
        cdef size_t c_size = len(data)

        with nogil:
            rv = xmlSecEncCtxBinaryEncrypt(self._handle, template._c_node, c_data, c_size)
        if rv < 0:
            raise Error("failed to encrypt binary", rv)
        return template

    def encrypt_xml(self, _Element template not None, _Element node not None):
        """encrpyt *node* using *template* and return the resulting `EncryptedData` element.
        The `Type` attribute of *template* decides whether *node* itself is
        encrypted (`http://www.w3.org/2001/04/xmlenc#Element`)
        or its content (`http://www.w3.org/2001/04/xmlenc#Content`).
        It must have one of these two
        values (or an exception is raised).
        The operation modifies the tree containing *node* in a way that
        `lxml` references to or into this tree may see a surprising state. You
        should no longer rely on them. Especially, you should use
        `getroottree()` on the result to obtain the encrypted result tree.
        """

        cdef int rv
        cdef xmlNode *n
        cdef xmlNode *nn
        cdef xmlSecEncCtxPtr context = self._handle
        cdef xmlNode *c_node = template._c_node

        et = template.get("Type")
        if et not in (EncryptionType.ELEMENT,  EncryptionType.CONTENT):
            raise Error("unsupported `Type` for `encryptXML` (must be `%s` or `%s`)" % (EncryptionType.ELEMENT,  EncryptionType.CONTENT), et)

        # `xmlSecEncCtxEncrypt` expects *template* to belong to the document of *node*
        #  if this is not the case, we copy the `libxml2` subtree there.

        if template._doc._c_doc != node._doc._c_doc:
            with nogil:
                c_node = xmlDocCopyNode(c_node, node._doc._c_doc, 1) # recursive
            if c_node == NULL:
                raise MemoryError("could not copy template tree")

        # `xmlSecEncCtxXmlEncrypt` will replace the subtree rooted
        #   at `node._c_node` or its children by an extended subtree
        #   rooted at "c_node".
        #   We set `XMLSEC_ENC_RETURN_REPLACED_NODE` to prevent deallocation
        #   of the replaced node. This is important as `node` is still
        #   referencing it

        context.flags = XMLSEC_ENC_RETURN_REPLACED_NODE

        with nogil:
            rv = xmlSecEncCtxXmlEncrypt(context, c_node, node._c_node)

        # release the replaced nodes in a way safe for `lxml`

        n = <xmlNode*> context.replacedNodeList

        while n != NULL:
            nn = n.next
            _lxml_safe_dealloc(node._doc, n)
            n = nn

        context.replacedNodeList = NULL
        if rv < 0:
            if c_node._private == NULL:
                # template tree was copied; free it again.
                # Note: if the problem happened late (e.g. a `MemoryError`)
                #  `c_node' might already be part of the result tree.
                #  In this case, memory corruption may result. But,
                #  we have an inconsistent state anyway and the probability
                #  should be very low.

                with nogil:
                    xmlFreeNode(c_node) # free formerly copied template subtree

                raise Error("failed to encrypt xml", rv)

        # `c_node` contains the resulting `EncryptedData` element.
        return elementFactory(node._doc, c_node)

    def encrypt_uri(self, _Element template not None, uri not None):
        """encrypt binary data obtained from *uri* according to *template*."""

        cdef int rv
        cdef const_xmlChar* c_uri = _b(uri)

        with nogil:
            rv = xmlSecEncCtxUriEncrypt(self._handle, template._c_node, c_uri)

        if rv < 0:
            raise Error("failed to encrypt uri", rv)
        return template

    def decrypt(self, _Element node not None):
        """decrypt *node* (an `EncryptedData` element) and return the result.
        The decryption may result in binary data or an XML subtree.
        In the former case, the binary data is returned. In the latter case,
        the input tree is modified and a reference to the decrypted
        XML subtree is returned.
        If the operation modifies the tree,
        `lxml` references to or into this tree may see a surprising state. You
        should no longer rely on them. Especially, you should use
        `getroottree()` on the result to obtain the decrypted result tree.
        """

        cdef int rv
        cdef xmlSecEncCtxPtr context = self._handle
        cdef bint decrypt_content
        cdef xmlNode *n
        cdef xmlNode *nn
        cdef xmlNode *c_root
        cdef xmlSecBufferPtr result

        decrypt_content = node.get("Type") == EncryptionType.CONTENT

        # must provide sufficient context to find the decrypted node
        parent = node.getparent()

        if parent is not None:
            enc_index = parent.index(node)

        context.flags = XMLSEC_ENC_RETURN_REPLACED_NODE

        with nogil:
            rv = xmlSecEncCtxDecrypt(context, node._c_node)

        # release the replaced nodes in a way safe for `lxml`
        n = <xmlNode*> context.replacedNodeList
        while n != NULL:
            nn = n.next
            _lxml_safe_dealloc(node._doc, n)
            n = nn

        context.replacedNodeList = NULL

        if rv < 0:
            raise Error("failed to decrypt", rv)

        if not context.resultReplaced:
            # binary result
            result = context.result
            return <bytes> (<char*>context.result.data)[:result.size]
        # XML result
        if parent is not None:
            if decrypt_content:
                return parent
            else:
                return parent[enc_index]

        # root has been replaced
        c_root = xmlDocGetRootElement(node._doc._c_doc)
        if c_root == NULL:
            raise Error("decryption resulted in a non well formed document")
        return elementFactory(node._doc, c_root)
