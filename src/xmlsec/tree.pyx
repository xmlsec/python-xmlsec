# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals, division

from libc cimport stdlib
from lxml.includes.etreepublic cimport import_lxml__etree
import_lxml__etree()

from lxml.includes.etreepublic cimport _ElementTree, _Element, elementFactory
from .tree cimport *
from .utils cimport _b
from .constants import Namespace


__all__ = [
    'find_child',
    'find_parent',
    'find_node',
    'add_ids'
]


def find_child(_Element parent not None,
               name not None,
               namespace=Namespace.DS):
    """
    Searches a direct child of the parent node having given name and
    namespace href.
    """
    cdef xmlNode* c_node
    c_node = xmlSecFindChild(parent._c_node, _b(name), _b(namespace))
    return elementFactory(parent._doc, c_node) if c_node else None


def find_parent(_Element node not None,
                name not None,
                namespace=Namespace.DS):
    """
    Searches the ancestors axis of the node for a node having given name
    and namespace href.
    """
    cdef xmlNode* c_node
    c_node = xmlSecFindParent(node._c_node, _b(name), _b(namespace))
    return elementFactory(node._doc, c_node) if c_node else None


def find_node(_Element parent not None,
              name not None,
              namespace=Namespace.DS):
    """
    Searches all children of the parent node having given name and
    namespace href.
    """
    cdef xmlNode* c_node
    c_node = xmlSecFindNode(parent._c_node, _b(name), _b(namespace))
    return elementFactory(parent._doc, c_node) if c_node else None



def add_ids(_Element node, ids):
    """register *ids* as ids used below *node*.
    *ids* is a sequence of attribute names used as XML ids in the subtree
    rooted at *node*.
    A call to `addIds` may be necessary to make known which attributes
    contain XML ids. This is the case, if a transform references
    an id via `XPointer` or a self document uri and the id
    inkey_data_formation is not available by other means (e.g. an associated
    DTD or XML schema).
    """

    cdef const_xmlChar **lst
    cdef int i, n

    n = len(ids)
    lst = <const_xmlChar**> stdlib.malloc(sizeof(const_xmlChar*) * (n + 1))
    if lst == NULL:
        raise MemoryError
    try:
        for i in range(n):
            lst[i] = _b(ids[i])
        lst[n] = NULL
        with nogil:
            xmlSecAddIDs(node._doc._c_doc, node._c_node, lst)
    finally:
        stdlib.free(lst)
