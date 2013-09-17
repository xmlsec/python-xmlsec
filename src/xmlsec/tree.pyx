# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals, division

from lxml.includes.etreepublic cimport import_lxml__etree
import_lxml__etree()

from lxml.includes.etreepublic cimport _ElementTree, _Element, elementFactory
from lxml.includes.tree cimport const_xmlChar, xmlNode
from xmlsec.tree cimport *
from xmlsec.utils cimport *
from . import constants

__all__ = [
    'find_child',
    'find_parent',
    'find_node',
]


def find_child(_Element parent not None,
               name not None,
               namespace=constants.Namespace.DS):
    """
    Searches a direct child of the parent node having given name and
    namespace href.
    """
    cdef xmlNode* c_node
    c_node = xmlSecFindChild(parent._c_node, _b(name), _b(namespace))
    return elementFactory(parent._doc, c_node) if c_node else None


def find_parent(_Element node not None,
                name not None,
                namespace=constants.Namespace.DS):
    """
    Searches the ancestors axis of the node for a node having given name
    and namespace href.
    """
    cdef xmlNode* c_node
    c_node = xmlSecFindParent(node._c_node, _b(name), _b(namespace))
    return elementFactory(node._doc, c_node) if c_node else None


def find_node(_Element parent not None,
              name not None,
              namespace=constants.Namespace.DS):
    """
    Searches all children of the parent node having given name and
    namespace href.
    """
    cdef xmlNode* c_node
    c_node = xmlSecFindNode(parent._c_node, _b(name), _b(namespace))
    return elementFactory(parent._doc, c_node) if c_node else None
