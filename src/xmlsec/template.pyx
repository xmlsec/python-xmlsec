# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals, division

from lxml.includes.etreepublic cimport import_lxml__etree
import_lxml__etree()

from .template cimport *
from lxml.includes.etreepublic cimport _Element, elementFactory
from lxml.includes.tree cimport xmlStrdup
from .constants cimport _Transform
from .utils cimport _b


def create(_Element node not None,
           _Transform c14n_method not None,
           _Transform sign_method not None,
           name=None,
           ns=None):

    cdef xmlNode* c_node
    cdef const_xmlChar* c_name = _b(name)
    cdef const_xmlChar* c_ns = _b(ns)

    c_node = xmlSecTmplSignatureCreateNsPref(
        node._doc._c_doc, c14n_method.target, sign_method.target, c_name, c_ns)

    return elementFactory(node._doc, c_node)


def add_reference(_Element node not None,
                  _Transform digest_method not None,
                  id=None, uri=None, type=None):

    cdef xmlNode* c_node
    cdef const_xmlChar* c_id = _b(id)
    cdef const_xmlChar* c_uri = _b(uri)
    cdef const_xmlChar* c_type = _b(type)

    c_node = xmlSecTmplSignatureAddReference(
        node._c_node, digest_method.target, c_id, c_uri, c_type)

    return elementFactory(node._doc, c_node)


def add_transform(_Element node not None, _Transform transform not None):
    cdef xmlNode* c_node

    c_node = xmlSecTmplReferenceAddTransform(
        node._c_node, transform.target)

    return elementFactory(node._doc, c_node)


def ensure_key_info(_Element node not None, id=None):

    cdef xmlNode* c_node
    cdef const_xmlChar* c_id = _b(id)

    c_node = xmlSecTmplSignatureEnsureKeyInfo(node._c_node, c_id)

    return elementFactory(node._doc, c_node)


def add_key_name(_Element node not None, name=None):

    cdef xmlNode* c_node
    cdef const_xmlChar* c_name = _b(name)

    c_node = xmlSecTmplKeyInfoAddKeyName(node._c_node, c_name)

    return elementFactory(node._doc, c_node)


def add_key_value(_Element node not None):

    cdef xmlNode* c_node

    c_node = xmlSecTmplKeyInfoAddKeyValue(node._c_node)

    return elementFactory(node._doc, c_node)


def add_x509_data(_Element node not None):

    cdef xmlNode* c_node

    c_node = xmlSecTmplKeyInfoAddX509Data(node._c_node)

    return elementFactory(node._doc, c_node)


def x509_data_add_issuer_serial(_Element node not None):

    cdef xmlNode* c_node

    c_node = xmlSecTmplX509DataAddIssuerSerial(node._c_node)

    return elementFactory(node._doc, c_node)


def x509_issuer_serial_add_issuer_name(_Element node not None, name=None):

    cdef xmlNode* c_node
    cdef const_xmlChar* c_name = _b(name)

    c_node = xmlSecTmplX509IssuerSerialAddIssuerName(node._c_node, c_name)

    return elementFactory(node._doc, c_node)


def x509_issuer_serial_add_serial_number(_Element node not None, serial=None):

    cdef xmlNode* c_node
    cdef const_xmlChar* c_serial = _b(serial)

    c_node = xmlSecTmplX509IssuerSerialAddSerialNumber(node._c_node, c_serial)

    return elementFactory(node._doc, c_node)


def x509_data_add_subject_name(_Element node not None):

    cdef xmlNode* c_node

    c_node = xmlSecTmplX509DataAddSubjectName(node._c_node)

    return elementFactory(node._doc, c_node)


def x509_data_add_ski(_Element node not None):

    cdef xmlNode* c_node

    c_node = xmlSecTmplX509DataAddSKI(node._c_node)

    return elementFactory(node._doc, c_node)


def x509_data_add_certificate(_Element node not None):

    cdef xmlNode* c_node

    c_node = xmlSecTmplX509DataAddCertificate(node._c_node)

    return elementFactory(node._doc, c_node)


def x509_data_add_crl(_Element node not None):

    cdef xmlNode* c_node

    c_node = xmlSecTmplX509DataAddCRL(node._c_node)

    return elementFactory(node._doc, c_node)


def add_encrypted_key(_Element node not None,
                      _Transform method not None,
                      id=None,
                      type=None,
                      recipient=None):
    """Adds <enc:EncryptedKey/> node with given attributes to the <dsig:KeyInfo/> node keyInfoNode.
    """

    cdef xmlNode* c_node
    cdef const_xmlChar* c_id = _b(id)
    cdef const_xmlChar* c_type = _b(type)
    cdef const_xmlChar* c_recipient = _b(recipient)

    c_node = xmlSecTmplKeyInfoAddEncryptedKey(node._c_node, method.target, c_id, c_type, c_recipient)
    return elementFactory(node._doc, c_node)


def encrypted_data_create(_Element node not None,
                          _Transform method not None,
                          id=None,
                          type=None,
                          mime_type=None,
                          encoding=None,
                          ns=None):
    """
    Creates new <{ns}:EncryptedData /> node for encryption template.
    """
    cdef xmlNode* c_node
    cdef const_xmlChar* c_id = _b(id)
    cdef const_xmlChar* c_type = _b(type)
    cdef const_xmlChar* c_mtype = _b(mime_type)
    cdef const_xmlChar* c_encoding = _b(encoding)

    c_node = xmlSecTmplEncDataCreate(
        node._doc._c_doc, method.target, c_id, c_type, c_mtype, c_encoding)

    if ns is not None:
        c_node.ns.prefix = xmlStrdup(_b(ns))
    return elementFactory(node._doc, c_node)


def encrypted_data_ensure_key_info(_Element node not None, id=None, ns=None):
    """
        Adds <{ns}:KeyInfo/> to the <enc:EncryptedData/> node encNode.
    """

    cdef xmlNode* c_node
    cdef const_xmlChar* c_id = _b(id)

    c_node = xmlSecTmplEncDataEnsureKeyInfo(node._c_node, c_id)
    if ns is not None:
        c_node.ns.prefix = xmlStrdup(_b(ns))

    return elementFactory(node._doc, c_node)


def encrypted_data_ensure_cipher_value(_Element node not None):
    cdef xmlNode* c_node
    c_node = xmlSecTmplEncDataEnsureCipherValue(node._c_node)

    return elementFactory(node._doc, c_node)
