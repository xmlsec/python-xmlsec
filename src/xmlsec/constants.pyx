# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals, division

from .constants cimport *
from .utils cimport _u

__all__ = [
    'Namespace',
    'Node',
    'Transform',
    'EncryptionType'
]


class Namespace:
    """Global namespaces."""
    BASE = _u(xmlSecNs)
    DS = _u(xmlSecDSigNs)
    ENC = _u(xmlSecEncNs)
    XPATH = _u(xmlSecXPathNs)
    XPATH2 = _u(xmlSecXPath2Ns)
    XPOINTER = _u(xmlSecXPointerNs)
    SOAP11 = _u(xmlSecSoap11Ns)
    SOAP12 = _u(xmlSecSoap12Ns)


class EncryptionType:
    CONTENT = _u(xmlSecTypeEncContent)
    ELEMENT = _u(xmlSecTypeEncElement)


class Node:
    """Digital signature nodes."""
    SIGNATURE = _u(xmlSecNodeSignature)
    SIGNED_INFO = _u(xmlSecNodeSignedInfo)
    CANONICALIZATION_METHOD = _u(xmlSecNodeCanonicalizationMethod)
    SIGNATURE_METHOD = _u(xmlSecNodeSignatureMethod)
    SIGNATURE_VALUE = _u(xmlSecNodeSignatureValue)
    DIGEST_METHOD = _u(xmlSecNodeDigestMethod)
    DIGEST_VALUE = _u(xmlSecNodeDigestValue)
    OBJECT = _u(xmlSecNodeObject)
    MANIFEST = _u(xmlSecNodeManifest)
    SIGNATURE_PROPERTIES = _u(xmlSecNodeSignatureProperties)
    ENCRYPTED_DATA = _u(xmlSecNodeEncryptedData)
    ENCRYPTED_KEY = _u(xmlSecNodeEncryptedKey)
    ENCRYPTION_METHOD = _u(xmlSecNodeEncryptionMethod)
    ENCRYPTION_PROPERTIES = _u(xmlSecNodeEncryptionProperties)
    ENCRYPTION_PROPERTY = _u(xmlSecNodeEncryptionProperty)
    CIPHER_DATA = _u(xmlSecNodeCipherData)
    CIPHER_VALUE = _u(xmlSecNodeCipherValue)
    CIPHER_REFERENCE = _u(xmlSecNodeCipherReference)
    REFERENCE_LIST = _u(xmlSecNodeReferenceList)
    DATA_REFERENCE = _u(xmlSecNodeDataReference)
    KEY_REFERENCE = _u(xmlSecNodeKeyReference)
    KEY_INFO = _u(xmlSecNodeKeyInfo)


cdef class _Transform:
    property name:
        def __get__(self):
            return _u(self.target.name)

    property href:
        def __get__(self):
            return _u(self.target.href)

    property usage:
        def __get__(self):
            return self.target.usage


cdef _Transform _mkti(xmlSecTransformId target):
    cdef _Transform r = _Transform.__new__(_Transform)
    r.target = target
    return r


class Transform:
    """Transform identifiers."""

    C14N = _mkti(xmlSecTransformInclC14NGetKlass())
    C14N_COMMENTS = _mkti(xmlSecTransformInclC14NWithCommentsGetKlass())
    C14N11 = _mkti(xmlSecTransformInclC14N11GetKlass())
    C14N11_COMMENTS = _mkti(xmlSecTransformInclC14N11WithCommentsGetKlass())
    EXCL_C14N = _mkti(xmlSecTransformExclC14NGetKlass())
    EXCL_C14N_COMMENTS = _mkti(xmlSecTransformExclC14NWithCommentsGetKlass())
    ENVELOPED = _mkti(xmlSecTransformEnvelopedGetKlass())
    XPATH = _mkti(xmlSecTransformXPathGetKlass())
    XPATH2 = _mkti(xmlSecTransformXPath2GetKlass())
    XPOINTER = _mkti(xmlSecTransformXPointerGetKlass())
    XSLT = _mkti(xmlSecTransformXsltGetKlass())
    REMOVE_XML_TAGS_C14N = _mkti(xmlSecTransformRemoveXmlTagsC14NGetKlass())
    VISA3D_HACK = _mkti(xmlSecTransformVisa3DHackGetKlass())

    AES128 = _mkti(xmlSecOpenSSLTransformAes128CbcGetKlass())
    AES192 = _mkti(xmlSecOpenSSLTransformAes192CbcGetKlass())
    AES256 = _mkti(xmlSecOpenSSLTransformAes256CbcGetKlass())
    KW_AES128 = _mkti(xmlSecOpenSSLTransformKWAes128GetKlass())
    KW_AES192 = _mkti(xmlSecOpenSSLTransformKWAes192GetKlass())
    KW_AES256 = _mkti(xmlSecOpenSSLTransformKWAes256GetKlass())
    DES3 = _mkti(xmlSecOpenSSLTransformDes3CbcGetKlass())
    KW_DES3 = _mkti(xmlSecOpenSSLTransformKWDes3GetKlass())
    DSA_SHA1 = _mkti(xmlSecOpenSSLTransformDsaSha1GetKlass())
    # ECDSA_SHA1 = _mkti(xmlSecOpenSSLTransformEcdsaSha1GetKlass())
    # ECDSA_SHA224 = _mkti(xmlSecOpenSSLTransformEcdsaSha224GetKlass())
    # ECDSA_SHA256 = _mkti(xmlSecOpenSSLTransformEcdsaSha256GetKlass())
    # ECDSA_SHA384 = _mkti(xmlSecOpenSSLTransformEcdsaSha384GetKlass())
    # ECDSA_SHA512 = _mkti(xmlSecOpenSSLTransformEcdsaSha512GetKlass())
    HMAC_MD5 = _mkti(xmlSecOpenSSLTransformHmacMd5GetKlass())
    HMAC_RIPEMD160 = _mkti(xmlSecOpenSSLTransformHmacRipemd160GetKlass())
    HMAC_SHA1 = _mkti(xmlSecOpenSSLTransformHmacSha1GetKlass())
    HMAC_SHA224 = _mkti(xmlSecOpenSSLTransformHmacSha224GetKlass())
    HMAC_SHA256 = _mkti(xmlSecOpenSSLTransformHmacSha256GetKlass())
    HMAC_SHA384 = _mkti(xmlSecOpenSSLTransformHmacSha384GetKlass())
    HMAC_SHA512 = _mkti(xmlSecOpenSSLTransformHmacSha512GetKlass())
    MD5 = _mkti(xmlSecOpenSSLTransformMd5GetKlass())
    RIPEMD160 = _mkti(xmlSecOpenSSLTransformRipemd160GetKlass())
    RSA_MD5 = _mkti(xmlSecOpenSSLTransformRsaMd5GetKlass())
    RSA_RIPEMD160 = _mkti(xmlSecOpenSSLTransformRsaRipemd160GetKlass())
    RSA_SHA1 = _mkti(xmlSecOpenSSLTransformRsaSha1GetKlass())
    RSA_SHA224 = _mkti(xmlSecOpenSSLTransformRsaSha224GetKlass())
    RSA_SHA256 = _mkti(xmlSecOpenSSLTransformRsaSha256GetKlass())
    RSA_SHA384 = _mkti(xmlSecOpenSSLTransformRsaSha384GetKlass())
    RSA_SHA512 = _mkti(xmlSecOpenSSLTransformRsaSha512GetKlass())
    RSA_PKCS1 = _mkti(xmlSecOpenSSLTransformRsaPkcs1GetKlass())
    RSA_OAEP = _mkti(xmlSecOpenSSLTransformRsaOaepGetKlass())
    SHA1 = _mkti(xmlSecOpenSSLTransformSha1GetKlass())
    SHA224 = _mkti(xmlSecOpenSSLTransformSha224GetKlass())
    SHA256 = _mkti(xmlSecOpenSSLTransformSha256GetKlass())
    SHA384 = _mkti(xmlSecOpenSSLTransformSha384GetKlass())
    SHA512 = _mkti(xmlSecOpenSSLTransformSha512GetKlass())
