# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals, division

from xmlsec.constants cimport *
from xmlsec.utils cimport *

__all__ = [
    'Namespace',
    'Node',
    'Transform'
]


class Namespace:
    """Global namespaces."""
    BASE = _u(xmlSecNs)
    DS = _u(xmlSecDSigNs)
    ENC = _u(xmlSecEncNs)
    XKMS = _u(xmlSecXkmsNs)
    XPATH = _u(xmlSecXPathNs)
    XPATH2 = _u(xmlSecXPath2Ns)
    XPOINTER = _u(xmlSecXPointerNs)
    SOAP11 = _u(xmlSecSoap11Ns)
    SOAP12 = _u(xmlSecSoap12Ns)


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


cdef _Transform _mkti(xmlSecTransformId target):
    cdef _Transform r = _Transform.__new__(_Transform)
    r.target = target
    return r


class Transform:
    """Transform identifiers."""

    C14N = _mkti(xmlSecTransformInclC14NId)
    C14N_COMMENTS = _mkti(xmlSecTransformInclC14NWithCommentsId)
    C14N11 = _mkti(xmlSecTransformInclC14N11Id)
    C14N11_COMMENTS = _mkti(xmlSecTransformInclC14N11WithCommentsId)
    EXCL_C14N = _mkti(xmlSecTransformExclC14NId)
    EXCL_C14N_COMMENTS = _mkti(xmlSecTransformExclC14NWithCommentsId)
    ENVELOPED = _mkti(xmlSecTransformEnvelopedId)
    XPATH = _mkti(xmlSecTransformXPathId)
    XPATH2 = _mkti(xmlSecTransformXPath2Id)
    XPOINTER = _mkti(xmlSecTransformXPointerId)
    XSLT = _mkti(xmlSecTransformXsltId)
    REMOVE_XML_TAGS_C14N = _mkti(xmlSecTransformRemoveXmlTagsC14NId)
    VISA3D_HACK = _mkti(xmlSecTransformVisa3DHackId)

    AES128 = _mkti(xmlSecTransformAes128CbcId)
    AES192 = _mkti(xmlSecTransformAes192CbcId)
    AES256 = _mkti(xmlSecTransformAes256CbcId)
    KW_AES128 = _mkti(xmlSecTransformKWAes128Id)
    KW_AES192 = _mkti(xmlSecTransformKWAes192Id)
    KW_AES256 = _mkti(xmlSecTransformKWAes256Id)
    DES3 = _mkti(xmlSecTransformDes3CbcId)
    KW_DES3 = _mkti(xmlSecTransformKWDes3Id)
    DSA_SHA1 = _mkti(xmlSecTransformDsaSha1Id)
    HMAC_MD5 = _mkti(xmlSecTransformHmacMd5Id)
    HMAC_RIPEMD160 = _mkti(xmlSecTransformHmacRipemd160Id)
    HMAC_SHA1 = _mkti(xmlSecTransformHmacSha1Id)
    HMAC_SHA224 = _mkti(xmlSecTransformHmacSha224Id)
    HMAC_SHA256 = _mkti(xmlSecTransformHmacSha256Id)
    HMAC_SHA384 = _mkti(xmlSecTransformHmacSha384Id)
    HMAC_SHA512 = _mkti(xmlSecTransformHmacSha512Id)
    MD5 = _mkti(xmlSecTransformMd5Id)
    RIPEMD160 = _mkti(xmlSecTransformRipemd160Id)
    RSA_MD5 = _mkti(xmlSecTransformRsaMd5Id)
    RSA_RIPEMD160 = _mkti(xmlSecTransformRsaRipemd160Id)
    RSA_SHA1 = _mkti(xmlSecTransformRsaSha1Id)
    RSA_SHA224 = _mkti(xmlSecTransformRsaSha224Id)
    RSA_SHA256 = _mkti(xmlSecTransformRsaSha256Id)
    RSA_SHA384 = _mkti(xmlSecTransformRsaSha384Id)
    RSA_SHA512 = _mkti(xmlSecTransformRsaSha512Id)
    RSA_PKCS1 = _mkti(xmlSecTransformRsaPkcs1Id)
    RSA_OAEP = _mkti(xmlSecTransformRsaOaepId)
    SHA1 = _mkti(xmlSecTransformSha1Id)
    SHA224 = _mkti(xmlSecTransformSha224Id)
    SHA256 = _mkti(xmlSecTransformSha256Id)
    SHA384 = _mkti(xmlSecTransformSha384Id)
    SHA512 = _mkti(xmlSecTransformSha512Id)
