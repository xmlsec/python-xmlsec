from constants cimport *
from utils cimport *

__all__ = [
    'namespace',
    'node'
]


class namespace:
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


class node:
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
