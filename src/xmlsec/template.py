import ctypes

from lxml.etree import _Element

from xmlsec.constants import __Transform as Transform

# Load the shared library (assuming it's named `libxmlsec.so` or similar)
libxmlsec = ctypes.CDLL('../template.c')

# Define the Python wrapper for the C function
libxmlsec.PyXmlSec_TemplateAddEncryptedKey.argtypes = [
    ctypes.POINTER(_Element),  # Assuming _Element is compatible
    ctypes.POINTER(Transform),
    ctypes.c_char_p,  # id
    ctypes.c_char_p,  # type
    ctypes.c_char_p,  # recipient
]
libxmlsec.PyXmlSec_TemplateAddEncryptedKey.restype = ctypes.POINTER(_Element)


def add_encrypted_key(
    node: _Element, method: Transform, id: str | None = None, type: str | None = None, recipient: str | None = None
) -> _Element:
    """
    Python wrapper for the C function `PyXmlSec_TemplateAddEncryptedKey`.

    :param node: The XML node to which the encrypted key will be added.
    :param method: The encryption method.
    :param id: Optional ID for the key.
    :param type: Optional type for the key.
    :param recipient: Optional recipient for the key.
    :return: The modified XML node.
    """
    # Convert Python strings to C strings
    c_id = ctypes.c_char_p(id.encode('utf-8') if id else None)
    c_type = ctypes.c_char_p(type.encode('utf-8') if type else None)
    c_recipient = ctypes.c_char_p(recipient.encode('utf-8') if recipient else None)

    # Call the C function
    result = libxmlsec.PyXmlSec_TemplateAddEncryptedKey(node, method, c_id, c_type, c_recipient)

    if not result:
        raise RuntimeError('Failed to add encrypted key')

    return result


def add_key_name(node: _Element, name: str | None = None) -> _Element:
    """
    Python wrapper for the C function `PyXmlSec_TemplateAddKeyName`.

    :param node: The XML node to which the key name will be added.
    :param name: Optional name for the key.
    :return: The modified XML node.
    """
    c_name = ctypes.c_char_p(name.encode('utf-8') if name else None)
    result = libxmlsec.PyXmlSec_TemplateAddKeyName(node, c_name)

    if not result:
        raise RuntimeError('Failed to add key name')

    return result


def add_key_value(node: _Element) -> _Element:
    """
    Python wrapper for the C function `PyXmlSec_TemplateAddKeyValue`.

    :param node: The XML node to which the key value will be added.
    :return: The modified XML node.
    """
    result = libxmlsec.PyXmlSec_TemplateAddKeyValue(node)

    if not result:
        raise RuntimeError('Failed to add key value')

    return result


def add_reference(
    node: _Element, digest_method: Transform, id: str | None = None, uri: str | None = None, type: str | None = None
) -> _Element:
    """
    Python wrapper for the C function `PyXmlSec_TemplateAddReference`.

    :param node: The XML node to which the reference will be added.
    :param digest_method: The digest method for the reference.
    :param id: Optional ID for the reference.
    :param uri: Optional URI for the reference.
    :param type: Optional type for the reference.
    :return: The modified XML node.
    """
    c_id = ctypes.c_char_p(id.encode('utf-8') if id else None)
    c_uri = ctypes.c_char_p(uri.encode('utf-8') if uri else None)
    c_type = ctypes.c_char_p(type.encode('utf-8') if type else None)

    result = libxmlsec.PyXmlSec_TemplateAddReference(node, digest_method, c_id, c_uri, c_type)

    if not result:
        raise RuntimeError('Failed to add reference')

    return result


def add_transform(node: _Element, transform: Transform) -> Any:
    """
    Python wrapper for the C function `PyXmlSec_TemplateAddTransform`.

    :param node: The XML node to which the transform will be added.
    :param transform: The transform to add.
    :return: The modified XML node.
    """
    result = libxmlsec.PyXmlSec_TemplateAddTransform(node, transform)

    if not result:
        raise RuntimeError('Failed to add transform')

    return result


def add_x509_data(node: _Element) -> _Element:
    """
    Python wrapper for the C function `PyXmlSec_TemplateAddX509Data`.

    :param node: The XML node to which the X509 data will be added.
    :return: The modified XML node.
    """
    result = libxmlsec.PyXmlSec_TemplateAddX509Data(node)

    if not result:
        raise RuntimeError('Failed to add X509 data')

    return result


def create(node: _Element, c14n_method: Transform, sign_method: Transform) -> _Element:
    """
    Python wrapper for the C function `PyXmlSec_TemplateCreate`.

    :param node: The XML node to create.
    :param c14n_method: The canonicalization method.
    :param sign_method: The signature method.
    :return: The created XML node.
    """
    result = libxmlsec.PyXmlSec_TemplateCreate(node, c14n_method, sign_method)

    if not result:
        raise RuntimeError('Failed to create template')

    return result


def encrypted_data_create(
    node: _Element,
    method: Transform,
    id: str | None = None,
    type: str | None = None,
    mime_type: str | None = None,
    encoding: str | None = None,
    ns: str | None = None,
) -> _Element:
    """
    Python wrapper for the C function `PyXmlSec_TemplateEncryptedDataCreate`.

    :param node: The XML node to create encrypted data for.
    :param method: The encryption method.
    :param id: Optional ID for the encrypted data.
    :param type: Optional type for the encrypted data.
    :param mime_type: Optional MIME type for the encrypted data.
    :param encoding: Optional encoding for the encrypted data.
    :param ns: Optional namespace for the encrypted data.
    :return: The created encrypted data node.
    """
    c_id = ctypes.c_char_p(id.encode('utf-8') if id else None)
    c_type = ctypes.c_char_p(type.encode('utf-8') if type else None)
    c_mime_type = ctypes.c_char_p(mime_type.encode('utf-8') if mime_type else None)
    c_encoding = ctypes.c_char_p(encoding.encode('utf-8') if encoding else None)
    c_ns = ctypes.c_char_p(ns.encode('utf-8') if ns else None)

    result = libxmlsec.PyXmlSec_TemplateEncryptedDataCreate(node, method, c_id, c_type, c_mime_type, c_encoding, c_ns)

    if not result:
        raise RuntimeError('Failed to create encrypted data')

    return result


def encrypted_data_ensure_cipher_value(node: _Element) -> _Element:
    """
    Python wrapper for the C function `PyXmlSec_TemplateEncryptedDataEnsureCipherValue`.

    :param node: The XML node to ensure cipher value for.
    :return: The modified XML node.
    """
    result = libxmlsec.PyXmlSec_TemplateEncryptedDataEnsureCipherValue(node)

    if not result:
        raise RuntimeError('Failed to ensure cipher value')

    return result


def encrypted_data_ensure_key_info(node: _Element, id: str | None = None, ns: str | None = None) -> _Element:
    """
    Python wrapper for the C function `PyXmlSec_TemplateEncryptedDataEnsureKeyInfo`.

    :param node: The XML node to ensure key info for.
    :param id: Optional ID for the key info.
    :param ns: Optional namespace for the key info.
    :return: The modified XML node.
    """
    c_id = ctypes.c_char_p(id.encode('utf-8') if id else None)
    c_ns = ctypes.c_char_p(ns.encode('utf-8') if ns else None)

    result = libxmlsec.PyXmlSec_TemplateEncryptedDataEnsureKeyInfo(node, c_id, c_ns)

    if not result:
        raise RuntimeError('Failed to ensure key info')

    return result


def ensure_key_info(node: _Element, id: str | None = None) -> _Element:
    """
    Python wrapper for the C function `PyXmlSec_TemplateEnsureKeyInfo`.

    :param node: The XML node to ensure key info for.
    :param id: Optional ID for the key info.
    :return: The modified XML node.
    """
    c_id = ctypes.c_char_p(id.encode('utf-8') if id else None)

    result = libxmlsec.PyXmlSec_TemplateEnsureKeyInfo(node, c_id)

    if not result:
        raise RuntimeError('Failed to ensure key info')

    return result


def transform_add_c14n_inclusive_namespaces(node: _Element, prefixes: str | Sequence[str]) -> None:
    """
    Python wrapper for the C function `PyXmlSec_TemplateTransformAddC14NInclusiveNamespaces`.

    :param node: The XML node to add inclusive namespaces to.
    :param prefixes: The prefixes to add.
    """
    if isinstance(prefixes, str):
        prefixes = [prefixes]

    c_prefixes = (ctypes.c_char_p * len(prefixes))(*[p.encode('utf-8') for p in prefixes])

    result = libxmlsec.PyXmlSec_TemplateTransformAddC14NInclusiveNamespaces(node, c_prefixes)

    if not result:
        raise RuntimeError('Failed to add inclusive namespaces')


def x509_data_add_certificate(node: _Element) -> _Element:
    """
    Python wrapper for the C function `PyXmlSec_TemplateX509DataAddCertificate`.

    :param node: The XML node to add the certificate to.
    :return: The modified XML node.
    """
    result = libxmlsec.PyXmlSec_TemplateX509DataAddCertificate(node)

    if not result:
        raise RuntimeError('Failed to add certificate')

    return result


def x509_data_add_crl(node: _Element) -> _Element:
    """
    Python wrapper for the C function `PyXmlSec_TemplateX509DataAddCRL`.

    :param node: The XML node to add the CRL to.
    :return: The modified XML node.
    """
    result = libxmlsec.PyXmlSec_TemplateX509DataAddCRL(node)

    if not result:
        raise RuntimeError('Failed to add CRL')

    return result


def x509_data_add_issuer_serial(node: _Element) -> _Element:
    """
    Python wrapper for the C function `PyXmlSec_TemplateX509DataAddIssuerSerial`.

    :param node: The XML node to add the issuer serial to.
    :return: The modified XML node.
    """
    result = libxmlsec.PyXmlSec_TemplateX509DataAddIssuerSerial(node)

    if not result:
        raise RuntimeError('Failed to add issuer serial')

    return result


def x509_data_add_ski(node: _Element) -> _Element:
    """
    Python wrapper for the C function `PyXmlSec_TemplateX509DataAddSKI`.

    :param node: The XML node to add the SKI to.
    :return: The modified XML node.
    """
    result = libxmlsec.PyXmlSec_TemplateX509DataAddSKI(node)

    if not result:
        raise RuntimeError('Failed to add SKI')

    return result


def x509_data_add_subject_name(node: _Element) -> _Element:
    """
    Python wrapper for the C function `PyXmlSec_TemplateX509DataAddSubjectName`.

    :param node: The XML node to add the subject name to.
    :return: The modified XML node.
    """
    result = libxmlsec.PyXmlSec_TemplateX509DataAddSubjectName(node)

    if not result:
        raise RuntimeError('Failed to add subject name')

    return result


def x509_issuer_serial_add_issuer_name(node: _Element, name: str | None = None) -> _Element:
    """
    Python wrapper for the C function `PyXmlSec_TemplateX509IssuerSerialAddIssuerName`.

    :param node: The XML node to add the issuer name to.
    :param name: The issuer name to add.
    :return: The modified XML node.
    """
    c_name = ctypes.c_char_p(name.encode('utf-8') if name else None)

    result = libxmlsec.PyXmlSec_TemplateX509IssuerSerialAddIssuerName(node, c_name)

    if not result:
        raise RuntimeError('Failed to add issuer name')

    return result


def x509_issuer_serial_add_serial_number(node: _Element, serial: str | None = None) -> _Element:
    """
    Python wrapper for the C function `PyXmlSec_TemplateX509IssuerSerialAddSerialNumber`.

    :param node: The XML node to add the serial number to.
    :param serial: The serial number to add.
    :return: The modified XML node.
    """
    c_serial = ctypes.c_char_p(serial.encode('utf-8') if serial else None)

    result = libxmlsec.PyXmlSec_TemplateX509IssuerSerialAddSerialNumber(node, c_serial)

    if not result:
        raise RuntimeError('Failed to add serial number')

    return result
