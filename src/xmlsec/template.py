from lxml.etree import _Element
from xmlsec.constants import __Transform as Transform
import ctypes

# Load the shared library (assuming it's named `libxmlsec.so` or similar)
libxmlsec = ctypes.CDLL("../template.c")

# Define the Python wrapper for the C function
libxmlsec.PyXmlSec_TemplateAddEncryptedKey.argtypes = [
    ctypes.POINTER(_Element),  # Assuming _Element is compatible
    ctypes.POINTER(Transform),
    ctypes.c_char_p,  # id
    ctypes.c_char_p,  # type
    ctypes.c_char_p   # recipient
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
        raise RuntimeError("Failed to add encrypted key")

    return result
