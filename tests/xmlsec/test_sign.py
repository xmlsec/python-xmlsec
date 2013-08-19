from os import path
import xmlsec
from lxml import etree

BASE_DIR = path.dirname(__file__)


def test_sign_1():
    """Should sign a pre-constructed template file using a key from a PEM file.
    """

    # Load the pre-constructed XML template.
    template = etree.parse(path.join(BASE_DIR, 'sign1-tmpl.xml')).getroot()

    # Find the <Signature/> node.
    signature_node = xmlsec.tree.find_node(template, xmlsec.Node.SIGNATURE)

    assert signature_node is not None
    assert signature_node.tag.endswith(xmlsec.Node.SIGNATURE)

    # Create a digital signature context (no key manager is needed).
    ctx = xmlsec.SignatureContext()

    # Load private key (assuming that there is no password).
    filename = path.join(BASE_DIR, 'rsakey.pem')
    ctx.key = xmlsec.Key(filename, xmlsec.Key.Format.PEM)

    # Set key name to the file name (note: this is just a test).
    ctx.key.name = filename

    # Sign the template.
    ctx.sign(signature_node)

    # TODO: Assert the contents of the XML document.
