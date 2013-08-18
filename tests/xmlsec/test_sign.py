from os import path
import xmlsec
from lxml import etree


def load(name):
    base = path.dirname(__file__)
    return etree.parse(path.join(base, name))


def test_sign_template_pem():
    """Should sign a template file using a key from a PEM file.
    """

    # Load the pre-constructed XML template.
    template = load('sign1-tmpl.xml').getroot()

    # Find the <Signature/> node.
    signature_node = xmlsec.tree.find_node(template, xmlsec.node.SIGNATURE)

    assert signature_node is not None
    assert signature_node.tag.endswith(xmlsec.node.SIGNATURE)
