from os import path
import xmlsec
from lxml import etree

BASE_DIR = path.dirname(__file__)


def parse_xml(name):
    return etree.parse(path.join(BASE_DIR, name))


def compare(name, result):
    # Parse the expected file.
    xml = parse_xml(name).getroot()

    # Stringify the root, <Envelope/> nodes of the two documents.
    expected_text = etree.tostring(xml)
    result_text = etree.tostring(result)

    # Compare the results.
    assert expected_text == result_text


def test_sign_template_pem():
    """Should sign a pre-constructed template file using a key from a PEM file.
    """

    # Load the pre-constructed XML template.
    template = parse_xml('sign1-tmpl.xml')
    root = template.getroot()

    # Find the <Signature/> node.
    signature_node = xmlsec.tree.find_node(root, xmlsec.Node.SIGNATURE)

    assert signature_node is not None
    assert signature_node.tag.endswith(xmlsec.Node.SIGNATURE)

    # Create a digital signature context (no key manager is needed).
    ctx = xmlsec.SignatureContext()

    # Load private key (assuming that there is no password).
    filename = path.join(BASE_DIR, 'rsakey.pem')
    key = xmlsec.Key.from_file(filename, xmlsec.KeyFormat.PEM)

    assert key is not None

    # Set key name to the file name (note: this is just a test).
    key.name = path.basename(filename)

    # Set the key on the context.
    ctx.key = key

    assert ctx.key is not None
    assert ctx.key.name == path.basename(filename)

    # Sign the template.
    ctx.sign(signature_node)

    # Assert the contents of the XML document against the expected result.
    compare('sign1-res.xml', root)
