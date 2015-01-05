from os import path
import xmlsec
from tests.examples.base import parse_xml, BASE_DIR


def test_verify_with_pem_file(index):
    """Should verify a signed file using a key from a PEM file.
    """

    # Load the XML document.
    template = parse_xml('sign%d-res.xml' % index)

    # Find the <Signature/> node.
    signature_node = xmlsec.tree.find_node(template, xmlsec.Node.SIGNATURE)

    assert signature_node is not None
    assert signature_node.tag.endswith(xmlsec.Node.SIGNATURE)

    # Create a digital signature context (no key manager is needed).
    ctx = xmlsec.SignatureContext()

    # Load the public key.
    filename = path.join(BASE_DIR, 'rsapub.pem')
    key = xmlsec.Key.from_file(filename, xmlsec.KeyFormat.PEM)

    assert key is not None

    # Set key name to the file name (note: this is just a test).
    key.name = path.basename(filename)

    # Set the key on the context.
    ctx.key = key

    assert ctx.key is not None
    assert ctx.key.name == path.basename(filename)

    # Verify the signature.
    ctx.verify(signature_node)
    print('done:', index)


if __name__ == '__main__':
    for i in range(1, 4):
        test_verify_with_pem_file(i)