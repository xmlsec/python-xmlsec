from os import path
from pytest import mark
import xmlsec
from .base import parse_xml, BASE_DIR


@mark.parametrize('index', range(1, 5))
def test_verify_with_pem_file(index):
    """Should verify a signed file using a key from a PEM file.
    """

    # Load the XML document.
    template = parse_xml('sign%d-res.xml' % index)
    xmlsec.tree.add_ids(template, ["ID"])
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


def test_validate_binary_sign():
    ctx = xmlsec.SignatureContext()
    filename = path.join(BASE_DIR, 'rsakey.pem')
    print("!!!", BASE_DIR, filename)
    key = xmlsec.Key.from_file(filename, xmlsec.KeyFormat.PEM)
    assert key is not None

    key.name = path.basename(filename)

    # Set the key on the context.
    ctx.key = key

    assert ctx.key is not None
    assert ctx.key.name == path.basename(filename)

    data = b'\xa8f4dP\x82\x02\xd3\xf5.\x02\xc1\x03\xef\xc4\x86\xabC\xec\xb7>\x8e\x1f\xa3\xa3\xc5\xb9qc\xc2\x81\xb1-\xa4B\xdf\x03>\xba\xd1'
    sign = b"h\xcb\xb1\x82\xfa`e\x89x\xe5\xc5ir\xd6\xd1Q\x9a\x0b\xeaU_G\xcc'\xa4c\xa3>\x9b27\xbf^`\xa7p\xfb\x98\xcb\x81\xd2\xb1\x0c'\x9d\xe2\n\xec\xb2<\xcf@\x98=\xe0}O8}fy\xc2\xc4\xe9\xec\x87\xf6\xc1\xde\xfd\x96*o\xab\xae\x12\xc9{\xcc\x0e\x93y\x9a\x16\x80o\x92\xeb\x02^h|\xa0\x9b<\x99_\x97\xcb\xe27\xe9u\xc3\xfa_\xcct/sTb\xa0\t\xd3\x93'\xb4\xa4\x0ez\xcbL\x14D\xdb\xe3\x84\x886\xe9J[\xe7\xce\xc0\xb1\x99\x07\x17{\xc6:\xff\x1dt\xfd\xab^2\xf7\x9e\xa4\xccT\x8e~b\xdb\x9a\x04\x04\xbaM\xfa\xbd\xec)z\xbb\x89\xd7\xb2Q\xac\xaf\x13\xdcD\xcd\n6\x92\xfao\xb9\xd9\x96$\xce\xa6\xcf\xf8\xe4Bb60\xf5\xd2a\xb1o\x8c\x0f\x8bl\x88vh\xb5h\xfa\xfa\xb66\xedQ\x10\xc4\xef\xfa\x81\xf0\xc9.^\x98\x1ePQS\x9e\xafAy\x90\xe4\x95\x03V\xc2\xa0\x18\xa5d\xc2\x15*\xb6\xd7$\xc0\t2\xa1"
    ctx.verify_binary(data, xmlsec.Transform.RSA_SHA1, sign)
