from os import path
import xmlsec
from .base import parse_xml, compare, BASE_DIR


def test_sign_template_pem():
    """
    Should sign a pre-constructed template file
    using a key from a PEM file.
    """

    # Load the pre-constructed XML template.
    template = parse_xml('sign1-tmpl.xml')

    # Find the <Signature/> node.
    signature_node = xmlsec.tree.find_node(template, xmlsec.Node.SIGNATURE)

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
    del key

    # Sign the template.
    ctx.sign(signature_node)

    # Assert the contents of the XML document against the expected result.
    compare('sign1-res.xml', template)


def test_sign_generated_template_pem():
    """
    Should sign a dynamicaly constructed template file
    using a key from a PEM file.
    """

    # Load document file.
    template = parse_xml('sign2-doc.xml')

    # Create a signature template for RSA-SHA1 enveloped signature.
    signature_node = xmlsec.template.create(
        template,
        xmlsec.Transform.EXCL_C14N,
        xmlsec.Transform.RSA_SHA1)

    assert signature_node is not None

    # Add the <ds:Signature/> node to the document.
    template.append(signature_node)

    # Add the <ds:Reference/> node to the signature template.
    ref = xmlsec.template.add_reference(signature_node, xmlsec.Transform.SHA1)

    # Add the enveloped transform descriptor.
    xmlsec.template.add_transform(ref, xmlsec.Transform.ENVELOPED)

    # Add the <ds:KeyInfo/> and <ds:KeyName/> nodes.
    key_info = xmlsec.template.ensure_key_info(signature_node)
    xmlsec.template.add_key_name(key_info)

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
    compare('sign2-res.xml', template)


def test_sign_generated_template_pem_with_x509():
    """
    Should sign a file using a dynamicaly created template, key from PEM
    file and an X509 certificate.
    """

    # Load document file.
    template = parse_xml('sign3-doc.xml')

    # Create a signature template for RSA-SHA1 enveloped signature.
    signature_node = xmlsec.template.create(
        template,
        xmlsec.Transform.EXCL_C14N,
        xmlsec.Transform.RSA_SHA1)

    assert signature_node is not None

    # Add the <ds:Signature/> node to the document.
    template.append(signature_node)

    # Add the <ds:Reference/> node to the signature template.
    ref = xmlsec.template.add_reference(signature_node, xmlsec.Transform.SHA1)

    # Add the enveloped transform descriptor.
    xmlsec.template.add_transform(ref, xmlsec.Transform.ENVELOPED)

    # Add the <ds:KeyInfo/> and <ds:KeyName/> nodes.
    key_info = xmlsec.template.ensure_key_info(signature_node)
    xmlsec.template.add_x509_data(key_info)

    # Create a digital signature context (no key manager is needed).
    ctx = xmlsec.SignatureContext()

    # Load private key (assuming that there is no password).
    filename = path.join(BASE_DIR, 'rsakey.pem')
    key = xmlsec.Key.from_file(filename, xmlsec.KeyFormat.PEM)

    assert key is not None

    # Load the certificate and add it to the key.
    filename = path.join(BASE_DIR, 'rsacert.pem')
    key.load_cert_from_file(filename, xmlsec.KeyFormat.PEM)

    # Set key name to the file name (note: this is just a test).
    key.name = path.basename(filename)

    # Set the key on the context.
    ctx.key = key

    assert ctx.key is not None
    assert ctx.key.name == path.basename(filename)

    # Sign the template.
    ctx.sign(signature_node)

    # Assert the contents of the XML document against the expected result.
    compare('sign3-res.xml', template)


def test_sign_generated_template_pem_with_x509_with_custom_ns():
    """
    Should sign a file using a dynamicaly created template, key from PEM
    file and an X509 certificate with custom ns.
    """

    # Load document file.
    template = parse_xml('sign4-doc.xml')
    xmlsec.tree.add_ids(template, ["ID"])
    elem_id = template.get('ID', None)
    if elem_id:
        elem_id = '#' + elem_id
    # Create a signature template for RSA-SHA1 enveloped signature.
    signature_node = xmlsec.template.create(
        template,
        xmlsec.Transform.EXCL_C14N,
        xmlsec.Transform.RSA_SHA1, ns='ds')

    assert signature_node is not None

    # Add the <ds:Signature/> node to the document.
    template.append(signature_node)

    # Add the <ds:Reference/> node to the signature template.
    ref = xmlsec.template.add_reference(signature_node, xmlsec.Transform.SHA1, uri=elem_id)

    # Add the enveloped transform descriptor.
    xmlsec.template.add_transform(ref, xmlsec.Transform.ENVELOPED)
    # Add the excl_c14n transform descriptor.
    xmlsec.template.add_transform(ref, xmlsec.Transform.EXCL_C14N)

    # Add the <ds:KeyInfo/> and <ds:KeyName/> nodes.
    key_info = xmlsec.template.ensure_key_info(signature_node)
    xmlsec.template.add_x509_data(key_info)

    # Create a digital signature context (no key manager is needed).
    ctx = xmlsec.SignatureContext()

    # Load private key (assuming that there is no password).
    filename = path.join(BASE_DIR, 'rsakey.pem')
    key = xmlsec.Key.from_file(filename, xmlsec.KeyFormat.PEM)

    assert key is not None

    # Load the certificate and add it to the key.
    filename = path.join(BASE_DIR, 'rsacert.pem')
    key.load_cert_from_file(filename, xmlsec.KeyFormat.PEM)

    # Set key name to the file name (note: this is just a test).
    key.name = path.basename(filename)

    # Set the key on the context.
    ctx.key = key

    assert ctx.key is not None
    assert ctx.key.name == path.basename(filename)

    # Sign the template.
    ctx.sign(signature_node)

    # Assert the contents of the XML document against the expected result.
    compare('sign4-res.xml', template)


def test_sign_binary():
    ctx = xmlsec.SignatureContext()
    filename = path.join(BASE_DIR, 'rsakey.pem')
    key = xmlsec.Key.from_file(filename, xmlsec.KeyFormat.PEM)
    assert key is not None

    key.name = path.basename(filename)

    # Set the key on the context.
    ctx.key = key

    assert ctx.key is not None
    assert ctx.key.name == path.basename(filename)

    data = b'\xa8f4dP\x82\x02\xd3\xf5.\x02\xc1\x03\xef\xc4\x86\xabC\xec\xb7>\x8e\x1f\xa3\xa3\xc5\xb9qc\xc2\x81\xb1-\xa4B\xdf\x03>\xba\xd1'
    expected_sign = b"h\xcb\xb1\x82\xfa`e\x89x\xe5\xc5ir\xd6\xd1Q\x9a\x0b\xeaU_G\xcc'\xa4c\xa3>\x9b27\xbf^`\xa7p\xfb\x98\xcb\x81\xd2\xb1\x0c'\x9d\xe2\n\xec\xb2<\xcf@\x98=\xe0}O8}fy\xc2\xc4\xe9\xec\x87\xf6\xc1\xde\xfd\x96*o\xab\xae\x12\xc9{\xcc\x0e\x93y\x9a\x16\x80o\x92\xeb\x02^h|\xa0\x9b<\x99_\x97\xcb\xe27\xe9u\xc3\xfa_\xcct/sTb\xa0\t\xd3\x93'\xb4\xa4\x0ez\xcbL\x14D\xdb\xe3\x84\x886\xe9J[\xe7\xce\xc0\xb1\x99\x07\x17{\xc6:\xff\x1dt\xfd\xab^2\xf7\x9e\xa4\xccT\x8e~b\xdb\x9a\x04\x04\xbaM\xfa\xbd\xec)z\xbb\x89\xd7\xb2Q\xac\xaf\x13\xdcD\xcd\n6\x92\xfao\xb9\xd9\x96$\xce\xa6\xcf\xf8\xe4Bb60\xf5\xd2a\xb1o\x8c\x0f\x8bl\x88vh\xb5h\xfa\xfa\xb66\xedQ\x10\xc4\xef\xfa\x81\xf0\xc9.^\x98\x1ePQS\x9e\xafAy\x90\xe4\x95\x03V\xc2\xa0\x18\xa5d\xc2\x15*\xb6\xd7$\xc0\t2\xa1"
    sign = ctx.sign_binary(data, xmlsec.Transform.RSA_SHA1)
    assert sign == expected_sign
