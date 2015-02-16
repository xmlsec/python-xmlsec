from os import path
import xmlsec
from lxml import etree
from .base import parse_xml, BASE_DIR


def compare(name, result):
    # Parse the expected file.
    xml = parse_xml(name)

    # Stringify the root, <Envelope/> nodes of the two documents.
    expected_text = etree.tostring(xml)
    result_text = etree.tostring(result)

    # Compare the results.
    assert expected_text == result_text


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
