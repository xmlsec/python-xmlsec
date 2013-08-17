import xmlsec


def test_create_signature_template():
    node = xmlsec.create_signature_template()

    assert node.tag.endswith('Signature')
    assert node.xpath('*[local-name() = "SignatureValue"]')
    assert node.xpath('*[local-name() = "SignedInfo"]')


def test_add_reference():
    node = xmlsec.create_signature_template()
    ref = xmlsec.add_reference(node, uri=b'#_34275907093489075620748690')

    assert ref.tag.endswith('Reference')
    assert node.xpath('.//*[local-name() = "Reference"]')


def test_add_transform():
    node = xmlsec.create_signature_template()
    ref = xmlsec.add_reference(node, uri=b'#_34275907093489075620748690')
    xmlsec.add_transform(ref, xmlsec.method.ENVELOPED)

    assert ref.xpath('.//*[local-name() = "Transform"]')


def test_ensure_key_info():
    node = xmlsec.create_signature_template()
    xmlsec.ensure_key_info(node)

    assert node.xpath('.//*[local-name() = "KeyInfo"]')


def test_add_x509_data():
    node = xmlsec.create_signature_template()
    info = xmlsec.ensure_key_info(node)
    xmlsec.add_x509_data(info)

    assert node.xpath('.//*[local-name() = "X509Data"]')


def test_add_key_name():
    node = xmlsec.create_signature_template()
    info = xmlsec.ensure_key_info(node)
    xmlsec.add_key_name(info, b'bob.pem')

    assert node.xpath('.//*[local-name() = "KeyName" and text() = "bob.pem"]')
