import xmlsec


def test_create_signature_template():
    node = xmlsec.create_signature_template()

    assert node.tag.endswith('Signature')
    assert node.xpath('*[local-name() = "SignatureValue"]')
    assert node.xpath('*[local-name() = "SignedInfo"]')

    return node


def test_add_reference():
    node = test_create_signature_template()
    ref = xmlsec.add_reference(node, uri=b'#_34275907093489075620748690')

    assert ref.tag.endswith('Reference')
    assert node.xpath('.//*[local-name() = "Reference"]')
