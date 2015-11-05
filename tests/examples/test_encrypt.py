from os import path
import xmlsec
from .base import parse_xml, BASE_DIR
from lxml import etree


def read_from_file(filename):
    with open(filename, "rb") as stream:
        return stream.read()


def test_encrypt_xml():
    # Load the public cert
    manager = xmlsec.KeysManager()
    filename = path.join(BASE_DIR, 'rsacert.pem')
    key = xmlsec.Key.from_memory(read_from_file(filename), xmlsec.KeyFormat.CERT_PEM, None)
    assert key is not None
    manager.add_key(key)
    template = parse_xml('enc1-doc.xml')
    assert template is not None
    # Prepare for encryption
    enc_data = xmlsec.template.encrypted_data_create(
        template, xmlsec.Transform.AES128, type=xmlsec.EncryptionType.ELEMENT, ns="xenc")

    xmlsec.template.encrypted_data_ensure_cipher_value(enc_data)
    key_info = xmlsec.template.encrypted_data_ensure_key_info(enc_data, ns="dsig")
    enc_key = xmlsec.template.add_encrypted_key(key_info, xmlsec.Transform.RSA_OAEP)
    xmlsec.template.encrypted_data_ensure_cipher_value(enc_key)

    data = template.find('./Data')

    assert data is not None
    # Encrypt!
    enc_ctx = xmlsec.EncryptionContext(manager)
    enc_ctx.key = xmlsec.Key.generate(xmlsec.KeyData.AES, 128, xmlsec.KeyDataType.SESSION)
    enc_datsa = enc_ctx.encrypt_xml(enc_data, data)
    assert enc_data is not None
    enc_method = xmlsec.tree.find_child(enc_data, xmlsec.Node.ENCRYPTION_METHOD, xmlsec.Namespace.ENC)
    assert enc_method is not None
    assert enc_method.get("Algorithm") == "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
    key_info = xmlsec.tree.find_child(enc_data, xmlsec.Node.KEY_INFO, xmlsec.Namespace.DS)
    assert key_info is not None
    enc_method = xmlsec.tree.find_node(key_info, xmlsec.Node.ENCRYPTION_METHOD, xmlsec.Namespace.ENC)
    assert enc_method is not None
    assert enc_method.get("Algorithm") == "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
    cipher_value = xmlsec.tree.find_node(key_info, xmlsec.Node.CIPHER_VALUE, xmlsec.Namespace.ENC)
    assert cipher_value is not None


def test_encrypt_binary():
    # Load the public cert
    manager = xmlsec.KeysManager()
    filename = path.join(BASE_DIR, 'rsacert.pem')
    key = xmlsec.Key.from_memory(read_from_file(filename), xmlsec.KeyFormat.CERT_PEM, None)
    assert key is not None
    manager.add_key(key)
    template = etree.Element("root")
    assert template is not None
    # Prepare for encryption
    enc_data = xmlsec.template.encrypted_data_create(
        template, xmlsec.Transform.AES128, type=xmlsec.EncryptionType.CONTENT, ns="xenc",
        mime_type="binary/octet-stream")

    xmlsec.template.encrypted_data_ensure_cipher_value(enc_data)
    key_info = xmlsec.template.encrypted_data_ensure_key_info(enc_data, ns="dsig")
    enc_key = xmlsec.template.add_encrypted_key(key_info, xmlsec.Transform.RSA_OAEP)
    xmlsec.template.encrypted_data_ensure_cipher_value(enc_key)

    # Encrypt!
    enc_ctx = xmlsec.EncryptionContext(manager)
    enc_ctx.key = xmlsec.Key.generate(xmlsec.KeyData.AES, 128, xmlsec.KeyDataType.SESSION)
    enc_data = enc_ctx.encrypt_binary(enc_data, b'test')
    assert enc_data is not None
    assert enc_data.tag == "{%s}%s" % (xmlsec.Namespace.ENC, xmlsec.Node.ENCRYPTED_DATA)
    print(xmlsec.Node.ENCRYPTION_METHOD)
    enc_method = xmlsec.tree.find_child(enc_data, xmlsec.Node.ENCRYPTION_METHOD, xmlsec.Namespace.ENC)
    assert enc_method is not None
    assert enc_method.get("Algorithm") == "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
    key_info = xmlsec.tree.find_child(enc_data, xmlsec.Node.KEY_INFO, xmlsec.Namespace.DS)
    assert key_info is not None
    enc_method = xmlsec.tree.find_node(key_info, xmlsec.Node.ENCRYPTION_METHOD, xmlsec.Namespace.ENC)
    assert enc_method is not None
    assert enc_method.get("Algorithm") == "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
    cipher_value = xmlsec.tree.find_node(key_info, xmlsec.Node.CIPHER_VALUE, xmlsec.Namespace.ENC)
    assert cipher_value is not None
