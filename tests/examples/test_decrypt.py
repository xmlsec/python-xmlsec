from __future__ import with_statement
from os import path
import xmlsec
from .base import parse_xml, BASE_DIR, compare

def read_from_file(filename):
    with open(filename, "rb") as stream:
        return stream.read()


def test_decrypt1():
    manager = xmlsec.KeysManager()
    filename = path.join(BASE_DIR, 'rsakey.pem')
    key = xmlsec.Key.from_memory(read_from_file(filename), xmlsec.KeyFormat.PEM, None)
    assert key is not None
    manager.add_key(key)

    enc_ctx = xmlsec.EncryptionContext(manager)

    root = parse_xml("enc1-res.xml")
    enc_data = xmlsec.tree.find_child(root, "EncryptedData", xmlsec.Namespace.ENC)
    assert enc_data is not None
    decrypted = enc_ctx.decrypt(enc_data)
    assert decrypted.tag == "Data"

    compare("enc1-doc.xml", root)


def test_decrypt2():
    manager = xmlsec.KeysManager()
    filename = path.join(BASE_DIR, 'rsakey.pem')
    key = xmlsec.Key.from_memory(read_from_file(filename), xmlsec.KeyFormat.PEM, None)
    assert key is not None
    manager.add_key(key)

    enc_ctx = xmlsec.EncryptionContext(manager)

    root = parse_xml("enc2-res.xml")
    enc_data = xmlsec.tree.find_child(root, xmlsec.constants.Node.ENCRYPTED_DATA, xmlsec.Namespace.ENC)
    assert enc_data is not None
    decrypted = enc_ctx.decrypt(enc_data)
    assert decrypted.text == "\ntest\n"
