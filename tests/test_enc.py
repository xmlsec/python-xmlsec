import io
import tempfile

from lxml import etree

import xmlsec
from tests import base

consts = xmlsec.constants


class TestEncryptionContext(base.TestMemoryLeaks):
    def test_init(self):
        ctx = xmlsec.EncryptionContext(manager=xmlsec.KeysManager())
        del ctx

    def test_init_no_keys_manager(self):
        ctx = xmlsec.EncryptionContext()
        del ctx

    def test_init_bad_args(self):
        with self.assertRaisesRegex(TypeError, 'KeysManager required'):
            xmlsec.EncryptionContext(manager='foo')

    def test_no_key(self):
        ctx = xmlsec.EncryptionContext(manager=xmlsec.KeysManager())
        self.assertIsNone(ctx.key)

    def test_get_key(self):
        ctx = xmlsec.EncryptionContext(manager=xmlsec.KeysManager())
        self.assertIsNone(ctx.key)
        ctx.key = xmlsec.Key.from_file(self.path('rsacert.pem'), format=consts.KeyDataFormatCertPem)
        self.assertIsNotNone(ctx.key)

    def test_del_key(self):
        ctx = xmlsec.EncryptionContext(manager=xmlsec.KeysManager())
        ctx.key = xmlsec.Key.from_file(self.path('rsacert.pem'), format=consts.KeyDataFormatCertPem)
        del ctx.key
        self.assertIsNone(ctx.key)

    def test_set_key(self):
        ctx = xmlsec.EncryptionContext(manager=xmlsec.KeysManager())
        ctx.key = xmlsec.Key.from_file(self.path('rsacert.pem'), format=consts.KeyDataFormatCertPem)
        self.assertIsNotNone(ctx.key)

    def test_set_key_bad_type(self):
        ctx = xmlsec.EncryptionContext(manager=xmlsec.KeysManager())
        with self.assertRaisesRegex(TypeError, r'instance of \*xmlsec.Key\* expected.'):
            ctx.key = ''

    def test_set_invalid_key(self):
        ctx = xmlsec.EncryptionContext(manager=xmlsec.KeysManager())
        with self.assertRaisesRegex(TypeError, 'empty key.'):
            ctx.key = xmlsec.Key()

    def test_encrypt_xml(self):
        root = self.load_xml('enc1-in.xml')
        enc_data = xmlsec.template.encrypted_data_create(root, consts.TransformAes128Cbc, type=consts.TypeEncElement, ns='xenc')
        xmlsec.template.encrypted_data_ensure_cipher_value(enc_data)
        ki = xmlsec.template.encrypted_data_ensure_key_info(enc_data, ns='dsig')
        ek = xmlsec.template.add_encrypted_key(ki, consts.TransformRsaOaep)
        xmlsec.template.encrypted_data_ensure_cipher_value(ek)
        data = root.find('./Data')
        self.assertIsNotNone(data)

        manager = xmlsec.KeysManager()
        manager.add_key(xmlsec.Key.from_file(self.path('rsacert.pem'), format=consts.KeyDataFormatCertPem))

        ctx = xmlsec.EncryptionContext(manager)
        ctx.key = xmlsec.Key.generate(consts.KeyDataAes, 128, consts.KeyDataTypeSession)

        encrypted = ctx.encrypt_xml(enc_data, data)
        self.assertIsNotNone(encrypted)

        enc_method = xmlsec.tree.find_child(enc_data, consts.NodeEncryptionMethod, consts.EncNs)
        self.assertIsNotNone(enc_method)
        self.assertEqual('http://www.w3.org/2001/04/xmlenc#aes128-cbc', enc_method.get('Algorithm'))
        ki = xmlsec.tree.find_child(enc_data, consts.NodeKeyInfo, consts.DSigNs)
        self.assertIsNotNone(ki)
        enc_method2 = xmlsec.tree.find_node(ki, consts.NodeEncryptionMethod, consts.EncNs)
        self.assertIsNotNone(enc_method2)
        self.assertEqual('http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p', enc_method2.get('Algorithm'))
        cipher_value = xmlsec.tree.find_node(ki, consts.NodeCipherValue, consts.EncNs)
        self.assertIsNotNone(cipher_value)

    def test_encrypt_xml_root(self):
        # Type=Element on the document root replaces the root itself: the new
        # root keeps the template's namespace prefix and the document-level
        # siblings, and decrypting it restores the document in place
        xml = b'<!--c--><Doc xmlns="urn:d" xmlns:p="urn:p" a="1"><p:x>t</p:x>tail</Doc>'
        root = etree.parse(io.BytesIO(xml)).getroot()
        key = xmlsec.Key.generate(consts.KeyDataAes, 128, consts.KeyDataTypeSession)
        enc_data = xmlsec.template.encrypted_data_create(root, consts.TransformAes128Cbc, type=consts.TypeEncElement, ns='xenc')
        xmlsec.template.encrypted_data_ensure_cipher_value(enc_data)
        ctx = xmlsec.EncryptionContext()
        ctx.key = key
        encrypted = ctx.encrypt_xml(enc_data, root)
        self.assertEqual(f'{{{consts.EncNs}}}{consts.NodeEncryptedData}', encrypted.tag)
        self.assertEqual('xenc', encrypted.prefix)
        self.assertIsNone(encrypted.getparent())
        self.assertIs(encrypted.getroottree().getroot(), encrypted)
        self.assertTrue(etree.tostring(encrypted.getroottree()).startswith(b'<!--c--><xenc:EncryptedData '))
        self.assertIsNotNone(xmlsec.tree.find_child(encrypted, consts.NodeCipherData, consts.EncNs))

        ctx = xmlsec.EncryptionContext()
        ctx.key = key
        decrypted = ctx.decrypt(encrypted)
        self.assertIsNone(decrypted.getparent())
        self.assertIs(decrypted.getroottree().getroot(), decrypted)
        self.assertEqual(xml, etree.tostring(decrypted.getroottree()))

    def test_encrypt_xml_bad_args(self):
        ctx = xmlsec.EncryptionContext()
        with self.assertRaises(TypeError):
            ctx.encrypt_xml('', 0)

    def test_encrypt_xml_bad_template(self):
        ctx = xmlsec.EncryptionContext()
        with self.assertRaisesRegex(xmlsec.Error, 'unsupported `Type`, it should be `element` or `content`'):
            ctx.encrypt_xml(etree.Element('root'), etree.Element('node'))

    def test_encrypt_xml_bad_template_bad_type_attribute(self):
        ctx = xmlsec.EncryptionContext()
        with self.assertRaisesRegex(xmlsec.Error, 'unsupported `Type`, it should be `element` or `content`'):
            root = etree.Element('root')
            root.attrib['Type'] = 'foo'
            ctx.encrypt_xml(root, etree.Element('node'))

    def test_encrypt_xml_fail(self):
        ctx = xmlsec.EncryptionContext()
        with self.assertRaisesRegex(xmlsec.Error, 'failed to encrypt xml'):
            root = etree.Element('root')
            root.attrib['Type'] = consts.TypeEncElement
            ctx.encrypt_xml(root, etree.Element('node'))

    def test_encrypt_binary(self):
        root = self.load_xml('enc2-in.xml')
        enc_data = xmlsec.template.encrypted_data_create(
            root, consts.TransformAes128Cbc, type=consts.TypeEncContent, ns='xenc', mime_type='binary/octet-stream'
        )
        xmlsec.template.encrypted_data_ensure_cipher_value(enc_data)
        ki = xmlsec.template.encrypted_data_ensure_key_info(enc_data, ns='dsig')
        ek = xmlsec.template.add_encrypted_key(ki, consts.TransformRsaOaep)
        xmlsec.template.encrypted_data_ensure_cipher_value(ek)

        manager = xmlsec.KeysManager()
        manager.add_key(xmlsec.Key.from_file(self.path('rsacert.pem'), format=consts.KeyDataFormatCertPem))

        ctx = xmlsec.EncryptionContext(manager)
        ctx.key = xmlsec.Key.generate(consts.KeyDataAes, 128, consts.KeyDataTypeSession)

        encrypted = ctx.encrypt_binary(enc_data, b'test')
        self.assertIsNotNone(encrypted)
        self.assertEqual(f'{{{consts.EncNs}}}{consts.NodeEncryptedData}', encrypted.tag)

        enc_method = xmlsec.tree.find_child(enc_data, consts.NodeEncryptionMethod, consts.EncNs)
        self.assertIsNotNone(enc_method)
        self.assertEqual('http://www.w3.org/2001/04/xmlenc#aes128-cbc', enc_method.get('Algorithm'))

        ki = xmlsec.tree.find_child(enc_data, consts.NodeKeyInfo, consts.DSigNs)
        self.assertIsNotNone(ki)
        enc_method2 = xmlsec.tree.find_node(ki, consts.NodeEncryptionMethod, consts.EncNs)
        self.assertIsNotNone(enc_method2)
        self.assertEqual('http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p', enc_method2.get('Algorithm'))
        cipher_value = xmlsec.tree.find_node(ki, consts.NodeCipherValue, consts.EncNs)
        self.assertIsNotNone(cipher_value)

    def test_encrypt_binary_bad_args(self):
        ctx = xmlsec.EncryptionContext()
        with self.assertRaises(TypeError):
            ctx.encrypt_binary('', 0)

    def test_encrypt_binary_bad_template(self):
        ctx = xmlsec.EncryptionContext()
        with self.assertRaisesRegex(xmlsec.Error, 'failed to encrypt binary'):
            ctx.encrypt_binary(etree.Element('root'), b'data')

    def test_encrypt_uri(self):
        root = self.load_xml('enc2-in.xml')
        enc_data = xmlsec.template.encrypted_data_create(
            root, consts.TransformAes128Cbc, type=consts.TypeEncContent, ns='xenc', mime_type='binary/octet-stream'
        )
        xmlsec.template.encrypted_data_ensure_cipher_value(enc_data)
        ki = xmlsec.template.encrypted_data_ensure_key_info(enc_data, ns='dsig')
        ek = xmlsec.template.add_encrypted_key(ki, consts.TransformRsaOaep)
        xmlsec.template.encrypted_data_ensure_cipher_value(ek)

        manager = xmlsec.KeysManager()
        manager.add_key(xmlsec.Key.from_file(self.path('rsacert.pem'), format=consts.KeyDataFormatCertPem))

        ctx = xmlsec.EncryptionContext(manager)
        ctx.key = xmlsec.Key.generate(consts.KeyDataAes, 128, consts.KeyDataTypeSession)

        with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
            tmpfile.write(b'test')

        encrypted = ctx.encrypt_binary(enc_data, 'file://' + tmpfile.name)
        self.assertIsNotNone(encrypted)
        self.assertEqual(f'{{{consts.EncNs}}}{consts.NodeEncryptedData}', encrypted.tag)

        enc_method = xmlsec.tree.find_child(enc_data, consts.NodeEncryptionMethod, consts.EncNs)
        self.assertIsNotNone(enc_method)
        self.assertEqual('http://www.w3.org/2001/04/xmlenc#aes128-cbc', enc_method.get('Algorithm'))

        ki = xmlsec.tree.find_child(enc_data, consts.NodeKeyInfo, consts.DSigNs)
        self.assertIsNotNone(ki)
        enc_method2 = xmlsec.tree.find_node(ki, consts.NodeEncryptionMethod, consts.EncNs)
        self.assertIsNotNone(enc_method2)
        self.assertEqual('http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p', enc_method2.get('Algorithm'))
        cipher_value = xmlsec.tree.find_node(ki, consts.NodeCipherValue, consts.EncNs)
        self.assertIsNotNone(cipher_value)

    def test_encrypt_uri_bad_args(self):
        ctx = xmlsec.EncryptionContext()
        with self.assertRaises(TypeError):
            ctx.encrypt_uri('', 0)

    def test_encrypt_uri_fail(self):
        ctx = xmlsec.EncryptionContext()
        with self.assertRaisesRegex(xmlsec.Error, 'failed to encrypt URI'):
            ctx.encrypt_uri(etree.Element('root'), '')

    def test_decrypt1(self):
        self.check_decrypt(1)

    def test_decrypt2(self):
        self.check_decrypt(2)

    def test_decrypt_key(self):
        root = self.load_xml('enc3-out.xml')
        enc_key = xmlsec.tree.find_child(root, consts.NodeEncryptedKey, consts.EncNs)
        self.assertIsNotNone(enc_key)

        manager = xmlsec.KeysManager()
        manager.add_key(xmlsec.Key.from_file(self.path('rsakey.pem'), format=consts.KeyDataFormatPem))
        ctx = xmlsec.EncryptionContext(manager)
        keydata = ctx.decrypt(enc_key)
        ctx.reset()
        root.remove(enc_key)
        ctx.key = xmlsec.Key.from_binary_data(consts.KeyDataAes, keydata)
        enc_data = xmlsec.tree.find_child(root, consts.NodeEncryptedData, consts.EncNs)
        self.assertIsNotNone(enc_data)
        decrypted = ctx.decrypt(enc_data)
        self.assertIsNotNone(decrypted)
        self.assertEqual(self.load_xml('enc3-in.xml'), decrypted)

    def check_decrypt(self, i):
        root = self.load_xml(f'enc{i}-out.xml')
        enc_data = xmlsec.tree.find_child(root, consts.NodeEncryptedData, consts.EncNs)
        self.assertIsNotNone(enc_data)

        manager = xmlsec.KeysManager()
        manager.add_key(xmlsec.Key.from_file(self.path('rsakey.pem'), format=consts.KeyDataFormatPem))
        ctx = xmlsec.EncryptionContext(manager)
        decrypted = ctx.decrypt(enc_data)
        self.assertIsNotNone(decrypted)
        self.assertEqual(self.load_xml(f'enc{i}-in.xml'), root)

    def encrypt_content(self, xml, path):
        """Encrypts the content of the element at ``path`` with a fresh session key."""
        root = etree.fromstring(xml)
        key = xmlsec.Key.generate(consts.KeyDataAes, 128, consts.KeyDataTypeSession)
        enc_data = xmlsec.template.encrypted_data_create(root, consts.TransformAes128Cbc, type=consts.TypeEncContent, ns='xenc')
        xmlsec.template.encrypted_data_ensure_cipher_value(enc_data)
        ctx = xmlsec.EncryptionContext()
        ctx.key = key
        ctx.encrypt_xml(enc_data, root.find(path))
        return root, key

    def test_decrypt_root_content(self):
        # a root EncryptedData of Type=Content gives way to its decrypted
        # content, which becomes the new document root
        root, key = self.encrypt_content(b'<Doc><x>t</x></Doc>', '.')
        enc_data = etree.fromstring(etree.tostring(root[0]))
        self.assertIsNone(enc_data.getparent())
        ctx = xmlsec.EncryptionContext()
        ctx.key = key
        decrypted = ctx.decrypt(enc_data)
        self.assertEqual('x', decrypted.tag)
        self.assertEqual('t', decrypted.text)
        self.assertIsNone(decrypted.getparent())
        self.assertIs(decrypted.getroottree().getroot(), decrypted)

    def test_decrypt_content_text_between_whitespace(self):
        # in a pretty-printed document the decrypted text lands between the
        # whitespace that surrounded <EncryptedData/>; the parent's text must
        # carry all three pieces
        root, key = self.encrypt_content(b'<root><Password>secret</Password><Other/></root>', 'Password')
        pretty = etree.fromstring(etree.tostring(root, pretty_print=True))
        enc_data = xmlsec.tree.find_node(pretty, consts.NodeEncryptedData, consts.EncNs)
        ctx = xmlsec.EncryptionContext()
        ctx.key = key
        password = ctx.decrypt(enc_data)
        self.assertIs(password, pretty[0])
        self.assertEqual('\n    secret\n  ', password.text)
        self.assertEqual(0, len(password))

    def test_decrypt_content_mixed(self):
        root, key = self.encrypt_content(b'<root><Box>hello <b>world</b> end</Box></root>', 'Box')
        pretty = etree.fromstring(etree.tostring(root, pretty_print=True))
        enc_data = xmlsec.tree.find_node(pretty, consts.NodeEncryptedData, consts.EncNs)
        ctx = xmlsec.EncryptionContext()
        ctx.key = key
        box = ctx.decrypt(enc_data)
        self.assertEqual(b'<Box>\n    hello <b>world</b> end\n  </Box>', etree.tostring(box, with_tail=False))

    def test_decrypt_bad_args(self):
        ctx = xmlsec.EncryptionContext()
        with self.assertRaises(TypeError):
            ctx.decrypt('')
