from tests import base

import xmlsec


consts = xmlsec.constants


class TestEncryptionContext(base.TestMemoryLeaks):
    def test_init(self):
        ctx = xmlsec.EncryptionContext(manager=xmlsec.KeysManager())
        del ctx

    def test_key(self):
        ctx = xmlsec.EncryptionContext(manager=xmlsec.KeysManager())
        self.assertIsNone(ctx.key)
        ctx.key = xmlsec.Key.from_file(self.path("rsacert.pem"), format=consts.KeyDataFormatCertPem)
        self.assertIsNotNone(ctx.key)

    def test_encrypt_xml(self):
        root = self.load_xml('enc1-in.xml')
        enc_data = xmlsec.template.encrypted_data_create(
            root, consts.TransformAes128Cbc, type=consts.TypeEncElement, ns="xenc"
        )
        xmlsec.template.encrypted_data_ensure_cipher_value(enc_data)
        ki = xmlsec.template.encrypted_data_ensure_key_info(enc_data, ns="dsig")
        ek = xmlsec.template.add_encrypted_key(ki, consts.TransformRsaOaep)
        xmlsec.template.encrypted_data_ensure_cipher_value(ek)
        data = root.find('./Data')
        self.assertIsNotNone(data)

        manager = xmlsec.KeysManager()
        manager.add_key(xmlsec.Key.from_file(self.path("rsacert.pem"), format=consts.KeyDataFormatCertPem))

        ctx = xmlsec.EncryptionContext(manager)
        ctx.key = xmlsec.Key.generate(consts.KeyDataAes, 128, consts.KeyDataTypeSession)

        encrypted = ctx.encrypt_xml(enc_data, data)
        self.assertIsNotNone(encrypted)

        enc_method = xmlsec.tree.find_child(enc_data, consts.NodeEncryptionMethod, consts.EncNs)
        self.assertIsNotNone(enc_method)
        self.assertEqual("http://www.w3.org/2001/04/xmlenc#aes128-cbc", enc_method.get("Algorithm"))
        ki = xmlsec.tree.find_child(enc_data, consts.NodeKeyInfo, consts.DSigNs)
        self.assertIsNotNone(ki)
        enc_method2 = xmlsec.tree.find_node(ki, consts.NodeEncryptionMethod, consts.EncNs)
        self.assertIsNotNone(enc_method2)
        self.assertEqual("http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p", enc_method2.get("Algorithm"))
        cipher_value = xmlsec.tree.find_node(ki, consts.NodeCipherValue, consts.EncNs)
        self.assertIsNotNone(cipher_value)

    def test_encrypt_binary(self):
        root = self.load_xml('enc2-in.xml')
        enc_data = xmlsec.template.encrypted_data_create(
            root, consts.TransformAes128Cbc, type=consts.TypeEncContent, ns="xenc", mime_type="binary/octet-stream"
        )
        xmlsec.template.encrypted_data_ensure_cipher_value(enc_data)
        ki = xmlsec.template.encrypted_data_ensure_key_info(enc_data, ns="dsig")
        ek = xmlsec.template.add_encrypted_key(ki, consts.TransformRsaOaep)
        xmlsec.template.encrypted_data_ensure_cipher_value(ek)

        manager = xmlsec.KeysManager()
        manager.add_key(xmlsec.Key.from_file(self.path("rsacert.pem"), format=consts.KeyDataFormatCertPem))

        ctx = xmlsec.EncryptionContext(manager)
        ctx.key = xmlsec.Key.generate(consts.KeyDataAes, 128, consts.KeyDataTypeSession)

        encrypted = ctx.encrypt_binary(enc_data, b'test')
        self.assertIsNotNone(encrypted)
        self.assertEqual("{%s}%s" % (consts.EncNs, consts.NodeEncryptedData), encrypted.tag)

        enc_method = xmlsec.tree.find_child(enc_data, consts.NodeEncryptionMethod, consts.EncNs)
        self.assertIsNotNone(enc_method)
        self.assertEqual("http://www.w3.org/2001/04/xmlenc#aes128-cbc", enc_method.get("Algorithm"))

        ki = xmlsec.tree.find_child(enc_data, consts.NodeKeyInfo, consts.DSigNs)
        self.assertIsNotNone(ki)
        enc_method2 = xmlsec.tree.find_node(ki, consts.NodeEncryptionMethod, consts.EncNs)
        self.assertIsNotNone(enc_method2)
        self.assertEqual("http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p", enc_method2.get("Algorithm"))
        cipher_value = xmlsec.tree.find_node(ki, consts.NodeCipherValue, consts.EncNs)
        self.assertIsNotNone(cipher_value)

    def test_decrypt1(self):
        self.check_decrypt(1)

    def test_decrypt2(self):
        self.check_decrypt(2)

    def test_decrypt_key(self):
        root = self.load_xml('enc3-out.xml')
        enc_key = xmlsec.tree.find_child(root, consts.NodeEncryptedKey, consts.EncNs)
        self.assertIsNotNone(enc_key)

        manager = xmlsec.KeysManager()
        manager.add_key(xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem))
        ctx = xmlsec.EncryptionContext(manager)
        keydata = ctx.decrypt(enc_key)
        ctx.reset()
        root.remove(enc_key)
        ctx.key = xmlsec.Key.from_binary_data(consts.KeyDataAes, keydata)
        enc_data = xmlsec.tree.find_child(root, consts.NodeEncryptedData, consts.EncNs)
        self.assertIsNotNone(enc_data)
        decrypted = ctx.decrypt(enc_data)
        self.assertIsNotNone(decrypted)
        self.assertEqual(self.load_xml("enc3-in.xml"), decrypted)

    def check_decrypt(self, i):
        root = self.load_xml('enc%d-out.xml' % i)
        enc_data = xmlsec.tree.find_child(root, consts.NodeEncryptedData, consts.EncNs)
        self.assertIsNotNone(enc_data)

        manager = xmlsec.KeysManager()
        manager.add_key(xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem))
        ctx = xmlsec.EncryptionContext(manager)
        decrypted = ctx.decrypt(enc_data)
        self.assertIsNotNone(decrypted)
        self.assertEqual(self.load_xml("enc%d-in.xml" % i), root)


    def check_no_segfault(self):
        namespaces = {
            'soap': 'http://schemas.xmlsoap.org/soap/envelope/'
        }

        manager = xmlsec.KeysManager()
        key = xmlsec.Key.from_file(self.path("rsacert.pem"), format=consts.KeyDataFormatCertPem)
        manager.add_key(key)
        template = self.load_xml('enc-bad-in.xml')
        enc_data = xmlsec.template.encrypted_data_create(
            template, xmlsec.Transform.AES128, type=xmlsec.EncryptionType.CONTENT, ns='xenc')
        xmlsec.template.encrypted_data_ensure_cipher_value(enc_data)
        key_info = xmlsec.template.encrypted_data_ensure_key_info(enc_data, ns='dsig')
        enc_key = xmlsec.template.add_encrypted_key(key_info, xmlsec.Transform.RSA_PKCS1)
        xmlsec.template.encrypted_data_ensure_cipher_value(enc_key)
        data = template.find('soap:Body', namespaces=namespaces)
        enc_ctx = xmlsec.EncryptionContext(manager)
        enc_ctx.key = xmlsec.Key.generate(xmlsec.KeyData.AES, 192, xmlsec.KeyDataType.SESSION)
        self.assertRaises(Exception, enc_ctx.encrypt_xml(enc_data, data))
