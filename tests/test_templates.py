import unittest

from lxml import etree

import xmlsec
from tests import base

consts = xmlsec.constants


class TestTemplates(base.TestMemoryLeaks):
    def test_create(self):
        root = self.load_xml("doc.xml")
        sign = xmlsec.template.create(
            root, c14n_method=consts.TransformExclC14N, sign_method=consts.TransformRsaSha1, id="Id", ns="test"
        )
        self.assertEqual("Id", sign.get("Id"))
        self.assertEqual("test", sign.prefix)

    def test_create_bad_args(self):
        with self.assertRaises(TypeError):
            xmlsec.template.create('', c14n_method=consts.TransformExclC14N, sign_method=consts.TransformRsaSha1)

    def test_encrypt_data_create(self):
        root = self.load_xml("doc.xml")
        enc = xmlsec.template.encrypted_data_create(
            root, method=consts.TransformDes3Cbc, id="Id", type="Type", mime_type="MimeType", encoding="Encoding", ns="test"
        )
        for a in ("Id", "Type", "MimeType", "Encoding"):
            self.assertEqual(a, enc.get(a))
        self.assertEqual("test", enc.prefix)

    def test_ensure_key_info(self):
        root = self.load_xml("doc.xml")
        sign = xmlsec.template.create(root, c14n_method=consts.TransformExclC14N, sign_method=consts.TransformRsaSha1)
        ki = xmlsec.template.ensure_key_info(sign, id="Id")
        self.assertEqual("Id", ki.get("Id"))

    def test_ensure_key_info_fail(self):
        with self.assertRaisesRegex(xmlsec.Error, 'cannot ensure key info.'):
            xmlsec.template.ensure_key_info(etree.fromstring(b'<Data/>'), id="Id")

    def test_ensure_key_info_bad_args(self):
        with self.assertRaises(TypeError):
            xmlsec.template.ensure_key_info('', id=0)

    def test_add_encrypted_key(self):
        root = self.load_xml("doc.xml")
        sign = xmlsec.template.create(root, c14n_method=consts.TransformExclC14N, sign_method=consts.TransformRsaSha1)
        ki = xmlsec.template.ensure_key_info(sign)
        ek = xmlsec.template.add_encrypted_key(ki, consts.TransformRsaOaep)
        self.assertEqual(ek, xmlsec.tree.find_node(self.load_xml("sign_template.xml"), consts.NodeEncryptedKey, consts.EncNs))
        ek2 = xmlsec.template.add_encrypted_key(ki, consts.TransformRsaOaep, id="Id", type="Type", recipient="Recipient")
        for a in ("Id", "Type", "Recipient"):
            self.assertEqual(a, ek2.get(a))

    def test_add_key_name(self):
        root = self.load_xml("doc.xml")
        sign = xmlsec.template.create(root, c14n_method=consts.TransformExclC14N, sign_method=consts.TransformRsaSha1)
        ki = xmlsec.template.ensure_key_info(sign)
        kn = xmlsec.template.add_key_name(ki)
        self.assertEqual(kn, xmlsec.tree.find_node(self.load_xml("sign_template.xml"), consts.NodeKeyName, consts.DSigNs))
        kn2 = xmlsec.template.add_key_name(ki, name="name")
        self.assertEqual("name", kn2.text)

    def test_add_key_name_none(self):
        root = self.load_xml("doc.xml")
        sign = xmlsec.template.create(root, c14n_method=consts.TransformExclC14N, sign_method=consts.TransformRsaSha1)
        ki = xmlsec.template.ensure_key_info(sign)
        kn2 = xmlsec.template.add_key_name(ki, name=None)
        self.assertEqual(kn2.text, None)
        print(etree.tostring(kn2))

    def test_add_key_name_bad_args(self):
        with self.assertRaises(TypeError):
            xmlsec.template.add_key_name('')

    def test_add_reference(self):
        root = self.load_xml("doc.xml")
        sign = xmlsec.template.create(root, c14n_method=consts.TransformExclC14N, sign_method=consts.TransformRsaSha1)
        ref = xmlsec.template.add_reference(sign, consts.TransformSha1, id="Id", uri="URI", type="Type")
        for a in ("Id", "URI", "Type"):
            self.assertEqual(a, ref.get(a))

    def test_add_reference_bad_args(self):
        with self.assertRaises(TypeError):
            xmlsec.template.add_reference('', consts.TransformSha1)
        with self.assertRaises(TypeError):
            xmlsec.template.add_reference(etree.Element('root'), '')

    def test_add_reference_fail(self):
        with self.assertRaisesRegex(xmlsec.Error, 'cannot add reference.'):
            xmlsec.template.add_reference(etree.Element('root'), consts.TransformSha1)

    def test_add_transform_bad_args(self):
        with self.assertRaises(TypeError):
            xmlsec.template.add_transform('', consts.TransformSha1)
        with self.assertRaises(TypeError):
            xmlsec.template.add_transform(etree.Element('root'), '')

    def test_add_key_value(self):
        root = self.load_xml("doc.xml")
        sign = xmlsec.template.create(root, c14n_method=consts.TransformExclC14N, sign_method=consts.TransformRsaSha1)
        ki = xmlsec.template.ensure_key_info(sign)
        kv = xmlsec.template.add_key_value(ki)
        self.assertEqual(kv, xmlsec.tree.find_node(self.load_xml("sign_template.xml"), consts.NodeKeyValue, consts.DSigNs))

    def test_add_key_value_bad_args(self):
        with self.assertRaises(TypeError):
            xmlsec.template.add_key_value('')

    def test_add_x509_data(self):
        root = self.load_xml("doc.xml")
        sign = xmlsec.template.create(root, c14n_method=consts.TransformExclC14N, sign_method=consts.TransformRsaSha1)
        ki = xmlsec.template.ensure_key_info(sign)
        x509 = xmlsec.template.add_x509_data(ki)
        xmlsec.template.x509_data_add_certificate(x509)
        xmlsec.template.x509_data_add_crl(x509)
        issuer = xmlsec.template.x509_data_add_issuer_serial(x509)
        xmlsec.template.x509_data_add_ski(x509)
        xmlsec.template.x509_data_add_subject_name(x509)
        xmlsec.template.x509_issuer_serial_add_issuer_name(issuer)
        xmlsec.template.x509_issuer_serial_add_serial_number(issuer)
        self.assertEqual(x509, xmlsec.tree.find_node(self.load_xml("sign_template.xml"), consts.NodeX509Data, consts.DSigNs))

    def test_add_x509_data_bad_args(self):
        with self.assertRaises(TypeError):
            xmlsec.template.add_x509_data('')

    def test_x509_issuer_serial_add_issuer(self):
        root = self.load_xml("doc.xml")
        sign = xmlsec.template.create(root, c14n_method=consts.TransformExclC14N, sign_method=consts.TransformRsaSha1)
        ki = xmlsec.template.ensure_key_info(sign)
        x509 = xmlsec.template.add_x509_data(ki)
        issuer = xmlsec.template.x509_data_add_issuer_serial(x509)
        name = xmlsec.template.x509_issuer_serial_add_issuer_name(issuer, name="Name")
        serial = xmlsec.template.x509_issuer_serial_add_serial_number(issuer, serial="Serial")
        self.assertEqual("Name", name.text)
        self.assertEqual("Serial", serial.text)

    def test_x509_issuer_serial_add_issuer_bad_args(self):
        with self.assertRaises(TypeError):
            xmlsec.template.x509_data_add_issuer_serial('')

    def test_x509_issuer_serial_add_issuer_name_bad_args(self):
        with self.assertRaises(TypeError):
            xmlsec.template.x509_issuer_serial_add_issuer_name('')

    def test_x509_issuer_serial_add_serial_number_bad_args(self):
        with self.assertRaises(TypeError):
            xmlsec.template.x509_issuer_serial_add_serial_number('')

    def test_x509_data_add_subject_name_bad_args(self):
        with self.assertRaises(TypeError):
            xmlsec.template.x509_data_add_subject_name('')

    def test_x509_data_add_ski_bad_args(self):
        with self.assertRaises(TypeError):
            xmlsec.template.x509_data_add_ski('')

    def test_x509_data_add_certificate_bad_args(self):
        with self.assertRaises(TypeError):
            xmlsec.template.x509_data_add_certificate('')

    def test_x509_data_add_crl_bad_args(self):
        with self.assertRaises(TypeError):
            xmlsec.template.x509_data_add_crl('')

    def test_add_encrypted_key_bad_args(self):
        with self.assertRaises(TypeError):
            xmlsec.template.add_encrypted_key('', 0)

    def test_encrypted_data_create_bad_args(self):
        with self.assertRaises(TypeError):
            xmlsec.template.encrypted_data_create('', 0)

    def test_encrypted_data_ensure_cipher_value(self):
        root = self.load_xml("doc.xml")
        enc = xmlsec.template.encrypted_data_create(root, method=consts.TransformDes3Cbc)
        cv = xmlsec.template.encrypted_data_ensure_cipher_value(enc)
        self.assertEqual(cv, xmlsec.tree.find_node(self.load_xml("sign_template.xml"), consts.NodeCipherValue, consts.EncNs))

    def test_encrypted_data_ensure_cipher_value_bad_args(self):
        with self.assertRaises(TypeError):
            xmlsec.template.encrypted_data_ensure_cipher_value('')

    def test_encrypted_data_ensure_key_info(self):
        root = self.load_xml("doc.xml")
        enc = xmlsec.template.encrypted_data_create(root, method=consts.TransformDes3Cbc)
        ki = xmlsec.template.encrypted_data_ensure_key_info(enc)
        self.assertEqual(ki, xmlsec.tree.find_node(self.load_xml("enc_template.xml"), consts.NodeKeyInfo, consts.DSigNs))
        ki2 = xmlsec.template.encrypted_data_ensure_key_info(enc, id="Id", ns="test")
        self.assertEqual("Id", ki2.get("Id"))
        self.assertEqual("test", ki2.prefix)

    def test_encrypted_data_ensure_key_info_bad_args(self):
        with self.assertRaises(TypeError):
            xmlsec.template.encrypted_data_ensure_key_info('')

    @unittest.skipIf(not hasattr(consts, 'TransformXslt'), reason='XSLT transformations not enabled')
    def test_transform_add_c14n_inclusive_namespaces(self):
        root = self.load_xml("doc.xml")
        sign = xmlsec.template.create(root, c14n_method=consts.TransformExclC14N, sign_method=consts.TransformRsaSha1)
        ref = xmlsec.template.add_reference(sign, consts.TransformSha1)
        trans1 = xmlsec.template.add_transform(ref, consts.TransformEnveloped)
        xmlsec.template.transform_add_c14n_inclusive_namespaces(trans1, "default")
        trans2 = xmlsec.template.add_transform(ref, consts.TransformXslt)
        xmlsec.template.transform_add_c14n_inclusive_namespaces(trans2, ["ns1", "ns2"])
        self.assertEqual(ref, xmlsec.tree.find_node(self.load_xml("sign_template.xml"), consts.NodeReference, consts.DSigNs))

    def test_transform_add_c14n_inclusive_namespaces_bad_args(self):
        with self.assertRaises(TypeError):
            xmlsec.template.transform_add_c14n_inclusive_namespaces('', [])
