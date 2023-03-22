import unittest

import xmlsec
from tests import base

consts = xmlsec.constants


class TestSignContext(base.TestMemoryLeaks):
    def test_init(self):
        ctx = xmlsec.SignatureContext(manager=xmlsec.KeysManager())
        del ctx

    def test_init_no_keys_manager(self):
        ctx = xmlsec.SignatureContext()
        del ctx

    def test_init_bad_args(self):
        with self.assertRaisesRegex(TypeError, 'KeysManager required'):
            xmlsec.SignatureContext(manager='foo')

    def test_no_key(self):
        ctx = xmlsec.SignatureContext(manager=xmlsec.KeysManager())
        self.assertIsNone(ctx.key)

    def test_del_key(self):
        ctx = xmlsec.SignatureContext(manager=xmlsec.KeysManager())
        ctx.key = xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem)
        del ctx.key
        self.assertIsNone(ctx.key)

    def test_set_key(self):
        ctx = xmlsec.SignatureContext(manager=xmlsec.KeysManager())
        ctx.key = xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem)
        self.assertIsNotNone(ctx.key)

    def test_set_key_bad_type(self):
        ctx = xmlsec.SignatureContext(manager=xmlsec.KeysManager())
        with self.assertRaisesRegex(TypeError, r'instance of \*xmlsec.Key\* expected.'):
            ctx.key = ''

    def test_set_invalid_key(self):
        ctx = xmlsec.SignatureContext(manager=xmlsec.KeysManager())
        with self.assertRaisesRegex(TypeError, 'empty key.'):
            ctx.key = xmlsec.Key()

    def test_register_id(self):
        ctx = xmlsec.SignatureContext()
        root = self.load_xml("sign_template.xml")
        sign = xmlsec.template.create(root, consts.TransformExclC14N, consts.TransformRsaSha1, "Id")
        ctx.register_id(sign, "Id")

    def test_register_id_bad_args(self):
        ctx = xmlsec.SignatureContext()
        with self.assertRaises(TypeError):
            ctx.register_id('')

    def test_register_id_with_namespace_without_attribute(self):
        ctx = xmlsec.SignatureContext()
        root = self.load_xml("sign_template.xml")
        sign = xmlsec.template.create(root, consts.TransformExclC14N, consts.TransformRsaSha1, "Id")
        with self.assertRaisesRegex(xmlsec.Error, 'missing attribute.'):
            ctx.register_id(sign, "Id", id_ns='foo')

    def test_sign_bad_args(self):
        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem)
        with self.assertRaises(TypeError):
            ctx.sign('')

    def test_sign_fail(self):
        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem)
        with self.assertRaisesRegex(xmlsec.Error, 'failed to sign'):
            ctx.sign(self.load_xml('sign1-in.xml'))

    def test_sign_case1(self):
        """Should sign a pre-constructed template file using a key from a PEM file."""
        root = self.load_xml("sign1-in.xml")
        sign = xmlsec.tree.find_node(root, consts.NodeSignature)
        self.assertIsNotNone(sign)

        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem)
        self.assertIsNotNone(ctx.key)
        ctx.key.name = 'rsakey.pem'
        self.assertEqual("rsakey.pem", ctx.key.name)

        ctx.sign(sign)
        self.assertEqual(self.load_xml("sign1-out.xml"), root)

    def test_sign_case2(self):
        """Should sign a dynamicaly constructed template file using a key from a PEM file."""
        root = self.load_xml("sign2-in.xml")
        sign = xmlsec.template.create(root, consts.TransformExclC14N, consts.TransformRsaSha1)
        self.assertIsNotNone(sign)
        root.append(sign)
        ref = xmlsec.template.add_reference(sign, consts.TransformSha1)
        xmlsec.template.add_transform(ref, consts.TransformEnveloped)
        ki = xmlsec.template.ensure_key_info(sign)
        xmlsec.template.add_key_name(ki)

        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem)
        self.assertIsNotNone(ctx.key)
        ctx.key.name = 'rsakey.pem'
        self.assertEqual("rsakey.pem", ctx.key.name)

        ctx.sign(sign)
        self.assertEqual(self.load_xml("sign2-out.xml"), root)

    def test_sign_case3(self):
        """Should sign a file using a dynamicaly created template, key from PEM and an X509 cert."""
        root = self.load_xml("sign3-in.xml")
        sign = xmlsec.template.create(root, consts.TransformExclC14N, consts.TransformRsaSha1)
        self.assertIsNotNone(sign)
        root.append(sign)
        ref = xmlsec.template.add_reference(sign, consts.TransformSha1)
        xmlsec.template.add_transform(ref, consts.TransformEnveloped)
        ki = xmlsec.template.ensure_key_info(sign)
        xmlsec.template.add_x509_data(ki)

        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem)
        self.assertIsNotNone(ctx.key)
        ctx.key.load_cert_from_file(self.path('rsacert.pem'), consts.KeyDataFormatPem)
        ctx.key.name = 'rsakey.pem'
        self.assertEqual("rsakey.pem", ctx.key.name)

        ctx.sign(sign)
        self.assertEqual(self.load_xml("sign3-out.xml"), root)

    def test_sign_case4(self):
        """Should sign a file using a dynamically created template, key from PEM and an X509 cert with custom ns."""
        root = self.load_xml("sign4-in.xml")
        xmlsec.tree.add_ids(root, ["ID"])
        elem_id = root.get('ID', None)
        if elem_id:
            elem_id = '#' + elem_id
        sign = xmlsec.template.create(root, consts.TransformExclC14N, consts.TransformRsaSha1, ns="ds")
        self.assertIsNotNone(sign)
        root.append(sign)
        ref = xmlsec.template.add_reference(sign, consts.TransformSha1, uri=elem_id)
        xmlsec.template.add_transform(ref, consts.TransformEnveloped)
        xmlsec.template.add_transform(ref, consts.TransformExclC14N)
        ki = xmlsec.template.ensure_key_info(sign)
        xmlsec.template.add_x509_data(ki)

        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem)
        self.assertIsNotNone(ctx.key)
        ctx.key.load_cert_from_file(self.path('rsacert.pem'), consts.KeyDataFormatPem)
        ctx.key.name = 'rsakey.pem'
        self.assertEqual("rsakey.pem", ctx.key.name)

        ctx.sign(sign)
        self.assertEqual(self.load_xml("sign4-out.xml"), root)

    def test_sign_case5(self):
        """Should sign a file using a dynamicaly created template, key from PEM file and an X509 certificate."""
        root = self.load_xml("sign5-in.xml")
        sign = xmlsec.template.create(root, consts.TransformExclC14N, consts.TransformRsaSha1)
        self.assertIsNotNone(sign)
        root.append(sign)
        ref = xmlsec.template.add_reference(sign, consts.TransformSha1)
        xmlsec.template.add_transform(ref, consts.TransformEnveloped)

        ki = xmlsec.template.ensure_key_info(sign)
        x509 = xmlsec.template.add_x509_data(ki)
        xmlsec.template.x509_data_add_subject_name(x509)
        xmlsec.template.x509_data_add_certificate(x509)
        xmlsec.template.x509_data_add_ski(x509)
        x509_issuer_serial = xmlsec.template.x509_data_add_issuer_serial(x509)
        xmlsec.template.x509_issuer_serial_add_issuer_name(x509_issuer_serial, 'Test Issuer')
        xmlsec.template.x509_issuer_serial_add_serial_number(x509_issuer_serial, '1')

        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem)
        self.assertIsNotNone(ctx.key)
        ctx.key.load_cert_from_file(self.path('rsacert.pem'), consts.KeyDataFormatPem)
        ctx.key.name = 'rsakey.pem'
        self.assertEqual("rsakey.pem", ctx.key.name)

        ctx.sign(sign)
        if (1, 2, 36) <= xmlsec.get_libxmlsec_version() <= (1, 2, 37):
            expected_xml_file = 'sign5-out-xmlsec_1_2_36_to_37.xml'
        else:
            expected_xml_file = 'sign5-out.xml'
        self.assertEqual(self.load_xml(expected_xml_file), root)

    def test_sign_binary_bad_args(self):
        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem)
        with self.assertRaises(TypeError):
            ctx.sign_binary(bytes=1, transform='')

    def test_sign_binary_no_key(self):
        ctx = xmlsec.SignatureContext()
        with self.assertRaisesRegex(xmlsec.Error, 'Sign key is not specified.'):
            ctx.sign_binary(bytes=b'', transform=consts.TransformRsaSha1)

    @unittest.skipIf(not hasattr(consts, 'TransformXslt'), reason='XSLT transformations not enabled')
    def test_sign_binary_invalid_signature_method(self):
        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem)
        with self.assertRaisesRegex(xmlsec.Error, 'incompatible signature method'):
            ctx.sign_binary(bytes=b'', transform=consts.TransformXslt)

    def test_sign_binary(self):
        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem)
        self.assertIsNotNone(ctx.key)
        ctx.key.name = 'rsakey.pem'
        self.assertEqual("rsakey.pem", ctx.key.name)

        sign = ctx.sign_binary(self.load("sign6-in.bin"), consts.TransformRsaSha1)
        self.assertEqual(self.load("sign6-out.bin"), sign)

    def test_sign_binary_twice_not_possible(self):
        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem)
        data = self.load('sign6-in.bin')
        ctx.sign_binary(data, consts.TransformRsaSha1)
        with self.assertRaisesRegex(xmlsec.Error, 'Signature context already used; it is designed for one use only.'):
            ctx.sign_binary(data, consts.TransformRsaSha1)

    def test_verify_bad_args(self):
        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem)
        with self.assertRaises(TypeError):
            ctx.verify('')

    def test_verify_fail(self):
        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem)
        with self.assertRaisesRegex(xmlsec.Error, 'failed to verify'):
            ctx.verify(self.load_xml('sign1-in.xml'))

    def test_verify_case_1(self):
        self.check_verify(1)

    def test_verify_case_2(self):
        self.check_verify(2)

    def test_verify_case_3(self):
        self.check_verify(3)

    def test_verify_case_4(self):
        self.check_verify(4)

    def test_verify_case_5(self):
        self.check_verify(5)

    def check_verify(self, i):
        root = self.load_xml("sign{}-out.xml".format(i))
        xmlsec.tree.add_ids(root, ["ID"])
        sign = xmlsec.tree.find_node(root, consts.NodeSignature)
        self.assertIsNotNone(sign)
        self.assertEqual(consts.NodeSignature, sign.tag.partition("}")[2])

        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_file(self.path("rsapub.pem"), format=consts.KeyDataFormatPem)
        self.assertIsNotNone(ctx.key)
        ctx.key.name = 'rsapub.pem'
        self.assertEqual("rsapub.pem", ctx.key.name)
        ctx.verify(sign)

    def test_validate_binary_sign(self):
        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem)
        self.assertIsNotNone(ctx.key)
        ctx.key.name = 'rsakey.pem'
        self.assertEqual("rsakey.pem", ctx.key.name)

        ctx.verify_binary(self.load("sign6-in.bin"), consts.TransformRsaSha1, self.load("sign6-out.bin"))

    def test_validate_binary_sign_fail(self):
        ctx = xmlsec.SignatureContext()

        ctx.key = xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem)
        self.assertIsNotNone(ctx.key)
        ctx.key.name = 'rsakey.pem'
        self.assertEqual("rsakey.pem", ctx.key.name)
        with self.assertRaises(xmlsec.Error):
            ctx.verify_binary(self.load("sign6-in.bin"), consts.TransformRsaSha1, b"invalid")

    def test_enable_reference_transform(self):
        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem)
        ctx.enable_reference_transform(consts.TransformRsaSha1)

    def test_enable_reference_transform_bad_args(self):
        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_file(self.path('rsakey.pem'), format=consts.KeyDataFormatPem)
        with self.assertRaises(TypeError):
            ctx.enable_reference_transform('')
        with self.assertRaises(TypeError):
            ctx.enable_reference_transform(0)
        with self.assertRaises(TypeError):
            ctx.enable_reference_transform(consts.KeyDataAes)

    def test_enable_signature_transform(self):
        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem)
        ctx.enable_signature_transform(consts.TransformRsaSha1)

    def test_enable_signature_transform_bad_args(self):
        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_file(self.path('rsakey.pem'), format=consts.KeyDataFormatPem)
        with self.assertRaises(TypeError):
            ctx.enable_signature_transform('')
        with self.assertRaises(TypeError):
            ctx.enable_signature_transform(0)
        with self.assertRaises(TypeError):
            ctx.enable_signature_transform(consts.KeyDataAes)

    def test_set_enabled_key_data(self):
        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem)
        ctx.set_enabled_key_data([consts.KeyDataAes])

    def test_set_enabled_key_data_empty(self):
        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem)
        ctx.set_enabled_key_data([])

    def test_set_enabled_key_data_bad_args(self):
        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_file(self.path('rsakey.pem'), format=consts.KeyDataFormatPem)
        with self.assertRaises(TypeError):
            ctx.set_enabled_key_data(0)

    def test_set_enabled_key_data_bad_list(self):
        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_file(self.path('rsakey.pem'), format=consts.KeyDataFormatPem)
        with self.assertRaisesRegex(TypeError, 'expected list of KeyData constants.'):
            ctx.set_enabled_key_data('foo')
