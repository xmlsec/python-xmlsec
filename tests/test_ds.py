import unittest

from lxml import etree

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
        ctx.key = xmlsec.Key.from_file(self.path('rsakey.pem'), format=consts.KeyDataFormatPem)
        del ctx.key
        self.assertIsNone(ctx.key)

    def test_set_key(self):
        ctx = xmlsec.SignatureContext(manager=xmlsec.KeysManager())
        ctx.key = xmlsec.Key.from_file(self.path('rsakey.pem'), format=consts.KeyDataFormatPem)
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
        root = self.load_xml('sign_template.xml')
        sign = xmlsec.template.create(root, consts.TransformExclC14N, consts.TransformRsaSha1, 'Id')
        ctx.register_id(sign, 'Id')

    def test_register_id_bad_args(self):
        ctx = xmlsec.SignatureContext()
        with self.assertRaises(TypeError):
            ctx.register_id('')

    def test_register_id_matches_namespaced_attribute_by_local_name(self):
        """Should accept a namespaced id attribute when no id_ns is given, as xmlHasProp does."""
        ctx = xmlsec.SignatureContext()
        root = self.load_xml('sign_template.xml')
        sign = xmlsec.template.create(root, consts.TransformExclC14N, consts.TransformRsaSha1)
        sign.set('{http://www.example.org/ns}Id', 'sig-1')
        ctx.register_id(sign, 'Id')

    def test_register_id_rejects_an_id_value_already_registered(self):
        """A value another registration claimed cannot be registered again: only one attribute can win the id lookup."""
        ctx = xmlsec.SignatureContext()
        root = etree.fromstring(b'<Root><Decoy ID="dup"/><Real Id="dup"/></Root>')
        ctx.register_id(root[0], 'ID')
        with self.assertRaisesRegex(xmlsec.Error, 'duplicated id.'):
            ctx.register_id(root[1], 'Id')

    def test_register_id_rejects_an_id_value_the_document_declares(self):
        """An xml:id the document was parsed with already claims the value, so another attribute for it is refused."""
        root = etree.fromstring(b'<Root><A xml:id="dup"/><B ID="dup"/></Root>')
        with self.assertRaisesRegex(xmlsec.Error, 'duplicated id.'):
            xmlsec.SignatureContext().register_id(root[1], 'ID')

    def test_register_id_rejects_an_id_value_add_ids_claimed(self):
        """Registrations made over a subtree by add_ids claim their values too."""
        root = etree.fromstring(b'<Root><Scope><A ID="dup"/></Scope><B Id="dup"/></Root>')
        xmlsec.tree.add_ids(root[0], ['ID'])
        with self.assertRaisesRegex(xmlsec.Error, 'duplicated id.'):
            xmlsec.SignatureContext().register_id(root[1], 'Id')

    def test_register_id_accepts_the_same_attribute_twice(self):
        """Re-registering an attribute is the no-op the id lookup already resolves; only another claim is a duplicate."""
        ctx = xmlsec.SignatureContext()
        root = etree.fromstring(b'<Root><N ID="dup"/></Root>')
        ctx.register_id(root[0], 'ID')
        ctx.register_id(root[0], 'ID')

    def test_register_id_accepts_an_attribute_add_ids_registered(self):
        """add_ids already registered this very attribute, which the fast path's `tmpAttr == attr` accepts."""
        root = etree.fromstring(b'<Root><Scope><A ID="dup"/></Scope></Root>')
        xmlsec.tree.add_ids(root[0], ['ID'])
        xmlsec.SignatureContext().register_id(root[0][0], 'ID')

    def test_register_id_rejects_a_value_a_sibling_attribute_declares(self):
        """The declared id of an element can sit on another of its attributes, which claims the value all the same."""
        root = etree.fromstring(b'<Root><N xml:id="dup" ID="dup"/></Root>')
        with self.assertRaisesRegex(xmlsec.Error, 'duplicated id.'):
            xmlsec.SignatureContext().register_id(root[0], 'ID')

    def test_register_id_accepts_the_declared_attribute_beside_a_twin(self):
        """A second attribute repeating the value is not the declared one, so registering the declared one is the no-op."""
        xml = b'<!DOCTYPE Root SYSTEM "id_attr.dtd">\n<Root><Node ID="dup" other="dup"/></Root>\n'
        xmlsec.SignatureContext().register_id(self.parse_with_external_dtd(xml)[0], 'ID')

    def test_register_id_rejects_a_value_a_namespaced_registration_claimed(self):
        """Two attributes of one element differing only in namespace are two attributes: the second cannot win the lookup."""
        ctx = xmlsec.SignatureContext()
        root = etree.fromstring(b'<Root xmlns:a="urn:a"><N Id="dup" a:Id="dup"/></Root>')
        ctx.register_id(root[0], 'Id', id_ns='urn:a')
        with self.assertRaisesRegex(xmlsec.Error, 'duplicated id.'):
            ctx.register_id(root[0], 'Id')

    def test_register_id_accepts_the_same_namespaced_attribute_twice(self):
        """The no-op holds for a namespaced attribute too, which the key comparison must not read as a collision."""
        ctx = xmlsec.SignatureContext()
        root = etree.fromstring(b'<Root xmlns:a="urn:a"><N a:Id="dup"/></Root>')
        ctx.register_id(root[0], 'Id', id_ns='urn:a')
        ctx.register_id(root[0], 'Id', id_ns='urn:a')

    def test_register_id_with_namespace_without_attribute(self):
        ctx = xmlsec.SignatureContext()
        root = self.load_xml('sign_template.xml')
        sign = xmlsec.template.create(root, consts.TransformExclC14N, consts.TransformRsaSha1, 'Id')
        with self.assertRaisesRegex(xmlsec.Error, 'missing attribute.'):
            ctx.register_id(sign, 'Id', id_ns='foo')

    def sign_id_reference(self, root, uri):
        """Signs `root` with a single reference to `uri` and returns the digest of that reference."""
        sign = xmlsec.template.create(root, consts.TransformExclC14N, consts.TransformRsaSha1, ns='ds')
        root.append(sign)
        ref = xmlsec.template.add_reference(sign, consts.TransformSha1, uri=uri)
        xmlsec.template.add_transform(ref, consts.TransformExclC14N)
        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_file(self.path('rsakey.pem'), format=consts.KeyDataFormatPem)
        ctx.sign(sign)
        return xmlsec.tree.find_node(sign, consts.NodeDigestValue, consts.DSigNs).text

    def test_add_ids_ignores_an_id_that_joins_the_scope_later(self):
        """add_ids registers what the scope carries at the call, which is where xmlSecAddIDs walks it."""
        root = etree.fromstring(b'<Root><A ID="a"/></Root>')
        xmlsec.tree.add_ids(root, ['ID'])
        etree.SubElement(root, 'B', {'ID': 'b'})
        with self.assertRaisesRegex(xmlsec.Error, 'failed to sign'):
            self.sign_id_reference(root, '#b')

    def test_add_ids_claims_a_value_in_document_order(self):
        """xmlSecAddIDs walks the scope element by element, the names within each: <Y B="v"/> claims "v" first."""
        xml = b'<Root><Y B="v"><Data>y</Data></Y><X A="v"><Data>x</Data></X></Root>'
        root = etree.fromstring(xml)
        xmlsec.tree.add_ids(root, ['A', 'B'])
        both = self.sign_id_reference(root, '#v')
        root = etree.fromstring(xml)
        xmlsec.tree.add_ids(root, ['B'])
        self.assertEqual(both, self.sign_id_reference(root, '#v'))

    def test_sign_bad_args(self):
        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_file(self.path('rsakey.pem'), format=consts.KeyDataFormatPem)
        with self.assertRaises(TypeError):
            ctx.sign('')

    def test_sign_fail(self):
        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_file(self.path('rsakey.pem'), format=consts.KeyDataFormatPem)
        with self.assertRaisesRegex(xmlsec.Error, 'failed to sign'):
            ctx.sign(self.load_xml('sign1-in.xml'))

    def test_sign_case1(self):
        """Should sign a pre-constructed template file using a key from a PEM file."""
        root = self.load_xml('sign1-in.xml')
        sign = xmlsec.tree.find_node(root, consts.NodeSignature)
        self.assertIsNotNone(sign)

        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_file(self.path('rsakey.pem'), format=consts.KeyDataFormatPem)
        self.assertIsNotNone(ctx.key)
        ctx.key.name = 'rsakey.pem'
        self.assertEqual('rsakey.pem', ctx.key.name)

        ctx.sign(sign)
        self.assertEqual(self.load_xml('sign1-out.xml'), root)

    def test_sign_case2(self):
        """Should sign a dynamicaly constructed template file using a key from a PEM file."""
        root = self.load_xml('sign2-in.xml')
        sign = xmlsec.template.create(root, consts.TransformExclC14N, consts.TransformRsaSha1)
        self.assertIsNotNone(sign)
        root.append(sign)
        ref = xmlsec.template.add_reference(sign, consts.TransformSha1)
        xmlsec.template.add_transform(ref, consts.TransformEnveloped)
        ki = xmlsec.template.ensure_key_info(sign)
        xmlsec.template.add_key_name(ki)

        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_file(self.path('rsakey.pem'), format=consts.KeyDataFormatPem)
        self.assertIsNotNone(ctx.key)
        ctx.key.name = 'rsakey.pem'
        self.assertEqual('rsakey.pem', ctx.key.name)

        ctx.sign(sign)
        self.assertEqual(self.load_xml('sign2-out.xml'), root)

    def test_sign_case3(self):
        """Should sign a file using a dynamicaly created template, key from PEM and an X509 cert."""
        root = self.load_xml('sign3-in.xml')
        sign = xmlsec.template.create(root, consts.TransformExclC14N, consts.TransformRsaSha1)
        self.assertIsNotNone(sign)
        root.append(sign)
        ref = xmlsec.template.add_reference(sign, consts.TransformSha1)
        xmlsec.template.add_transform(ref, consts.TransformEnveloped)
        ki = xmlsec.template.ensure_key_info(sign)
        xmlsec.template.add_x509_data(ki)

        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_file(self.path('rsakey.pem'), format=consts.KeyDataFormatPem)
        self.assertIsNotNone(ctx.key)
        ctx.key.load_cert_from_file(self.path('rsacert.pem'), consts.KeyDataFormatPem)
        ctx.key.name = 'rsakey.pem'
        self.assertEqual('rsakey.pem', ctx.key.name)

        ctx.sign(sign)
        self.assertEqual(self.load_xml('sign3-out.xml'), root)

    def test_sign_case4(self):
        """Should sign a file using a dynamically created template, key from PEM and an X509 cert with custom ns."""
        root = self.load_xml('sign4-in.xml')
        xmlsec.tree.add_ids(root, ['ID'])
        elem_id = root.get('ID', None)
        if elem_id:
            elem_id = '#' + elem_id
        sign = xmlsec.template.create(root, consts.TransformExclC14N, consts.TransformRsaSha1, ns='ds')
        self.assertIsNotNone(sign)
        root.append(sign)
        ref = xmlsec.template.add_reference(sign, consts.TransformSha1, uri=elem_id)
        xmlsec.template.add_transform(ref, consts.TransformEnveloped)
        xmlsec.template.add_transform(ref, consts.TransformExclC14N)
        ki = xmlsec.template.ensure_key_info(sign)
        xmlsec.template.add_x509_data(ki)

        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_file(self.path('rsakey.pem'), format=consts.KeyDataFormatPem)
        self.assertIsNotNone(ctx.key)
        ctx.key.load_cert_from_file(self.path('rsacert.pem'), consts.KeyDataFormatPem)
        ctx.key.name = 'rsakey.pem'
        self.assertEqual('rsakey.pem', ctx.key.name)

        ctx.sign(sign)
        self.assertEqual(self.load_xml('sign4-out.xml'), root)

    def test_sign_case5(self):
        """Should sign a file using a dynamicaly created template, key from PEM file and an X509 certificate."""
        root = self.load_xml('sign5-in.xml')
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
        ctx.key = xmlsec.Key.from_file(self.path('rsakey.pem'), format=consts.KeyDataFormatPem)
        self.assertIsNotNone(ctx.key)
        ctx.key.load_cert_from_file(self.path('rsacert.pem'), consts.KeyDataFormatPem)
        ctx.key.name = 'rsakey.pem'
        self.assertEqual('rsakey.pem', ctx.key.name)

        ctx.sign(sign)
        if (1, 2, 36) <= xmlsec.get_libxmlsec_version() <= (1, 2, 37):
            expected_xml_file = 'sign5-out-xmlsec_1_2_36_to_37.xml'
        else:
            expected_xml_file = 'sign5-out.xml'
        self.assertEqual(self.load_xml(expected_xml_file), root)

    def test_sign_and_verify_with_registered_id(self):
        """Should resolve a #id reference registered through register_id (not add_ids) on sign and verify."""
        root = self.load_xml('sign4-in.xml')
        ctx = xmlsec.SignatureContext()
        ctx.register_id(root, 'ID')
        sign = xmlsec.template.create(root, consts.TransformExclC14N, consts.TransformRsaSha1, ns='ds')
        root.append(sign)
        ref = xmlsec.template.add_reference(sign, consts.TransformSha1, uri='#' + root.get('ID'))
        xmlsec.template.add_transform(ref, consts.TransformEnveloped)
        xmlsec.template.add_transform(ref, consts.TransformExclC14N)
        ki = xmlsec.template.ensure_key_info(sign)
        xmlsec.template.add_x509_data(ki)

        ctx.key = xmlsec.Key.from_file(self.path('rsakey.pem'), format=consts.KeyDataFormatPem)
        ctx.key.load_cert_from_file(self.path('rsacert.pem'), consts.KeyDataFormatPem)
        ctx.key.name = 'rsakey.pem'
        ctx.sign(sign)
        self.assertEqual(self.load_xml('sign4-out.xml'), root)

        verify_ctx = xmlsec.SignatureContext()
        verify_ctx.register_id(root, 'ID')
        verify_ctx.key = xmlsec.Key.from_file(self.path('rsapub.pem'), format=consts.KeyDataFormatPem)
        verify_ctx.verify(sign)

    def test_sign_and_verify_a_template_removed_from_its_document(self):
        """A template taken out of its tree still signs: lxml leaves it pointing at the document it left,
        and that is where its URI="" reference resolves — on the raw path too (issue #356)."""
        root = self.load_xml('sign1-in.xml')
        sign = xmlsec.tree.find_node(root, consts.NodeSignature, consts.DSigNs)
        sign.getparent().remove(sign)

        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_file(self.path('rsakey.pem'), format=consts.KeyDataFormatPem)
        ctx.sign(sign)
        # the signature is written into the removed subtree, and nothing is
        # written into the document it covers
        self.assertTrue(xmlsec.tree.find_node(sign, consts.NodeSignatureValue, consts.DSigNs).text)
        self.assertIsNone(xmlsec.tree.find_node(root, consts.NodeSignature, consts.DSigNs))

        verify_ctx = xmlsec.SignatureContext()
        verify_ctx.key = xmlsec.Key.from_file(self.path('rsakey.pem'), format=consts.KeyDataFormatPem)
        verify_ctx.verify(sign)

        # the digest covers that document: changing it invalidates the signature
        root.find('{urn:envelope}Data').text = 'tampered'
        tampered_ctx = xmlsec.SignatureContext()
        tampered_ctx.key = xmlsec.Key.from_file(self.path('rsakey.pem'), format=consts.KeyDataFormatPem)
        with self.assertRaises(xmlsec.VerificationError):
            tampered_ctx.verify(sign)

    def test_sign_and_verify_a_removed_template_against_a_registered_id(self):
        """A #id reference from a removed subtree resolves in the document it left (issue #356)."""
        root = self.load_xml('sign4-in.xml')
        sign = xmlsec.template.create(root, consts.TransformExclC14N, consts.TransformRsaSha1, ns='ds')
        root.append(sign)
        ref = xmlsec.template.add_reference(sign, consts.TransformSha1, uri='#' + root.get('ID'))
        xmlsec.template.add_transform(ref, consts.TransformExclC14N)
        root.remove(sign)

        ctx = xmlsec.SignatureContext()
        ctx.register_id(root, 'ID')
        ctx.key = xmlsec.Key.from_file(self.path('rsakey.pem'), format=consts.KeyDataFormatPem)
        ctx.sign(sign)

        verify_ctx = xmlsec.SignatureContext()
        verify_ctx.register_id(root, 'ID')
        verify_ctx.key = xmlsec.Key.from_file(self.path('rsapub.pem'), format=consts.KeyDataFormatPem)
        verify_ctx.verify(sign)

    # A document whose id attribute is typed by an external DTD subset — the
    # declarations live in a file the DOCTYPE names, and only a parse that
    # loads it knows "#ext" resolves to the Node (issue #356).
    EXTERNAL_DTD_XML = b'<!DOCTYPE Root SYSTEM "id_attr.dtd">\n<Root><Node ID="ext"><Data>signed</Data></Node></Root>\n'

    def parse_with_external_dtd(self, xml):
        """Parse `xml` with its external subset loaded, or skip the test when this build forbids that.

        xmlsec installs a no-XXE external entity loader globally at
        ``xmlSecInit`` (1.2.34 and later, and the patched 1.2.33 some
        distributions ship), so merely importing xmlsec can refuse lxml its
        own ``load_dtd=True`` parse. Nothing then types the id, on either
        path, and there is no declaration left for the copy to carry across.
        """
        root = etree.fromstring(xml, etree.XMLParser(load_dtd=True), base_url=self.path('doc.xml'))
        if root.getroottree().docinfo.externalDTD is None:
            self.skipTest('this build refuses to load an external DTD subset')
        return root

    def test_sign_and_verify_with_an_id_an_external_dtd_declares(self):
        """Should resolve a #id reference whose id attribute an external subset the caller loaded declares."""
        root = self.parse_with_external_dtd(self.EXTERNAL_DTD_XML)
        sign = xmlsec.template.create(root, consts.TransformExclC14N, consts.TransformRsaSha1, ns='ds')
        root.append(sign)
        ref = xmlsec.template.add_reference(sign, consts.TransformSha1, uri='#ext')
        xmlsec.template.add_transform(ref, consts.TransformExclC14N)

        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_file(self.path('rsakey.pem'), format=consts.KeyDataFormatPem)
        ctx.sign(sign)

        verify_ctx = xmlsec.SignatureContext()
        verify_ctx.key = xmlsec.Key.from_file(self.path('rsapub.pem'), format=consts.KeyDataFormatPem)
        verify_ctx.verify(sign)

    # A document where an unregistered element carries the same id value as the
    # registered one, and comes first. Only the registered element may answer
    # the "#dup" reference (issue #356).
    DUPLICATE_ID_XML = (
        b'<Root>\n'
        b'  <Decoy ID="dup"><Data>decoy</Data></Decoy>\n'
        b'  <Scope><Real ID="dup"><Data>real</Data></Real></Scope>\n'
        b'</Root>\n'
    )

    def sign_duplicate_id(self, register):
        """Signs a "#dup" reference over the document above, registering the ids with `register`."""
        root = etree.fromstring(self.DUPLICATE_ID_XML)
        ctx = xmlsec.SignatureContext()
        register(root)
        sign = xmlsec.template.create(root, consts.TransformExclC14N, consts.TransformRsaSha1, ns='ds')
        root.append(sign)
        ref = xmlsec.template.add_reference(sign, consts.TransformSha1, uri='#dup')
        xmlsec.template.add_transform(ref, consts.TransformExclC14N)
        ctx.key = xmlsec.Key.from_file(self.path('rsakey.pem'), format=consts.KeyDataFormatPem)
        ctx.sign(sign)
        return etree.tostring(root)

    def verify_duplicate_id(self, signed, register, tamper):
        """Re-parses `signed`, rewrites the text of the `tamper` element and verifies."""
        root = etree.fromstring(signed)
        register(root)
        root.find(tamper).text = 'tampered'
        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_file(self.path('rsapub.pem'), format=consts.KeyDataFormatPem)
        ctx.verify(root.find('dsig:Signature', namespaces=base.ns))

    def assert_covers_registered_element_only(self, register):
        signed = self.sign_duplicate_id(register)
        # the decoy is not what the reference resolved to, so it is not covered
        self.verify_duplicate_id(signed, register, 'Decoy/Data')
        # the registered element is
        with self.assertRaises(xmlsec.VerificationError):
            self.verify_duplicate_id(signed, register, 'Scope/Real/Data')

    def test_register_id_covers_only_the_registered_node(self):
        """register_id registers the node it is given, not every element with that attribute."""
        self.assert_covers_registered_element_only(
            lambda root: xmlsec.SignatureContext().register_id(root.find('Scope/Real'), 'ID')
        )

    def test_add_ids_covers_only_the_given_subtree(self):
        """add_ids registers the subtree it is given, not the whole document."""
        self.assert_covers_registered_element_only(lambda root: xmlsec.tree.add_ids(root.find('Scope'), ['ID']))

    def test_add_ids_records_nothing_when_an_item_is_not_a_name(self):
        """A rejected add_ids leaves no part of its list registered, so the "#dup" reference resolves to nothing."""

        def register(root):
            with self.assertRaises(TypeError):
                xmlsec.tree.add_ids(root.find('Scope'), ['ID', 1])

        with self.assertRaises(xmlsec.Error):
            self.sign_duplicate_id(register)

    def test_sign_binary_bad_args(self):
        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_file(self.path('rsakey.pem'), format=consts.KeyDataFormatPem)
        with self.assertRaises(TypeError):
            ctx.sign_binary(bytes=1, transform='')

    def test_sign_binary_no_key(self):
        ctx = xmlsec.SignatureContext()
        with self.assertRaisesRegex(xmlsec.Error, 'Sign key is not specified.'):
            ctx.sign_binary(bytes=b'', transform=consts.TransformRsaSha1)

    @unittest.skipIf(not hasattr(consts, 'TransformXslt'), reason='XSLT transformations not enabled')
    def test_sign_binary_invalid_signature_method(self):
        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_file(self.path('rsakey.pem'), format=consts.KeyDataFormatPem)
        with self.assertRaisesRegex(xmlsec.Error, 'incompatible signature method'):
            ctx.sign_binary(bytes=b'', transform=consts.TransformXslt)

    def test_sign_binary(self):
        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_file(self.path('rsakey.pem'), format=consts.KeyDataFormatPem)
        self.assertIsNotNone(ctx.key)
        ctx.key.name = 'rsakey.pem'
        self.assertEqual('rsakey.pem', ctx.key.name)

        sign = ctx.sign_binary(self.load('sign6-in.bin'), consts.TransformRsaSha1)
        self.assertEqual(self.load('sign6-out.bin'), sign)

    def test_sign_binary_twice_not_possible(self):
        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_file(self.path('rsakey.pem'), format=consts.KeyDataFormatPem)
        data = self.load('sign6-in.bin')
        ctx.sign_binary(data, consts.TransformRsaSha1)
        with self.assertRaisesRegex(xmlsec.Error, 'Signature context already used; it is designed for one use only.'):
            ctx.sign_binary(data, consts.TransformRsaSha1)

    def test_verify_bad_args(self):
        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_file(self.path('rsakey.pem'), format=consts.KeyDataFormatPem)
        with self.assertRaises(TypeError):
            ctx.verify('')

    def test_verify_fail(self):
        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_file(self.path('rsakey.pem'), format=consts.KeyDataFormatPem)
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
        root = self.load_xml(f'sign{i}-out.xml')
        xmlsec.tree.add_ids(root, ['ID'])
        sign = xmlsec.tree.find_node(root, consts.NodeSignature)
        self.assertIsNotNone(sign)
        self.assertEqual(consts.NodeSignature, sign.tag.partition('}')[2])

        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_file(self.path('rsapub.pem'), format=consts.KeyDataFormatPem)
        self.assertIsNotNone(ctx.key)
        ctx.key.name = 'rsapub.pem'
        self.assertEqual('rsapub.pem', ctx.key.name)
        ctx.verify(sign)

    def test_validate_binary_sign(self):
        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_file(self.path('rsakey.pem'), format=consts.KeyDataFormatPem)
        self.assertIsNotNone(ctx.key)
        ctx.key.name = 'rsakey.pem'
        self.assertEqual('rsakey.pem', ctx.key.name)

        ctx.verify_binary(self.load('sign6-in.bin'), consts.TransformRsaSha1, self.load('sign6-out.bin'))

    def test_validate_binary_sign_fail(self):
        ctx = xmlsec.SignatureContext()

        ctx.key = xmlsec.Key.from_file(self.path('rsakey.pem'), format=consts.KeyDataFormatPem)
        self.assertIsNotNone(ctx.key)
        ctx.key.name = 'rsakey.pem'
        self.assertEqual('rsakey.pem', ctx.key.name)
        with self.assertRaises(xmlsec.Error):
            ctx.verify_binary(self.load('sign6-in.bin'), consts.TransformRsaSha1, b'invalid')

    def test_enable_reference_transform(self):
        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_file(self.path('rsakey.pem'), format=consts.KeyDataFormatPem)
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
        ctx.key = xmlsec.Key.from_file(self.path('rsakey.pem'), format=consts.KeyDataFormatPem)
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
        ctx.key = xmlsec.Key.from_file(self.path('rsakey.pem'), format=consts.KeyDataFormatPem)
        ctx.set_enabled_key_data([consts.KeyDataAes])

    def test_set_enabled_key_data_empty(self):
        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_file(self.path('rsakey.pem'), format=consts.KeyDataFormatPem)
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


class TestIdRegistryLifetime(base.TestMemoryLeaks):
    """Guards the lifetime rule of the shadow-mode id registry (issue #356)."""

    # The document churn below is this test's point; the leak harness would repeat it ten times.
    iterations = 0

    # Far more documents than any bounded registry would have held at once.
    OTHER_DOCUMENTS = 5000

    def test_registration_survives_other_live_documents(self):
        """Registering ids for other documents must never drop a live document's own registration."""
        root = self.load_xml('sign4-out.xml')
        ctx = xmlsec.SignatureContext()
        ctx.register_id(root, 'ID')

        # All kept alive, so none of these registrations may be traded for another.
        others = [etree.fromstring(f'<Envelope ID="doc-{i}"/>') for i in range(self.OTHER_DOCUMENTS)]
        for other in others:
            ctx.register_id(other, 'ID')

        sign = xmlsec.tree.find_node(root, consts.NodeSignature)
        ctx.key = xmlsec.Key.from_file(self.path('rsapub.pem'), format=consts.KeyDataFormatPem)
        ctx.verify(sign)  # resolves #ID through the registration made before the churn

    def test_registration_dies_with_its_element(self):
        """A dropped element takes its registration with it: libxml2 drops the id entry when it frees the attribute."""
        root = etree.fromstring(b'<Root/>')
        ctx = xmlsec.SignatureContext()
        for _ in range(2):  # the second registration claims the value the first one did
            node = etree.SubElement(root, 'T', {'ID': 'x'})
            ctx.register_id(node, 'ID')
            root.remove(node)
            del node

    def test_registration_survives_its_element_being_removed(self):
        """An element out of its document is not gone: lxml keeps the subtree, and the id entry stands."""
        root = etree.fromstring(b'<Root><Removed ID="x"/><Other ID="x"/></Root>')
        ctx = xmlsec.SignatureContext()
        removed = root[0]
        ctx.register_id(removed, 'ID')
        root.remove(removed)
        with self.assertRaisesRegex(xmlsec.Error, 'duplicated id.'):
            ctx.register_id(root[0], 'ID')

    def test_registration_survives_a_descendant_being_held(self):
        """A proxy anywhere in a removed subtree keeps it alive, registration included."""
        root = etree.fromstring(b'<Root><Removed ID="x"><Inner/></Removed><Other ID="x"/></Root>')
        ctx = xmlsec.SignatureContext()
        ctx.register_id(root[0], 'ID')
        inner = root[0][0]
        root.remove(inner.getparent())
        with self.assertRaisesRegex(xmlsec.Error, 'duplicated id.'):
            ctx.register_id(root[0], 'ID')
        del inner

    def test_registration_survives_an_entity_reference_being_held(self):
        """An entity reference is a proxy like any other: holding one keeps its removed subtree alive."""
        parser = etree.XMLParser(resolve_entities=False)
        root = etree.fromstring(
            b'<!DOCTYPE Root [<!ENTITY e "text">]><Root><Removed ID="x">&e;</Removed><Other ID="x"/></Root>', parser
        )
        ctx = xmlsec.SignatureContext()
        ctx.register_id(root[0], 'ID')
        entity = root[0][0]
        root.remove(entity.getparent())
        with self.assertRaisesRegex(xmlsec.Error, 'duplicated id.'):
            ctx.register_id(root[0], 'ID')
        del entity

    def test_registration_survives_a_sibling_being_adopted_away(self):
        """An element moved into another document must not make its old document's registrations look collectable."""
        root = etree.fromstring(b'<Root><Moved ID="moved"/><Stays ID="stays"><Data>x</Data></Stays></Root>')
        ctx = xmlsec.SignatureContext()
        moved = root.find('Moved')
        ctx.register_id(moved, 'ID')
        ctx.register_id(root.find('Stays'), 'ID')

        etree.fromstring(b'<Other/>').append(moved)  # `moved` now references the other document
        del moved
        ctx.register_id(etree.fromstring(b'<Churn ID="churn"/>'), 'ID')  # a new document prunes the registry

        sign = xmlsec.template.create(root, consts.TransformExclC14N, consts.TransformRsaSha1, ns='ds')
        root.append(sign)
        ref = xmlsec.template.add_reference(sign, consts.TransformSha1, uri='#stays')
        xmlsec.template.add_transform(ref, consts.TransformExclC14N)
        ctx.key = xmlsec.Key.from_file(self.path('rsakey.pem'), format=consts.KeyDataFormatPem)
        ctx.sign(sign)  # resolves #stays only if `root`'s registrations survived the prune
