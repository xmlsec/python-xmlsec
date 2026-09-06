from lxml import etree

import xmlsec
from tests import base

consts = xmlsec.constants


class TestTree(base.TestMemoryLeaks):
    def test_find_child(self):
        root = self.load_xml('sign_template.xml')
        si = xmlsec.tree.find_child(root, consts.NodeSignedInfo, consts.DSigNs)
        self.assertEqual(consts.NodeSignedInfo, si.tag.partition('}')[2])
        self.assertIsNone(xmlsec.tree.find_child(root, consts.NodeReference))
        self.assertIsNone(xmlsec.tree.find_child(root, consts.NodeSignedInfo, consts.EncNs))

    def test_find_child_bad_args(self):
        with self.assertRaises(TypeError):
            xmlsec.tree.find_child('', 0, True)

    def test_find_parent(self):
        root = self.load_xml('sign_template.xml')
        si = xmlsec.tree.find_child(root, consts.NodeSignedInfo, consts.DSigNs)
        self.assertIs(root, xmlsec.tree.find_parent(si, consts.NodeSignature))
        self.assertIsNone(xmlsec.tree.find_parent(root, consts.NodeSignedInfo))

    def test_find_parent_in_a_removed_subtree(self):
        """The walk upward stops at the top of a subtree removed from its document (issue #356)."""
        root = self.load_xml('sign1-in.xml')
        sign = xmlsec.tree.find_node(root, consts.NodeSignature, consts.DSigNs)
        si = xmlsec.tree.find_child(sign, consts.NodeSignedInfo, consts.DSigNs)
        sign.getparent().remove(sign)
        self.assertIs(sign, xmlsec.tree.find_parent(si, consts.NodeSignature, consts.DSigNs))
        self.assertIsNone(xmlsec.tree.find_parent(si, 'Envelope', 'urn:envelope'))

    def test_find_parent_bad_args(self):
        with self.assertRaises(TypeError):
            xmlsec.tree.find_parent('', 0, True)

    def test_find_node(self):
        root = self.load_xml('sign_template.xml')
        ref = xmlsec.tree.find_node(root, consts.NodeReference)
        self.assertEqual(consts.NodeReference, ref.tag.partition('}')[2])
        self.assertIsNone(xmlsec.tree.find_node(root, consts.NodeReference, consts.EncNs))

    def test_find_node_bad_args(self):
        with self.assertRaises(TypeError):
            xmlsec.tree.find_node('', 0, True)

    def test_add_ids(self):
        root = self.load_xml('sign_template.xml')
        xmlsec.tree.add_ids(root, ['id1', 'id2', 'id3'])

    # A document whose entity declarations live in its internal subset, parsed the way callers who
    # refuse entity expansion do. The subtree cannot be serialized on its own then (issue #356).
    ENTITY_XML = (
        b'<!DOCTYPE Root [ <!ENTITY greet "hello"> ]>\n'
        b'<Root xmlns="http://www.w3.org/2000/09/xmldsig#">'
        b'<Signature><SignedInfo>&greet;</SignedInfo></Signature></Root>'
    )

    def load_entity_xml(self):
        root = etree.fromstring(self.ENTITY_XML, etree.XMLParser(resolve_entities=False))
        return root, etree.tostring(root.getroottree())

    def test_find_child_keeps_entity_references(self):
        """The finders must work on a document that declares entities, and leave its references alone."""
        root, before = self.load_entity_xml()
        sign = xmlsec.tree.find_child(root, consts.NodeSignature, consts.DSigNs)
        self.assertEqual(consts.NodeSignature, sign.tag.partition('}')[2])
        self.assertEqual(before, etree.tostring(root.getroottree()))

    def test_find_node_keeps_entity_references(self):
        root, before = self.load_entity_xml()
        si = xmlsec.tree.find_node(root, consts.NodeSignedInfo, consts.DSigNs)
        self.assertEqual(consts.NodeSignedInfo, si.tag.partition('}')[2])
        self.assertEqual(before, etree.tostring(root.getroottree()))

    def test_find_parent_keeps_entity_references(self):
        root, before = self.load_entity_xml()
        si = xmlsec.tree.find_node(root, consts.NodeSignedInfo, consts.DSigNs)
        self.assertIs(root[0], xmlsec.tree.find_parent(si, consts.NodeSignature))
        self.assertEqual(before, etree.tostring(root.getroottree()))

    def test_deeply_nested_document_fails_cleanly(self):
        """A tree nested deeper than the private copy walks must be refused, never crash (issue #356)."""
        root = etree.Element('Root')
        deepest = root
        for _ in range(3000):  # past the 2048 levels libxml2 2.14+ parses, and the walks' own ceiling
            deepest = etree.SubElement(deepest, 'a')
        etree.SubElement(deepest, f'{{{consts.DSigNs}}}Signature')
        try:
            found = xmlsec.tree.find_node(root, consts.NodeSignature, consts.DSigNs)
        except xmlsec.InternalError:
            return  # the shadow path refuses a document this deep
        self.assertEqual(consts.NodeSignature, found.tag.partition('}')[2])

    def test_add_ids_bad_args(self):
        with self.assertRaises(TypeError):
            xmlsec.tree.add_ids('', [])
