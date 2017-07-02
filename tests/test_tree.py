from tests import base

import xmlsec


consts = xmlsec.constants


class TestTree(base.TestMemoryLeaks):
    def test_find_child(self):
        root = self.load_xml("sign_template.xml")
        si = xmlsec.tree.find_child(root, consts.NodeSignedInfo, consts.DSigNs)
        self.assertEqual(consts.NodeSignedInfo, si.tag.partition('}')[2])
        self.assertIsNone(xmlsec.tree.find_child(root, consts.NodeReference))
        self.assertIsNone(xmlsec.tree.find_child(root, consts.NodeSignedInfo, consts.EncNs))

    def test_find_parent(self):
        root = self.load_xml("sign_template.xml")
        si = xmlsec.tree.find_child(root, consts.NodeSignedInfo, consts.DSigNs)
        self.assertIs(root, xmlsec.tree.find_parent(si, consts.NodeSignature))
        self.assertIsNone(xmlsec.tree.find_parent(root, consts.NodeSignedInfo))

    def test_find_node(self):
        root = self.load_xml("sign_template.xml")
        ref = xmlsec.tree.find_node(root, consts.NodeReference)
        self.assertEqual(consts.NodeReference, ref.tag.partition('}')[2])
        self.assertIsNone(xmlsec.tree.find_node(root, consts.NodeReference, consts.EncNs))

    def test_add_ids(self):
        root = self.load_xml("sign_template.xml")
        xmlsec.tree.add_ids(root, ["id1", "id2", "id3"])
