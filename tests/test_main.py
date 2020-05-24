import xmlsec
from tests import base


class TestBase64LineSize(base.TestMemoryLeaks):
    def tearDown(self):
        xmlsec.base64_default_line_size(64)
        super(TestBase64LineSize, self).tearDown()

    def test_get_base64_default_line_size(self):
        self.assertEqual(xmlsec.base64_default_line_size(), 64)

    def test_set_base64_default_line_size_positional_arg(self):
        xmlsec.base64_default_line_size(0)
        self.assertEqual(xmlsec.base64_default_line_size(), 0)

    def test_set_base64_default_line_size_keyword_arg(self):
        xmlsec.base64_default_line_size(size=0)
        self.assertEqual(xmlsec.base64_default_line_size(), 0)

    def test_set_base64_default_line_size_with_bad_args(self):
        size = xmlsec.base64_default_line_size()
        for bad_size in (None, '', object()):
            with self.assertRaises(TypeError):
                xmlsec.base64_default_line_size(bad_size)
        self.assertEqual(xmlsec.base64_default_line_size(), size)

    def test_set_base64_default_line_size_rejects_negative_values(self):
        size = xmlsec.base64_default_line_size()
        with self.assertRaises(ValueError):
            xmlsec.base64_default_line_size(-1)
        self.assertEqual(xmlsec.base64_default_line_size(), size)
