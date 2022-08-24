import gc
import os
import sys
import unittest

from lxml import etree

import xmlsec

etype = type(etree.Element('test'))

ns = {'dsig': xmlsec.constants.DSigNs, 'enc': xmlsec.constants.EncNs}


try:
    import resource

    test_iterations = int(os.environ.get('PYXMLSEC_TEST_ITERATIONS', '10'))
except (ImportError, ValueError):
    test_iterations = 0


class TestMemoryLeaks(unittest.TestCase):
    maxDiff = None

    iterations = test_iterations

    data_dir = os.path.join(os.path.dirname(__file__), "data")

    def setUp(self):
        gc.disable()
        self.addTypeEqualityFunc(etype, "assertXmlEqual")
        xmlsec.enable_debug_trace(1)

    def run(self, result=None):
        # run first time
        super(TestMemoryLeaks, self).run(result=result)
        if self.iterations == 0:
            return

        m_usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        o_count = gc.get_count()[0]
        m_hits = 0
        o_hits = 0
        for _ in range(self.iterations):
            super(TestMemoryLeaks, self).run(result=result)
            m_usage_n = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            if m_usage_n > m_usage:
                m_usage = m_usage_n
                m_hits += 1
            o_count_n = gc.get_count()[0]
            if o_count_n > o_count:
                o_count = o_count_n
                o_hits += 1
            del m_usage_n
            del o_count_n

        if m_hits > int(self.iterations * 0.8):
            result.buffer = False
            try:
                raise AssertionError("memory leak detected")
            except AssertionError:
                result.addError(self, sys.exc_info())
        if o_hits > int(self.iterations * 0.8):
            result.buffer = False
            try:
                raise AssertionError("unreferenced objects detected")
            except AssertionError:
                result.addError(self, sys.exc_info())

    def path(self, name):
        """Return full path for resource."""
        return os.path.join(self.data_dir, name)

    def load(self, name):
        """Load resource by name."""
        with open(self.path(name), "rb") as stream:
            return stream.read()

    def load_xml(self, name, xpath=None):
        """Return xml.etree."""
        with open(self.path(name)) as f:
            root = etree.parse(f).getroot()
            if xpath is None:
                return root
            return root.find(xpath)

    def dump(self, root):
        print(etree.tostring(root))

    def assertXmlEqual(self, first, second, msg=None):  # noqa: N802
        """Check equality of etree.roots."""
        msg = msg or ''
        if first.tag != second.tag:
            self.fail('Tags do not match: {} and {}. {}'.format(first.tag, second.tag, msg))
        for name, value in first.attrib.items():
            if second.attrib.get(name) != value:
                self.fail('Attributes do not match: {}={!r}, {}={!r}. {}'.format(name, value, name, second.attrib.get(name), msg))
        for name in second.attrib.keys():
            if name not in first.attrib:
                self.fail('x2 has an attribute x1 is missing: {}. {}'.format(name, msg))
        if not _xml_text_compare(first.text, second.text):
            self.fail('text: {!r} != {!r}. {}'.format(first.text, second.text, msg))
        if not _xml_text_compare(first.tail, second.tail):
            self.fail('tail: {!r} != {!r}. {}'.format(first.tail, second.tail, msg))
        cl1 = sorted(first.getchildren(), key=lambda x: x.tag)
        cl2 = sorted(second.getchildren(), key=lambda x: x.tag)
        if len(cl1) != len(cl2):
            self.fail('children length differs, {} != {}. {}'.format(len(cl1), len(cl2), msg))
        i = 0
        for c1, c2 in zip(cl1, cl2):
            i += 1
            self.assertXmlEqual(c1, c2)


def _xml_text_compare(t1, t2):
    if not t1 and not t2:
        return True
    if t1 == '*' or t2 == '*':
        return True
    return (t1 or '').strip() == (t2 or '').strip()
