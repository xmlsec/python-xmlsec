import xmlsec
from xmlsec import constants as consts

from io import BytesIO

import pytest
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


class TestCallbacks(base.TestMemoryLeaks):
    def setUp(self):
        super().setUp()
        xmlsec.cleanup_callbacks()

    def _sign_doc(self):
        root = self.load_xml("doc.xml")
        sign = xmlsec.template.create(
            root,
            c14n_method=consts.TransformExclC14N,
            sign_method=consts.TransformRsaSha1
        )
        xmlsec.template.add_reference(
            sign, consts.TransformSha1, uri="cid:123456")

        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_file(
            self.path("rsakey.pem"), format=consts.KeyDataFormatPem
        )
        ctx.sign(sign)
        return sign

    def _expect_sign_failure(self):
        exc_info = pytest.raises(xmlsec.Error, self._sign_doc)
        self.assertEqual(exc_info.value.args, (1, 'failed to sign'))

    def _register_mismatch_callbacks(self, match_cb=lambda filename: False):
        xmlsec.register_callbacks(
            match_cb,
            lambda filename: None,
            lambda none, buf: 0,
            lambda none: None,
        )

    def _register_match_callbacks(self):
        xmlsec.register_callbacks(
            lambda filename: filename == b'cid:123456',
            lambda filename: BytesIO(b'<html><head/><body/></html>'),
            lambda bio, buf: bio.readinto(buf),
            lambda bio: bio.close(),
        )

    def _find(self, elem, *tags):
        for tag in tags:
            elem = elem.find(
                '{{http://www.w3.org/2000/09/xmldsig#}}{}'.format(tag))
        return elem

    def _verify_external_data_signature(self):
        signature = self._sign_doc()
        digest = self._find(
            signature, 'SignedInfo', 'Reference', 'DigestValue'
        ).text
        self.assertEqual(digest, 'VihZwVMGJ48NsNl7ertVHiURXk8=')

    def test_sign_external_data_no_callbacks_fails(self):
        self._expect_sign_failure()

    def test_sign_external_data_default_callbacks_fails(self):
        xmlsec.register_default_callbacks()
        self._expect_sign_failure()

    def test_sign_external_data_no_matching_callbacks_fails(self):
        self._register_mismatch_callbacks()
        self._expect_sign_failure()

    def test_sign_data_from_callbacks(self):
        self._register_match_callbacks()
        self._verify_external_data_signature()

    def test_sign_data_not_first_callback(self):
        bad_match_calls = 0

        def match_cb(filename):
            nonlocal bad_match_calls
            bad_match_calls += 1
            False

        for _ in range(2):
            self._register_mismatch_callbacks(match_cb)

        self._register_match_callbacks()

        for _ in range(2):
            self._register_mismatch_callbacks()

        self._verify_external_data_signature()
        self.assertEqual(bad_match_calls, 0)

    def test_failed_sign_because_default_callbacks(self):
        mismatch_calls = 0

        def mismatch_cb(filename):
            nonlocal mismatch_calls
            mismatch_calls += 1
            False

        # NB: These first two sets of callbacks should never get called,
        # because the default callbacks always match beforehand:
        self._register_match_callbacks()
        self._register_mismatch_callbacks(mismatch_cb)
        xmlsec.register_default_callbacks()
        self._register_mismatch_callbacks(mismatch_cb)
        self._register_mismatch_callbacks(mismatch_cb)
        self._expect_sign_failure()
        self.assertEqual(mismatch_calls, 2)
