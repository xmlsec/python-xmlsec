import sys
from io import BytesIO
from unittest import skipIf

import xmlsec
from tests import base
from xmlsec import constants as consts


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
        sign = xmlsec.template.create(root, c14n_method=consts.TransformExclC14N, sign_method=consts.TransformRsaSha1)
        xmlsec.template.add_reference(sign, consts.TransformSha1, uri="cid:123456")

        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem)
        ctx.sign(sign)
        return sign

    def _expect_sign_failure(self):
        with self.assertRaisesRegex(xmlsec.Error, 'failed to sign'):
            self._sign_doc()

    def _mismatch_callbacks(self, match_cb=lambda filename: False):
        return [
            match_cb,
            lambda filename: None,
            lambda none, buf: 0,
            lambda none: None,
        ]

    def _register_mismatch_callbacks(self, match_cb=lambda filename: False):
        xmlsec.register_callbacks(*self._mismatch_callbacks(match_cb))

    def _register_match_callbacks(self):
        xmlsec.register_callbacks(
            lambda filename: filename == b'cid:123456',
            lambda filename: BytesIO(b'<html><head/><body/></html>'),
            lambda bio, buf: bio.readinto(buf),
            lambda bio: bio.close(),
        )

    def _find(self, elem, *tags):
        try:
            return elem.xpath(
                './' + '/'.join('xmldsig:{}'.format(tag) for tag in tags),
                namespaces={
                    'xmldsig': 'http://www.w3.org/2000/09/xmldsig#',
                },
            )[0]
        except IndexError as e:
            raise KeyError(tags) from e

    def _verify_external_data_signature(self):
        signature = self._sign_doc()
        digest = self._find(signature, 'SignedInfo', 'Reference', 'DigestValue').text
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
            return False

        for _ in range(2):
            self._register_mismatch_callbacks(match_cb)

        self._register_match_callbacks()

        for _ in range(2):
            self._register_mismatch_callbacks()

        self._verify_external_data_signature()
        self.assertEqual(bad_match_calls, 0)

    @skipIf(sys.platform == "win32", "unclear behaviour on windows")
    def test_failed_sign_because_default_callbacks(self):
        mismatch_calls = 0

        def mismatch_cb(filename):
            nonlocal mismatch_calls
            mismatch_calls += 1
            return False

        # NB: These first two sets of callbacks should never get called,
        # because the default callbacks always match beforehand:
        self._register_match_callbacks()
        self._register_mismatch_callbacks(mismatch_cb)
        xmlsec.register_default_callbacks()
        self._register_mismatch_callbacks(mismatch_cb)
        self._register_mismatch_callbacks(mismatch_cb)
        self._expect_sign_failure()
        self.assertEqual(mismatch_calls, 2)

    def test_register_non_callables(self):
        for idx in range(4):
            cbs = self._mismatch_callbacks()
            cbs[idx] = None
            self.assertRaises(TypeError, xmlsec.register_callbacks, *cbs)

    def test_sign_external_data_fails_on_read_callback_wrong_returns(self):
        xmlsec.register_callbacks(
            lambda filename: filename == b'cid:123456',
            lambda filename: BytesIO(b'<html><head/><body/></html>'),
            lambda bio, buf: None,
            lambda bio: bio.close(),
        )
        self._expect_sign_failure()
