import xmlsec
from tests import base
from xmlsec import constants as consts

KEY_URL = "pkcs11;pkcs11:token=test;object=test;pin-value=secret1"


def setUpModule():
    from tests import softhsm_setup

    softhsm_setup.setup()


def tearDownModule():
    from tests import softhsm_setup

    softhsm_setup.teardown()


class TestKeys(base.TestMemoryLeaks):
    def test_del_key(self):
        ctx = xmlsec.SignatureContext(manager=xmlsec.KeysManager())
        ctx.key = xmlsec.Key.from_engine(KEY_URL)
        del ctx.key
        self.assertIsNone(ctx.key)

    def test_set_key(self):
        ctx = xmlsec.SignatureContext(manager=xmlsec.KeysManager())
        ctx.key = xmlsec.Key.from_engine(KEY_URL)
        self.assertIsNotNone(ctx.key)

    def test_sign_bad_args(self):
        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_engine(KEY_URL)
        with self.assertRaises(TypeError):
            ctx.sign('')

    def test_sign_fail(self):
        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_engine(KEY_URL)
        with self.assertRaisesRegex(xmlsec.Error, 'failed to sign'):
            ctx.sign(self.load_xml('sign1-in.xml'))

    def test_sign_case1(self):
        """Should sign a pre-constructed template file using a key from a pkcs11 engine."""
        root = self.load_xml("sign1-in.xml")
        sign = xmlsec.tree.find_node(root, consts.NodeSignature)
        self.assertIsNotNone(sign)

        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_engine(KEY_URL)
        self.assertIsNotNone(ctx.key)
        ctx.key.name = 'rsakey.pem'
        self.assertEqual("rsakey.pem", ctx.key.name)

        ctx.sign(sign)
        self.assertEqual(self.load_xml("sign1-out.xml"), root)
