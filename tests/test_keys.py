from tests import base

import copy

import xmlsec


consts = xmlsec.constants


class TestKeys(base.TestMemoryLeaks):
    def test_key_from_memory(self):
        key = xmlsec.Key.from_memory(self.load("rsakey.pem"), format=consts.KeyDataFormatPem)
        self.assertIsNotNone(key)

    def test_key_from_memory_with_bad_args(self):
        with self.assertRaises(TypeError):
            xmlsec.Key.from_memory(1, format="")

    def test_key_from_file(self):
        key = xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem)
        self.assertIsNotNone(key)

    def test_key_from_file_with_bad_args(self):
        with self.assertRaises(TypeError):
            xmlsec.Key.from_file(1, format="")

    def test_key_from_fileobj(self):
        with open(self.path("rsakey.pem"), "rb") as fobj:
            key = xmlsec.Key.from_file(fobj, format=consts.KeyDataFormatPem)
        self.assertIsNotNone(key)

    def test_generate(self):
        key = xmlsec.Key.generate(klass=consts.KeyDataAes, size=256, type=consts.KeyDataTypeSession)
        self.assertIsNotNone(key)

    def test_generate_with_bad_args(self):
        with self.assertRaises(TypeError):
            xmlsec.Key.generate(klass="", size="", type="")

    def test_from_binary_file(self):
        key = xmlsec.Key.from_binary_file(klass=consts.KeyDataDes, filename=self.path("deskey.bin"))
        self.assertIsNotNone(key)

    def test_from_binary_file_with_bad_args(self):
        with self.assertRaises(TypeError):
            xmlsec.Key.from_binary_file(klass="", filename=1)

    def test_from_binary_data(self):
        key = xmlsec.Key.from_binary_data(klass=consts.KeyDataDes, data=self.load("deskey.bin"))
        self.assertIsNotNone(key)

    def test_from_binary_data_with_bad_args(self):
        with self.assertRaises(TypeError):
            xmlsec.Key.from_binary_data(klass="", data=1)

    def test_load_cert_from_file(self):
        key = xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem)
        self.assertIsNotNone(key)
        key.load_cert_from_file(self.path("rsacert.pem"), format=consts.KeyDataFormatPem)

    def test_load_cert_from_file_with_bad_args(self):
        key = xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem)
        self.assertIsNotNone(key)
        with self.assertRaises(TypeError):
            key.load_cert_from_file(1, format="")

    def test_load_cert_from_fileobj(self):
        key = xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem)
        self.assertIsNotNone(key)
        with open(self.path("rsacert.pem"), "rb") as fobj:
            key.load_cert_from_file(fobj, format=consts.KeyDataFormatPem)

    def test_load_cert_from_memory(self):
        key = xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem)
        self.assertIsNotNone(key)
        key.load_cert_from_memory(self.load("rsacert.pem"), format=consts.KeyDataFormatPem)

    def test_load_cert_from_memory_with_bad_args(self):
        key = xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem)
        self.assertIsNotNone(key)
        with self.assertRaises(TypeError):
            key.load_cert_from_memory(1, format="")

    def test_name(self):
        key = xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem)
        self.assertIsNone(key.name)
        key.name = "rsakey"
        self.assertEqual("rsakey", key.name)

    def test_copy(self):
        key = xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem)
        key2 = copy.copy(key)
        del key
        key2.load_cert_from_file(self.path("rsacert.pem"), format=consts.KeyDataFormatPem)


class TestKeysManager(base.TestMemoryLeaks):
    def test_add_key(self):
        key = xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem)
        mngr = xmlsec.KeysManager()
        mngr.add_key(key)

    def test_add_key_with_bad_args(self):
        mngr = xmlsec.KeysManager()
        with self.assertRaises(TypeError):
            mngr.add_key("")

    def test_load_cert(self):
        mngr = xmlsec.KeysManager()
        mngr.add_key(xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem))
        mngr.load_cert(self.path("rsacert.pem"), format=consts.KeyDataFormatPem, type=consts.KeyDataTypeTrusted)

    def test_load_cert_with_bad_args(self):
        mngr = xmlsec.KeysManager()
        mngr.add_key(xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem))
        with self.assertRaises(TypeError):
            mngr.load_cert(1, format="", type="")

    def test_load_cert_from_memory(self):
        mngr = xmlsec.KeysManager()
        mngr.add_key(xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem))
        mngr.load_cert_from_memory(self.load("rsacert.pem"), format=consts.KeyDataFormatPem, type=consts.KeyDataTypeTrusted)

    def test_load_cert_from_memory_with_bad_args(self):
        mngr = xmlsec.KeysManager()
        mngr.add_key(xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem))
        with self.assertRaises(TypeError):
            mngr.load_cert_from_memory(1, format="", type="")

    def test_load_invalid_key(self):
        mngr = xmlsec.KeysManager()
        with self.assertRaises(ValueError):
            mngr.add_key(xmlsec.Key())
