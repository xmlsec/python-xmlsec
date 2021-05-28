import copy
import tempfile

import xmlsec
from tests import base

consts = xmlsec.constants


class TestKeys(base.TestMemoryLeaks):
    def test_key_from_memory(self):
        key = xmlsec.Key.from_memory(self.load("rsakey.pem"), format=consts.KeyDataFormatPem)
        self.assertIsNotNone(key)

    def test_key_from_memory_with_bad_args(self):
        with self.assertRaises(TypeError):
            xmlsec.Key.from_memory(1, format="")

    def test_key_from_memory_invalid_data(self):
        with self.assertRaisesRegex(xmlsec.Error, '.*cannot load key.*'):
            xmlsec.Key.from_memory(b'foo', format=consts.KeyDataFormatPem)

    def test_key_from_file(self):
        key = xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem)
        self.assertIsNotNone(key)

    def test_key_from_file_with_bad_args(self):
        with self.assertRaises(TypeError):
            xmlsec.Key.from_file(1, format="")

    def test_key_from_invalid_file(self):
        with self.assertRaisesRegex(xmlsec.Error, '.*cannot read key.*'):
            with tempfile.NamedTemporaryFile() as tmpfile:
                tmpfile.write(b'foo')
                xmlsec.Key.from_file(tmpfile.name, format=consts.KeyDataFormatPem)

    def test_key_from_fileobj(self):
        with open(self.path("rsakey.pem"), "rb") as fobj:
            key = xmlsec.Key.from_file(fobj, format=consts.KeyDataFormatPem)
        self.assertIsNotNone(key)

    def test_key_from_invalid_fileobj(self):
        with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
            tmpfile.write(b'foo')
        with self.assertRaisesRegex(xmlsec.Error, '.*cannot read key.*'), open(tmpfile.name) as fp:
            xmlsec.Key.from_file(fp, format=consts.KeyDataFormatPem)

    def test_generate(self):
        key = xmlsec.Key.generate(klass=consts.KeyDataAes, size=256, type=consts.KeyDataTypeSession)
        self.assertIsNotNone(key)

    def test_generate_with_bad_args(self):
        with self.assertRaises(TypeError):
            xmlsec.Key.generate(klass="", size="", type="")

    def test_generate_invalid_size(self):
        with self.assertRaisesRegex(xmlsec.Error, '.*cannot generate key.*'):
            xmlsec.Key.generate(klass=consts.KeyDataAes, size=0, type=consts.KeyDataTypeSession)

    def test_from_binary_file(self):
        key = xmlsec.Key.from_binary_file(klass=consts.KeyDataDes, filename=self.path("deskey.bin"))
        self.assertIsNotNone(key)

    def test_from_binary_file_with_bad_args(self):
        with self.assertRaises(TypeError):
            xmlsec.Key.from_binary_file(klass="", filename=1)

    def test_from_invalid_binary_file(self):
        with self.assertRaisesRegex(xmlsec.Error, '.*cannot read key.*'):
            with tempfile.NamedTemporaryFile() as tmpfile:
                tmpfile.write(b'foo')
                xmlsec.Key.from_binary_file(klass=consts.KeyDataDes, filename=tmpfile.name)

    def test_from_binary_data(self):
        key = xmlsec.Key.from_binary_data(klass=consts.KeyDataDes, data=self.load("deskey.bin"))
        self.assertIsNotNone(key)

    def test_from_binary_data_with_bad_args(self):
        with self.assertRaises(TypeError):
            xmlsec.Key.from_binary_data(klass="", data=1)

    def test_from_invalid_binary_data(self):
        with self.assertRaisesRegex(xmlsec.Error, '.*cannot read key.*'):
            xmlsec.Key.from_binary_data(klass=consts.KeyDataDes, data=b'')

    def test_load_cert_from_file(self):
        key = xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem)
        self.assertIsNotNone(key)
        key.load_cert_from_file(self.path("rsacert.pem"), format=consts.KeyDataFormatPem)

    def test_load_cert_from_file_with_bad_args(self):
        key = xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem)
        self.assertIsNotNone(key)
        with self.assertRaises(TypeError):
            key.load_cert_from_file(1, format="")

    def test_load_cert_from_invalid_file(self):
        key = xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem)
        self.assertIsNotNone(key)
        with self.assertRaisesRegex(xmlsec.Error, '.*cannot load cert.*'):
            with tempfile.NamedTemporaryFile() as tmpfile:
                tmpfile.write(b'foo')
                key.load_cert_from_file(tmpfile.name, format=consts.KeyDataFormatPem)

    def test_load_cert_from_fileobj(self):
        key = xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem)
        self.assertIsNotNone(key)
        with open(self.path("rsacert.pem"), "rb") as fobj:
            key.load_cert_from_file(fobj, format=consts.KeyDataFormatPem)

    def test_load_cert_from_fileobj_with_bad_args(self):
        key = xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem)
        self.assertIsNotNone(key)
        with self.assertRaises(TypeError), open(self.path("rsacert.pem"), "rb") as fobj:
            key.load_cert_from_file(fobj, format='')

    def test_load_cert_from_invalid_fileobj(self):
        key = xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem)
        self.assertIsNotNone(key)
        with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
            tmpfile.write(b'foo')
        with self.assertRaisesRegex(xmlsec.Error, '.*cannot load cert.*'), open(tmpfile.name) as fp:
            key.load_cert_from_file(fp, format=consts.KeyDataFormatPem)

    def test_load_cert_from_memory(self):
        key = xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem)
        self.assertIsNotNone(key)
        key.load_cert_from_memory(self.load("rsacert.pem"), format=consts.KeyDataFormatPem)

    def test_load_cert_from_memory_with_bad_args(self):
        key = xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem)
        self.assertIsNotNone(key)
        with self.assertRaises(TypeError):
            key.load_cert_from_memory(1, format="")

    def test_load_cert_from_memory_invalid_data(self):
        key = xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem)
        self.assertIsNotNone(key)
        with self.assertRaisesRegex(xmlsec.Error, '.*cannot load cert.*'):
            key.load_cert_from_memory(b'', format=consts.KeyDataFormatPem)

    def test_get_name(self):
        key = xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem)
        self.assertIsNone(key.name)

    def test_get_name_invalid_key(self):
        key = xmlsec.Key()
        with self.assertRaisesRegex(ValueError, 'key is not ready'):
            key.name

    def test_del_name(self):
        key = xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem)
        key.name = "rsakey"
        del key.name
        self.assertIsNone(key.name)

    def test_set_name(self):
        key = xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem)
        key.name = "rsakey"
        self.assertEqual("rsakey", key.name)

    def test_set_name_invalid_key(self):
        key = xmlsec.Key()
        with self.assertRaisesRegex(ValueError, 'key is not ready'):
            key.name = 'foo'

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
        with self.assertRaisesRegex(xmlsec.Error, '.*cannot load cert.*'):
            with tempfile.NamedTemporaryFile() as tmpfile:
                tmpfile.write(b'foo')
                mngr.load_cert(tmpfile.name, format=consts.KeyDataFormatPem, type=consts.KeyDataTypeTrusted)

    def test_load_invalid_cert(self):
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

    def test_load_cert_from_memory_invalid_data(self):
        mngr = xmlsec.KeysManager()
        mngr.add_key(xmlsec.Key.from_file(self.path("rsakey.pem"), format=consts.KeyDataFormatPem))
        with self.assertRaisesRegex(xmlsec.Error, '.*cannot load cert.*'):
            mngr.load_cert_from_memory(b'', format=consts.KeyDataFormatPem, type=consts.KeyDataTypeTrusted)

    def test_load_invalid_key(self):
        mngr = xmlsec.KeysManager()
        with self.assertRaises(ValueError):
            mngr.add_key(xmlsec.Key())
