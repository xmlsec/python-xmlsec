import subprocess
import sys
import unittest
from pathlib import Path

import xmlsec
from tests import base


class TestModule(base.TestMemoryLeaks):
    def test_reinitialize_module(self):
        """This test doesn't explicitly verify anything, but will be invoked first in the suite.

        So if the subsequent tests don't fail, we know that the ``init()``/``shutdown()``
        function pair doesn't break anything.
        """
        xmlsec.shutdown()
        xmlsec.init()


class TestInterpreterShutdown(unittest.TestCase):
    def test_interpreter_exit_with_live_xmlsec_objects(self):
        key_path = Path(__file__).with_name('data') / 'rsakey.pem'
        script = f"""
import xmlsec

key = xmlsec.Key.from_file({str(key_path)!r}, format=xmlsec.constants.KeyDataFormatPem)
ctx = xmlsec.SignatureContext()
ctx.key = key
"""
        proc = subprocess.run([sys.executable, '-c', script], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_reinitialize_module_preserves_constants(self):
        script = """
import xmlsec

transform = xmlsec.constants.TransformExclC14N
keydata = xmlsec.constants.KeyDataAes

xmlsec.shutdown()
xmlsec.init()

assert transform.name == "exc-c14n"
assert keydata.name == "aes"
"""
        proc = subprocess.run([sys.executable, '-c', script], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
