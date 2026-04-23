import subprocess
import sys

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

    def test_interpreter_exit_with_live_xmlsec_objects(self):
        key_path = self.path('rsakey.pem')
        script = f"""
import xmlsec

key = xmlsec.Key.from_file({key_path!r}, format=xmlsec.constants.KeyDataFormatPem)
ctx = xmlsec.SignatureContext()
ctx.key = key
"""
        proc = subprocess.run([sys.executable, '-c', script], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
