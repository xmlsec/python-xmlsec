import xmlsec
from tests import base


class TestModule(base.TestMemoryLeaks):
    def test_reinitialize_module(self):
        """
        This doesn't explicitly test anything, but will
        be invoked first in the suite, so if the subsequent
        tests don't fail, we know that the ``init()``/``shutdown()``
        function pair doesn't break anything.
        """
        xmlsec.shutdown()
        xmlsec.init()
