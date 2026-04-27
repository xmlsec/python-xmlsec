import xmlsec
from tests import base


class TestModule(base.TestMemoryLeaks):
    iterations = 0

    def test_initialize_module(self):
        """Check explicit initialization before final module shutdown.

        This test is invoked last because shutdown is process-final: since
        xmlsec1 1.3.11, its OpenSSL backend may call OPENSSL_cleanup(), after
        which OpenSSL cannot be reinitialized in the same process.
        """
        xmlsec.init()
        xmlsec.shutdown()
