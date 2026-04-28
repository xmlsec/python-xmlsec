def pytest_collection_modifyitems(items):
    """Put the module shutdown test last.

    xmlsec shutdown is process-final with OpenSSL cleanup introduced in
    xmlsec1 1.3.11, so no tests should use xmlsec after it runs.
    """

    def module_init_shutdown_tests_last(item):
        return int('test_xmlsec.py::TestModule::test_init_shutdown_module' in item.nodeid)

    items.sort(key=module_init_shutdown_tests_last)
