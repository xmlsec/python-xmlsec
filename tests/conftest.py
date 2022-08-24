def pytest_collection_modifyitems(items):
    """
    Put the module init test first.

    This way, we implicitly check whether any subsequent test fails because of module reinitialization.
    """

    def module_init_tests_first(item):
        return int('test_xmlsec.py::TestModule::test_reinitialize_module' not in item.nodeid)

    items.sort(key=module_init_tests_first)
