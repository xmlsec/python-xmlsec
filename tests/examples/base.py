from os import path
from lxml import etree

BASE_DIR = path.dirname(__file__)


def parse_xml(name):
    return etree.parse(path.join(BASE_DIR, name)).getroot()


def compare(name, result):
    # Parse the expected file.
    xml = parse_xml(name)

    # Stringify the root, <Envelope/> nodes of the two documents.
    expected_text = etree.tostring(xml, pretty_print=False)
    result_text = etree.tostring(result, pretty_print=False)

    # Compare the results.
    assert expected_text == result_text

