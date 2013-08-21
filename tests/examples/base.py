from os import path
import xmlsec
from lxml import etree

BASE_DIR = path.dirname(__file__)


def parse_xml(name):
    return etree.parse(path.join(BASE_DIR, name)).getroot()
