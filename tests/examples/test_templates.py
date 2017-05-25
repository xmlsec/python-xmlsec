import xmlsec
from .base import parse_xml
from lxml import etree


def _check_transform_add_custom_c14n_inclusive_namespaces(prefixes, expected):
    template = parse_xml('sign2-doc.xml')
    assert template is not None

    # Create a signature template for RSA-SHA1 enveloped signature.
    signature_node = xmlsec.template.create(template, xmlsec.Transform.EXCL_C14N, xmlsec.Transform.RSA_SHA1)
    assert signature_node is not None

    # Add the <ds:Signature/> node to the document.
    template.append(signature_node)

    # Add the <ds:Reference/> node to the signature template.
    ref = xmlsec.template.add_reference(signature_node, xmlsec.Transform.SHA1)

    # Add the enveloped transform descriptor.
    transform = xmlsec.template.add_transform(ref, xmlsec.Transform.ENVELOPED)
    assert transform is not None

    xmlsec.template.transform_add_c14n_inclusive_namespaces(transform, prefixes)
    ins = xmlsec.tree.find_child(transform, "InclusiveNamespaces", xmlsec.constants.NsExcC14N)
    assert ins is not None
    assert expected == ins.get("PrefixList")


def test_transform_add_custom_c14n_inclusive_namespaces():
    _check_transform_add_custom_c14n_inclusive_namespaces(["ns1", "ns2"], "ns1 ns2")


def test_transform_add_default_c14n_inclusive_namespaces():
    _check_transform_add_custom_c14n_inclusive_namespaces("default", "default")
