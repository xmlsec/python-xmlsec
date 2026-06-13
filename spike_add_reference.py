"""Focused validation for the serialized template.add_reference (issue #356).

Run under the REAL libxml2 mismatch on this box (lxml bundles a different
libxml2 than the system one xmlsec links). The input template is built purely
with lxml so we exercise only add_reference's new serialize/round-trip path,
not the still-unsafe create().
"""

from lxml import etree

import xmlsec

consts = xmlsec.constants

print('lxml  libxml2 :', etree.LIBXML_VERSION)
print('xmlsec libxml2:', xmlsec.get_libxml_version())
print('mismatch      :', etree.LIBXML_VERSION[:2] != tuple(xmlsec.get_libxml_version()[:2]))
print()

DSIG = consts.DSigNs

# A signature template skeleton, built with lxml (no xmlsec node creation).
SIGN_XML = (
    '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">'
    '<SignedInfo>'
    '<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
    '<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>'
    '</SignedInfo>'
    '<SignatureValue/>'
    '</Signature>'
)


def test_happy_path():
    sign = etree.fromstring(SIGN_XML)
    before = etree.tostring(sign)

    ref = xmlsec.template.add_reference(sign, consts.TransformSha1, id='Id', uri='URI', type='Type')

    # returned node carries the requested attributes
    assert ref.get('Id') == 'Id', ref.get('Id')
    assert ref.get('URI') == 'URI', ref.get('URI')
    assert ref.get('Type') == 'Type', ref.get('Type')
    assert ref.tag == '{%s}Reference' % DSIG, ref.tag

    # returned node is live and part of the original tree's SignedInfo
    si = sign.find('{%s}SignedInfo' % DSIG)
    assert ref in list(si), 'reference was not grafted into SignedInfo'
    assert ref.getparent() is si

    # DigestMethod algorithm preserved across the round-trip
    dm = ref.find('{%s}DigestMethod' % DSIG)
    assert dm is not None and dm.get('Algorithm') == consts.TransformSha1.href, etree.tostring(ref)

    print('happy path OK; input before vs whole tree after:')
    print('  before:', before.decode())
    print('  after :', etree.tostring(sign).decode())

    # the returned handle still drives the incremental builder (add_transform)
    trans = xmlsec.template.add_transform(ref, consts.TransformEnveloped)
    assert trans.tag == '{%s}Transform' % DSIG, trans.tag
    print('  +transform:', etree.tostring(ref).decode())


def test_multiple_references():
    sign = etree.fromstring(SIGN_XML)
    r1 = xmlsec.template.add_reference(sign, consts.TransformSha1, uri='#a')
    r2 = xmlsec.template.add_reference(sign, consts.TransformSha1, uri='#b')
    si = sign.find('{%s}SignedInfo' % DSIG)
    refs = si.findall('{%s}Reference' % DSIG)
    assert len(refs) == 2, len(refs)
    assert [r.get('URI') for r in refs] == ['#a', '#b'], [r.get('URI') for r in refs]
    assert refs[0] is r1 and refs[1] is r2
    print('multiple references OK:', etree.tostring(si).decode())


def test_fail_no_signed_info():
    try:
        xmlsec.template.add_reference(etree.Element('root'), consts.TransformSha1)
    except xmlsec.Error as exc:
        assert 'cannot add reference' in str(exc), exc
        print('failure path OK:', exc)
    else:
        raise AssertionError('expected xmlsec.Error for a node without SignedInfo')


def test_bad_args():
    for bad in [lambda: xmlsec.template.add_reference('', consts.TransformSha1),
                lambda: xmlsec.template.add_reference(etree.Element('root'), '')]:
        try:
            bad()
        except TypeError:
            pass
        else:
            raise AssertionError('expected TypeError')
    print('bad-args path OK')


if __name__ == '__main__':
    test_happy_path()
    print()
    test_multiple_references()
    print()
    test_fail_no_signed_info()
    test_bad_args()
    print('\nALL CHECKS PASSED')
