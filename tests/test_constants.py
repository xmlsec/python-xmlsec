"""Test constants from :mod:`xmlsec.constants` module."""

import xmlsec
from hypothesis import given, strategies


def _constants(typename):
    return list(
        sorted(
            (
                getattr(xmlsec.constants, name)
                for name in dir(xmlsec.constants)
                if type(getattr(xmlsec.constants, name)).__name__ == typename
            ),
            key=lambda t: t.name.lower(),
        )
    )


@given(transform=strategies.sampled_from(_constants('__Transform')))
def test_transform_str(transform):
    """Test string representation of ``xmlsec.constants.__Transform``."""
    assert str(transform) == '{}, {}'.format(transform.name, transform.href)


@given(transform=strategies.sampled_from(_constants('__Transform')))
def test_transform_repr(transform):
    """Test raw string representation of ``xmlsec.constants.__Transform``."""
    assert repr(transform) == '__Transform({!r}, {!r}, {})'.format(transform.name, transform.href, transform.usage)


@given(keydata=strategies.sampled_from(_constants('__KeyData')))
def test_keydata_str(keydata):
    """Test string representation of ``xmlsec.constants.__KeyData``."""
    assert str(keydata) == '{}, {}'.format(keydata.name, keydata.href)


@given(keydata=strategies.sampled_from(_constants('__KeyData')))
def test_keydata_repr(keydata):
    """Test raw string representation of ``xmlsec.constants.__KeyData``."""
    assert repr(keydata) == '__KeyData({!r}, {!r})'.format(keydata.name, keydata.href)
