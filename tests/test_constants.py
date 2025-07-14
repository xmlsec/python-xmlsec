"""Test constants from :mod:`xmlsec.constants` module."""

import pytest

import xmlsec


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


@pytest.mark.parametrize('transform', _constants('__Transform'), ids=repr)
def test_transform_str(transform):
    """Test string representation of ``xmlsec.constants.__Transform``."""
    assert str(transform) == f'{transform.name}, {transform.href}'


@pytest.mark.parametrize('transform', _constants('__Transform'), ids=repr)
def test_transform_repr(transform):
    """Test raw string representation of ``xmlsec.constants.__Transform``."""
    assert repr(transform) == f'__Transform({transform.name!r}, {transform.href!r}, {transform.usage})'


@pytest.mark.parametrize('keydata', _constants('__KeyData'), ids=repr)
def test_keydata_str(keydata):
    """Test string representation of ``xmlsec.constants.__KeyData``."""
    assert str(keydata) == f'{keydata.name}, {keydata.href}'


@pytest.mark.parametrize('keydata', _constants('__KeyData'), ids=repr)
def test_keydata_repr(keydata):
    """Test raw string representation of ``xmlsec.constants.__KeyData``."""
    assert repr(keydata) == f'__KeyData({keydata.name!r}, {keydata.href!r})'
