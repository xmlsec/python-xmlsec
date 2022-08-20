"""Test type stubs for correctness where possible."""

import os

import pytest

import xmlsec

black = pytest.importorskip('black')


constants_stub_header = """
import sys
from typing import NamedTuple

if sys.version_info >= (3, 8):
    from typing import Final
else:
    from typing_extensions import Final

class __KeyData(NamedTuple):  # __KeyData type
    href: str
    name: str

class __KeyDataNoHref(NamedTuple):  # __KeyData type
    href: None
    name: str

class __Transform(NamedTuple):  # __Transform type
    href: str
    name: str
    usage: int

class __TransformNoHref(NamedTuple):  # __Transform type
    href: None
    name: str
    usage: int

"""


def gen_constants_stub():
    """
    Generate contents of the file:`xmlsec/constants.pyi`.

    Simply load all constants at runtime,
    generate appropriate type hint for each constant type.
    """

    def process_constant(name):
        """Generate line in stub file for constant name."""
        obj = getattr(xmlsec.constants, name)
        type_name = type(obj).__name__
        if type_name in ('__KeyData', '__Transform') and obj.href is None:
            type_name += 'NoHref'
        return '{name}: Final[{type_name}]'.format(name=name, type_name=type_name)

    names = list(sorted(name for name in dir(xmlsec.constants) if not name.startswith('__')))
    lines = [process_constant(name) for name in names]
    return constants_stub_header + os.linesep.join(lines)


def test_xmlsec_constants_stub(request):
    """
    Generate the stub file for :mod:`xmlsec.constants` from existing code.

    Compare it against the existing stub :file:`xmlsec/constants.pyi`.
    """
    stub = request.config.rootpath / 'src' / 'xmlsec' / 'constants.pyi'
    mode = black.FileMode(target_versions={black.TargetVersion.PY39}, line_length=130, is_pyi=True, string_normalization=False)
    formatted = black.format_file_contents(gen_constants_stub(), fast=False, mode=mode)
    assert formatted == stub.read_text()
