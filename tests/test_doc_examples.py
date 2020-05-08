"""Run tests over code examples in the documentation."""

import contextlib
import os
import runpy
import sys

import pytest

if sys.version_info >= (3, 4):
    from pathlib import Path
else:  # python2.7 compat
    from _pytest.pathlib import Path


examples_dir = Path(__file__, '../../doc/source/examples').resolve()
examples = sorted(examples_dir.glob('*.py'))


@contextlib.contextmanager
def cd(where_to):
    """
    Temporarily change the working directory.

    Restore the current working dir after exiting the context.
    """
    curr = Path.cwd()
    try:
        os.chdir(str(where_to))
        yield
    finally:
        os.chdir(str(curr))


@pytest.mark.parametrize('example', examples, ids=lambda p: p.name)
def test_doc_example(example):
    """
    Verify example scripts included in the docs are up to date.

    Execute each script in :file:`docs/source/examples`,
    not raising any errors is good enough.
    """
    with cd(example.parent):
        runpy.run_path(str(example))
