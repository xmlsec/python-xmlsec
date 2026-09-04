"""Source-level guard for the shadow-copy invariants (issue #356).

The extension may hand lxml's raw libxml2 nodes to xmlsec only on the fast path, when both
link the same libxml2. ``developer.md`` describes the design; this module scans ``src/*.c`` and
checks the two rules that keep every binding on the shadow path whenever it is on:

1. every C function that accepts an lxml element (it uses ``PyXmlSec_LxmlElementConverter``)
   either runs its xmlsec call through a ``PyXmlSec_LxmlShadowBegin*`` helper, or is one of
   the dual-body functions in ``DUAL_BODY_FUNCTIONS``, which must consult
   ``PyXmlSec_LxmlShadowIsActive()`` before touching a raw node;
2. raw node access (``->_c_node`` / ``->_c_doc``) appears only inside the functions listed in
   ``RAW_ACCESS_ALLOWED``.

Comments and string literals are blanked first, so only real code counts for either rule.

Adding a function to either list is a deliberate design decision; see developer.md.
"""

import glob
import os
import re
import unittest
from collections.abc import Iterator

SRC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'src')

# Bindings with a raw body for the fast path and a shadow body behind IsActive().
DUAL_BODY_FUNCTIONS = frozenset(
    {
        'PyXmlSec_SignatureContextRegisterId',
        'PyXmlSec_TreeAddIds',
        'PyXmlSec_EncryptionContextEncryptXml',
        'PyXmlSec_EncryptionContextDecrypt',
    }
)

# Functions allowed to dereference lxml's raw node/document pointers: the dual bodies above
# and the fast-path branches of the shadow helpers.
RAW_ACCESS_ALLOWED = DUAL_BODY_FUNCTIONS | frozenset(
    {
        'PyXmlSec_LxmlShadowBegin',
        'PyXmlSec_LxmlShadowBeginDoc',
        'PyXmlSec_LxmlShadowBeginNewDoc',
        'PyXmlSec_LxmlShadowEnd',
        'PyXmlSec_LxmlShadowEndFind',
    }
)

# A function definition at column 0: `[static ]<type>[*] PyXmlSec_<Name>(`; prototypes end in ';'.
FUNCTION_DEF = re.compile(r'^(?:static\s+)?[\w\s]+?\**\s*\**(PyXmlSec_\w+)\s*\(')
RAW_ACCESS = re.compile(r'->_c_(?:node|doc)\b')
BEGIN_CALL = re.compile(r'\bPyXmlSec_LxmlShadowBegin\w*\s*\(')
CONVERTER = 'PyXmlSec_LxmlElementConverter'
IS_ACTIVE = 'PyXmlSec_LxmlShadowIsActive()'


def _blank_comments_and_literals(source: str) -> str:
    """Blanks the body of every comment and string/char literal, keeping lines and columns.

    The checks below match raw text, so without this a comment explaining ``->_c_node`` or
    naming a ``PyXmlSec_LxmlShadowBegin*`` helper would read as the code itself — a binding
    could lose its guard and still pass because of the comment describing it.
    """
    out: list[str] = []
    i, n = 0, len(source)
    while i < n:
        pair = source[i : i + 2]
        if pair in ('//', '/*'):
            end = source.find('\n', i) if pair == '//' else source.find('*/', i + 2) + 2
            if end < 2:  # unterminated: the rest of the file is comment
                end = n
            out.append(''.join('\n' if c == '\n' else ' ' for c in source[i:end]))
            i = end
        elif source[i] in '"\'':
            quote = source[i]
            out.append(quote)
            i += 1
            while i < n and source[i] != quote:
                step = 2 if source[i] == '\\' and i + 1 < n else 1
                out.append(''.join('\n' if c == '\n' else ' ' for c in source[i : i + step]))
                i += step
            if i < n:
                out.append(quote)
                i += 1
        else:
            out.append(source[i])
            i += 1
    return ''.join(out)


def _functions(source: str) -> Iterator[tuple[str, list[str]]]:
    """Yields (name, [lines]) for every PyXmlSec_* function defined in the C source."""
    name = None
    body: list[str] = []
    for line in _blank_comments_and_literals(source).splitlines():
        match = FUNCTION_DEF.match(line)
        if match and not line.rstrip().endswith(';'):
            if name is not None:
                yield name, body
            name, body = match.group(1), []
        elif name is not None:
            body.append(line)
    if name is not None:
        yield name, body


def violations(source: str, filename: str = '<source>') -> list[str]:
    """Returns a description of every rule violation in one C source file."""
    found: list[str] = []
    for name, body in _functions(source):
        where = f'{filename}:{name}'
        raw_lines = [i for i, line in enumerate(body) if RAW_ACCESS.search(line)]
        active_lines = [i for i, line in enumerate(body) if IS_ACTIVE in line]
        takes_element = any(CONVERTER in line for line in body)
        begins = any(BEGIN_CALL.search(line) for line in body)

        if name in DUAL_BODY_FUNCTIONS:
            if not active_lines:
                found.append(f'{where}: dual-body function never consults {IS_ACTIVE}')
            elif raw_lines and raw_lines[0] < active_lines[0]:
                found.append(f'{where}: raw node access before {IS_ACTIVE}')
        elif takes_element and not begins:
            found.append(f'{where}: takes an lxml element but never calls a PyXmlSec_LxmlShadowBegin* helper')

        if raw_lines and name not in RAW_ACCESS_ALLOWED:
            found.append(f'{where}: raw node access (->_c_node / ->_c_doc) outside the allowed functions')
    return found


@unittest.skipUnless(os.path.isdir(SRC_DIR), 'C sources not available (installed package)')
class TestShadowAudit(unittest.TestCase):
    def sources(self) -> Iterator[tuple[str, str]]:
        files = sorted(glob.glob(os.path.join(SRC_DIR, '*.c')))
        self.assertTrue(files, f'no C sources under {SRC_DIR}')
        for path in files:
            with open(path, encoding='utf-8') as f:
                yield os.path.basename(path), f.read()

    def test_scanner_sees_the_bindings(self) -> None:
        # guards the scanner itself: a broken regex would make the sources look clean
        names: set[str] = set()
        raw_files: set[str] = set()
        for filename, source in self.sources():
            for name, body in _functions(source):
                if any(CONVERTER in line for line in body):
                    names.add(name)
                if any(RAW_ACCESS.search(line) for line in body):
                    raw_files.add(filename)
        self.assertGreaterEqual(len(names), 30)
        self.assertTrue(names.issuperset({'PyXmlSec_TemplateAddReference', 'PyXmlSec_SignatureContextSign'}))
        self.assertTrue(names.issuperset(DUAL_BODY_FUNCTIONS))
        self.assertEqual({'ds.c', 'enc.c', 'lxml.c', 'tree.c'}, raw_files)

    def test_every_binding_goes_through_the_shadow(self) -> None:
        found: list[str] = []
        for filename, source in self.sources():
            found.extend(violations(source, filename))
        self.assertEqual([], found, '\n'.join(found))

    def test_checker_flags_a_raw_binding(self) -> None:
        bad = (
            'static PyObject* PyXmlSec_Bad(PyObject* self, PyObject* args) {\n'
            '    PyXmlSec_LxmlElementPtr node = NULL;\n'
            '    if (!PyArg_ParseTuple(args, "O&:bad", PyXmlSec_LxmlElementConverter, &node)) return NULL;\n'
            '    return (PyObject*)PyXmlSec_elementFactory(node->_doc, xmlSecFindChild(node->_c_node, NULL, NULL));\n'
            '}\n'
        )
        found = violations(bad, 'bad.c')
        self.assertEqual(2, len(found), found)
        self.assertIn('never calls a PyXmlSec_LxmlShadowBegin*', found[0])
        self.assertIn('outside the allowed functions', found[1])

    def test_checker_reads_code_not_comments(self) -> None:
        # the guard named in a comment does not guard anything, and a mention in a literal is not access
        bad = (
            'static PyObject* PyXmlSec_Bad(PyObject* self, PyObject* args) {\n'
            '    PyXmlSec_LxmlElementPtr node = NULL;\n'
            '    if (!PyArg_ParseTuple(args, "O&:bad", PyXmlSec_LxmlElementConverter, &node)) return NULL;\n'
            '    // PyXmlSec_LxmlShadowBegin(&shadow, node, "cannot copy.") belongs here\n'
            '    /* and node->_c_node would then be shadow.root */\n'
            '    PyErr_SetString(PyXmlSec_Error, "node->_c_node is not for xmlsec.");\n'
            '    return NULL;\n'
            '}\n'
        )
        found = violations(bad, 'bad.c')
        self.assertEqual(1, len(found), found)
        self.assertIn('never calls a PyXmlSec_LxmlShadowBegin*', found[0])

    def test_checker_flags_raw_access_before_the_switch(self) -> None:
        bad = (
            'static PyObject* PyXmlSec_TreeAddIds(PyObject* self, PyObject* args) {\n'
            '    PyXmlSec_LxmlElementPtr node = NULL;\n'
            '    if (!PyArg_ParseTuple(args, "O&:add_ids", PyXmlSec_LxmlElementConverter, &node)) return NULL;\n'
            '    xmlDocPtr doc = node->_doc->_c_doc;\n'
            '    if (PyXmlSec_LxmlShadowIsActive()) Py_RETURN_NONE;\n'
            '    return NULL;\n'
            '}\n'
        )
        found = violations(bad, 'bad.c')
        self.assertEqual(1, len(found), found)
        self.assertIn('raw node access before', found[0])
