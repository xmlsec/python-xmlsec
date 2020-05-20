# -*- coding: utf-8 -*-

import sys
import urllib.request

import lxml

from docutils.nodes import reference
from packaging.version import parse
from sphinx.errors import ExtensionError

if sys.version_info >= (3, 8):
    from importlib import metadata as importlib_metadata
else:
    import importlib_metadata


extensions = ['sphinx.ext.autodoc', 'sphinx.ext.viewcode', 'sphinx.ext.intersphinx']

intersphinx_mapping = {'python': ('https://docs.python.org/3/', None)}

templates_path = ['_templates']
source_suffix = '.rst'
master_doc = 'index'

project = u'python-xmlsec'
copyright = u'2020, Oleg Hoefling <oleg.hoefling@gmail.com>'
author = u'Bulat Gaifullin <gaifullinbf@gmail.com>'
release = importlib_metadata.version('xmlsec')
parsed = parse(release)
version = '{}.{}'.format(parsed.major, parsed.minor)

language = None
exclude_patterns = []
pygments_style = 'sphinx'
todo_include_todos = False

html_theme = 'nature'
html_static_path = []
htmlhelp_basename = 'python-xmlsecdoc'

latex_elements = {}
latex_documents = [
    (
        master_doc,
        'python-xmlsec.tex',
        u'python-xmlsec Documentation',
        u'Bulat Gaifullin \\textless{}gaifullinbf@gmail.com\\textgreater{}',
        'manual',
    )
]

man_pages = [(master_doc, 'python-xmlsec', u'python-xmlsec Documentation', [author], 1)]

texinfo_documents = [
    (
        master_doc,
        'python-xmlsec',
        u'python-xmlsec Documentation',
        author,
        'python-xmlsec',
        'One line description of project.',
        'Miscellaneous',
    )
]

autodoc_member_order = 'groupwise'
autodoc_docstring_signature = True

# LXML crossref'ing stuff:
# LXML doesn't have an intersphinx docs,
# so we link to lxml.etree._Element explicitly
lxml_element_cls_doc_uri = 'https://lxml.de/api/lxml.etree._Element-class.html'


def lxml_element_doc_reference(app, env, node, contnode):
    """
    Handle a missing reference only if it is a ``lxml.etree._Element`` ref.

    We handle only :class:`lxml.etree._Element` and :class:`~lxml.etree._Element` nodes.
    """
    if (
        node.get('reftype', None) == 'class'
        and node.get('reftarget', None) == 'lxml.etree._Element'
        and contnode.astext() in ('lxml.etree._Element', '_Element')
    ):
        reftitle = '(in lxml v{})'.format(lxml.__version__)
        newnode = reference('', '', internal=False, refuri=lxml_element_cls_doc_uri, reftitle=reftitle)
        newnode.append(contnode)
        return newnode


def setup(app):
    # first, check whether the doc URL is still valid
    if urllib.request.urlopen(lxml_element_cls_doc_uri).getcode() != 200:
        raise ExtensionError('URL to `lxml.etree._Element` docs is not accesible.')
    app.connect('missing-reference', lxml_element_doc_reference)
