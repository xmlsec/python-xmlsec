# Decoupling lxml and xmlsec across libxml2 (#356)

`python-xmlsec` glues together two libraries that both build on **libxml2**:
lxml (the tree the user edits) and xmlsec1 (the C library that signs/encrypts).
Historically the extension reached into an lxml `_Element` for its raw
`xmlNodePtr` and handed it to xmlsec1. That is only safe when both libraries
link the *same* libxml2 at runtime — and they often don't (lxml wheels bundle
their own). Mixing two libxml2 builds on one tree corrupts memory: segfaults,
double-frees, wrong signatures
([#356](https://github.com/xmlsec/python-xmlsec/issues/356)). The only guard
was refusing to import on a version mismatch (#283).

## The fix: shadow copies

Never share nodes; share **bytes**. Each xmlsec call runs on a private,
throwaway copy of the element ("shadow") owned by *our* libxml2, and the
change it makes is reflected back into the live lxml tree afterwards — again
via bytes. Implemented as one pair of helpers in [src/lxml.c](src/lxml.c)
(contract in [src/lxml.h](src/lxml.h)); converting a function is four lines,
with no per-function callback or context struct:

```c
PyXmlSec_LxmlShadow shadow;
if (PyXmlSec_LxmlShadowBegin(&shadow, node) < 0) goto ON_FAIL;      // lxml → bytes → our copy
Py_BEGIN_ALLOW_THREADS;
res = xmlSecTmplSignatureAddReference(shadow.root, ...);            // xmlsec mutates the copy
Py_END_ALLOW_THREADS;
result = PyXmlSec_LxmlShadowEnd(&shadow, res, "cannot add reference."); // reflect back, return lxml node
```

`Begin` serializes the element with lxml's own `etree.tostring` and re-parses
the bytes with `xmlReadMemory`, tagging every pre-existing node through the
libxml2 `_private` field. `End` walks up from `res` to find the topmost
untagged (= new) node and reflects generically, covering every shape in the
`xmlSecTmpl*` family:

- **plain add** (`add_reference`): the new subtree is grafted into the live
  tree at the same position, located by child-index path.
- **intermediate ancestors** (`add_transform` creating `<Transforms>` around
  the `<Transform>`): the *topmost* new node is grafted; the returned element
  is the descendant matching `res`.
- **find-or-create** (`ensure_key_info`): nothing new in the tree — the
  existing live element is returned, plus any attributes the call set (`Id`).

Two serialization details are load-bearing for byte-identical signatures:

- `End` dumps the **whole** mutated copy (`xmlDocDumpMemory`), not just the new
  node, so ancestor-declared namespaces (dsig on `<Signature>`) and xmlsec's
  `"\n"` formatting siblings survive the lxml re-parse with no manual fix-up;
  the new node's tail travels with it through `insert()`.
- xmlsec may also emit a `"\n"` *before* the new node (`xmlSecAddChild` /
  `AddNextSibling` / `AddPrevSibling`); `End` mirrors that one text slot
  (parent `.text` or previous sibling `.tail`) from the copy.

Child indices count exactly the node types lxml exposes as children (elements,
comments, PIs, entity refs), so paths recorded on the raw copy resolve
identically through lxml's `__getitem__`/`insert`. `End` assumes the xmlsec
call mutates at most one place in the tree — true for all `xmlSecTmpl*`
functions. Whole-document operations (`sign`, `encrypt`) mutate many places
and will need a different reflect step on top of the same Begin machinery.

> The shadow decouples *lxml* from xmlsec. The extension and `libxmlsec1`
> must still share one libxml2 (wheels/static builds guarantee this).

## Building & validating under a real mismatch (macOS / homebrew)

lxml wheels bundle libxml2; build the extension against homebrew's (which
libxmlsec1 links) so only lxml differs — the true #356 scenario. Watch the
three-way trap: the linker prefers the SDK stub `/usr/lib/libxml2.2.dylib`,
so rewrite the runtime dependency after building:

```sh
rm -rf build/ src/xmlsec.cpython-*-darwin.so
PKG_CONFIG_PATH=/opt/homebrew/opt/libxml2/lib/pkgconfig \
  python setup.py build_ext --inplace --force
install_name_tool -change /usr/lib/libxml2.2.dylib \
  /opt/homebrew/opt/libxml2/lib/libxml2.16.dylib src/xmlsec.cpython-*-darwin.so

# verify the mismatch is real, then run the suite under it
PYXMLSEC_SKIP_VERSION_CHECK=1 PYTHONPATH=src python -c \
  "import xmlsec; from lxml import etree; \
   print('lxml', etree.LIBXML_VERSION, 'xmlsec', xmlsec.get_libxml_version())"
PYXMLSEC_SKIP_VERSION_CHECK=1 PYTHONPATH=src python -m pytest tests/
```

`PYXMLSEC_SKIP_VERSION_CHECK` bypasses the import-time mismatch guard. It
exists to exercise the shadow paths; it is **unsafe** for every operation
still on the raw-node path, so keep it off in normal use. The guard can only
be relaxed once all node-passing paths are converted.

## Status

- ✅ `template.add_reference`, `template.add_transform`,
  `template.ensure_key_info` — one per reflect shape. Validated under a real
  2.14 ↔ 2.15 mismatch: full suite green, 10k-iteration loop with no crash,
  no leak, byte-identical output.
- ⬜ Rest of `src/template.c` — mechanical: the four-line pattern above.
- ⬜ `src/ds.c` (sign/verify), `src/enc.c` (encrypt/decrypt), `src/tree.c` —
  need a whole-document reflect strategy.
