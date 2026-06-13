# CLAUDE.md — developer notes

This file is for anyone (human or AI) working on the C internals of
`python-xmlsec`. User-facing docs live in `doc/source/`. The focus here is the
libxml2 ABI work tracked in
[issue #356](https://github.com/xmlsec/python-xmlsec/issues/356).

For the design narrative — the before/after of the approach with code — see
[developer.md](developer.md). This file is the operational companion: build
commands, gotchas to remember, and the rollout checklist.

## What this project is

A CPython C extension (`src/*.c`) that bridges two libraries that both build on
**libxml2**:

- **lxml** — provides the XML tree the user manipulates in Python (`_Element`).
- **xmlsec1** (`libxmlsec1`) — the C library that signs/encrypts XML.

The extension takes lxml `_Element` objects, reaches into them for the raw
`xmlNodePtr` (`node->_c_node`) / `xmlDocPtr` (`node->_doc->_c_doc`), and hands
those pointers to `xmlsec1`.

## The ABI problem (#356)

That pointer-passing is only safe when **lxml and xmlsec1 link the *same*
libxml2 at runtime**. They often don't:

- lxml wheels bundle their own static libxml2.
- xmlsec is built against a system / homebrew / static libxml2.

When the two libxml2 versions differ, passing a node allocated by one to the
other mixes incompatible struct layouts and allocators → memory corruption,
double-frees, bogus signatures, and segfaults.

Historically the only mitigation was a hard refusal to import on mismatch (the
`"lxml & xmlsec libxml2 library version mismatch"` guard, issue #283, in
`PyXmlSec_InitLxmlModule` in [src/lxml.c](src/lxml.c)).

## The fix strategy: serialize across the boundary

Instead of passing raw pointers, round-trip through **serialized XML bytes**.
Bytes have no ABI; each library only ever touches nodes its *own* libxml2
allocated:

1. **lxml → bytes**: serialize the input element with lxml's own libxml2
   (`etree.tostring`). Input is never mutated by xmlsec.
2. **bytes → xmlsec node**: re-parse with xmlsec's libxml2 (`xmlReadMemory`).
3. Run the xmlsec operation on that fresh, xmlsec-owned node.
4. **xmlsec node → bytes → lxml**: serialize the result with xmlsec's libxml2
   (`xmlNodeDump`), re-parse with lxml (`etree.fromstring`), and graft it into
   the original lxml tree.

Only bytes cross between the two libxml2 worlds — never a pointer.

> **This decouples lxml from xmlsec, but it assumes the extension and
> `libxmlsec1` share one libxml2.** If *those two* disagree (e.g. the extension
> links system libxml2 while libxmlsec1 links homebrew's), step 3 still mixes
> allocators and crashes. See "Building & validating under a mismatch" below.

### Bridge helpers

Two small helpers in [src/lxml.c](src/lxml.c) (declared in
[src/lxml.h](src/lxml.h)) are the only sanctioned crossing points. They go
through lxml's Python API so the tree is always walked by lxml's libxml2:

- `PyXmlSec_LxmlElementToBytes(element)` → `etree.tostring(element, with_tail=False)`
- `PyXmlSec_LxmlElementFromBytes(data)` → `etree.fromstring(data)`

## Reference implementation: `template.add_reference`

`PyXmlSec_TemplateAddReference` in [src/template.c](src/template.c) is the first
function converted and the **template for converting the rest**. Read it
alongside this section. The flow:

1. `PyXmlSec_LxmlElementToBytes(node)` — serialize the `<Signature>` element.
2. `xmlReadMemory(...)` — parse into a throwaway xmlsec-owned `xmlDocPtr`.
3. `xmlSecTmplSignatureAddReference(xmlDocGetRootElement(doc), ...)` — xmlsec
   adds the `<Reference>` to the copy and returns it (`res`).
4. Reflect back: dump `res`, `PyXmlSec_LxmlElementFromBytes(...)`, then
   `find` the `SignedInfo` of the *original* node and `append` the new element.
5. Return the grafted lxml element (a live node in the user's tree, so the
   incremental builder — `add_transform(ref, ...)` — keeps working).

### Two non-obvious gotchas (the reason this took iterations)

These will recur in every function we convert, so they're worth understanding:

**(a) Namespaces are lost on a naive node dump.** `xmlNodeDump` of a subtree does
*not* emit namespace declarations that live on ancestors. The `<Reference>`
uses the dsig namespace declared up on `<Signature>`, so dumping it alone yields
`<Reference>` with no `xmlns` → re-parses into the *wrong* (empty) namespace.
Fix: **`xmlUnlinkNode(res)` first, then `xmlReconciliateNs(doc, res)`.** Order
matters — while the node is still attached, the namespace is reachable via its
ancestors, so reconcile thinks nothing is wrong and does nothing. Only after
unlinking does reconcile redeclare the namespace onto the node itself.

**(b) Whitespace changes the signature.** xmlsec pretty-prints by inserting
newline text nodes between children. The newline it puts *after* the
`<Reference>` element is a *sibling* tail node, not part of the dumped subtree,
so the round-trip drops it.
That single missing `\n` changes the canonicalized `SignedInfo` bytes, which
changes the computed `SignatureValue` and breaks byte-exact signature fixtures.
Fix: capture `res->next`'s text (the tail) *before* unlinking, and reapply it as
the grafted element's `.tail`. Any converted function that relies on xmlsec's
formatting must preserve these tail text nodes to stay byte-compatible.

### Memory / ref-count notes

- `res` is unlinked from `doc`, so it is **not** freed by `xmlFreeDoc(doc)` — it
  must be `xmlFreeNode`'d separately.
- The captured `tail` is `xmlStrdup`'d → `xmlFree` it (NULL-safe on the success
  path).
- Every `PyObject_CallMethod`/`PyUnicode_*` result is a new reference and is
  `Py_DECREF`'d, including the `None` returned by `.append(...)`.
- The pure-C libxml2 work runs inside `Py_BEGIN_ALLOW_THREADS`; all the lxml
  Python-API calls run with the GIL held, outside it.

## Version guard / opt-in escape hatch

`PyXmlSec_InitLxmlModule` in [src/lxml.c](src/lxml.c) still blocks import on a
libxml2 mismatch **by default**. Setting `PYXMLSEC_SKIP_VERSION_CHECK` bypasses
the guard. It's needed to exercise the decoupled paths under a mismatch, but it
is **unsafe for any operation still on the raw-node path** — keep it off in
normal use, on only for developing/testing #356.

## Building & validating under a mismatch (macOS / homebrew)

Standard in-place build (dynamic, via pkg-config):

```sh
python -m pip install pkgconfig
python setup.py build_ext --inplace --force   # copies the .so into src/
PYTHONPATH=src python -m pytest tests/
```

To actually reproduce #356 you need lxml and xmlsec on **different** libxml2.
The trap on a homebrew Mac is a *three-way* split:

- lxml: bundled libxml2 (static, e.g. 2.14.x)
- the extension: links `/usr/lib/libxml2.2.dylib` (old system libxml2)
- `libxmlsec1.dylib`: links homebrew `libxml2` (e.g. 2.15.x)

The extension and libxmlsec1 disagreeing crashes regardless of the serialize
work. Force them onto the **same** libxml2 (homebrew's, matching libxmlsec1),
leaving only lxml different — the real #356 scenario:

```sh
# build & compile against homebrew libxml2 headers/libs
rm -rf build/ src/xmlsec.cpython-*-darwin.so
PKG_CONFIG_PATH=/opt/homebrew/opt/libxml2/lib/pkgconfig \
  python setup.py build_ext --inplace --force

# the linker still prefers the SDK stub, so rewrite the runtime dep
install_name_tool -change /usr/lib/libxml2.2.dylib \
  /opt/homebrew/opt/libxml2/lib/libxml2.16.dylib \
  src/xmlsec.cpython-*-darwin.so

# verify: lxml and xmlsec now report different libxml2
PYXMLSEC_SKIP_VERSION_CHECK=1 PYTHONPATH=src python -c \
  "import xmlsec; from lxml import etree; \
   print('lxml', etree.LIBXML_VERSION, 'xmlsec', xmlsec.get_libxml_version())"

# run the suite under the mismatch
PYXMLSEC_SKIP_VERSION_CHECK=1 PYXMLSEC_TEST_ITERATIONS=0 \
  PYTHONPATH=src python -m pytest tests/
```

A `PYXMLSEC_STATIC_DEPS=true` build statically links one libxml2 into the
extension+xmlsec and avoids the whole dance (this is what CI/wheels do).

Useful env vars: `PYXMLSEC_ENABLE_DEBUG=1` (debug build + trace),
`PYXMLSEC_TEST_ITERATIONS=N` (per-test leak-detection reruns in `tests/base.py`;
note `ru_maxrss` is **bytes** on macOS, kB on Linux).

## Status & rollout

- ✅ `template.add_reference` — converted and validated (full suite green +
  10k-iteration loop, no crash/leak, under a real 2.14↔2.15 mismatch).
- ⬜ Everything else still passes raw lxml nodes to xmlsec and is unsafe on a
  mismatch: the rest of `src/template.c`, `src/ds.c` (sign/verify),
  `src/enc.c` (encrypt/decrypt), `src/tree.c`.

When converting another function, reuse the `add_reference` pattern and watch
for the same two gotchas (namespace reconciliation after unlink; preserving
xmlsec's formatting tail nodes). Each function differs in *where* the result
grafts back (e.g. `add_reference` → `SignedInfo`; `ensure_key_info` →
`Signature`). The default version guard can only be relaxed once **all**
node-passing paths are converted.
