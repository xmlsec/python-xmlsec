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
4. **xmlsec doc → bytes → lxml**: serialize the whole mutated document with
   xmlsec's libxml2 (`xmlDocDumpMemory`), re-parse with lxml
   (`etree.fromstring`), locate the new node, and graft it into the original
   lxml tree.

Only bytes cross between the two libxml2 worlds — never a pointer.

> **This decouples lxml from xmlsec, but it assumes the extension and
> `libxmlsec1` share one libxml2.** If *those two* disagree (e.g. the extension
> links system libxml2 while libxmlsec1 links homebrew's), step 3 still mixes
> allocators and crashes. See "Building & validating under a mismatch" below.

### Bridge helpers

Three helpers in [src/lxml.c](src/lxml.c) (declared in [src/lxml.h](src/lxml.h))
are the only sanctioned crossing points. The first two go through lxml's Python
API so the tree is always walked by lxml's libxml2:

- `PyXmlSec_LxmlElementToBytes(element)` → `etree.tostring(element, with_tail=False)`
- `PyXmlSec_LxmlElementFromBytes(data)` → `etree.fromstring(data)`

- **`PyXmlSec_LxmlAddChildViaXmlSec(element, op, ctx, error)`** — the reusable
  round-trip. It is the ABI-safe drop-in for the old "call an `xmlSecTmpl*Add*`
  function on `element->_c_node`, then `elementFactory` the result" one-liner.
  It owns the entire serialize → mutate → reflect dance (below); a converted
  function supplies only the `op` callback (the `xmlSecTmpl*` call + its args via
  `ctx`) and an error string. **Convert new functions by writing an `op`, not by
  re-implementing the round-trip.**

## Reference implementation: `template.add_reference`

`PyXmlSec_TemplateAddReference` in [src/template.c](src/template.c) is the first
function converted and the **template for converting the rest**. After the
refactor it is tiny: parse args, build a `ctx`, and call the helper. The
xmlsec-specific part is the `op`:

```c
static xmlNodePtr PyXmlSec_TemplateAddReferenceOp(xmlNodePtr root, void* ctx) {
    struct ... * c = ctx;
    return xmlSecTmplSignatureAddReference(root, c->digest, XSTR(c->id), XSTR(c->uri), XSTR(c->type));
}
```

`op` receives `root` = the copy's root element, i.e. the equivalent of the
original `element->_c_node`, and returns the node it created (same contract as
the old direct call). Everything else is the helper's job.

### What the helper does (and the key decision)

1. `PyXmlSec_LxmlElementToBytes(element)` — serialize the subtree.
2. `xmlReadMemory(...)` — parse into a throwaway xmlsec-owned `xmlDocPtr`.
3. `res = op(xmlDocGetRootElement(doc), ctx)` — run the caller's xmlsec
   mutation on the copy. `res` stays attached to `doc`.
4. Record `res`'s **element-index path** from the root (so it can be re-found
   after a round-trip), then dump the **whole** mutated document with
   `xmlDocDumpMemory` — *not* the lone `res` subtree.
5. `PyXmlSec_LxmlElementFromBytes(...)` the dump, walk the recorded path to the
   new node, walk the same path (minus the last step) in the *original*
   `element` to reach the parent, and `append` the new node there.
6. Return the grafted lxml node (a live node in the user's tree, so the
   incremental builder — `add_transform(ref, ...)` — keeps working).

Dumping the **entire** document in step 4 (rather than just `res`) is the load-
bearing decision: it keeps the round-trip byte-identical to the old raw-pointer
code *without* any manual fix-up, because two things that would otherwise
diverge only exist in the surrounding document:

**(a) Namespaces.** `xmlNodeDump` of a *subtree* does not emit namespace
declarations that live on ancestors. `<Reference>` uses the dsig namespace
declared up on `<Signature>`; dump it alone and you get `<Reference>` with no
`xmlns` → it re-parses into the *wrong* (empty) namespace, and xmlsec no longer
recognizes it. Dumping the whole document keeps the `<Signature>` declaration in
the bytes, so lxml re-parses the reference into the correct dsig namespace.

**(b) Whitespace.** xmlsec pretty-prints by inserting newline text nodes between
children. The `\n` it puts *after* `<Reference>` is a *sibling* tail node, not
part of the `<Reference>` subtree. Drop it and the canonicalized `<SignedInfo>`
bytes change → the computed `SignatureValue` changes → byte-exact signature
fixtures break. In a whole-document dump that `\n` is just bytes between two
elements; lxml re-parses it as the new element's `.tail`, and `append` carries
the tail along.

> An earlier (pre-helper) version dumped only the `res` subtree and hit both as
> bugs, patching them by hand (`xmlUnlinkNode` + `xmlReconciliateNs` for the
> namespace; `xmlStrdup`-ing `res->next`'s text and reapplying it as `.tail` for
> the whitespace). The whole-document dump deletes all of that. The cost is that
> the new node must be *located* after the round-trip instead of handed back as
> `res`; the helper does this generically via the element-index path.

### Helper assumptions & when *not* to use it

The path-based reflect assumes `op` **appends exactly one new node beneath a
parent that already exists in `element`**, and that the templates contain no
comment/PI siblings (so a libxml2 element index equals an lxml child index).
This holds for the `xmlSecTmpl*Add*` family. Two shapes need more than the
current helper:

- **find-or-create** (`xmlSecTmpl*Ensure*`, e.g. `ensure_key_info`): `op` may
  return an *existing* node without adding anything → appending it would
  duplicate. Needs a "did the tree actually grow?" check before grafting.
- **intermediate ancestors** (e.g. `add_transform` may create a `<Transforms>`
  wrapper *and* the `<Transform>`): the topmost new node, not `res`, is what
  must be grafted.

Extend the helper (or branch inside it) when you reach those; don't force-fit.

### Memory / ref-count notes (inside the helper)

- `res` stays attached to `doc`, so `xmlFreeDoc(doc)` reclaims it — it is **not**
  freed separately.
- `xmlDocDumpMemory`'s output buffer is `xmlFree`'d (NULL-safe on failure).
- Every `PySequence_GetItem` / `PyObject_CallMethod` result is a new reference
  and is `Py_DECREF`'d, including the `None` returned by `.append(...)` and the
  reparsed whole-document tree (dropped once the new node is grafted out of it).
- `op` runs inside `Py_BEGIN_ALLOW_THREADS` (pure libxml2/xmlsec, no Python);
  all the lxml Python-API calls run with the GIL held, outside it.

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
  10k-iteration loop, no crash/leak, under a real 2.14↔2.15 mismatch). The
  reusable round-trip lives in `PyXmlSec_LxmlAddChildViaXmlSec`.
- ⬜ Everything else still passes raw lxml nodes to xmlsec and is unsafe on a
  mismatch: the rest of `src/template.c`, `src/ds.c` (sign/verify),
  `src/enc.c` (encrypt/decrypt), `src/tree.c`.

When converting another function, **write an `op` and call
`PyXmlSec_LxmlAddChildViaXmlSec`** rather than re-implementing the round-trip;
the helper handles serialization, the whole-document dump, and grafting (which
sidesteps the namespace/whitespace divergences for free). For the simple
`xmlSecTmpl*Add*` family that is the whole change. Watch for the two shapes the
current helper does not yet cover — find-or-create (`ensure_key_info`) and
intermediate-ancestor creation (`add_transform`) — and extend the helper when
you reach them (see "Helper assumptions & when *not* to use it"). The default
version guard can only be relaxed once **all** node-passing paths are converted.
