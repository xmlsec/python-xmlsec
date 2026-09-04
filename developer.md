# Decoupling lxml and xmlsec across libxml2 (#356)

**TL;DR** — `python-xmlsec` crashes when `lxml` and `xmlsec1` are built
against different `libxml2` versions, because it passes raw libxml2 node
pointers between them. Every xmlsec call now runs on a private *copy* of the
element ("shadow") owned by our libxml2, and the change it makes is reflected
back into the live lxml tree afterwards, so only serialized bytes ever cross
the boundary. Converting a binding is four lines; when the libxml2 versions
match, the copy is skipped and the old direct code runs unchanged.

## The problem

`python-xmlsec` glues together two libraries that both build on **libxml2**:
lxml (the tree the user edits in Python) and xmlsec1 (the C library that
signs/encrypts). Historically the extension reached into an lxml `_Element`
for its raw `xmlNodePtr` and handed it to xmlsec1. That is only safe when both
libraries link the *same* libxml2 at runtime — and they often don't, because
lxml wheels bundle their own. Two libxml2 builds touching one tree means
mismatched struct layouts, dictionaries and allocators: segfaults,
double-frees, wrong signatures
([#356](https://github.com/xmlsec/python-xmlsec/issues/356)). The only
mitigation so far was refusing to import on a version mismatch (#283).

## The fix: shadow copies

Bytes have no ABI. Each binding therefore does:

```text
 lxml element ──(lxml's libxml2 serializes)──► bytes
 bytes ──(our libxml2 parses)──► private "shadow" copy
 xmlsec mutates the shadow (it never sees an lxml node)
 shadow ──(our libxml2 dumps)──► bytes ──(lxml parses)──► changes grafted
                                                          into the live tree
```

The user-visible behaviour is unchanged: the input element gains exactly what
xmlsec added, the returned node is live in the caller's tree (incremental
building like `add_transform(ref, ...)` keeps working, and proxies the caller
holds stay valid), and the serialized output is byte-identical — namespaces
and xmlsec's `"\n"` formatting included.

The whole mechanism lives in [src/lxml.c](src/lxml.c), with the contract in
[src/lxml.h](src/lxml.h). A binding looks like this (`add_reference`):

```c
PyXmlSec_LxmlShadow shadow;
if (PyXmlSec_LxmlShadowBegin(&shadow, node) < 0) goto ON_FAIL;        // lxml → bytes → our copy
Py_BEGIN_ALLOW_THREADS;
res = xmlSecTmplSignatureAddReference(shadow.root, ...);              // xmlsec mutates the copy
Py_END_ALLOW_THREADS;
result = PyXmlSec_LxmlShadowEnd(&shadow, res, "cannot add reference."); // reflect back, return lxml node
```

No per-function callback or context struct: the call site is the plain xmlsec
call, and the helper works out what the call did.

## The API

Three `Begin` flavours make the copy, four `End` functions consume it. Every
End always releases the copy, on success and on error.

| Function | Use |
| --- | --- |
| `Begin(&shadow, element)` | copy of the element's subtree; `shadow.root` is the copy |
| `BeginDoc(&shadow, element, &target)` | copy of the element's whole document, for calls that follow references or walk upward; `target` is the copy's counterpart of `element`; registered IDs are replayed onto the copy |
| `BeginNewDoc(&shadow, element)` → `xmlDocPtr` | no copy at all: a private document for calls that only build a *detached* subtree (`create`) |
| `End(&shadow, res, error)` → element | the lxml element for a result node — grafted into the live tree if the call created it, or the existing live element (with the attributes / prefix the call changed) if it found it; NULL `res` raises `error` |
| `EndFind(&shadow, res)` → element or `None` | the same for read-only finders; NULL is "not found" |
| `Reflect(&shadow, rv, error)` → int | for calls returning only a status: `rv < 0` raises `error`, otherwise every change is reflected |
| `Discard(&shadow)` | release without reflecting (read-only calls, error paths before End) |

Plus three helpers for the call sites whose *semantics* differ per mode:
`IsActive()` (which path is on), `ImportElement()` (encrypt_xml's template
import into the shadow document) and `RecordId()` (ID registration, below).

Which pair a binding uses follows from what the xmlsec call does:

| The xmlsec call ... | Begin | End | Bindings |
| --- | --- | --- | --- |
| adds or finds a node under the element | `Begin` | `End` | every `xmlSecTmpl*` add / ensure call |
| builds a detached subtree, needs only a document | `BeginNewDoc` | `End` | `create`, `encrypted_data_create` |
| searches the subtree, read-only | `Begin` | `EndFind` | `find_child`, `find_node` |
| searches upward, read-only | `BeginDoc` | `EndFind` | `find_parent` |
| mutates the subtree, returns a status | `Begin` | `Reflect` | `transform_add_c14n_inclusive_namespaces`, `encrypt_binary`, `encrypt_uri` |
| mutates anywhere in the document, returns a status | `BeginDoc` | `Reflect` | `sign` |
| reads the document, returns a status | `BeginDoc` | `Discard` | `verify` |
| *replaces* the element or its content | `BeginDoc` | remove the consumed live node/content, then `Reflect` | `encrypt_xml`, `decrypt` |

Rules every call site must keep:

- swap `node->_c_node` for `shadow.root` (or `target`) and change **nothing
  else** about the xmlsec call or its error string;
- run **exactly one** xmlsec call between Begin and End, and no Python code
  in between (the `Py_*_ALLOW_THREADS` pair is fine — the call is pure C);
- call exactly one End function after a successful Begin.

**Invariant, enforced by `tests/test_shadow_audit.py`:** every C function that
accepts an lxml element (`PyXmlSec_LxmlElementConverter`) either calls a
`PyXmlSec_LxmlShadowBegin*` helper or is one of the four dual-body functions
(`register_id`, `add_ids`, `encrypt_xml`, `decrypt`), which must consult
`IsActive()` before touching a raw node; and `->_c_node` / `->_c_doc` appear
only in those four, in the helpers' fast-path branches, and in the ID registry
(which uses the addresses as keys only). The test scans `src/*.c`, so a raw
access anywhere else fails the suite on both paths.

## How the reflection works

`Begin` serializes the element with lxml's own `etree.tostring`, re-parses
the bytes with `xmlReadMemory`, and tags every node of the copy through the
libxml2 `_private` field (never serialized, never touched by the parser or
xmlsec). After the call, whatever is untagged is what the call created. The
reflection then walks the tagged structure of the copy in document order and
records two kinds of *site*:

- **graft** — a fresh node (element, comment, PI) to insert at its child
  index. Fresh subtrees are grafted wholesale; the scan never descends into
  them.
- **sync** — a tagged parent that gained any fresh node (element or text)
  gets its text slots (its `.text` and each child's `.tail`) copied over from
  the re-parsed copy. That covers everything xmlsec does to text: the `"\n"`
  formatting around a new node, values filled into empty elements
  (`DigestValue`, `SignatureValue`), and content it removed (encrypt
  `Type=Content`) — a removal leaves no fresh node behind, so only a
  wholesale sync can see it.

Sites are addressed by **child-index paths** from the copy root, counting
exactly the node types lxml exposes as children (elements, comments, PIs,
entity refs), so a path recorded on the raw copy resolves identically through
lxml's `__getitem__` / `insert` on the live tree. The reflection is
**two-phase**: every payload is fetched from the re-parsed copy first, while
it is still in its final state, then everything is applied to the live tree in
document order (a graft moves a node out of the re-parsed copy, which would
invalidate later fetches; each live insert makes the later, larger indices
valid; a parent's sync is recorded after its grafts).

Two serialization details are load-bearing for byte-identical signatures:
the **whole** copy is dumped (`xmlDocDumpMemory`), not just the fresh nodes,
so ancestor-declared namespaces and the formatting siblings survive the lxml
re-parse without any manual fix-up; and lxml's `insert` carries a node's tail
along and reconciles namespaces against the live ancestry.

`End` then maps the result node back: it records the path of `res` in the
copy before reflecting, and after the reflection the live tree mirrors the
copy's element structure, so the same path resolves to the live counterpart —
whether the call created it (now grafted) or found it. For a found node the
tree did not grow there, so the live element is returned with the attributes
the call set (`Id`) synced onto it; a renamed namespace prefix
(`encrypted_data_ensure_key_info(ns=...)` on an existing `KeyInfo`) has no
lxml API, so the live element is swapped for the copy's version and the
caller gets a new proxy object.

`BeginDoc` records the element's position through lxml's API (`getparent` /
`index`), serializes `element.getroottree()` — comments/PIs outside the root
and the internal DTD subset survive — and hands back the copy's counterpart;
`shadow.element` becomes the live *root*, which is where the reflection maps
paths onto. `BeginNewDoc` creates an empty private document; `End` roots the
detached result there, dumps it and returns it as a new detached lxml element
(in a document of its own until grafted; lxml moves it when the caller
appends it, like the raw path's detached node).

## The fast path: shadows only when needed

Copying is pointless when lxml links the same libxml2 as the extension — the
raw-node behaviour that shipped for years is safe then, and it is the only
configuration the import guard currently lets run. `Begin`/`End` are
dual-path, decided once at import:

- **matched versions** (the guard passed): `Begin` aliases the live
  `_c_node` into `shadow.root` with no serialization, `End` just wraps the
  node xmlsec returned, `Reflect` does nothing — machine-identical to the
  pre-shadow code, zero overhead;
- **mismatch** (import allowed via `PYXMLSEC_SKIP_VERSION_CHECK` today,
  automatic once the guard becomes a mode switch), **or `PYXMLSEC_FORCE_SHADOW`
  set**: the full shadow round-trip.

Call sites cannot tell the difference. `PYXMLSEC_FORCE_SHADOW` exists so CI
keeps the shadow path exercised on matched libraries (the workflows run the
suite twice), where it must also pass the full suite. Measured cost of the
shadow path per template call: about 8x (72 µs vs 8.6 µs for create +
add_reference + add_transform + ensure_key_info); whole-document operations
scale with document size.

The re-parse on our side uses `XML_PARSE_HUGE` and the lxml side a cached
`XMLParser(huge_tree=True)`, so a `CipherValue` above libxml2's 10 MB
text-node limit (large `encrypt_binary` payloads) or a document the user
parsed with `huge_tree` still reflects. That is safe: what gets parsed is
lxml's own dump of a tree it already parsed.

> The shadow decouples *lxml* from xmlsec. The extension and `libxmlsec1`
> must still share one libxml2 (wheels and static builds guarantee this).

## ID registration under the shadow

`SignatureContext.register_id` and `tree.add_ids` used to write lxml's ID
hash with our libxml2 — exactly the cross-library access the shadow forbids.
Under the shadow they record the id-attribute specs in a registry keyed by
document identity (`RecordId`), and every `BeginDoc` replays them onto its
copy so that `#id` references resolve during sign/verify/decrypt. The replay
scans the whole copy for the recorded attribute names — a superset of the
single-node registration on the raw path, mirroring what `xmlSecAddIDs` does
from the root. The registry holds no strong references to documents (lxml's
classes refuse weak references), so entries are validated by a stored
`_c_doc` address and capped in size. The two bindings are the only places,
together with encrypt_xml/decrypt's replacement bodies, that branch on
`IsActive()`.

## Converting a binding

1. Classify the xmlsec call with the table above.
2. Edit: swap `node->_c_node` for `shadow.root`, wrap the call in the
   matching Begin/End pair, keep the error string.
3. Build and run the suite (see below). Add a test asserting the
   *reflection*: the returned node is live in the caller's tree
   (`assertIs(node.getroottree().getroot(), root)`) and at the position
   xmlsec puts it; for find-or-create, a second call returns the same element.
4. Validate under a real libxml2 mismatch, and on a matched build with
   `PYXMLSEC_FORCE_SHADOW=1`.

Beware the leak detector in `tests/base.py`: it reruns each test with
`gc.disable()` and fails on monotonic object-count growth, which plain
allocation churn can trigger with no real leak. Keep each test small (split
rather than combine scenarios), prefer `assertIs(parent[0], tr)` over
building lists to compare, and check stability with
`PYXMLSEC_TEST_ITERATIONS=50 PYTHONPATH=src python -m pytest tests/`.

## Known divergences and limitations (shadow path only)

All invisible to the documented API:

- created templates (`create`, `encrypted_data_create`) live in their own
  document until grafted;
- `encrypted_data_ensure_key_info(ns=...)` on an existing `KeyInfo` returns
  a new element object rather than the original proxy;
- `register_id` skips the live duplicate-id check (it runs per copy instead);
- `encrypt_xml` *copies* a template that is attached inside the target tree
  rather than moving it, so it also remains at its original position;
- signature/encryption contexts keep no live result nodes after the call
  (they never usefully did);
- documents nested deeper than 256 levels (only possible with `huge_tree`)
  are refused with an internal error;
- operations that replace the **document root** (encrypting the root element
  with `Type=Element`, decrypting a root `EncryptedData`) morph the live root
  element in place into the replacement, because lxml's API cannot swap a
  document's root (`_ElementTree._setroot` only rebinds that one Python
  object). The result is the same as on the raw path — the returned element
  is the new root, with the replacement's own namespace declarations and
  document-level siblings intact — except that the caller's root proxy (and
  any `_ElementTree` holding it) *becomes* the replacement instead of going
  stale as a detached copy of the old root. A root replaced by anything but a
  single element (a `Type=Content` decryption of the root) is refused with
  `xmlsec.Error`.

## Building & validating

### Under a real mismatch (macOS / homebrew)

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

`PYXMLSEC_SKIP_VERSION_CHECK` bypasses the import-time mismatch guard so the
shadow paths can be exercised; keep it off in normal use until the guard
becomes a mode switch. For anything non-trivial, also loop the converted
function ~10k times under the mismatch and check `ru_maxrss` stays flat and
the serialized output stays byte-identical between iterations.

### On a matched build (static wheel)

`PYXMLSEC_STATIC_DEPS=true python -m build --wheel` bundles a libxml2 matched
to lxml's wheels; install it into a venv with wheel lxml
(`pip install --no-deps --force-reinstall dist/*.whl`) and run the suite twice
— plain (fast path) and with `PYXMLSEC_FORCE_SHADOW=1` (shadow path on
matched libraries; safe everywhere, so the whole suite must pass). Gotcha:
setuptools reuses stale objects from `build/`, so `rm -rf build/lib.*
build/temp.*` before switching between the dynamic in-place build and the
static wheel, or the wheel silently ships the old dynamically linked module
(it is then ~50 KB instead of several MB).

## Status

- ✅ Every binding that hands a node to xmlsec goes through a shadow:
  all of `src/template.c`, `src/tree.c`, `src/ds.c` and `src/enc.c`.
- ✅ Validated under a real 2.14 ↔ 2.15 mismatch (full suite, 10k-iteration
  sign/verify/encrypt/decrypt loop with flat RSS and byte-identical output,
  12 MB binary round trip) and on a matched static build on both the fast
  path and `PYXMLSEC_FORCE_SHADOW=1`.
- ⬜ Endgame, kept as its own change: turn the import-time guard into a mode
  switch (a mismatch sets the shadow flag instead of refusing to import) and
  retire `PYXMLSEC_SKIP_VERSION_CHECK`. That is the user-facing resolution of
  #356.
