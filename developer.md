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
functions.

## Beyond templates: the whole-code rollout

Every binding that used to hand a raw lxml node to xmlsec now goes through a
shadow. The extra shapes (all in [src/lxml.c](src/lxml.c), contracts in
[src/lxml.h](src/lxml.h)):

- **Create** (`template.create`, `encrypted_data_create`):
  `BeginNewDoc`/`EndNewDoc`. The call builds a *detached* subtree and only
  needs a document to allocate in — a private one on the shadow path. The
  result comes back as a new detached lxml element (in its own document; lxml
  moves it when the caller grafts it), instead of the raw path's "detached
  node inside the source document", which lxml's API cannot express.
- **Finders** (`tree.find_child`/`find_node`/`find_parent`): `EndFind` maps
  the found copy node back by path and returns `None` on not-found.
  `find_parent` walks upward, so it uses the whole-document Begin.
- **Whole-document** (`sign`, `verify`, `decrypt`, `find_parent`):
  `BeginDoc` serializes `element.getroottree()` (comments/PIs outside the
  root and the internal DTD subset survive), records the element's position
  through lxml's API, and hands back the copy's counterpart node.
- **Multi-site reflect** (`sign`, `encrypt_binary`, `encrypt_uri`):
  `ReflectAll` scans the copy for *every* topmost untagged node and grafts
  each back — new subtrees via `insert`, new/changed text (DigestValue,
  SignatureValue) via the text slots. Two-phase: payloads are fetched from
  the re-parsed copy while it is still in its final state, then applied to
  the live tree in document order (a graft moves a node out of the re-parsed
  copy, which would invalidate later fetches).
- **Replacement reflect** (`encrypt_xml`, `decrypt`): encryption/decryption
  *replace* nodes, so the live target (or its content, or the document root
  via `_setroot`) is removed first and `ReflectAll` grafts what took its
  place. `encrypt_xml` re-serializes the template into the same shadow doc
  (`ImportElement`); a template attached inside the target's own tree is
  therefore copied, not moved. `verify` needs no reflect at all — `Discard`
  just frees the copy.
- **ID registration** (`tree.add_ids`, `SignatureContext.register_id`): these
  used to write lxml's ID hash with our libxml2. Under the shadow they record
  the id-attribute specs in a registry keyed by document identity
  (`RecordId`), and every `BeginDoc` replays them onto the copy
  (`ReplayIds`) so `#id` references resolve. The replay scans the whole copy
  for the recorded attribute names — a superset of the raw registration. The
  registry holds no strong references to documents (lxml objects refuse weak
  references, so entries are validated by a stored `_c_doc` address and
  capped in size).
- **Prefix rename** (`encrypted_data_ensure_key_info(ns=...)` on an existing
  KeyInfo): `EndReplace` swaps the live element for the copy's version, since
  lxml cannot rename a prefix in place; the returned element is then a new
  object rather than the original proxy.

## The fast path: shadows only when needed

Copying is pointless when lxml links the same libxml2 as the extension — the
raw-node behavior that shipped for years is safe then, and it is the only
configuration the import guard currently lets run. So `Begin`/`End` are
dual-path, decided once at import:

- **matched versions** (the guard passed): `Begin` aliases the live
  `_c_node` into `shadow.root` with no serialization, and `End` just wraps
  the node xmlsec returned — machine-identical to the pre-shadow code, zero
  overhead;
- **mismatch** (import allowed via `PYXMLSEC_SKIP_VERSION_CHECK` today,
  automatic once everything is converted), **or `PYXMLSEC_FORCE_SHADOW` set**:
  the full shadow round-trip described above.

Call sites cannot tell the difference; every converted function inherits both
paths. `PYXMLSEC_FORCE_SHADOW` exists so CI keeps the shadow path exercised on
matched libraries (see the test matrix), where it must also pass the full
suite.

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

On a *matched* build (no mismatch available), run the suite twice instead:
once plain (fast path) and once with `PYXMLSEC_FORCE_SHADOW=1` (shadow path
on matched libraries — safe everywhere, so the whole suite must pass).

## Status

- ✅ All of `src/template.c` (create, references, transforms, key info, x509,
  encrypted data, C14N namespaces).
- ✅ `src/tree.c` (find_child/find_node/find_parent, add_ids).
- ✅ `src/ds.c` (register_id, sign, verify; the binary operations never
  touched nodes).
- ✅ `src/enc.c` (encrypt_binary, encrypt_uri, encrypt_xml, decrypt).
- Validated under a real 2.14 ↔ 2.15 mismatch: full suite green, 10k-iteration
  sign/verify/encrypt/decrypt loop with no crash, no leak, byte-identical
  output; and on a matched static build: full suite green on both the fast
  path and `PYXMLSEC_FORCE_SHADOW=1`.
- ⬜ Endgame: turn the import-time guard into a mode switch (mismatch sets
  the shadow flag instead of refusing to import) and retire
  `PYXMLSEC_SKIP_VERSION_CHECK`. That is the actual user-facing resolution
  of #356, kept as its own change.

Known, deliberate divergences on the shadow path (all invisible to the
documented API): created templates live in their own document until grafted;
`encrypted_data_ensure_key_info(ns=...)` on an existing KeyInfo returns a new
element object; `register_id` skips the live duplicate-id check (it runs per
copy instead); `encrypt_xml` copies rather than moves a template that is
attached inside the target tree; signature/encryption contexts keep no live
result nodes after the call (they never usefully did). One hard limitation:
operations that would replace the **document root** (encrypting the root
element, decrypting a root `EncryptedData`) raise `xmlsec.Error` — lxml's API
cannot swap a document's root, and morphing it in place would rewrite
namespace prefixes, breaking signatures over the content. Re-parse the
document or work on a subelement instead.
