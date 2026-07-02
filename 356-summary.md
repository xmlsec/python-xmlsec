# Shadow copies for #356 — what was done, at a high level

**TL;DR** — `python-xmlsec` crashes when `lxml` and `xmlsec1` are built
against different `libxml2` versions, because it passes raw libxml2 node
pointers between them. This branch makes each xmlsec call run on a private
*copy* of the element and reflects the result back afterwards, so only
serialized bytes ever cross the boundary. Three template functions — one per
mutation shape — are converted; converting the rest is a four-line edit each.

## The problem

`python-xmlsec` glues together two libraries that both build on **libxml2**:
lxml (the XML tree the user edits in Python) and xmlsec1 (the C library that
signs/encrypts). The extension reaches into an lxml `_Element` for its raw
`xmlNodePtr` and hands it to xmlsec1. That is only safe when both libraries
link the *same* libxml2 at runtime — and they often don't, because lxml wheels
bundle their own. Two libxml2 builds touching one tree means mismatched struct
layouts and allocators: segfaults, double-frees, wrong signatures
([#356](https://github.com/xmlsec/python-xmlsec/issues/356)). The only
existing mitigation was refusing to import on a version mismatch (#283).

## The idea: shadow copies

Bytes have no ABI. So instead of sharing nodes, each converted binding now:

```
 lxml element ──(lxml's libxml2 serializes)──► bytes
 bytes ──(our libxml2 parses)──► private "shadow" copy
 xmlsec mutates the shadow (it never sees an lxml node)
 shadow ──(our libxml2 dumps)──► bytes ──(lxml parses)──► change grafted
                                                          into the live tree
```

The user-visible behaviour is unchanged: the input element gains exactly what
xmlsec added, the returned node is live in their tree (so incremental building
like `add_transform(ref, ...)` keeps working), and the serialized output stays
byte-identical — namespaces and xmlsec's `"\n"` formatting included.

## What the change consists of

- **One helper pair** in `src/lxml.c`/`src/lxml.h`:
  `PyXmlSec_LxmlShadowBegin` (element → shadow copy) and
  `PyXmlSec_LxmlShadowEnd` (reflect the mutation back, return the lxml node).
  `Begin` tags every pre-existing node of the copy through libxml2's private
  field, which lets `End` *discover* what the call did instead of being told —
  that is what makes the reflection generic.
- **Three bindings converted** in `src/template.c`, deliberately one per
  mutation shape so the helper is proven against all of them:
  - `add_reference` — plain "add a subtree",
  - `add_transform` — also creates an intermediate `<Transforms>` wrapper at a
    chosen position,
  - `ensure_key_info` — find-or-create: returns the existing node (attributes
    synced) instead of duplicating it.
  A conversion is four lines: `Begin` / the unchanged xmlsec call on
  `shadow.root` / `End` — no per-function callback or context struct.
- **An escape hatch** for development: `PYXMLSEC_SKIP_VERSION_CHECK` bypasses
  the import-time mismatch guard so the converted paths can be exercised under
  a real mismatch. The guard itself stays on by default.
- **Tests** in `tests/test_templates.py` asserting the reflection semantics
  (liveness, position, no duplication on repeated ensure).
- **Two docs**: [developer.md](developer.md) — the design and the build/
  validation recipe; [converting-functions.md](converting-functions.md) — the
  step-by-step guide for converting the remaining functions.

## Why this design (vs. the first attempt)

An earlier branch (`fix/356-decouple-add-reference`) proved the
serialize-across-the-boundary idea but required a callback function plus a
context struct per converted binding, and its reflection only handled the
"append exactly one child" shape — `ensure_key_info` and `add_transform`
would have needed helper extensions. The shadow design inverts control: the
call site stays a plain xmlsec call, and the helper works out what changed by
diffing tagged vs. untagged nodes. Result: less code overall, zero
per-function boilerplate, and all `xmlSecTmpl*` shapes covered by one
mechanism.

## Validation

Exercised under a **real** libxml2 mismatch (lxml bundling 2.14.6, extension +
libxmlsec1 on homebrew 2.15.3):

- full test suite: **288 passed, 6 skipped**, including the per-test leak
  detector, across repeated runs;
- 10,000-iteration loop over all three converted functions: no crash, no RSS
  growth, byte-identical output every iteration.

> Caveat (unchanged from before): this decouples *lxml* from xmlsec. The
> extension and `libxmlsec1` must still share one libxml2 — which wheels and
> static builds guarantee.

## What's left

The rest of `src/template.c` is a mechanical rollout of the four-line pattern
(see the guide). `src/ds.c` (sign/verify), `src/enc.c` (encrypt/decrypt) and
`src/tree.c` operate on whole documents and need a reflect strategy of their
own on top of the same `Begin` machinery. The import-time version guard can
only be relaxed once every node-passing path is converted.
