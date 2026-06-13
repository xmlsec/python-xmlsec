# Developer guide: decoupling lxml and xmlsec across libxml2 (#356)

This document explains the approach change introduced for
[issue #356](https://github.com/xmlsec/python-xmlsec/issues/356): how
`python-xmlsec` used to hand XML nodes to `xmlsec1`, why that is unsafe, and the
serialize-based approach that replaces it. The first function converted is
`template.add_reference`; it is the blueprint for the rest.

For day-to-day build/validation commands and the ongoing rollout checklist, see
[CLAUDE.md](CLAUDE.md). This file is the *why* and the *before/after*.

---

## Background

`python-xmlsec` is a C extension that glues together two libraries, **both built
on libxml2**:

| Library    | Role                                         | Its libxml2                    |
|------------|----------------------------------------------|--------------------------------|
| `lxml`     | the XML tree the user edits in Python        | usually bundled in the wheel   |
| `xmlsec1`  | signs / encrypts XML                         | system / homebrew / static     |

An lxml `_Element` is a Python object that wraps a raw libxml2 `xmlNode`:

```c
struct LxmlElement {
    PyObject_HEAD
    struct LxmlDocument* _doc;   //  _doc->_c_doc  is the xmlDocPtr
    xmlNode* _c_node;            //  the raw libxml2 node
    ...
};
```

The extension reaches in for `_c_node` / `_c_doc` and passes those pointers
straight to `xmlsec1`.

## The problem

That only works if **lxml and xmlsec1 use the same libxml2 at runtime**. They
frequently don't — lxml wheels bundle their own static libxml2, while xmlsec is
built against whatever libxml2 is on the system. When the versions differ:

- the `xmlNode` / `xmlDoc` struct layouts and allocators don't match,
- a node allocated by one library and freed/mutated by the other corrupts the
  heap,

…producing segfaults, double-frees, and silently wrong signatures. Until now the
only protection was to refuse to import on a version mismatch (issue #283).

## Before: pass the raw lxml node to xmlsec

The original `add_reference` handed `node->_c_node` directly to xmlsec and
wrapped the node xmlsec created (inside lxml's document) back as an `_Element`:

```c
// BEFORE — src/template.c
Py_BEGIN_ALLOW_THREADS;
res = xmlSecTmplSignatureAddReference(node->_c_node, digest->id,
                                      XSTR(id), XSTR(uri), XSTR(type));
Py_END_ALLOW_THREADS;
if (res == NULL) {
    PyXmlSec_SetLastError("cannot add reference.");
    goto ON_FAIL;
}
return (PyObject*)PyXmlSec_elementFactory(node->_doc, res);
```

`xmlSecTmplSignatureAddReference` (xmlsec's libxml2) walks `node->_c_node`
(lxml's libxml2) and allocates new nodes into lxml's document. Two libxml2
builds touching the same tree → the #356 crash.

## After: exchange serialized XML, never pointers

The new approach keeps each library on its own libxml2 and lets only **bytes**
cross between them:

```
          lxml's libxml2                 xmlsec's libxml2                lxml's libxml2
 node ──► etree.tostring ──► bytes ──► xmlReadMemory ──► xmlSecTmpl... ──► xmlNodeDump ──► bytes ──► etree.fromstring ──► graft into node's SignedInfo
 (input, never mutated)                 (throwaway copy xmlsec owns)                       (new node lxml owns)
```

```c
// AFTER — src/template.c (abridged; full version has the comments + cleanup)

// 1. lxml serializes the template with its OWN libxml2
serialized = PyXmlSec_LxmlElementToBytes((PyObject*)node);
PyBytes_AsStringAndSize(serialized, &xml_data, &xml_size);

Py_BEGIN_ALLOW_THREADS;
// 2. xmlsec re-parses the bytes into a private copy it owns
doc = xmlReadMemory(xml_data, (int)xml_size, NULL, NULL, XML_PARSE_NONET);
if (doc != NULL) {
    // 3. run the xmlsec op on the copy
    res = xmlSecTmplSignatureAddReference(xmlDocGetRootElement(doc),
                                          digest->id, XSTR(id), XSTR(uri), XSTR(type));
    if (res != NULL) {
        tail = capture res->next text;          // gotcha (b)
        xmlUnlinkNode(res);                      // gotcha (a): unlink BEFORE
        xmlReconciliateNs(doc, res);             //            reconcile
        buffer = xmlBufferCreate();
        xmlNodeDump(buffer, doc, res, 0, 0);     // serialize just the new node
    }
}
Py_END_ALLOW_THREADS;

// 4. lxml re-parses the new node and grafts it back into the user's tree
ref_bytes = PyBytes_FromStringAndSize(xmlBufferContent(buffer), xmlBufferLength(buffer));
new_ref   = PyXmlSec_LxmlElementFromBytes(ref_bytes);
signed_info = node.find("{dsig}SignedInfo");
signed_info.append(new_ref);
new_ref.tail = tail;                             // gotcha (b)
return new_ref;
```

The input `node` is never touched by xmlsec. The returned `new_ref` is a live
lxml node in the user's document, so the incremental builder still works:

```python
ref   = xmlsec.template.add_reference(sign, consts.TransformSha1, uri="#data")
trans = xmlsec.template.add_transform(ref, consts.TransformEnveloped)  # ref is real
```

### The two bridge helpers

Added in [src/lxml.c](src/lxml.c) / [src/lxml.h](src/lxml.h) — the only
sanctioned crossing points, both going through lxml's Python API so lxml's
libxml2 always does the work:

```c
PyObject* PyXmlSec_LxmlElementToBytes(PyObject* element); // etree.tostring(el, with_tail=False)
PyObject* PyXmlSec_LxmlElementFromBytes(PyObject* data);  // etree.fromstring(data)
```

## The two gotchas (these recur in every function we convert)

**(a) Namespaces vanish from a naive node dump.** `xmlNodeDump` does not emit
namespace declarations inherited from *ancestors*. The `<Reference>` lives in
the dsig namespace declared up on `<Signature>`, so dumping it alone gives
`<Reference>` with no `xmlns` and it re-parses into the empty namespace.
Fix: **unlink first, then reconcile** — `xmlUnlinkNode(res)` then
`xmlReconciliateNs(doc, res)`. While the node is still attached the namespace is
reachable via ancestors, so reconcile is a no-op; only after unlinking does it
redeclare the namespace onto the node.

**(b) Whitespace is load-bearing.** xmlsec pretty-prints by inserting `"\n"` text
nodes between siblings. The newline *after* `<Reference>` is a sibling tail node,
not part of the dumped subtree, so the round-trip loses it. That one missing
`\n` changes the canonicalized `SignedInfo`, which changes the computed
`SignatureValue` and breaks byte-exact signature fixtures (`tests/test_ds.py`).
Fix: capture `res->next`'s text before unlinking and reapply it as
`new_ref.tail`.

## Files changed

| File                                | Change                                                                 |
|-------------------------------------|------------------------------------------------------------------------|
| [src/template.c](src/template.c)    | `PyXmlSec_TemplateAddReference` rewritten to the serialize round-trip   |
| [src/lxml.c](src/lxml.c)            | added `…ToBytes`/`…FromBytes`; version guard gained an opt-in bypass    |
| [src/lxml.h](src/lxml.h)            | declarations for the two helpers                                       |

## Version guard / opt-in

`PyXmlSec_InitLxmlModule` ([src/lxml.c](src/lxml.c)) still **refuses to import on
a libxml2 mismatch by default**. `PYXMLSEC_SKIP_VERSION_CHECK` opts out — needed
to exercise the decoupled paths under a mismatch, but **unsafe for any operation
still on the raw-node path**. The guard can only be removed once every
node-passing function is converted.

## Validation

Under a real mismatch (lxml 2.14.6 ↔ xmlsec 2.15.3): full suite **285 passed,
6 skipped**, plus a 10,000-iteration `add_reference` + `add_transform` loop with
no crash and no leak. See [CLAUDE.md](CLAUDE.md) for the exact build/relink
recipe (note the homebrew three-way libxml2 trap) and the rollout checklist.
