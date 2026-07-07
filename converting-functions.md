# Converting a function to the shadow-copy pattern — step by step

This is the how-to companion to [developer.md](developer.md) (which explains
*why* the shadow copy exists and how the reflection works). Follow these steps
to move one more binding off the raw-node path for
[#356](https://github.com/xmlsec/python-xmlsec/issues/356).

## 1. Pick a function

Anything still touching `node->_c_node` / `node->_doc->_c_doc` is on the raw
path:

```sh
grep -n '_c_node\|_c_doc' src/template.c
```

## 2. Classify the xmlsec call

Read the `xmlSecTmpl*` function it wraps (xmlsec1's `src/templates.c`) and
match it to a row:

| Shape | Examples | How |
|---|---|---|
| Adds a subtree under the element (any position, possibly with intermediate nodes) | `add_key_name`, `add_key_value`, `add_x509_data`, `x509_data_add_*`, `add_encrypted_key` | ✅ just follow step 3 |
| Find-or-create, may set attributes on the existing node | `encrypted_data_ensure_key_info`, `encrypted_data_ensure_cipher_value` | ✅ just follow step 3 (a call that can also *rename the prefix* of the existing node uses `EndReplace` instead of `End`) |
| Returns a status `int`, mutates one child | `transform_add_c14n_inclusive_namespaces` | ✅ pass `PyXmlSec_LxmlShadowFindFresh(&shadow)` to `End`; discard the returned element and return `None` |
| Returns a **detached** node — the element argument only supplies the document | `create`, `encrypted_data_create` | ✅ `BeginNewDoc`/`EndNewDoc`: the call runs against a private document and the result comes back as a new detached lxml element |
| Read-only search | `tree.c` find_child/find_node (subtree), find_parent (whole doc) | ✅ `Begin` (or `BeginDoc` when the search leaves the subtree) + `EndFind`, which returns `None` on not-found |
| Reads or mutates the **whole document**, possibly at several places | `ds.c` sign (whole-doc + multi-site), verify (read-only) | ✅ `BeginDoc` + `ReplayIds`, then `ReflectAll` (sign) or `Discard` (verify) |
| **Replaces** nodes | `enc.c` encrypt_xml/decrypt (`encrypt_binary`/`encrypt_uri` are template-shaped: `Begin` + `ReflectAll`) | ✅ `BeginDoc`, remove the consumed live node/content first, then `ReflectAll` grafts the replacement (`_setroot` when the document root itself was replaced) |

All shapes are converted; `developer.md`'s "Beyond templates" section explains
each reflect. This guide stays as the recipe should new bindings appear.

`res` does not have to be the topmost node the call created — `End` walks up
to the topmost new ancestor itself. Any node inside the new subtree works.

## 3. Edit the binding

The change is mechanical; `add_key_name` as the worked example:

```c
     PyXmlSec_LxmlElementPtr node = NULL;
     const char* name = NULL;
     xmlNodePtr res;
+    PyObject* result;
+    PyXmlSec_LxmlShadow shadow;

     PYXMLSEC_DEBUG("template add_key_name - start");
     if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O&|z:add_key_name", kwlist,
         PyXmlSec_LxmlElementConverter, &node, &name))
     {
         goto ON_FAIL;
     }

+    if (PyXmlSec_LxmlShadowBegin(&shadow, node) < 0) {
+        goto ON_FAIL;
+    }
     Py_BEGIN_ALLOW_THREADS;
-    res = xmlSecTmplKeyInfoAddKeyName(node->_c_node, XSTR(name));
+    res = xmlSecTmplKeyInfoAddKeyName(shadow.root, XSTR(name));
     Py_END_ALLOW_THREADS;
-    if (res == NULL) {
-        PyXmlSec_SetLastError("cannot add key name.");
+    result = PyXmlSec_LxmlShadowEnd(&shadow, res, "cannot add key name.");
+    if (result == NULL) {
         goto ON_FAIL;
     }

     PYXMLSEC_DEBUG("template add_key_name - ok");
-    return (PyObject*)PyXmlSec_elementFactory(node->_doc, res);
+    return result;
```

Rules the pattern must keep:

- swap `node->_c_node` for `shadow.root` and change **nothing else** about the
  xmlsec call or its error string;
- run **exactly one** xmlsec call between `Begin` and `End`, and no Python
  code (the `Py_*_ALLOW_THREADS` pair is fine — the call is pure C);
- call `End` **exactly once** after a successful `Begin`; it frees the copy on
  every path, including when `res == NULL`.

## 4. Build

```sh
python setup.py build_ext --inplace --force
PYTHONPATH=src python -m pytest tests/
```

(On a homebrew Mac the plain build links mismatched libxml2s — see
"Building & validating under a real mismatch" in [developer.md](developer.md)
for the `PKG_CONFIG_PATH` + `install_name_tool` recipe.)

## 5. Add a targeted test

Existing tests cover return values; add one asserting the *reflection*, in
`tests/test_templates.py`:

- the returned node is live in the caller's tree
  (`self.assertIs(kn.getroottree().getroot(), root)`) and at the position
  xmlsec puts it;
- for find-or-create: a second call returns the same element
  (`assertIs`), sets the requested attributes on it, and does not duplicate it.

Beware the leak detector in `tests/base.py`: it reruns each test with
`gc.disable()` and fails on monotonic object-count growth, which plain
allocation churn can trigger with no real leak. Keep each test small (split
rather than combine scenarios), prefer `assertIs(parent[0], tr)` over building
lists to compare, and check stability with a few rounds of:

```sh
PYXMLSEC_TEST_ITERATIONS=50 PYTHONPATH=src python -m pytest tests/test_templates.py
```

## 6. Validate under a real libxml2 mismatch

Build per the developer.md recipe so lxml and the extension report different
libxml2 versions, then:

```sh
PYXMLSEC_SKIP_VERSION_CHECK=1 PYTHONPATH=src python -m pytest tests/
```

For anything non-trivial, also loop the converted function ~10k times under
the mismatch and watch `ru_maxrss` stays flat and the serialized output stays
byte-identical between iterations.

## 7. Record it

Move the function to the ✅ list in [developer.md](developer.md)'s Status
section. Once nothing passes raw nodes anymore, the import-time version guard
can be relaxed.
