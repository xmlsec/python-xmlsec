// Copyright (c) 2017 Ryan Leckey
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include "common.h"
#include "platform.h"
#include "exception.h"

#include <libxml/tree.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#ifndef XMLSEC_NO_XSLT
#include <libxslt/xslt.h>
#include <libxslt/security.h>
#endif /* XMLSEC_NO_XSLT */

#include <xmlsec/xmlsec.h>
#include <xmlsec/crypto.h>
#include <xmlsec/errors.h>

#define _FREE_NONE 0
#define _FREE_XMLLIB 1
#define _FREE_XMLSEC 2
#define _FREE_ALL 3

static xsltSecurityPrefsPtr xsltSecPrefs = NULL;
static int free_mode = _FREE_NONE;

static void PyXmlSec_Free(int what) {
    PYXMLSEC_DEBUGF("free resources %d", what);
    switch (what) {
    case _FREE_ALL:
        xmlSecCryptoAppShutdown();
    case _FREE_XMLSEC:
        xmlSecShutdown();
    case _FREE_XMLLIB:
#ifndef XMLSEC_NO_XSLT
        xsltFreeSecurityPrefs(xsltSecPrefs);
        xsltCleanupGlobals();
#endif /* XMLSEC_NO_XSLT */
        xmlCleanupParser();
    }
    free_mode = _FREE_NONE;
}

static int PyXmlSec_Init(void) {
    /* Init libxml and libxslt libraries */
    xmlInitParser();
    LIBXML_TEST_VERSION
    xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
    xmlSubstituteEntitiesDefault(1);
#ifndef XMLSEC_NO_XSLT
    xmlIndentTreeOutput = 1;
#endif /* XMLSEC_NO_XSLT */

    /* Init libxslt */
#ifndef XMLSEC_NO_XSLT
    /* disable everything */
    xsltSecurityPrefsPtr xsltSecPrefs = xsltNewSecurityPrefs();
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_READ_FILE,        xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_WRITE_FILE,       xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_CREATE_DIRECTORY, xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_READ_NETWORK,     xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_WRITE_NETWORK,    xsltSecurityForbid);
    xsltSetDefaultSecurityPrefs(xsltSecPrefs);
#endif /* XMLSEC_NO_XSLT */

    if (xmlSecInit() < 0) {
        PyXmlSec_SetLastError("cannot initialize xmlsec library.");
        PyXmlSec_Free(_FREE_XMLLIB);
        return -1;
    }

    if (xmlSecCheckVersion() != 1) {
        PyXmlSec_SetLastError("xmlsec library version mismatch.");
        PyXmlSec_Free(_FREE_XMLSEC);
        return -1;
    }

#ifndef XMLSEC_NO_CRYPTO_DYNAMIC_LOADING
    if (xmlSecCryptoDLLoadLibrary(NULL) < 0) {
        PyXmlSec_SetLastError("cannot load crypto library for xmlsec.");
        PyXmlSec_Free(_FREE_XMLSEC);
        return -1;
    }
#endif /* XMLSEC_CRYPTO_DYNAMIC_LOADING */

  /* Init crypto library */
    if (xmlSecCryptoAppInit(NULL) < 0) {
        PyXmlSec_SetLastError("cannot initialize crypto library application.");
        PyXmlSec_Free(_FREE_XMLSEC);
        return -1;
    }

  /* Init xmlsec-crypto library */
    if (xmlSecCryptoInit() < 0) {
        PyXmlSec_SetLastError("cannot initialize crypto library.");
        PyXmlSec_Free(_FREE_ALL);
        return -1;
    }
    free_mode = _FREE_ALL;
    return 0;
}

static char PyXmlSec_PyInit__doc__[] =
"Initialize the library for general operation.\n" \
"This is called upon library import and does not need to be called\n" \
"again (unless @ref _shutdown is called explicitly).\n";
static PyObject* PyXmlSec_PyInit(PyObject *self) {
   if (PyXmlSec_Init() < 0) {
        return NULL;
   }
   Py_RETURN_NONE;
}

static char PyXmlSec_PyShutdown__doc__[] =
"Shutdown the library and cleanup any leftover resources.\n"  \
"This is called automatically upon interpreter termination and\n" \
"should not need to be called explicitly.";
static PyObject* PyXmlSec_PyShutdown(PyObject* self) {
    PyXmlSec_Free(_FREE_ALL);
    Py_RETURN_NONE;
}

static char PyXmlSec_PyEnableDebugOutput__doc__[] =
"Enables or disables calling LibXML2 callback from the default errors callback.\n";
static PyObject* PyXmlSec_PyEnableDebugOutput(PyObject *self, PyObject* args, PyObject* kwargs) {
    static char *kwlist[] = { "enabled", NULL};
    PyObject* enabled = Py_True;
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|O:enable_debug_trace", kwlist, &enabled)) {
        return NULL;
    }
    xmlSecErrorsDefaultCallbackEnableOutput(PyObject_IsTrue(enabled));
    Py_RETURN_NONE;
}

static PyMethodDef PyXmlSec_MainMethods[] = {
    {
        "init",
        (PyCFunction)PyXmlSec_PyInit,
        METH_NOARGS,
        PyXmlSec_PyInit__doc__
    },
    {
        "shutdown",
        (PyCFunction)PyXmlSec_PyShutdown,
        METH_NOARGS,
        PyXmlSec_PyShutdown__doc__
    },
    {
        "enable_debug_trace",
        (PyCFunction)PyXmlSec_PyEnableDebugOutput,
        METH_VARARGS|METH_KEYWORDS,
        PyXmlSec_PyEnableDebugOutput__doc__
    },
    {NULL, NULL} /* sentinel */
};

// modules entry points
// loads lxml module
int PyXmlSec_InitLxmlModule(void);
// constants
int PyXmlSec_ConstantsModule_Init(PyObject* package);
// exceptions
int PyXmlSec_ExceptionsModule_Init(PyObject* package);
// keys management
int PyXmlSec_KeyModule_Init(PyObject* package);
// init lxml.tree integration
int PyXmlSec_TreeModule_Init(PyObject* package);
// digital signature management
int PyXmlSec_DSModule_Init(PyObject* package);
// encryption management
int PyXmlSec_EncModule_Init(PyObject* package);
// templates management
int PyXmlSec_TemplateModule_Init(PyObject* package);

#ifdef PY3K

static int PyXmlSec_PyClear(PyObject *self) {
    PyXmlSec_Free(free_mode);
    return 0;
}

static PyModuleDef PyXmlSecModule = {
    PyModuleDef_HEAD_INIT,
    STRINGIFY(MODULE_NAME), /* name of module */
    STRINGIFY(MODULE_DOC),             /* module documentation, may be NULL */
    -1,                     /* size of per-interpreter state of the module,
                               or -1 if the module keeps state in global variables. */
    PyXmlSec_MainMethods,   /* m_methods */
    NULL,                   /* m_slots */
    NULL,                   /* m_traverse */
    PyXmlSec_PyClear,       /* m_clear */
    NULL,                   /* m_free */
};

#define PYENTRY_FUNC_NAME JOIN(PyInit_, MODULE_NAME)
#define PY_MOD_RETURN(m) return m
#else // PY3K
#define PYENTRY_FUNC_NAME JOIN(init, MODULE_NAME)
#define PY_MOD_RETURN(m) return


static void PyXmlSec_PyModuleGuard__del__(PyObject* self)
{
    PyXmlSec_Free(free_mode);
    Py_TYPE(self)->tp_free(self);
}

// we need guard to free resources on module unload
typedef struct {
    PyObject_HEAD
} PyXmlSec_PyModuleGuard;

static PyTypeObject PyXmlSec_PyModuleGuardType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    STRINGIFY(MODULE_NAME) "__Guard",              /* tp_name */
    sizeof(PyXmlSec_PyModuleGuard),                /* tp_basicsize */
    0,                                             /* tp_itemsize */
    PyXmlSec_PyModuleGuard__del__,                 /* tp_dealloc */
    0,                                             /* tp_print */
    0,                                             /* tp_getattr */
    0,                                             /* tp_setattr */
    0,                                             /* tp_reserved */
    0,                                             /* tp_repr */
    0,                                             /* tp_as_number */
    0,                                             /* tp_as_sequence */
    0,                                             /* tp_as_mapping */
    0,                                             /* tp_hash  */
    0,                                             /* tp_call */
    0,                                             /* tp_str */
    0,                                             /* tp_getattro */
    0,                                             /* tp_setattro */
    0,                                             /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,                            /* tp_flags */
};
#endif  // PY3K

PyMODINIT_FUNC
PYENTRY_FUNC_NAME(void)
{
    PyObject *module = NULL;
#ifdef PY3K
    module = PyModule_Create(&PyXmlSecModule);
#else
    module = Py_InitModule3(STRINGIFY(MODULE_NAME), PyXmlSec_MainMethods, STRINGIFY(MODULE_DOC));
#endif
    if (!module) {
        PY_MOD_RETURN(NULL); /* this really should never happen */
    }

    if (PyXmlSec_Init() < 0) goto ON_FAIL;

#ifndef PY3K
    if (PyType_Ready(&PyXmlSec_PyModuleGuardType) < 0) goto ON_FAIL;
    // added guard to free resources on module unload
    if (PyModule_AddObject(module, "__guard", _PyObject_New(&PyXmlSec_PyModuleGuardType)) < 0) goto ON_FAIL;
#endif

    if (PyModule_AddStringConstant(module, "__version__", STRINGIFY(MODULE_VERSION)) < 0) goto ON_FAIL;

    if (PyXmlSec_InitLxmlModule() < 0) goto ON_FAIL;
    /* Populate final object settings */
    if (PyXmlSec_ConstantsModule_Init(module) < 0) goto ON_FAIL;
    if (PyXmlSec_ExceptionsModule_Init(module) < 0) goto ON_FAIL;
    if (PyXmlSec_KeyModule_Init(module) < 0) goto ON_FAIL;
    if (PyXmlSec_TreeModule_Init(module) < 0) goto ON_FAIL;
    if (PyXmlSec_DSModule_Init(module) < 0) goto ON_FAIL;
    if (PyXmlSec_EncModule_Init(module) < 0) goto ON_FAIL;
    if (PyXmlSec_TemplateModule_Init(module) < 0) goto ON_FAIL;

    PY_MOD_RETURN(module);

ON_FAIL:
    Py_DECREF(module);
    PY_MOD_RETURN(NULL);
}
