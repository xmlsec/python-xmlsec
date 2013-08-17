import atexit
from xmlsec cimport *
from etreepublic cimport _Element, _ElementTree, _Document
from etreepublic cimport import_lxml__etree, pyunicode, elementFactory
from tree cimport xmlNode, xmlDoc
from lxml.etree import ElementTree

# Ensure internal lxml utilities are initialized for this module.
import_lxml__etree()


def _init():
    """Initialize the library for general operation.

    This is called upon library import and does not need to be called
    again (unless @ref _shutdown is called explicitly).
    """
    r = xmlSecInit()
    if r != 0:
        return False

    r = xmlSecCryptoInit()
    if r != 0:
        return False

    r = xmlSecCryptoAppInit(NULL)
    return r == 0

if not _init():
    raise RuntimeError('Failed to initialize the xmlsec library.')


@atexit.register
def _shutdown():
    """Shutdown the library and cleanup any leftover resources.

    This is called automatically upon interpreter termination and
    should not need to be called explicitly.
    """
    r = xmlSecShutdown()
    if r != 0:
        return False

    r = xmlSecCryptoShutdown()
    if r != 0:
        return False

    r = xmlSecCryptoAppShutdown()
    return r == 0


cdef make_document():
    # Create a new element tree object and return its newly created
    # document as lxml does not expose any other way to make a Document.
    cdef _ElementTree tree = ElementTree()
    return tree._doc


cdef inline xmlChar_to_python(xmlChar * xs):
  if xs == NULL: return None
  return pyunicode(xs)


cdef inline char * string_or_null(s):
  return NULL if s is None else <char *> s


cdef class _Transform:
  cdef xmlSecTransformId id

  property name:
    def __get__(self):
        return xmlChar_to_python(<xmlChar*>self.id.name)

  property href:
    def __get__(self):
        return xmlChar_to_python(<xmlChar*>self.id.href)


cdef _mkti(xmlSecTransformId id):
    cdef _Transform o = _Transform()
    o.id = id
    return o


class method:
    """
    Constants the define cryptographic and canonicalization
    signature methods.
    """

    INCLUSIVE_C14N = _mkti(xmlSecTransformInclC14NId)
    INCLUSIVE_C14N_COMMENTS = _mkti(xmlSecTransformInclC14NWithCommentsId)

    EXCLUSIVE_C14N = _mkti(xmlSecTransformExclC14NId)
    EXCLUSIVE_C14N_COMMENTS = _mkti(xmlSecTransformExclC14NWithCommentsId)

    ENVELOPED = _mkti(xmlSecTransformEnvelopedId)

    XPATH = _mkti(xmlSecTransformXPathId)
    XPATH2 = _mkti(xmlSecTransformXPath2Id)
    XPOINTER = _mkti(xmlSecTransformXPointerId)
    XSLT = _mkti(xmlSecTransformXsltId)

    REMOVE_XML_TAGS_C14N = _mkti(xmlSecTransformRemoveXmlTagsC14NId)

    VISA3D_HACK = _mkti(xmlSecTransformVisa3DHackId)

    AES128 = _mkti(xmlSecTransformAes128CbcId)
    AES192 = _mkti(xmlSecTransformAes192CbcId)
    AES256 = _mkti(xmlSecTransformAes256CbcId)

    KW_AES128 = _mkti(xmlSecTransformKWAes128Id)
    KW_AES192 = _mkti(xmlSecTransformKWAes192Id)
    KW_AES256 = _mkti(xmlSecTransformKWAes256Id)

    DES3 = _mkti(xmlSecTransformDes3CbcId)

    KW_DES3 = _mkti(xmlSecTransformKWDes3Id)

    DSA_SHA1 = _mkti(xmlSecTransformDsaSha1Id)

    HMAC_MD5 = _mkti(xmlSecTransformHmacMd5Id)
    HMAC_RIPEMD160 = _mkti(xmlSecTransformHmacRipemd160Id)
    HMAC_SHA1 = _mkti(xmlSecTransformHmacSha1Id)
    HMAC_SHA224 = _mkti(xmlSecTransformHmacSha224Id)
    HMAC_SHA256 = _mkti(xmlSecTransformHmacSha256Id)
    HMAC_SHA384 = _mkti(xmlSecTransformHmacSha384Id)
    HMAC_SHA512 = _mkti(xmlSecTransformHmacSha512Id)

    MD5 = _mkti(xmlSecTransformMd5Id)

    RIPEMD160 = _mkti(xmlSecTransformRipemd160Id)

    RSA_MD5 = _mkti(xmlSecTransformRsaMd5Id)
    RSA_RIPEMD160 = _mkti(xmlSecTransformRsaRipemd160Id)
    RSA_SHA1 = _mkti(xmlSecTransformRsaSha1Id)
    RSA_SHA224 = _mkti(xmlSecTransformRsaSha224Id)
    RSA_SHA256 = _mkti(xmlSecTransformRsaSha256Id)
    RSA_SHA384 = _mkti(xmlSecTransformRsaSha384Id)
    RSA_SHA512 = _mkti(xmlSecTransformRsaSha512Id)
    RSA_PKCS1 = _mkti(xmlSecTransformRsaPkcs1Id)
    RSA_OAEP = _mkti(xmlSecTransformRsaOaepId)

    SHA1 = _mkti(xmlSecTransformSha1Id)
    SHA224 = _mkti(xmlSecTransformSha224Id)
    SHA256 = _mkti(xmlSecTransformSha256Id)
    SHA384 = _mkti(xmlSecTransformSha384Id)
    SHA512 = _mkti(xmlSecTransformSha512Id)


def create_signature_template(
        _Transform canonicalization_method=method.EXCLUSIVE_C14N,
        _Transform signature_method=method.RSA_SHA1):
    """Creates a new XML signature template.
    """

    cdef _Document doc
    cdef xmlNode* c_node

    # Create a new XML document instance.
    doc = make_document()

    # Create the <dsig:Signature/> node.
    c_node = xmlSecTmplSignatureCreate(
        doc._c_doc,
        canonicalization_method.id,
        signature_method.id,
        NULL)

    # Return the constructed node.
    return elementFactory(doc, c_node)


def add_reference(
        _Element node not None,
        _Transform digest_method=method.RSA_SHA1,
        const_xmlChar* id=NULL,
        const_xmlChar* uri=NULL,
        const_xmlChar* type=NULL):
    """
    Adds <ds:Reference/> node with given URI, Id and
    Type attributes and the required children <ds:DigestMethod/> and
    <ds:DigestValue/> to the <ds:SignedInfo/> child.
    """

    cdef xmlNode* c_node = node._c_node

    c_node = xmlSecTmplSignatureAddReference(
        c_node, digest_method.id, id, uri, type)

    return elementFactory(node._doc, c_node)


def add_transform(_Element node not None, _Transform method not None):
    """Adds <ds:Transform/> node to the <ds:Reference/> node.
    """

    cdef xmlNode* c_node = node._c_node

    c_node = xmlSecTmplReferenceAddTransform(c_node, method.id)

    return elementFactory(node._doc, c_node)


def ensure_key_info(_Element node not None, const_xmlChar* id=NULL):
    """Adds (if necessary) <ds:KeyInfo/> node to the <ds:Signature/>.
    """

    cdef xmlNode* c_node = node._c_node

    c_node = xmlSecTmplSignatureEnsureKeyInfo(c_node, id)

    return elementFactory(node._doc, c_node)


def add_key_name(_Element node not None, const_xmlChar* name=NULL):
    """Adds <ds:KeyName/> node to the <ds:KeyInfo/> node.
    """

    cdef xmlNode* c_node = node._c_node

    c_node = xmlSecTmplKeyInfoAddKeyName(c_node, name)

    return elementFactory(node._doc, c_node)


def add_x509_data(_Element node not None):
    """Adds <ds:X509Data/> node to the <ds:KeyInfo/> node.
    """

    cdef xmlNode* c_node = node._c_node

    c_node = xmlSecTmplKeyInfoAddX509Data(c_node)

    return elementFactory(node._doc, c_node)


# cdef class Key:
#     cdef xmlSecKeyPtr _handle

#     def __dealloc__(self):
#         if self._handle != NULL:
#             xmlSecKeyDestroy(self._handle)

#     @classmethod
#     def load(
#             cls,
#             char* filename,
#             xmlSecKeyDataFormat format,
#             char* password=NULL):
#         """Load PKI key from the specified filename.
#         """

#         cdef xmlSecKeyPtr handle

#         handle = xmlSecCryptoAppKeyLoad(
#             filename, format, password, NULL, NULL)

#         if  handle == NULL:
#             raise ValueError('Failed to load the key from file', filename)

#         cdef Key instance = cls()
#         instance._handle = handle

#         return instance


# cdef class SignatureContext:
#     cdef xmlSecDSigCtxPtr _handle

#     def __cinit__(self): # , KeysMngr manager=None):
#         # cdef xmlSecKeysMngrPtr _mngr

#         # _mngr = mngr.mngr if mngr is not None else NULL
#         self._handle = xmlSecDSigCtxCreate(NULL)
#         if self._handle == NULL:
#             raise RuntimeError("Failed to create digital signature context.")

#     def __dealloc__(self):
#         if self._handle != NULL:
#             xmlSecDSigCtxDestroy(self._handle)
