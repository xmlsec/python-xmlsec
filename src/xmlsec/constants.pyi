import sys
from typing import NamedTuple

if sys.version_info >= (3, 8):
    from typing import Final, Literal
else:
    from typing_extensions import Final, Literal

class __KeyData(NamedTuple):  # __KeyData type
    href: str
    name: str

class __Transform(NamedTuple):  # __Transform type
    href: str
    name: str
    usage: int

DSigNs: Literal['http://www.w3.org/2000/09/xmldsig#'] = 'http://www.w3.org/2000/09/xmldsig#'
EncNs: Literal['http://www.w3.org/2001/04/xmlenc#'] = 'http://www.w3.org/2001/04/xmlenc#'
KeyDataAes: Final[__KeyData] = __KeyData('aes', 'http://www.aleksey.com/xmlsec/2002#AESKeyValue')
KeyDataDes: Final[__KeyData] = __KeyData('des', 'http://www.aleksey.com/xmlsec/2002#DESKeyValue')
KeyDataDsa: Final[__KeyData] = __KeyData('dsa', 'http://www.w3.org/2000/09/xmldsig#DSAKeyValue')
KeyDataEcdsa: Final[__KeyData] = __KeyData('ecdsa', 'http://scap.nist.gov/specifications/tmsad/#resource-1.0')
KeyDataEncryptedKey: Final[__KeyData] = __KeyData('enc-key', 'http://www.w3.org/2001/04/xmlenc#EncryptedKey')
KeyDataFormatBinary: Literal[1] = 1
KeyDataFormatCertDer: Literal[8] = 8
KeyDataFormatCertPem: Literal[7] = 7
KeyDataFormatDer: Literal[3] = 3
KeyDataFormatPem: Literal[2] = 2
KeyDataFormatPkcs12: Literal[6] = 6
KeyDataFormatPkcs8Der: Literal[5] = 5
KeyDataFormatPkcs8Pem: Literal[4] = 4
KeyDataFormatUnknown: Literal[0] = 0
KeyDataHmac: Final[__KeyData] = __KeyData('hmac', 'http://www.aleksey.com/xmlsec/2002#HMACKeyValue')
KeyDataName: Final[__KeyData] = __KeyData('key-name', '(null)')
KeyDataRawX509Cert: Final[__KeyData] = __KeyData('raw-x509-cert', 'http://www.w3.org/2000/09/xmldsig#rawX509Certificate')
KeyDataRetrievalMethod: Final[__KeyData] = __KeyData('retrieval-method', '(null)')
KeyDataRsa: Final[__KeyData] = __KeyData('rsa', 'http://www.w3.org/2000/09/xmldsig#RSAKeyValue')
KeyDataTypeAny: Literal[65535] = 65535
KeyDataTypeNone: Literal[0] = 0
KeyDataTypePermanent: Literal[16] = 16
KeyDataTypePrivate: Literal[2] = 2
KeyDataTypePublic: Literal[1] = 1
KeyDataTypeSession: Literal[8] = 8
KeyDataTypeSymmetric: Literal[4] = 4
KeyDataTypeTrusted: Literal[256] = 256
KeyDataTypeUnknown: Literal[0] = 0
KeyDataValue: Final[__KeyData] = __KeyData('key-value', '(null)')
KeyDataX509: Final[__KeyData] = __KeyData('x509', 'http://www.w3.org/2000/09/xmldsig#X509Data')
NodeCanonicalizationMethod: Literal['CanonicalizationMethod'] = 'CanonicalizationMethod'
NodeCipherData: Literal['CipherData'] = 'CipherData'
NodeCipherReference: Literal['CipherReference'] = 'CipherReference'
NodeCipherValue: Literal['CipherValue'] = 'CipherValue'
NodeDataReference: Literal['DataReference'] = 'DataReference'
NodeDigestMethod: Literal['DigestMethod'] = 'DigestMethod'
NodeDigestValue: Literal['DigestValue'] = 'DigestValue'
NodeEncryptedData: Literal['EncryptedData'] = 'EncryptedData'
NodeEncryptedKey: Literal['EncryptedKey'] = 'EncryptedKey'
NodeEncryptionMethod: Literal['EncryptionMethod'] = 'EncryptionMethod'
NodeEncryptionProperties: Literal['EncryptionProperties'] = 'EncryptionProperties'
NodeEncryptionProperty: Literal['EncryptionProperty'] = 'EncryptionProperty'
NodeKeyInfo: Literal['KeyInfo'] = 'KeyInfo'
NodeKeyName: Literal['KeyName'] = 'KeyName'
NodeKeyReference: Literal['KeyReference'] = 'KeyReference'
NodeKeyValue: Literal['KeyValue'] = 'KeyValue'
NodeManifest: Literal['Manifest'] = 'Manifest'
NodeObject: Literal['Object'] = 'Object'
NodeReference: Literal['Reference'] = 'Reference'
NodeReferenceList: Literal['ReferenceList'] = 'ReferenceList'
NodeSignature: Literal['Signature'] = 'Signature'
NodeSignatureMethod: Literal['SignatureMethod'] = 'SignatureMethod'
NodeSignatureProperties: Literal['SignatureProperties'] = 'SignatureProperties'
NodeSignatureValue: Literal['SignatureValue'] = 'SignatureValue'
NodeSignedInfo: Literal['SignedInfo'] = 'SignedInfo'
NodeX509Data: Literal['X509Data'] = 'X509Data'
Ns: Literal['http://www.aleksey.com/xmlsec/2002'] = 'http://www.aleksey.com/xmlsec/2002'
NsExcC14N: Literal['http://www.w3.org/2001/10/xml-exc-c14n#'] = 'http://www.w3.org/2001/10/xml-exc-c14n#'
NsExcC14NWithComments: Literal[
    'http://www.w3.org/2001/10/xml-exc-c14n#WithComments'
] = 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments'
Soap11Ns: Literal['http://schemas.xmlsoap.org/soap/envelope/'] = 'http://schemas.xmlsoap.org/soap/envelope/'
Soap12Ns: Literal['http://www.w3.org/2002/06/soap-envelope'] = 'http://www.w3.org/2002/06/soap-envelope'
TransformAes128Cbc: Final[__Transform] = __Transform('aes128-cbc', 'http://www.w3.org/2001/04/xmlenc#aes128-cbc', 16)
TransformAes192Cbc: Final[__Transform] = __Transform('aes192-cbc', 'http://www.w3.org/2001/04/xmlenc#aes192-cbc', 16)
TransformAes256Cbc: Final[__Transform] = __Transform('aes256-cbc', 'http://www.w3.org/2001/04/xmlenc#aes256-cbc', 16)
TransformDes3Cbc: Final[__Transform] = __Transform('tripledes-cbc', 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc', 16)
TransformDsaSha1: Final[__Transform] = __Transform('dsa-sha1', 'http://www.w3.org/2000/09/xmldsig#dsa-sha1', 8)
TransformEcdsaSha1: Final[__Transform] = __Transform('ecdsa-sha1', 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1', 8)
TransformEcdsaSha224: Final[__Transform] = __Transform('ecdsa-sha224', 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224', 8)
TransformEcdsaSha256: Final[__Transform] = __Transform('ecdsa-sha256', 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256', 8)
TransformEcdsaSha384: Final[__Transform] = __Transform('ecdsa-sha384', 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384', 8)
TransformEcdsaSha512: Final[__Transform] = __Transform('ecdsa-sha512', 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512', 8)
TransformEnveloped: Final[__Transform] = __Transform(
    'enveloped-signature', 'http://www.w3.org/2000/09/xmldsig#enveloped-signature', 1
)
TransformExclC14N: Final[__Transform] = __Transform('exc-c14n', 'http://www.w3.org/2001/10/xml-exc-c14n#', 3)
TransformExclC14NWithComments: Final[__Transform] = __Transform(
    'exc-c14n-with-comments', 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments', 3
)
TransformHmacMd5: Final[__Transform] = __Transform('hmac-md5', 'http://www.w3.org/2001/04/xmldsig-more#hmac-md5', 8)
TransformHmacRipemd160: Final[__Transform] = __Transform(
    'hmac-ripemd160', 'http://www.w3.org/2001/04/xmldsig-more#hmac-ripemd160', 8
)
TransformHmacSha1: Final[__Transform] = __Transform('hmac-sha1', 'http://www.w3.org/2000/09/xmldsig#hmac-sha1', 8)
TransformHmacSha224: Final[__Transform] = __Transform('hmac-sha224', 'http://www.w3.org/2001/04/xmldsig-more#hmac-sha224', 8)
TransformHmacSha256: Final[__Transform] = __Transform('hmac-sha256', 'http://www.w3.org/2001/04/xmldsig-more#hmac-sha256', 8)
TransformHmacSha384: Final[__Transform] = __Transform('hmac-sha384', 'http://www.w3.org/2001/04/xmldsig-more#hmac-sha384', 8)
TransformHmacSha512: Final[__Transform] = __Transform('hmac-sha512', 'http://www.w3.org/2001/04/xmldsig-more#hmac-sha512', 8)
TransformInclC14N: Final[__Transform] = __Transform('c14n', 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315', 3)
TransformInclC14N11: Final[__Transform] = __Transform('c14n11', 'http://www.w3.org/2006/12/xml-c14n11', 3)
TransformInclC14N11WithComments: Final[__Transform] = __Transform(
    'c14n11-with-comments', 'http://www.w3.org/2006/12/xml-c14n11#WithComments', 3
)
TransformInclC14NWithComments: Final[__Transform] = __Transform(
    'c14n-with-comments', 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments', 3
)
TransformKWAes128: Final[__Transform] = __Transform('kw-aes128', 'http://www.w3.org/2001/04/xmlenc#kw-aes128', 16)
TransformKWAes192: Final[__Transform] = __Transform('kw-aes192', 'http://www.w3.org/2001/04/xmlenc#kw-aes192', 16)
TransformKWAes256: Final[__Transform] = __Transform('kw-aes256', 'http://www.w3.org/2001/04/xmlenc#kw-aes256', 16)
TransformKWDes3: Final[__Transform] = __Transform('kw-tripledes', 'http://www.w3.org/2001/04/xmlenc#kw-tripledes', 16)
TransformMd5: Final[__Transform] = __Transform('md5', 'http://www.w3.org/2001/04/xmldsig-more#md5', 4)
TransformRemoveXmlTagsC14N: Final[__Transform] = __Transform('remove-xml-tags-transform', '(null)', 3)
TransformRipemd160: Final[__Transform] = __Transform('ripemd160', 'http://www.w3.org/2001/04/xmlenc#ripemd160', 4)
TransformRsaMd5: Final[__Transform] = __Transform('rsa-md5', 'http://www.w3.org/2001/04/xmldsig-more#rsa-md5', 8)
TransformRsaOaep: Final[__Transform] = __Transform('rsa-oaep-mgf1p', 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p', 16)
TransformRsaPkcs1: Final[__Transform] = __Transform('rsa-1_5', 'http://www.w3.org/2001/04/xmlenc#rsa-1_5', 16)
TransformRsaRipemd160: Final[__Transform] = __Transform(
    'rsa-ripemd160', 'http://www.w3.org/2001/04/xmldsig-more#rsa-ripemd160', 8
)
TransformRsaSha1: Final[__Transform] = __Transform('rsa-sha1', 'http://www.w3.org/2000/09/xmldsig#rsa-sha1', 8)
TransformRsaSha224: Final[__Transform] = __Transform('rsa-sha224', 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha224', 8)
TransformRsaSha256: Final[__Transform] = __Transform('rsa-sha256', 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256', 8)
TransformRsaSha384: Final[__Transform] = __Transform('rsa-sha384', 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384', 8)
TransformRsaSha512: Final[__Transform] = __Transform('rsa-sha512', 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512', 8)
TransformSha1: Final[__Transform] = __Transform('sha1', 'http://www.w3.org/2000/09/xmldsig#sha1', 4)
TransformSha224: Final[__Transform] = __Transform('sha224', 'http://www.w3.org/2001/04/xmldsig-more#sha224', 4)
TransformSha256: Final[__Transform] = __Transform('sha256', 'http://www.w3.org/2001/04/xmlenc#sha256', 4)
TransformSha384: Final[__Transform] = __Transform('sha384', 'http://www.w3.org/2001/04/xmldsig-more#sha384', 4)
TransformSha512: Final[__Transform] = __Transform('sha512', 'http://www.w3.org/2001/04/xmlenc#sha512', 4)
TransformUsageAny: Literal[65535] = 65535
TransformUsageC14NMethod: Literal[2] = 2
TransformUsageDSigTransform: Literal[1] = 1
TransformUsageDigestMethod: Literal[4] = 4
TransformUsageEncryptionMethod: Literal[16] = 16
TransformUsageSignatureMethod: Literal[8] = 8
TransformUsageUnknown: Literal[0] = 0
TransformVisa3DHack: Final[__Transform] = __Transform('Visa3DHackTransform', '(null)', 1)
TransformXPath: Final[__Transform] = __Transform('xpath', 'http://www.w3.org/TR/1999/REC-xpath-19991116', 1)
TransformXPath2: Final[__Transform] = __Transform('xpath2', 'http://www.w3.org/2002/06/xmldsig-filter2', 1)
TransformXPointer: Final[__Transform] = __Transform('xpointer', 'http://www.w3.org/2001/04/xmldsig-more/xptr', 1)
TransformXslt: Final[__Transform] = __Transform('xslt', 'http://www.w3.org/TR/1999/REC-xslt-19991116', 1)
TypeEncContent: Literal['http://www.w3.org/2001/04/xmlenc#Content'] = 'http://www.w3.org/2001/04/xmlenc#Content'
TypeEncElement: Literal['http://www.w3.org/2001/04/xmlenc#Element'] = 'http://www.w3.org/2001/04/xmlenc#Element'
XPath2Ns: Literal['http://www.w3.org/2002/06/xmldsig-filter2'] = 'http://www.w3.org/2002/06/xmldsig-filter2'
XPathNs: Literal['http://www.w3.org/TR/1999/REC-xpath-19991116'] = 'http://www.w3.org/TR/1999/REC-xpath-19991116'
XPointerNs: Literal['http://www.w3.org/2001/04/xmldsig-more/xptr'] = 'http://www.w3.org/2001/04/xmldsig-more/xptr'
