``xmlsec.constants``
--------------------

Various constants used by the library.

EncryptionType
**************

.. data:: xmlsec.constants.TypeEncContent
   :annotation: = 'http://www.w3.org/2001/04/xmlenc#Content'

.. data:: xmlsec.constants.TypeEncElement
   :annotation: = 'http://www.w3.org/2001/04/xmlenc#Element'

KeyData
*******

.. class:: __KeyData

   Base type for all :samp:`KeyData{XXX}` constants.

.. data:: xmlsec.constants.KeyDataName

   The :xml:`<dsig:KeyName>` processing class.

.. data:: xmlsec.constants.KeyDataValue

   The :xml:`<dsig:KeyValue>` processing class.

.. data:: xmlsec.constants.KeyDataRetrievalMethod

   The :xml:`<dsig:RetrievalMethod>` processing class.

.. data:: xmlsec.constants.KeyDataEncryptedKey

   The :xml:`<enc:EncryptedKey>` processing class.

.. data:: xmlsec.constants.KeyDataAes

   The AES key klass.

.. data:: xmlsec.constants.KeyDataDes

   The DES key klass.

.. data:: xmlsec.constants.KeyDataDsa

   The DSA key klass.

.. data:: xmlsec.constants.KeyDataEcdsa

   The ECDSA key klass.

.. data:: xmlsec.constants.KeyDataHmac

   The DHMAC key klass.

.. data:: xmlsec.constants.KeyDataRsa

   The RSA key klass.

.. data:: xmlsec.constants.KeyDataX509

   The X509 data klass.

.. data:: xmlsec.constants.KeyDataRawX509Cert

   The raw X509 certificate klass.

KeyDataFormat
*************

.. data:: xmlsec.constants.KeyDataFormatUnknown

   the key data format is unknown.

.. data:: xmlsec.constants.KeyDataFormatBinary

   the binary key data.

.. data:: xmlsec.constants.KeyDataFormatPem

   the PEM key data (cert or public/private key).

.. data:: xmlsec.constants.KeyDataFormatDer

   the DER key data (cert or public/private key).

.. data:: xmlsec.constants.KeyDataFormatPkcs8Pem

   the PKCS8 PEM private key.

.. data:: xmlsec.constants.KeyDataFormatPkcs8Der

   the PKCS8 DER private key.

.. data:: xmlsec.constants.KeyDataFormatPkcs12

   the PKCS12 format (bag of keys and certs)

.. data:: xmlsec.constants.KeyDataFormatCertPem

   the PEM cert.

.. data:: xmlsec.constants.KeyDataFormatCertDer

   the DER cert.

KeyDataType
***********

.. data:: xmlsec.constants.KeyDataTypeUnknown

   The key data type is unknown

.. data:: xmlsec.constants.KeyDataTypeNone

   The key data type is unknown

.. data:: xmlsec.constants.KeyDataTypePublic

   The key data contain a public key.

.. data:: xmlsec.constants.KeyDataTypePrivate

   The key data contain a private key.

.. data:: xmlsec.constants.KeyDataTypeSymmetric

   The key data contain a symmetric key.

.. data:: xmlsec.constants.KeyDataTypeSession

   The key data contain session key (one time key, not stored in keys manager).

.. data:: xmlsec.constants.KeyDataTypePermanent

   The key data contain permanent key (stored in keys manager).

.. data:: xmlsec.constants.KeyDataTypeTrusted

   The key data is trusted.

.. data:: xmlsec.constants.KeyDataTypeAny

   The key data is trusted.

Namespaces
**********

.. data:: xmlsec.constants.Ns
   :annotation: = 'http://www.aleksey.com/xmlsec/2002'

.. data:: xmlsec.constants.DSigNs
   :annotation: = 'http://www.w3.org/2000/09/xmldsig#'

.. data:: xmlsec.constants.EncNs
   :annotation: = 'http://www.w3.org/2001/04/xmlenc#'

.. data:: xmlsec.constants.XPathNs
   :annotation: = 'http://www.w3.org/TR/1999/REC-xpath-19991116'

.. data:: xmlsec.constants.XPath2Ns
   :annotation: = 'http://www.w3.org/2002/06/xmldsig-filter2'

.. data:: xmlsec.constants.XPointerNs
   :annotation: = 'http://www.w3.org/2001/04/xmldsig-more/xptr'

.. data:: xmlsec.constants.Soap11Ns
   :annotation: = 'http://schemas.xmlsoap.org/soap/envelope/'

.. data:: xmlsec.constants.Soap12Ns
   :annotation: = 'http://www.w3.org/2002/06/soap-envelope'

.. data:: xmlsec.constants.NsExcC14N
   :annotation: = 'http://www.w3.org/2001/10/xml-exc-c14n#'

.. data:: xmlsec.constants.NsExcC14NWithComments
   :annotation: = 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments'

Nodes
*****

.. data:: xmlsec.constants.NodeSignature
   :annotation: = 'Signature'

.. data:: xmlsec.constants.NodeSignedInfo
   :annotation: = 'SignedInfo'

.. data:: xmlsec.constants.NodeCanonicalizationMethod
   :annotation: = 'CanonicalizationMethod'

.. data:: xmlsec.constants.NodeSignatureMethod
   :annotation: = 'SignatureMethod'

.. data:: xmlsec.constants.NodeSignatureValue
   :annotation: = 'SignatureValue'

.. data:: xmlsec.constants.NodeSignatureProperties
   :annotation: = 'SignatureProperties'

.. data:: xmlsec.constants.NodeDigestMethod
   :annotation: = 'DigestMethod'

.. data:: xmlsec.constants.NodeDigestValue
   :annotation: = 'DigestValue'

.. data:: xmlsec.constants.NodeObject
   :annotation: = 'Object'

.. data:: xmlsec.constants.NodeManifest
   :annotation: = 'Manifest'

.. data:: xmlsec.constants.NodeEncryptedData
   :annotation: = 'EncryptedData'

.. data:: xmlsec.constants.NodeEncryptedKey
   :annotation: = 'EncryptedKey'

.. data:: xmlsec.constants.NodeEncryptionMethod
   :annotation: = 'EncryptionMethod'

.. data:: xmlsec.constants.NodeEncryptionProperties
   :annotation: = 'EncryptionProperties'

.. data:: xmlsec.constants.NodeEncryptionProperty
   :annotation: = 'EncryptionProperty'

.. data:: xmlsec.constants.NodeCipherData
   :annotation: = 'CipherData'

.. data:: xmlsec.constants.NodeCipherValue
   :annotation: = 'CipherValue'

.. data:: xmlsec.constants.NodeCipherReference
   :annotation: = 'CipherReference'

.. data:: xmlsec.constants.NodeReference
   :annotation: = 'Reference'

.. data:: xmlsec.constants.NodeReferenceList
   :annotation: = 'ReferenceList'

.. data:: xmlsec.constants.NodeDataReference
   :annotation: = 'DataReference'

.. data:: xmlsec.constants.NodeKeyReference
   :annotation: = 'KeyReference'

.. data:: xmlsec.constants.NodeKeyInfo
   :annotation: = 'KeyInfo'

.. data:: xmlsec.constants.NodeKeyName
   :annotation: = 'KeyName'

.. data:: xmlsec.constants.NodeKeyValue
   :annotation: = 'KeyValue'

.. data:: xmlsec.constants.NodeX509Data
   :annotation: = 'X509Data'

Transforms
**********

.. class:: __Transform

   Base type for all :samp:`Transform{XXX}` constants.

.. data:: xmlsec.constants.TransformUsageUnknown

   Transforms usage is unknown or undefined.

.. data:: xmlsec.constants.TransformUsageDSigTransform

   Transform could be used in :xml:`<dsig:Transform>`.

.. data:: xmlsec.constants.TransformUsageC14NMethod

   Transform could be used in :xml:`<dsig:CanonicalizationMethod>`.

.. data:: xmlsec.constants.TransformUsageDigestMethod

   Transform could be used in :xml:`<dsig:DigestMethod>`.

.. data:: xmlsec.constants.TransformUsageSignatureMethod

   Transform could be used in :xml:`<dsig:SignatureMethod>`.

.. data:: xmlsec.constants.TransformUsageEncryptionMethod

   Transform could be used in :xml:`<enc:EncryptionMethod>`.

.. data:: xmlsec.constants.TransformUsageAny

   Transform could be used for operation.

.. data:: xmlsec.constants.TransformInclC14N

   The regular (inclusive) C14N without comments transform klass.

.. data:: xmlsec.constants.TransformInclC14NWithComments

   The regular (inclusive) C14N with comments transform klass.

.. data:: xmlsec.constants.TransformInclC14N11

   The regular (inclusive) C14N 1.1 without comments transform klass.

.. data:: xmlsec.constants.TransformInclC14N11WithComments

   The regular (inclusive) C14N 1.1 with comments transform klass.

.. data:: xmlsec.constants.TransformExclC14N

   The exclusive C14N without comments transform klass.

.. data:: xmlsec.constants.TransformExclC14NWithComments

   The exclusive C14N with comments transform klass.

.. data:: xmlsec.constants.TransformEnveloped

   The "enveloped" transform klass.

.. data:: xmlsec.constants.TransformXPath

   The XPath transform klass.

.. data:: xmlsec.constants.TransformXPath2

   The XPath2 transform klass.

.. data:: xmlsec.constants.TransformXPointer

   The XPointer transform klass.

.. data:: xmlsec.constants.TransformXslt

   The XSLT transform klass.

.. data:: xmlsec.constants.TransformRemoveXmlTagsC14N

   The "remove all xml tags" transform klass (used before base64 transforms).

.. data:: xmlsec.constants.TransformVisa3DHack

   Selects node subtree by given node id string. The only reason why we need this is Visa3D protocol. It doesn't follow XML/XPointer/XMLDSig specs and allows invalid XPointer expressions in the URI attribute. Since we couldn't evaluate such expressions thru XPath/XPointer engine, we need to have this hack here.

.. data:: xmlsec.constants.TransformAes128Cbc

   The AES128 CBC cipher transform klass.

.. data:: xmlsec.constants.TransformAes192Cbc

   The AES192 CBC cipher transform klass.

.. data:: xmlsec.constants.TransformAes256Cbc

   The AES256 CBC cipher transform klass.

.. data:: xmlsec.constants.TransformKWAes128

   The AES 128 key wrap transform klass.

.. data:: xmlsec.constants.TransformKWAes192

   The AES 192 key wrap transform klass.

.. data:: xmlsec.constants.TransformKWAes256

   The AES 256 key wrap transform klass.

.. data:: xmlsec.constants.TransformDes3Cbc

   The DES3 CBC cipher transform klass.

.. data:: xmlsec.constants.TransformKWDes3

   The DES3 key wrap transform klass.

.. data:: xmlsec.constants.TransformDsaSha1

   The DSA-SHA1 signature transform klass.

.. data:: xmlsec.constants.TransformEcdsaSha1

   The ECDSA-SHA1 signature transform klass.

.. data:: xmlsec.constants.TransformEcdsaSha224

   The ECDSA-SHA224 signature transform klass.

.. data:: xmlsec.constants.TransformEcdsaSha256

   The ECDSA-SHA256 signature transform klass.

.. data:: xmlsec.constants.TransformEcdsaSha384

   The ECDS-SHA384 signature transform klass.

.. data:: xmlsec.constants.TransformEcdsaSha512

   The ECDSA-SHA512 signature transform klass.

.. data:: xmlsec.constants.TransformHmacMd5

   The HMAC with MD5 signature transform klass.

.. data:: xmlsec.constants.TransformHmacRipemd160

   The HMAC with RipeMD160 signature transform klass.

.. data:: xmlsec.constants.TransformHmacSha1

   The HMAC with SHA1 signature transform klass.

.. data:: xmlsec.constants.TransformHmacSha224

   The HMAC with SHA224 signature transform klass.

.. data:: xmlsec.constants.TransformHmacSha256

   The HMAC with SHA256 signature transform klass.

.. data:: xmlsec.constants.TransformHmacSha384

   The HMAC with SHA384 signature transform klass.

.. data:: xmlsec.constants.TransformHmacSha512

   The HMAC with SHA512 signature transform klass.

.. data:: xmlsec.constants.TransformRsaMd5

   The RSA-MD5 signature transform klass.

.. data:: xmlsec.constants.TransformRsaRipemd160

   The RSA-RIPEMD160 signature transform klass.

.. data:: xmlsec.constants.TransformRsaSha1

   The RSA-SHA1 signature transform klass.

.. data:: xmlsec.constants.TransformRsaSha224

   The RSA-SHA224 signature transform klass.

.. data:: xmlsec.constants.TransformRsaSha256

   The RSA-SHA256 signature transform klass.

.. data:: xmlsec.constants.TransformRsaSha384

   The RSA-SHA384 signature transform klass.

.. data:: xmlsec.constants.TransformRsaSha512

   The RSA-SHA512 signature transform klass.

.. data:: xmlsec.constants.TransformRsaPkcs1

   The RSA PKCS1 key transport transform klass.

.. data:: xmlsec.constants.TransformRsaOaep

   The RSA OAEP key transport transform klass.

.. data:: xmlsec.constants.TransformMd5

   The MD5 digest transform klass.

.. data:: xmlsec.constants.TransformRipemd160

   The RIPEMD160 digest transform klass.

.. data:: xmlsec.constants.TransformSha1

   The SHA1 digest transform klass.

.. data:: xmlsec.constants.TransformSha224

   The SHA224 digest transform klass.

.. data:: xmlsec.constants.TransformSha256

   The SHA256 digest transform klass.

.. data:: xmlsec.constants.TransformSha384

   The SHA384 digest transform klass.

.. data:: xmlsec.constants.TransformSha512

   The SHA512 digest transform klass.

:ref:`contents`
