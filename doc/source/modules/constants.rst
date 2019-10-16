xmlsec.constants
----------------

Various constants used by the library

EncryptionType
**************
- *TypeEncContent* - http://www.w3.org/2001/04/xmlenc#Content
- *TypeEncElement* - http://www.w3.org/2001/04/xmlenc#Element

KeyData
*******
- *KeyDataName* - The <dsig:KeyName> processing class.
- *KeyDataValue* - The <dsig:KeyValue> processing class.
- *KeyDataRetrievalMethod* - The <dsig:RetrievalMethod> processing class.
- *KeyDataEncryptedKey* - The <enc:EncryptedKey> processing class.
- *KeyDataAes* - The AES key klass.
- *KeyDataDes* - The DES key klass.
- *KeyDataDsa* - The DSA key klass.
- *KeyDataEcdsa* - The ECDSA key klass.
- *KeyDataHmac* - The DHMAC key klass.
- *KeyDataRsa* - The RSA key klass.
- *KeyDataX509* - The X509 data klass.
- *KeyDataRawX509Cert* - The raw X509 certificate klass.

KeyDataFormat
*************
- *KeyDataFormatUnknown* - the key data format is unknown.
- *KeyDataFormatBinary* - the binary key data.
- *KeyDataFormatPem* - the PEM key data (cert or public/private key).
- *KeyDataFormatDer* - the DER key data (cert or public/private key).
- *KeyDataFormatPkcs8Pem* - the PKCS8 PEM private key.
- *KeyDataFormatPkcs8Der* - the PKCS8 DER private key.
- *KeyDataFormatPkcs12* - the PKCS12 format (bag of keys and certs)
- *KeyDataFormatCertPem* - the PEM cert.
- *KeyDataFormatCertDer* - the DER cert.

KeyDataType
***********
- *KeyDataTypeUnknown* - The key data type is unknown
- *KeyDataTypeNone* - The key data type is unknown
- *KeyDataTypePublic* - The key data contain a public key.
- *KeyDataTypePrivate* - The key data contain a private key.
- *KeyDataTypeSymmetric* - The key data contain a symmetric key.
- *KeyDataTypeSession* - The key data contain session key (one time key, not stored in keys manager).
- *KeyDataTypePermanent* - The key data contain permanent key (stored in keys manager).
- *KeyDataTypeTrusted* - The key data is trusted.
- *KeyDataTypeAny* - The key data is trusted.

Namespaces
**********

- *Ns*         - http://www.aleksey.com/xmlsec/2002
- *DSigNs*     - http://www.w3.org/2000/09/xmldsig#
- *EncNs*      - http://www.w3.org/2001/04/xmlenc#
- *XPathNs*    - http://www.w3.org/TR/1999/REC-xpath-19991116
- *XPath2Ns*   - http://www.w3.org/2002/06/xmldsig-filter2
- *XPointerNs* - http://www.w3.org/2001/04/xmldsig-more/xptr
- *Soap11Ns*   - http://schemas.xmlsoap.org/soap/envelope/
- *Soap12Ns*   - http://www.w3.org/2002/06/soap-envelope
- *NsExcC14N*  - http://www.w3.org/2001/10/xml-exc-c14n#
- *NsExcC14NWithComments* - http://www.w3.org/2001/10/xml-exc-c14n#WithComments

Nodes
*****
- *NodeSignature*              - Signature
- *NodeSignedInfo*             - SignedInfo
- *NodeCanonicalizationMethod* - CanonicalizationMethod
- *NodeSignatureMethod*        - SignatureMethod
- *NodeSignatureValue*         - SignatureValue
- *NodeSignatureProperties*    - SignatureProperties
- *NodeDigestMethod*           - DigestMethod
- *NodeDigestValue*            - DigestValue
- *NodeObject*                 - Object
- *NodeManifest*               - Manifest
- *NodeEncryptedData*          - EncryptedData
- *NodeEncryptedKey*           - EncryptedKey
- *NodeEncryptionMethod*       - EncryptionMethod
- *NodeEncryptionProperties*   - EncryptionProperties
- *NodeEncryptionProperty*     - EncryptionProperty
- *NodeCipherData*             - CipherData
- *NodeCipherValue*            - CipherValue
- *NodeCipherReference*        - CipherReference
- *NodeReference               - Reference
- *NodeReferenceList*          - ReferenceList
- *NodeDataReference*          - DataReference
- *NodeKeyReference*           - KeyReference
- *NodeKeyInfo*                - KeyInfo
- *NodeKeyName                 - KeyName
- *NodeKeyValue                - KeyValue
- *NodeX509Data                - X509Data

Transforms
**********

- *TransformUsageUnknown* - Transforms usage is unknown or undefined.
- *TransformUsageDSigTransform* - Transform could be used in <dsig:Transform>.
- *TransformUsageC14NMethod* - Transform could be used in <dsig:CanonicalizationMethod>.
- *TransformUsageDigestMethod* - Transform could be used in <dsig:DigestMethod>.
- *TransformUsageSignatureMethod* - Transform could be used in <dsig:SignatureMethod>.
- *TransformUsageEncryptionMethod* - Transform could be used in <enc:EncryptionMethod>.
- *TransformUsageAny* - Transform could be used for operation.
- *TransformInclC14N* - The regular (inclusive) C14N without comments transform klass.
- *TransformInclC14NWithComments* - The regular (inclusive) C14N with comments transform klass.
- *TransformInclC14N11* - The regular (inclusive) C14N 1.1 without comments transform klass.
- *TransformInclC14N11WithComments* - The regular (inclusive) C14N 1.1 with comments transform klass.
- *TransformExclC14N* - The exclusive C14N without comments transform klass.
- *TransformExclC14NWithComments* - The exclusive C14N with comments transform klass.
- *TransformEnveloped* - The "enveloped" transform klass.
- *TransformXPath* - The XPath transform klass.
- *TransformXPath2* - The XPath2 transform klass.
- *TransformXPointer* - The XPointer transform klass.
- *TransformXslt* - The XSLT transform klass.
- *TransformRemoveXmlTagsC14N* - The "remove all xml tags" transform klass (used before base64 transforms).
- *TransformVisa3DHack* - Selects node subtree by given node id string. The only reason why we need this is Visa3D protocol. It doesn't follow XML/XPointer/XMLDSig specs and allows invalid XPointer expressions in the URI attribute. Since we couldn't evaluate such expressions thru XPath/XPointer engine, we need to have this hack here.
- *TransformAes128Cbc* - The AES128 CBC cipher transform klass.
- *TransformAes192Cbc* - The AES192 CBC cipher transform klass.
- *TransformAes256Cbc* - The AES256 CBC cipher transform klass.
- *TransformKWAes128* - The AES 128 key wrap transform klass.
- *TransformKWAes192* - The AES 192 key wrap transform klass.
- *TransformKWAes256* - The AES 256 key wrap transform klass.
- *TransformDes3Cbc* - The DES3 CBC cipher transform klass.
- *TransformKWDes3* - The DES3 key wrap transform klass.
- *TransformDsaSha1* - The DSA-SHA1 signature transform klass.
- *TransformEcdsaSha1* - The ECDSA-SHA1 signature transform klass.
- *TransformEcdsaSha224* - The ECDSA-SHA224 signature transform klass.
- *TransformEcdsaSha256* - The ECDSA-SHA256 signature transform klass.
- *TransformEcdsaSha384* - The ECDS-SHA384 signature transform klass.
- *TransformEcdsaSha512* - The ECDSA-SHA512 signature transform klass.
- *TransformHmacMd5* - The HMAC with MD5 signature transform klass.
- *TransformHmacRipemd160* - The HMAC with RipeMD160 signature transform klass.
- *TransformHmacSha1* - The HMAC with SHA1 signature transform klass.
- *TransformHmacSha224* - The HMAC with SHA224 signature transform klass.
- *TransformHmacSha256* - The HMAC with SHA256 signature transform klass.
- *TransformHmacSha384* - The HMAC with SHA384 signature transform klass.
- *TransformHmacSha512* - The HMAC with SHA512 signature transform klass.
- *TransformRsaMd5* - The RSA-MD5 signature transform klass.
- *TransformRsaRipemd160* - The RSA-RIPEMD160 signature transform klass.
- *TransformRsaSha1* - The RSA-SHA1 signature transform klass.
- *TransformRsaSha224* - The RSA-SHA224 signature transform klass.
- *TransformRsaSha256* - The RSA-SHA256 signature transform klass.
- *TransformRsaSha384* - The RSA-SHA384 signature transform klass.
- *TransformRsaSha512* - The RSA-SHA512 signature transform klass.
- *TransformRsaPkcs1* - The RSA PKCS1 key transport transform klass.
- *TransformRsaOaep* - The RSA OAEP key transport transform klass.
- *TransformMd5* - The MD5 digest transform klass.
- *TransformRipemd160* - The RIPEMD160 digest transform klass.
- *TransformSha1* - The SHA1 digest transform klass.
- *TransformSha224* - The SHA224 digest transform klass.
- *TransformSha256* - The SHA256 digest transform klass.
- *TransformSha384* - The SHA384 digest transform klass.
- *TransformSha512* - The SHA512 digest transform klass.

:ref:`contents`
