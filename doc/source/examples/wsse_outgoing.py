"""Build a WS-Security (WSSE) secured SOAP request: UsernameToken + Sign + Encrypt.

xmlsec exposes XML-DSig and XML-Enc primitives, but WS-Security profiles
build a specific *combination* of them inside a SOAP ``<wsse:Security>``
header that xmlsec does not template for you. This example shows one
common, interoperable combination:

1. A UsernameToken (plain-text password) in the Security header.
2. An enveloped-style XML signature over the SOAP Body, referenced by an
   ``Id`` attribute (WS-Security "Reference" pattern, not the enveloped
   XPath transform).
3. A "detached" ``xenc:EncryptedKey`` living directly under
   ``wsse:Security`` (not nested inside the ``EncryptedData`` it protects,
   which is where ``encrypt_xml``/``encrypt_binary`` would normally put
   it). This is the shape most SOAP stacks expect for WS-Security 1.1.

Because that detached ``EncryptedKey`` is not part of the ``EncryptedData``
tree, xmlsec's ``EncryptionContext.encrypt_binary``/``encrypt_xml`` cannot
fill it in directly -- both require an ``xenc:EncryptedData`` node as the
target template (see ``xmlSecEncCtxEncDataNodeRead`` in xmlsec1, which
rejects an ``EncryptedKey`` node with "invalid node"). So this example
wraps the AES session key with RSA-OAEP using the ``cryptography`` package
and places the result in the ``EncryptedKey``'s ``CipherValue`` by hand,
while still using xmlsec's own template helpers to build the element and
xmlsec's ``EncryptionContext`` to encrypt the Body itself.

Order matters: this example signs the Body *before* encrypting it, so the
signature covers the plaintext. A receiver must therefore decrypt first
and verify second -- see ``wsse_incoming.py``. If you instead need to
encrypt before signing (e.g. because a peer's stack requires the signature
to cover ciphertext), reverse the two steps below and sign the
``EncryptedData``'s ``Id`` instead of the Body's.
"""

import base64
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from lxml import etree

import xmlsec

NS = {
    'soapenv': 'http://schemas.xmlsoap.org/soap/envelope/',
    'wsse': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd',
    'wsu': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd',
    'ds': 'http://www.w3.org/2000/09/xmldsig#',
    'xenc': 'http://www.w3.org/2001/04/xmlenc#',
}

# Recommended defaults. Some legacy WS-Security 1.0-era stacks only accept
# rsa-sha1 / tripledes-cbc / rsa-1_5 -- swap the constants below (and the
# `cryptography` padding/hash objects to match) if you must interop with
# one of those, but prefer these unless you are told otherwise.
SIGNATURE_TRANSFORM = xmlsec.constants.TransformRsaSha256
DIGEST_TRANSFORM = xmlsec.constants.TransformSha256
BODY_ENCRYPTION_TRANSFORM = xmlsec.constants.TransformAes128Cbc
KEY_WRAP_HASH = hashes.SHA256()


def add_security_header(envelope):
    header = envelope.find('soapenv:Header', NS)
    if header is None:
        header = etree.SubElement(envelope, f'{{{NS["soapenv"]}}}Header')
        envelope.insert(0, header)
    return etree.SubElement(
        header,
        f'{{{NS["wsse"]}}}Security',
        nsmap={'wsse': NS['wsse'], 'wsu': NS['wsu']},
    )


def add_username_token(security, username, password):
    token = etree.SubElement(security, f'{{{NS["wsse"]}}}UsernameToken')
    etree.SubElement(token, f'{{{NS["wsse"]}}}Username').text = username
    password_elem = etree.SubElement(token, f'{{{NS["wsse"]}}}Password')
    password_elem.set(
        'Type',
        'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText',
    )
    password_elem.text = password
    return token


def sign_body(envelope, security, signing_key_file, body_id='body'):
    body = envelope.find('soapenv:Body', NS)
    body.set(f'{{{NS["wsu"]}}}Id', body_id)
    xmlsec.tree.add_ids(envelope, [f'{{{NS["wsu"]}}}Id', 'Id', 'id'])

    signature_node = xmlsec.template.create(envelope, xmlsec.constants.TransformExclC14N, SIGNATURE_TRANSFORM)
    security.append(signature_node)

    reference = xmlsec.template.add_reference(signature_node, DIGEST_TRANSFORM, uri='#' + body_id)
    xmlsec.template.add_transform(reference, xmlsec.constants.TransformExclC14N)

    ctx = xmlsec.SignatureContext()
    ctx.key = xmlsec.Key.from_file(signing_key_file, xmlsec.constants.KeyDataFormatPem)
    ctx.sign(signature_node)
    return signature_node


def encrypt_body(envelope, security, recipient_cert_file, data_id='body-data', key_id='body-key'):
    body = envelope.find('soapenv:Body', NS)

    with open(recipient_cert_file, 'rb') as fp:
        recipient_cert = x509.load_pem_x509_certificate(fp.read())

    # 1. Generate a random session key and use it to encrypt the Body
    #    content with xmlsec, exactly like the plain `encrypt.py` example.
    session_key_bytes = os.urandom(16)  # 16 bytes = AES-128

    enc_data_template = xmlsec.template.encrypted_data_create(
        body,
        BODY_ENCRYPTION_TRANSFORM,
        type=xmlsec.constants.TypeEncContent,
        ns='xenc',
    )
    enc_data_template.set('Id', data_id)
    xmlsec.template.encrypted_data_ensure_cipher_value(enc_data_template)

    enc_ctx = xmlsec.EncryptionContext()
    enc_ctx.key = xmlsec.Key.from_binary_data(xmlsec.constants.KeyDataAes, session_key_bytes)
    enc_ctx.encrypt_xml(enc_data_template, body)

    # 2. Wrap the session key with the recipient's RSA public key ourselves
    #    (see module docstring for why xmlsec can't do this part for a
    #    detached EncryptedKey), and place it directly under Security.
    wrapped_key = recipient_cert.public_key().encrypt(
        session_key_bytes,
        padding.OAEP(mgf=padding.MGF1(algorithm=KEY_WRAP_HASH), algorithm=KEY_WRAP_HASH, label=None),
    )

    enc_key_node = xmlsec.template.add_encrypted_key(security, xmlsec.constants.TransformRsaOaep, id=key_id)
    xmlsec.template.encrypted_data_ensure_cipher_value(enc_key_node).text = base64.b64encode(wrapped_key).decode()

    reference_list = etree.SubElement(enc_key_node, f'{{{NS["xenc"]}}}ReferenceList')
    etree.SubElement(reference_list, f'{{{NS["xenc"]}}}DataReference').set('URI', '#' + data_id)

    # A detached EncryptedKey must come before anything that references it,
    # so it is expected as the first child of Security by most consumers.
    security.remove(enc_key_node)
    security.insert(0, enc_key_node)


if __name__ == '__main__':
    with open('wsse-tmpl.xml') as fp:
        envelope = etree.parse(fp, etree.XMLParser(remove_blank_text=True)).getroot()

    security = add_security_header(envelope)
    add_username_token(security, username='demo-user', password='demo-password')
    sign_body(envelope, security, signing_key_file='wssekey.pem')
    encrypt_body(envelope, security, recipient_cert_file='wssecert.pem')

    # NOTE: do not pretty-print before/after signing -- inserting
    # whitespace-only text nodes changes what exclusive C14N canonicalizes,
    # so a pretty-printed copy would no longer verify.
    print(etree.tostring(envelope).decode())
