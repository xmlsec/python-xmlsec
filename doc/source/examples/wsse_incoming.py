"""Process a WS-Security (WSSE) secured SOAP response: Decrypt + Verify.

Companion to ``wsse_outgoing.py``. Loads a pre-built, signed-then-encrypted
envelope (``wsse-secured.xml``, produced the same way ``wsse_outgoing.py``
builds one) and reverses the two operations.

Order matters and is the mirror image of how the message was built: the
sender in this example signed the Body *before* encrypting it, so the
Signature's digest covers the plaintext Body. Verifying against the
still-encrypted Body would always fail, so this example decrypts first
(which restores the original Body content in place) and verifies second.
If a peer instead encrypts-then-signs (common for some backend-originated
responses, since it lets the signature cover exactly the bytes on the
wire), reverse the two steps here: verify first, decrypt second.
"""

import base64

from cryptography.hazmat.primitives import hashes, serialization
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

# Must match the peer's choices; see the note in wsse_outgoing.py about
# legacy (sha1 / tripledes / rsa-1_5) variants.
KEY_UNWRAP_HASH = hashes.SHA256()


def unwrap_session_key(security, private_key_file):
    """Recover the AES session key from the detached EncryptedKey.

    xmlsec's decrypt() only understands EncryptedData nodes (the mirror
    image of the encrypt_binary/encrypt_xml limitation described in
    wsse_outgoing.py), so a detached EncryptedKey has to be unwrapped by
    hand with the recipient's RSA private key.
    """
    with open(private_key_file, 'rb') as fp:
        private_key = serialization.load_pem_private_key(fp.read(), password=None)

    enc_key_node = security.find('xenc:EncryptedKey', NS)
    cipher_value = enc_key_node.find('.//xenc:CipherValue', NS)
    wrapped_key = base64.b64decode(cipher_value.text)

    return private_key.decrypt(
        wrapped_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=KEY_UNWRAP_HASH), algorithm=KEY_UNWRAP_HASH, label=None),
    )


def decrypt_body(envelope, security, session_key_bytes):
    enc_data_node = envelope.find('.//soapenv:Body/xenc:EncryptedData', NS)
    ctx = xmlsec.EncryptionContext()
    ctx.key = xmlsec.Key.from_binary_data(xmlsec.constants.KeyDataAes, session_key_bytes)
    ctx.decrypt(enc_data_node)


def verify_signature(envelope, sender_cert_file):
    xmlsec.tree.add_ids(envelope, [f'{{{NS["wsu"]}}}Id', 'Id', 'id'])
    signature_node = envelope.find('.//ds:Signature', NS)
    ctx = xmlsec.SignatureContext()
    ctx.key = xmlsec.Key.from_file(sender_cert_file, xmlsec.constants.KeyDataFormatCertPem)
    ctx.verify(signature_node)


if __name__ == '__main__':
    with open('wsse-secured.xml', 'rb') as fp:
        envelope = etree.parse(fp).getroot()

    security = envelope.find('.//wsse:Security', NS)

    session_key_bytes = unwrap_session_key(security, private_key_file='wssekey.pem')
    decrypt_body(envelope, security, session_key_bytes)
    verify_signature(envelope, sender_cert_file='wssecert.pem')

    print('Signature OK. Decrypted Body:')
    print(etree.tostring(envelope.find('soapenv:Body', NS)).decode())
