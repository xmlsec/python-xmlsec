from lxml import etree

import xmlsec

with open('enc1-doc.xml') as fp:
    template = etree.parse(fp).getroot()

enc_data = xmlsec.template.encrypted_data_create(
    template,
    xmlsec.constants.TransformAes128Cbc,
    type=xmlsec.constants.TypeEncElement,
    ns="xenc",
)

xmlsec.template.encrypted_data_ensure_cipher_value(enc_data)
key_info = xmlsec.template.encrypted_data_ensure_key_info(enc_data, ns="dsig")
enc_key = xmlsec.template.add_encrypted_key(key_info, xmlsec.constants.TransformRsaOaep)
xmlsec.template.encrypted_data_ensure_cipher_value(enc_key)
data = template.find('./Data')

# Encryption
manager = xmlsec.KeysManager()
key = xmlsec.Key.from_file('rsacert.pem', xmlsec.constants.KeyDataFormatCertPem, None)
manager.add_key(key)

enc_ctx = xmlsec.EncryptionContext(manager)
enc_ctx.key = xmlsec.Key.generate(
    xmlsec.constants.KeyDataAes, 128, xmlsec.constants.KeyDataTypeSession
)
enc_data = enc_ctx.encrypt_xml(enc_data, data)
enc_method = xmlsec.tree.find_child(
    enc_data, xmlsec.constants.NodeEncryptionMethod, xmlsec.constants.EncNs
)
key_info = xmlsec.tree.find_child(
    enc_data, xmlsec.constants.NodeKeyInfo, xmlsec.constants.DSigNs
)
enc_method = xmlsec.tree.find_node(
    key_info, xmlsec.constants.NodeEncryptionMethod, xmlsec.constants.EncNs
)
cipher_value = xmlsec.tree.find_node(
    key_info, xmlsec.constants.NodeCipherValue, xmlsec.constants.EncNs
)
print(etree.tostring(cipher_value))
