from lxml import etree

import xmlsec

manager = xmlsec.KeysManager()
key = xmlsec.Key.from_file('rsakey.pem', xmlsec.constants.KeyDataFormatPem)
manager.add_key(key)
enc_ctx = xmlsec.EncryptionContext(manager)
root = etree.parse("enc1-res.xml").getroot()
enc_data = xmlsec.tree.find_child(root, "EncryptedData", xmlsec.constants.EncNs)
decrypted = enc_ctx.decrypt(enc_data)
print(etree.tostring(decrypted))
