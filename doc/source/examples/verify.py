from lxml import etree

import xmlsec

with open('sign1-res.xml') as fp:
    template = etree.parse(fp).getroot()

xmlsec.tree.add_ids(template, ["ID"])
signature_node = xmlsec.tree.find_node(template, xmlsec.constants.NodeSignature)
# Create a digital signature context (no key manager is needed).
ctx = xmlsec.SignatureContext()
key = xmlsec.Key.from_file('rsapub.pem', xmlsec.constants.KeyDataFormatPem)
# Set the key on the context.
ctx.key = key
ctx.verify(signature_node)
