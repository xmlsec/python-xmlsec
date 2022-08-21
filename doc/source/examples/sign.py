from lxml import etree

import xmlsec

with open('sign1-tmpl.xml') as fp:
    template = etree.parse(fp).getroot()

signature_node = xmlsec.tree.find_node(template, xmlsec.constants.NodeSignature)
ctx = xmlsec.SignatureContext()
key = xmlsec.Key.from_file('rsakey.pem', xmlsec.constants.KeyDataFormatPem)
ctx.key = key
ctx.sign(signature_node)
print(etree.tostring(template))
