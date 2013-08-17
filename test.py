import xmlsec
from lxml import etree

# Create the signature template.
_xml = xmlsec.create_signature_template()

# Rewrap to change the namespace mapping.
nsmap = {'ds': _xml.nsmap[None]}
xml = etree.Element(_xml.tag, attrib=_xml.attrib, nsmap=nsmap)
xml.extend(_xml.getchildren())

# Add a reference.
ref = xmlsec.add_reference(xml, uri=b'#_34275907093489075620748690')

# Add an eveloped transformation declaration.
xmlsec.add_transform(ref, xmlsec.method.ENVELOPED)

# Add <ds:KeyInfo/> and <ds:X509Data/> nodes to store the key information.
info = xmlsec.ensure_key_info(xml)
xmlsec.add_x509_data(info)

# Create a digitial signature context.
ctx = xmlsec.SignatureContext()

# Load private key, assuming that there is no password.
key = ctx.load('key.pem')

# Load certificate and add to the key.
key.load_certificate('cert.pem')

# Sign the template.
ctx.sign(xml)

# Print out the message.
text = etree.tostring(xml, pretty_print=True).decode('utf8')
print(text)
