from os import path
from pytest import mark
import xmlsec
from lxml import etree
from .base import parse_xml, BASE_DIR


@mark.parametrize('index', range(1, 4))
def test_verify_with_pem_file(index):
    """Should verify a signed file using a key from a PEM file.
    """

    # Load the XML document.
    template = parse_xml('sign%d-res.xml' % index)

    # Find the <Signature/> node.
    signature_node = xmlsec.tree.find_node(template, xmlsec.Node.SIGNATURE)

    assert signature_node is not None
    assert signature_node.tag.endswith(xmlsec.Node.SIGNATURE)

    # /* load file */
    # doc = xmlParseFile(xml_file);
    # if ((doc == NULL) || (xmlDocGetRootElement(doc) == NULL)){
    #     fprintf(stderr, "Error: unable to parse file \"%s\"\n", xml_file);
    #     goto done;
    # }

    # /* find start node */
    # node = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeSignature, xmlSecDSigNs);
    # if(node == NULL) {
    #     fprintf(stderr, "Error: start node not found in \"%s\"\n", xml_file);
    #     goto done;
    # }

    # /* create signature context, we don't need keys manager in this example */
    # dsigCtx = xmlSecDSigCtxCreate(NULL);
    # if(dsigCtx == NULL) {
    #     fprintf(stderr,"Error: failed to create signature context\n");
    #     goto done;
    # }

    # /* load public key */
    # dsigCtx->signKey = xmlSecCryptoAppKeyLoad(key_file, xmlSecKeyDataFormatPem, NULL, NULL, NULL);
    # if(dsigCtx->signKey == NULL) {
    #     fprintf(stderr,"Error: failed to load public pem key from \"%s\"\n", key_file);
    #     goto done;
    # }

    # /* set key name to the file name, this is just an example! */
    # if(xmlSecKeySetName(dsigCtx->signKey, key_file) < 0) {
    #     fprintf(stderr,"Error: failed to set key name for key from \"%s\"\n", key_file);
    #     goto done;
    # }

    # /* Verify signature */
    # if(xmlSecDSigCtxVerify(dsigCtx, node) < 0) {
    #     fprintf(stderr,"Error: signature verify\n");
    #     goto done;
    # }

    # /* print verification result to stdout */
    # if(dsigCtx->status == xmlSecDSigStatusSucceeded) {
    #     fprintf(stdout, "Signature is OK\n");
    # } else {
    #     fprintf(stdout, "Signature is INVALID\n");
    # }
