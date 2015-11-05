from lxml.includes.tree cimport const_xmlChar, xmlNode, xmlDoc


cdef extern from "xmlsec.h":  # xmlsec/xmltree.h

    # const_xmlChar* xmlSecGetNodeNsHref(xmlNode* node)

    # bint xmlSecCheckNodeName(
    #     xmlNode* node, const_xmlChar* name, const_xmlChar* ns)

    # xmlNode* xmlSecGetNextElementNode(xmlNode* node)

    xmlNode* xmlSecFindChild(
        xmlNode* parent, const_xmlChar* name, const_xmlChar* ns) nogil

    xmlNode* xmlSecFindParent(
        xmlNode* node, const_xmlChar* name, const_xmlChar* ns) nogil

    xmlNode* xmlSecFindNode(
        xmlNode* parent, const_xmlChar* name, const_xmlChar* ns) nogil

    # xmlNode* xmlSecAddChild(
    #     xmlNode* parent, const_xmlChar* name, const_xmlChar* ns)

    # xmlNode* xmlSecAddChildNode(xmlNode* parent, xmlNode* child)

    # xmlNode* xmlSecAddNextSibling(
    #     xmlNode* node, const_xmlChar* name, const_xmlChar* ns)

    # xmlNode* xmlSecAddPrevSibling(
    #     xmlNode* node, const_xmlChar* name, const_xmlChar* ns)

    # int xmlSecReplaceNode(xmlNode* node, xmlNode* new_node)

    # int xmlSecReplaceNodeAndReturn(
    #     xmlNode* node, xmlNode* new_node, xmlNode** replaced)

    # int xmlSecReplaceContent(xmlNode* node, xmlNode* new_node)

    # int xmlSecReplaceContentAndReturn(
    #     xmlNode* node, xmlNode* new_node, xmlNode** replaced)

    # int xmlSecReplaceNodeBuffer(
    #     xmlNode* node, const_xmlSecByte* buffer, xmlSecSize size)

    # int xmlSecReplaceNodeBufferAndReturn(
    #     xmlNode* node, const_xmlSecByte* buffer, xmlSecSize size,
    #     xmlNode** replaced)

    # int xmlSecNodeEncodeAndSetContent(xmlNode* node, const_xmlChar* buffer)

    int xmlSecAddIDs(xmlDoc* document, xmlNode* node, const_xmlChar** ids) nogil

    # int xmlSecGenerateAndAddID(
    #     xmlNode* node, const_xmlChar* name, const_xmlChar* prefix)

    # xmlChar* xmlSecGenerateID(const_xmlChar* prefix, xmlSecSize length)

    # xmlDoc* xmlSecCreateTree(const_xmlChar* name, const_xmlChar* ns)

    # bint xmlSecIsEmptyNode(xmlNode* node)

    # bint xmlSecIsEmptyString(const_xmlChar* text)

    # xmlChar* xmlSecGetQName(
    #     xmlNode* node, const_xmlChar* href, const_xmlChar* local)

    # int xmlSecPrintXmlString(FILE*, const_xmlChar* text)
