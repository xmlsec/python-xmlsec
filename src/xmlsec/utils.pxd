from lxml.includes.tree cimport const_xmlChar


cdef inline const_xmlChar* _b(text):
    if isinstance(text, str):
        text = text.encode('utf8')
        return text

    return text


cdef inline _u(const_xmlChar* text):
    return text.decode('utf8')
