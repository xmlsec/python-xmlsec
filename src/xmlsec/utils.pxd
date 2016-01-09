from lxml.includes.tree cimport const_xmlChar


cdef inline const_xmlChar* _b(text):
    if text is None:
        return NULL

    if isinstance(text, str):
        text = text.encode('utf8')
        return text

    return text


cdef inline _u(const_xmlChar* text):
    return text.decode('utf8') if text != NULL else None


cdef extern from "xmlsec.h":  # xmlsec/xmlsec.h
    int xmlSecInit() nogil
    int xmlSecShutdown() nogil


cdef extern from "xmlsec.h":  # xmlsec/errors.h
    int xmlSecErrorsDefaultCallbackEnableOutput(int) nogil


cdef extern from "xmlsec.h":  # xmlsec/openssl/app.h
    int xmlSecOpenSSLInit() nogil
    int xmlSecOpenSSLShutdown() nogil

    int xmlSecOpenSSLAppInit(char* name) nogil
    int xmlSecOpenSSLAppShutdown() nogil
