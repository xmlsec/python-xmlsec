from utils cimport *

from logging import getLogger
logger = getLogger(__name__)

__all__ = [
    'init',
    'shutdown'
]


cdef void _error_callback(char *filename, int line, char *func,
                          char *errorObject, char *errorSubject,
                          int reason, char * msg) with gil:
    if filename == NULL: filename = "unknown"
    if func == NULL: func = "unknown"
    if errorObject == NULL: errorObject = "unknown"
    if errorSubject == NULL: errorSubject = "unknown"
    if msg == NULL: msg = ""

    logger.error(
        'internal xmlsec error: {msg} {obj} {subject} [{filename} in {func}]'.format(
            msg=msg.decode('utf8'),
            obj=errorObject.decode('utf8'),
            subject=errorSubject.decode('utf8'),
            filename=filename.decode('utf8'),
            func=func.decode('utf8')))


def init():
    """Initialize the library for general operation.

    This is called upon library import and does not need to be called
    again (unless @ref _shutdown is called explicitly).
    """
    r = xmlSecInit()
    if r != 0:
        return False

    r = xmlSecCryptoInit()
    if r != 0:
        return False

    r = xmlSecCryptoAppInit(NULL)
    if r != 0:
        return False

    xmlSecErrorsSetCallback(<void*>_error_callback)
    return True


def shutdown():
    """Shutdown the library and cleanup any leftover resources.

    This is called automatically upon interpreter termination and
    should not need to be called explicitly.
    """
    r = xmlSecCryptoAppShutdown()
    if r != 0:
        return False

    r = xmlSecCryptoShutdown()
    if r != 0:
        return False

    r = xmlSecShutdown()
    return r == 0
