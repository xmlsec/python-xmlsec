# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals, division

from .utils cimport *

__all__ = [
    'init',
    'shutdown',
    'enable_debug_trace'
]


def init():
    """Initialize the library for general operation.

    This is called upon library import and does not need to be called
    again (unless @ref _shutdown is called explicitly).
    """
    if xmlSecInit() < 0:
        return False

    if xmlSecOpenSSLAppInit(NULL) < 0:
        xmlSecShutdown()
        return False

    if xmlSecOpenSSLInit() < 0:
        xmlSecOpenSSLAppShutdown()
        xmlSecShutdown()
        return False

    return True


def shutdown():
    """Shutdown the library and cleanup any leftover resources.

    This is called automatically upon interpreter termination and
    should not need to be called explicitly.
    """
    if xmlSecOpenSSLShutdown() < 0:
        return False

    if xmlSecOpenSSLAppShutdown() < 0:
        return False

    if xmlSecShutdown() < 0:
        return False

    return True


def enable_debug_trace(flag):
    xmlSecErrorsDefaultCallbackEnableOutput(1 if flag else 0)
