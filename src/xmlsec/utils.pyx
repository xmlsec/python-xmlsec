# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals, division
from xmlsec.utils cimport *

__all__ = [
    'init',
    'shutdown'
]


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
