``xmlsec``
----------

Lifecycle
~~~~~~~~~

The module initializes the underlying xmlsec library on import. Applications
that call :func:`xmlsec.shutdown` should treat it as process-final and should
not call :func:`xmlsec.init` afterwards.

This is required because upstream xmlsec1 versions starting with 1.3.11 may
call ``OPENSSL_cleanup()`` during shutdown when using the OpenSSL backend.
OpenSSL cannot be reinitialized in the same process after that cleanup has run.

.. automodule:: xmlsec
    :members:
    :undoc-members:


:ref:`contents`
