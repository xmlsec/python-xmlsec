Examples
========

Decrypt
-------

.. literalinclude:: examples/decrypt.py

Encrypt
-------

.. literalinclude:: examples/encrypt.py


Sign
----

.. literalinclude:: examples/sign.py

Sign-Binary
-----------

.. literalinclude:: examples/sign_binary.py


Verify
------

.. literalinclude:: examples/verify.py


Verify-Binary
-------------

.. literalinclude:: examples/verify_binary.py


WS-Security (WSSE): UsernameToken, Sign, Encrypt
--------------------------------------------------

These two scripts show one way to build and process a WS-Security secured
SOAP envelope with xmlsec: a ``UsernameToken`` plus an XML signature over
the Body plus an XML encryption of the Body, using a "detached"
``EncryptedKey`` under ``wsse:Security`` (the shape most SOAP stacks
expect for WS-Security 1.1), instead of the ``EncryptedKey``-nested-inside-
``EncryptedData`` shape that :func:`~xmlsec.EncryptionContext.encrypt_xml`
produces by default.

xmlsec's ``EncryptionContext.encrypt_binary``/``encrypt_xml`` only accept
an ``xenc:EncryptedData`` node as their template, so they cannot fill in a
detached ``EncryptedKey`` directly; these examples wrap/unwrap the AES
session key with the ``cryptography`` package instead, while still using
xmlsec's template helpers to build the element and xmlsec's own contexts
to sign/verify and encrypt/decrypt the Body. See the docstrings in each
script for the full explanation, including why the two scripts process
Sign/Encrypt and Decrypt/Verify in mirrored (not identical) order.

.. warning::

   ``wssekey.pem`` and ``wssecert.pem`` in this directory are a self-signed
   key pair generated only for these examples (the certificate's
   Subject/Issuer CN says as much: "test key, DO NOT USE IN PRODUCTION").
   Do not reuse them for anything real -- generate your own pair, e.g.::

       openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
           -keyout wssekey.pem -out wssecert.pem \
           -subj "/CN=your identity here"

To keep the example short, both scripts reuse this *same* key pair for
every role, but in a real deployment each party has its own key pair and
only ever holds its own private key plus the other side's public
certificate:

* The **sender** (whoever calls ``sign_body``) signs with its own private
  key -- ``signing_key_file`` in ``wsse_outgoing.py``. Only the sender
  ever holds this key.
* To **encrypt** the Body, the sender needs the *recipient's* public
  certificate -- ``recipient_cert_file`` in ``encrypt_body``. This is the
  public cert of whoever will receive and decrypt the message (the
  service being called, or the calling client, depending on which
  direction the message flows), obtained out-of-band ahead of time.
* On the receiving side, ``verify_signature`` needs the *sender's* public
  certificate, to check who signed the message. ``unwrap_session_key``,
  on the other hand, needs the *recipient's own* private key, to decrypt
  the session key that was encrypted for it.

In other words: a real integration needs two independent key pairs, one
per party, not the single shared pair used here for brevity.

Outgoing (build a secured request)
+++++++++++++++++++++++++++++++++

.. literalinclude:: examples/wsse_outgoing.py

Incoming (process a secured response)
++++++++++++++++++++++++++++++++++++

.. literalinclude:: examples/wsse_incoming.py
