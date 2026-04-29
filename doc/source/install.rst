Installation
============

``xmlsec`` is available on PyPI:

.. code-block:: bash

   pip install xmlsec

Depending on your OS, you may need to install the required native
libraries first:

Linux (Debian)
--------------

.. code-block:: bash

   apt-get install libxml2-dev libxmlsec1-dev libxmlsec1-openssl

.. note:: There is no required version of LibXML2 for Ubuntu Precise,
   so you need to download and install it manually:

   .. code-block:: bash

      wget http://xmlsoft.org/sources/libxml2-2.9.1.tar.gz
      tar -xvf libxml2-2.9.1.tar.gz
      cd libxml2-2.9.1
      ./configure && make && make install


Linux (CentOS)
--------------

.. code-block:: bash

   yum install libxml2-devel xmlsec1-devel xmlsec1-openssl-devel libtool-ltdl-devel


Linux (Fedora)
--------------

.. code-block:: bash

   dnf install libxml2-devel xmlsec1-devel xmlsec1-openssl-devel libtool-ltdl-devel


Mac
---

.. code-block:: bash

   xcode-select --install
   brew upgrade
   brew install libxml2 libxmlsec1 pkg-config


Alpine
------

.. code-block:: bash

   apk add build-base openssl libffi-dev openssl-dev libxslt-dev libxml2-dev xmlsec-dev xmlsec


Troubleshooting
***************

``lxml & xmlsec libxml2 library version mismatch``
--------------------------------------------------

``xmlsec`` passes ``lxml`` XML nodes to the underlying ``xmlsec1``
library. Both libraries use ``libxml2``, so they must use compatible
``libxml2`` versions at runtime. If ``lxml`` is installed from a wheel
that bundles one ``libxml2`` version while ``xmlsec`` is built against
another system ``libxml2``, importing or using ``xmlsec`` can fail with:

.. code-block:: text

   xmlsec.InternalError: (-1, 'lxml & xmlsec libxml2 library version mismatch')

The most reliable fixes are:

* Use prebuilt wheels for both ``lxml`` and ``xmlsec`` when wheels are
  available for your platform:

  .. code-block:: bash

     pip install --only-binary=lxml,xmlsec lxml xmlsec

* If you need to build from source, build both packages against the same
  locally installed ``libxml2``:

  .. code-block:: bash

     pip install --no-binary=lxml,xmlsec lxml xmlsec

Do not mix a wheel-built ``lxml`` with a locally built ``xmlsec``, or the
other way around, unless you know they use the same ``libxml2`` version.

An ``lxml`` release upgrade does not by itself mean ``xmlsec`` is
incompatible; this error is about the ``libxml2`` libraries loaded in
that environment.

If the error appears only under uWSGI, uWSGI may have loaded the system
``libxml2`` before Python imports ``lxml`` or ``xmlsec``. In that case,
make sure uWSGI and the Python packages resolve to the same ``libxml2``,
or rebuild the Python packages from source in that environment. If you
use ``uv``, clear any cached mixed builds before reinstalling. For
example, to reinstall from wheels:

.. code-block:: bash

   uv pip uninstall lxml xmlsec
   uv cache clean
   uv pip install --only-binary lxml --only-binary xmlsec lxml xmlsec

For background, see `issue #356 <https://github.com/xmlsec/python-xmlsec/issues/356>`_
and the uWSGI edge case in
`issue #415 <https://github.com/xmlsec/python-xmlsec/issues/415>`_.


Mac
---

If you get any fatal errors about missing ``.h`` files, update your
``C_INCLUDE_PATH`` environment variable to include the appropriate
files from the ``libxml2`` and ``libxmlsec1`` libraries.


Windows
-------

Starting with 1.3.7, prebuilt wheels are available for Windows,
so running ``pip install xmlsec`` should suffice. If you want
to build from source:

#. Configure build environment, see `wiki.python.org <https://wiki.python.org/moin/WindowsCompilers>`_ for more details.

#. Install from source dist:

   .. code-block:: bash

      pip install xmlsec --no-binary=xmlsec
