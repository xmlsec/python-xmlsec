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

   apk add build-base libressl libffi-dev libressl-dev libxslt-dev libxml2-dev xmlsec-dev xmlsec


Troubleshooting
***************

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
