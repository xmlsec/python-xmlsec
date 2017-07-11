Install
-----------

Linux (Debian)
^^^^^^^^^^^^^^

.. code-block:: bash

    apt-get install libxml2-dev libxmlsec1-dev libxmlsec1-openssl
    pip install xmlsec


Note: There is no required version of libxml2 for ubuntu precise,
so need to download and install it manually.

.. code-block:: bash

    wget http://xmlsoft.org/sources/libxml2-2.9.1.tar.gz
    tar -xvf libxml2-2.9.1.tar.gz
    cd libxml2-2.9.1
    ./configure && make && make install


Linux (CentOS)
^^^^^^^^^^^^^^

.. code-block:: bash

    yum install libxml2-devel xmlsec1-devel xmlsec1-openssl-devel libtool-ltdl-devel
    pip install xmlsec


Mac
^^^

.. code-block:: bash

    xcode-select --install
    brew upgrade
    brew install libxml2 libxmlsec1 pkg-config
    pip install xmlsec

