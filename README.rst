python-xmlsec
=============

.. image:: https://travis-ci.org/mehcode/python-xmlsec.png?branch=master
    :target: https://travis-ci.org/mehcode/python-xmlsec
.. image:: https://ci.appveyor.com/api/projects/status/20rtt2wv96gag9cy?svg=true
    :target: https://ci.appveyor.com/project/bgaifullin/python-xmlsec
.. image:: https://img.shields.io/pypi/v/xmlsec.svg
    :target: https://pypi.python.org/pypi/xmlsec
.. image:: https://img.shields.io/badge/docs-latest-green.svg
    :target: http://pythonhosted.org/xmlsec/


Python bindings for the XML Security Library.

******
Usage
******

Check the `examples <http://pythonhosted.org/xmlsec/examples.html>`_ to see various examples of signing and verifying using the library.

************
Requirements
************
- libxml2 >= 2.9.1
- libxmlsec1 >= 1.2.14

*******
Install
*******

Pre-Install
-----------

Linux (Debian)
^^^^^^^^^^^^^^

.. code-block:: bash

   apt-get install libxml2-dev libxmlsec1-dev libxmlsec1-openssl


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


Mac
^^^

.. code-block:: bash

    brew install libxml2 libxmlsec1


Automated
---------
1. **xmlsec** can be installed through `easy_install` or `pip`.

.. code-block:: bash

    pip install xmlsec


Mac
^^^

If you get any fatal errors about missing .h files, update your C_INCLUDE_PATH environment variable to
include the appropriate files from the libxml2 and libxmlsec1 libraries.


Windows (Wheel)
^^^^^^^^^^^^^^^

#. Download appropriate binary wheel from `ci.appveyor.com <https://ci.appveyor.com/project/bgaifullin/python-xmlsec>`_ (see build`s artifacts).

#. Install wheel

    .. code-block:: bash

        pip install <wheel filename>


Windows (pip)
^^^^^^^^^^^^^

#. Configure build environment, see `wiki.python.org <https://wiki.python.org/moin/WindowsCompilers>`_ for more details.

#. Install from pip

    .. code-block:: bash

        pip install xmlsec


Manual
------

#. Clone the **xmlsec** repository to your local computer.

    .. code-block:: bash

        git clone git://github.com/mehcode/python-xmlsec.git

#. Change into the **xmlsec** root directory.

    .. code-block:: bash

        cd /path/to/xmlsec


#. Install the project and all its dependencies using `pip`.

    .. code-block:: bash

        pip install .


************
Contributing
************

Setting up your environment
---------------------------

#. Follow steps 1 and 2 of the `manual installation instructions <#manual>`_.


#. Initialize a virtual environment to develop in.
   This is done so as to ensure every contributor is working with
   close-to-identicial versions of packages.

    .. code-block:: bash

        mkvirtualenv xmlsec


    The `mkvirtualenv` command is available from `virtualenvwrapper` which
    can be installed by following `link <http://virtualenvwrapper.readthedocs.org/en/latest/install.html#basic-installation>`_

#. Install **xmlsec** in development mode with testing enabled.
   This will download all dependencies required for running the unit tests.

    .. code-block:: bash

        pip install -r requirements-test.txt
        pip install -e "."


Running the test suite
----------------------

#. [Set up your environment](#setting-up-your-environment).

#. Run the unit tests.

    .. code-block:: bash

        py.test tests

#. Tests configuration
    Env variable **PYXMLSEC_TEST_ITERATIONS** specifies number of test iterations to detect memory leaks.

Reporting a issue
-----------------
Please attach the output of following information:
version of python-xmlsec
version of libxmlsec1
version of libxml2

output from command:

.. code-block:: bash

    pkg-config --cflags xmlsec1


******************
Versions of python
******************

The following versions of python is supported:

 - python2.7
 - python3.4
 - python3.5 (required libxmlsec1 >=  1.2.18 and libxml2 >= 2.9.1)
 - python3.6 (required libxmlsec1 >=  1.2.18 and libxml2 >= 2.9.1)

*******
License
*******

Unless otherwise noted, all files contained within this project are liensed under the MIT opensource license.
See the included file LICENSE or visit `opensource.org <http://opensource.org/licenses/MIT>`_ for more information.
