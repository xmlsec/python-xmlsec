# python-xmlsec
[![Build Status](https://travis-ci.org/mehcode/python-xmlsec.png?branch=master)](https://travis-ci.org/mehcode/python-xmlsec)
[![PyPi Version](httpshttps://img.shields.io/pypi/v/xmlsec.svg)](https://pypi.python.org/pypi/xmlsec)
![PyPi Downloads](https://img.shields.io/pypi/dm/xmlsec.svg)
> Python bindings for the XML Security Library.

## Usage

Check the [examples](https://github.com/mehcode/python-xmlsec/tree/master/tests/examples) to see various examples of signing and verifying using the library.

## Install

### Pre-Install

#### Linux (Debian)

   ```sh
   apt-get install libxml2-dev libxmlsec1-dev
   ```
   
#### Linux (CentOS)

   ```sh
   yum install libxml2-devel xmlsec1-devel xmlsec1-openssl-devel libtool-ltdl-devel
   ```

#### Mac

   ```sh
   brew install libxml2 libxmlsec1
   ```

### Automated

1. **xmlsec** can be installed through `easy_install` or `pip`.

   ```sh
   pip install xmlsec
   ```

#### Mac

If you get any fatal errors about missing .h files, update your C_INCLUDE_PATH environment variable to
include the appropriate files from the libxml2 and libxmlsec1 libraries.

### Manual

1. Clone the **xmlsec** repository to your local computer.

   ```sh
   git clone git://github.com/mehcode/python-xmlsec.git
   ```

2. Change into the **xmlsec** root directory.

   ```sh
   cd /path/to/xmlsec
   ```

3. Install the project and all its dependencies using `pip`.

   ```sh
   pip install .
   ```

## Contributing

### Setting up your environment

1. Follow steps 1 and 2 of the [manual installation instructions][].

[manual installation instructions]: #manual

2. Initialize a virtual environment to develop in.
   This is done so as to ensure every contributor is working with
   close-to-identicial versions of packages.

   ```sh
   mkvirtualenv xmlsec
   ```

   The `mkvirtualenv` command is available from `virtualenvwrapper` which
   can be installed by following: http://virtualenvwrapper.readthedocs.org/en/latest/install.html#basic-installation

3. Install **xmlsec** in development mode with testing enabled.
   This will download all dependencies required for running the unit tests.

   ```sh
   pip install -e ".[test]"
   ```

### Running the test suite

1. [Set up your environment](#setting-up-your-environment).

2. Run the unit tests.

   ```sh
   py.test
   ```

## License

Unless otherwise noted, all files contained within this project are liensed under the MIT opensource license. See the included file LICENSE or visit [opensource.org][] for more information.

[opensource.org]: http://opensource.org/licenses/MIT
