# This has been moved to https://github.com/mehcode/python-xmlsec


-----

# python-xmlsec
[![Build Status](https://travis-ci.org/concordusapps/python-xmlsec.png?branch=master)](https://travis-ci.org/concordusapps/python-xmlsec)
> Python bindings for the XML Security Library.

## Usage

Check the [examples](https://github.com/concordusapps/python-xmlsec/tree/master/tests/examples) to see various examples of signing and verifying using the library.

## Install

### Automated

1. **xmlsec** can be installed through `easy_install` or `pip`.

   ```sh
   pip install xmlsec
   ```

### Manual

1. Clone the **xmlsec** repository to your local computer.

   ```sh
   git clone git://github.com/concordusapps/python-xmlsec.git
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
