# python-xmlsec

[![image](https://img.shields.io/pypi/v/xmlsec.svg?logo=python&logoColor=white)](https://pypi.python.org/pypi/xmlsec)
[![pre-commit.ci status](https://results.pre-commit.ci/badge/github/xmlsec/python-xmlsec/master.svg)](https://results.pre-commit.ci/latest/github/xmlsec/python-xmlsec/master)
[![image](https://github.com/xmlsec/python-xmlsec/actions/workflows/manylinux.yml/badge.svg)](https://github.com/xmlsec/python-xmlsec/actions/workflows/manylinux.yml)
[![image](https://github.com/xmlsec/python-xmlsec/actions/workflows/macosx.yml/badge.svg)](https://github.com/xmlsec/python-xmlsec/actions/workflows/macosx.yml)
[![image](https://github.com/xmlsec/python-xmlsec/actions/workflows/linuxbrew.yml/badge.svg)](https://github.com/xmlsec/python-xmlsec/actions/workflows/linuxbrew.yml)
[![image](https://codecov.io/gh/xmlsec/python-xmlsec/branch/master/graph/badge.svg)](https://codecov.io/gh/xmlsec/python-xmlsec)
[![Documentation Status](https://img.shields.io/readthedocs/xmlsec/latest?logo=read-the-docs)](https://xmlsec.readthedocs.io/en/latest/?badge=latest)

Python bindings for the [XML Security
Library](https://www.aleksey.com/xmlsec/).

## Documentation

Documentation for `xmlsec` can be found at
[xmlsec.readthedocs.io](https://xmlsec.readthedocs.io/).

## Usage

Check the
[examples](https://xmlsec.readthedocs.io/en/latest/examples.html)
section in the documentation to see various examples of signing and
verifying using the library.

## Requirements

- `libxml2 >= 2.9.1`
- `libxmlsec1 >= 1.2.33`

## Install

`xmlsec` is available on PyPI:

``` bash
pip install xmlsec
```

Depending on your OS, you may need to install the required native
libraries first:

### Linux (Debian)

``` bash
apt-get install pkg-config libxml2-dev libxmlsec1-dev libxmlsec1-openssl
```

Note: There is no required version of LibXML2 for Ubuntu Precise, so you
need to download and install it manually.

``` bash
wget http://xmlsoft.org/sources/libxml2-2.9.1.tar.gz
tar -xvf libxml2-2.9.1.tar.gz
cd libxml2-2.9.1
./configure && make && make install
```

### Linux (CentOS)

``` bash
yum install libxml2-devel xmlsec1-devel xmlsec1-openssl-devel libtool-ltdl-devel
```

### Linux (Fedora)

``` bash
dnf install libxml2-devel xmlsec1-devel xmlsec1-openssl-devel libtool-ltdl-devel
```

### Mac

``` bash
brew install libxml2 libxmlsec1 pkg-config
```

or

``` bash
port install libxml2 xmlsec pkgconfig
```

### Alpine

``` bash
apk add build-base openssl libffi-dev openssl-dev libxslt-dev libxml2-dev xmlsec-dev xmlsec
```

## Troubleshooting

### `lxml & xmlsec libxml2 library version mismatch`

`xmlsec` passes `lxml` XML nodes to the underlying `xmlsec1` library. Both
libraries use `libxml2`, so they must use compatible `libxml2` versions at
runtime. If `lxml` is installed from a wheel that bundles one `libxml2`
version while `xmlsec` is built against another system `libxml2`, importing
or using `xmlsec` can fail with:

``` text
xmlsec.InternalError: (-1, 'lxml & xmlsec libxml2 library version mismatch')
```

The most reliable fixes are:

- Use prebuilt wheels for both `lxml` and `xmlsec` when wheels are available
  for your platform:

  ``` bash
  pip install --only-binary=lxml,xmlsec lxml xmlsec
  ```

- If you need to build from source, build both packages against the same
  locally installed `libxml2`:

  ``` bash
  pip install --no-binary=lxml,xmlsec lxml xmlsec
  ```

Do not mix a wheel-built `lxml` with a locally built `xmlsec`, or the other
way around, unless you know they use the same `libxml2` version.

An `lxml` release upgrade does not by itself mean `xmlsec` is incompatible;
this error is about the `libxml2` libraries loaded in that environment.

If the error appears only under uWSGI, uWSGI may have loaded the system
`libxml2` before Python imports `lxml` or `xmlsec`. In that case, make sure
uWSGI and the Python packages resolve to the same `libxml2`, or rebuild the
Python packages from source in that environment. If you use `uv`, clear any
cached mixed builds before reinstalling. For example, to reinstall from
wheels:

``` bash
uv pip uninstall lxml xmlsec
uv cache clean
uv pip install --only-binary lxml --only-binary xmlsec lxml xmlsec
```

For background, see
[issue #356](https://github.com/xmlsec/python-xmlsec/issues/356) and the
uWSGI edge case in
[issue #415](https://github.com/xmlsec/python-xmlsec/issues/415).

### Mac

If you get any fatal errors about missing `.h` files, update your
`C_INCLUDE_PATH` environment variable to include the appropriate files
from the `libxml2` and `libxmlsec1` libraries.

### Windows

Starting with 1.3.7, prebuilt wheels are available for Windows, so
running `pip install xmlsec` should suffice. If you want to build from
source:

1. Configure build environment, see
   [wiki.python.org](https://wiki.python.org/moin/WindowsCompilers) for
   more details.

2. Install from source dist:

    ``` bash
    pip install xmlsec --no-binary=xmlsec
    ```

## Building from source

1. Clone the `xmlsec` source code repository to your local computer.

    ``` bash
    git clone https://github.com/xmlsec/python-xmlsec.git
    ```

2. Change into the `python-xmlsec` root directory.

    ``` bash
    cd /path/to/xmlsec
    ```

3. Install the project and all its dependencies using `pip`.

   ``` bash
   pip install .
   ```

## Contributing

### Setting up your environment

1. Follow steps 1 and 2 of the [manual installation
   instructions](#building-from-source).

2. Initialize a virtual environment to develop in. This is done so as
   to ensure every contributor is working with close-to-identical
   versions of packages.

   ``` bash
   mkvirtualenv xmlsec
   ```

   The `mkvirtualenv` command is available from `virtualenvwrapper`
   package which can be installed by following
   [link](http://virtualenvwrapper.readthedocs.org/en/latest/install.html#basic-installation).

3. Activate the created virtual environment:

   ``` bash
   workon xmlsec
   ```

4. Install `xmlsec` in development mode with testing enabled. This will
   download all dependencies required for running the unit tests.

   ``` bash
   pip install -r requirements-test.txt
   pip install -e "."
   ```

### Running the test suite

1. [Set up your environment](#setting-up-your-environment).

2. Run the unit tests.

   ``` bash
   pytest tests
   ```

3. Tests configuration

   Env variable `PYXMLSEC_TEST_ITERATIONS` specifies number of test
   iterations to detect memory leaks.

### Reporting an issue

Please attach the output of following information:

- version of `xmlsec`
- version of `libxmlsec1`
- version of `libxml2`
- output from the command

  ``` bash
  pkg-config --cflags xmlsec1
  ```

## License

Unless otherwise noted, all files contained within this project are
licensed under the MIT open source license. See the included `LICENSE`
file or visit [opensource.org](http://opensource.org/licenses/MIT) for
more information.
