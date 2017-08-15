from __future__ import print_function

import glob
import os
import pkg_resources
import sys

from distutils.errors import DistutilsOptionError


WIN32 = sys.platform.lower().startswith('win')

__MODULE_NAME = "xmlsec"
__MODULE_VERSION = None
__MODULE_DESCRIPTION = "Python bindings for the XML Security Library"
__MODULE_REQUIREMENTS = None
__XMLSEC_CONFIG = None


def name():
    return __MODULE_NAME


def version():
    global __MODULE_VERSION
    if __MODULE_VERSION is None:
        with open(os.path.join(get_base_dir(), 'version.txt')) as f:
            __MODULE_VERSION = f.read().strip()
    return __MODULE_VERSION


def description():
    return __MODULE_DESCRIPTION


def sources():
    return glob.glob(os.path.join(get_base_dir(), "src", "*.c"))


def define_macros():
    macros = [
        ("MODULE_NAME", __MODULE_NAME),
        ("MODULE_VERSION", version()),
    ]
    if OPTION_ENABLE_DEBUG:
        macros.append(("PYXMLSEC_ENABLE_DEBUG", "1"))

    macros.extend(xmlsec_config()['define_macros'])

    return macros


def cflags():
    options = []
    if WIN32:
        options.append("/Zi")
    else:
        options.append("-g")
        options.append("-std=c99")
        options.append("-fno-strict-aliasing")
        options.append("-Wno-error=declaration-after-statement")
        options.append("-Werror=implicit-function-declaration")

    if OPTION_ENABLE_DEBUG:
        options.append("-Wall")
        options.append("-O0")
    else:
        options.append("-Os")

    return options


def include_dirs():
    import lxml

    dirs = xmlsec_config()['include_dirs']
    dirs.extend(lxml.get_include())
    return dirs


def libraries():
    return xmlsec_config()['libraries']


def library_dirs():
    return xmlsec_config()['library_dirs']


def dev_status():
    _version = version()
    if 'a' in _version:
        return 'Development Status :: 3 - Alpha'
    elif 'b' in _version or 'c' in _version:
        return 'Development Status :: 4 - Beta'
    else:
        return 'Development Status :: 5 - Production/Stable'


def requirements():
    global __MODULE_REQUIREMENTS
    if __MODULE_REQUIREMENTS is None:
        with open(os.path.join(get_base_dir(), "requirements.txt")) as f:
            __MODULE_REQUIREMENTS = [str(req) for req in pkg_resources.parse_requirements(f)]
    return __MODULE_REQUIREMENTS


def xmlsec_config():
    global __XMLSEC_CONFIG

    if __XMLSEC_CONFIG is None:
        __XMLSEC_CONFIG = load_xmlsec1_config()

    return __XMLSEC_CONFIG


def load_xmlsec1_config():
    config = None

    if WIN32:
        import xmlsec_extra

        config = {
            'define_macros': [
                ('XMLSEC_CRYPTO', '\\"openssl\\"'),
                ('__XMLSEC_FUNCTION__', '__FUNCTION__'),
                ('XMLSEC_NO_GOST', '1'),
                ('XMLSEC_NO_XKMS', '1'),
                ('XMLSEC_NO_CRYPTO_DYNAMIC_LOADING', '1'),
                ('XMLSEC_CRYPTO_OPENSSL', '1'),
                ('UNICODE', '1'),
                ('_UNICODE', '1'),
                ('LIBXML_ICONV_ENABLED', 1),
                ('LIBXML_STATIC', '1'),
                ('LIBXSLT_STATIC', '1'),
                ('XMLSEC_STATIC', '1'),
                ('inline', '__inline'),
            ],
            'libraries': [
                'libxmlsec_a',
                'libxmlsec-openssl_a',
                'libeay32',
                'iconv_a',
                'libxslt_a',
                'libexslt_a',
                'libxml2_a',
                'zlib',
                'WS2_32',
                'Advapi32',
                'User32',
                'Gdi32',
                'Crypt32',
            ],
            'include_dirs': [],
            'library_dirs': [],
            }

        xmlsec_extra.get_prebuilt_libs(
            OPTION_DOWNLOAD_DIR, config['include_dirs'], config['library_dirs']
        )
    else:
        import pkgconfig

        try:
            config = pkgconfig.parse('xmlsec1')
        except EnvironmentError:
            pass

        if config is None or not config.get('libraries'):
            fatal_xmlsec1_error()

        config.setdefault('libraries', [])
        config.setdefault('include_dirs', [])
        config.setdefault('library_dirs', [])
        # fix macros
        macros = config.setdefault('define_macros', [])
        for i, v in enumerate(macros):
            if v[0] == 'XMLSEC_CRYPTO':
                macros[i] = ('XMLSEC_CRYPTO', '"{0}"'.format(v[1]))
                break
    return config


def fatal_xmlsec1_error():
    print('*********************************************************************************')
    print('Could not find xmlsec1 config. Are libxmlsec1-dev and pkg-config installed?')
    if sys.platform in ('darwin',):
        print('Perhaps try: xcode-select --install')
    print('*********************************************************************************')
    sys.exit(1)


def get_base_dir():
    return os.path.abspath(os.path.dirname(sys.argv[0]))


if sys.version_info[0] >= 3:
    _system_encoding = sys.getdefaultencoding()
    if _system_encoding is None:
        _system_encoding = "iso-8859-1"

    def decode_input(data):
        if isinstance(data, str):
            return data
        return data.decode(_system_encoding)
else:
    def decode_input(data):
        return data


def env_var(n):
    value = os.getenv(n)
    if value:
        value = decode_input(value)
        if sys.platform == 'win32' and ';' in value:
            return value.split(';')
        else:
            return value.split()
    else:
        return []


def env_var_name(n):
    return "PYXMLSEC_" + n.upper().replace('-', '_')


# Option handling:

def has_option(n):
    try:
        sys.argv.remove('--%s' % n)
        return True
    except ValueError:
        pass
    # allow passing all cmd line options also as environment variables
    env_val = os.getenv(env_var_name(n), 'false').lower()
    return env_val in ("true", "1")


def option_value(n, default=None):
    for index, option in enumerate(sys.argv):
        if option == '--' + n:
            if index+1 >= len(sys.argv):
                raise DistutilsOptionError(
                    'The option %s requires a value' % option)
            value = sys.argv[index+1]
            sys.argv[index:index+2] = []
            return value
        if option.startswith('--' + n + '='):
            value = option[len(n)+3:]
            sys.argv[index:index+1] = []
            return value
    return os.getenv(env_var_name(n), default)


OPTION_ENABLE_DEBUG = has_option('enable-debug')
OPTION_DOWNLOAD_DIR = option_value('download-dir', 'build/extra')
