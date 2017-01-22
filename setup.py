from __future__ import print_function

import glob
import os
import pkgconfig
from setuptools import setup
from setuptools import Extension
import sys

import lxml

__name__ = "xmlsec"
__version__ = "1.0.1"
__description__ = "Python bindings for the XML Security Library"


def is_debug():
    return bool(os.getenv("PYXMLSEC_DEBUG"))


macroses = [("MODULE_NAME", __name__), ("MODULE_VERSION", __version__), ("MODULE_DOC", __description__)]
cflags = ["-g", "-std=c99", "-fno-strict-aliasing", "-Wno-error=declaration-after-statement", "-Werror=implicit-function-declaration"]


if is_debug():
    macroses.append(("PYXMLSEC_ENABLE_DEBUG", 1))
    cflags.extend(["-Wall", "-O0"])
else:
    cflags.extend(["-Os"])


config = pkgconfig.parse("xmlsec1")


def add_to_config(key, args):
    value = list(config.get(key, []))
    value.extend(args)
    config[key] = value


add_to_config('define_macros', macroses)
add_to_config('include_dirs', lxml.get_include())

print(config, file=sys.stderr)


def find_sources(path):
    return glob.glob(os.path.join(path, "*.c"))


_xmlsec = Extension(
    __name__,
    sources=find_sources("./src"),
    extra_compile_args=cflags,
    libraries=list(config.get('libraries', [])),
    library_dirs=list(config.get('library_dirs', [])),
    include_dirs=list(config.get('include_dirs', [])),
    define_macros=config['define_macros']
)

setup(
    name=__name__,
    version=__version__,
    description=__description__,
    ext_modules=[_xmlsec],
    author="Ryan Leckey",
    author_email='support@mehcode.com',
    maintainer='Bulat Gaifullin',
    maintainer_email='gaifullinbf@gmail.com',
    url='https://github.com/mehcode/python-xmlsec',
    download_url="https://github.com/mehcode/python-xmlsec/archive/v%s.tar.gz" % __version__,
    license='MIT',
    keywords=["xmlsec"],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: C',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Topic :: Text Processing :: Markup :: XML'
    ],
)
