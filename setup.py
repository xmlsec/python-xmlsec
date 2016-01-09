#! /usr/bin/env python
# -*- coding: utf-8 -*-
# from __future__ import absolute_import, unicode_literals, division
from os import path
from pkgutil import get_importer
from setuptools import setup, Extension
from functools import wraps


def lazy(function):

    @wraps(function)
    def wrapped(*args, **kwargs):

        class LazyProxy(Extension):
            __arguments = dict()

            def __init__(self, function, args, kwargs):
                self.__arguments["function"] = function
                self.__arguments["args"] = args
                self.__arguments["kwargs"] = kwargs
                self.__arguments["result"] = None

            def __getattr__(self, item):
                if self.__arguments["result"] is None:
                    self.__arguments["result"] = self.__arguments["function"](*self.__arguments["args"],
                                                                              **self.__arguments["kwargs"])

                return getattr(self.__arguments["result"], item)

            def __setattr__(self, name, value):
                if self.__arguments["result"] is None:
                    self.__arguments["result"] = self.__arguments["function"](*self.__arguments["args"],
                                                                              **self.__arguments["kwargs"])

                setattr(self.__arguments["result"], name, value)

        return LazyProxy(function, args, kwargs)

    return wrapped


@lazy
def make_extension(name, cython=True):
    from pkgconfig import parse

    # Declare the crypto implementation.
    xmlsec_crypto = 'openssl'

    # Process the `pkg-config` utility and discover include and library
    # directories.
    config = {}
    for lib in ['libxml-2.0', 'xmlsec1-%s' % xmlsec_crypto]:
        config.update(parse(lib))

    config['extra_compile_args'] = ['-DXMLSEC_CRYPTO_OPENSSL=1', '-DXMLSEC_NO_CRYPTO_DYNAMIC_LOADING=1']

    # List-ify config for setuptools.
    for key in config:
        config[key] = list(config[key])

    if 'include_dirs' not in config:
        config['include_dirs'] = []

    # Add the source directories for inclusion.
    import lxml
    config['include_dirs'].insert(0, path.dirname(lxml.__file__))
    config['include_dirs'].insert(0, path.join(path.dirname(lxml.__file__), 'includes'))
    config['include_dirs'].insert(0, 'src')

    # Resolve extension location from name.
    location = path.join('src', *name.split('.'))
    location += '.pyx' if cython else '.c'

    # Create and return the extension.
    return Extension(name, [location], **config)


# Navigate, import, and retrieve the metadata of the project.
meta = get_importer('src/xmlsec').find_module('meta').load_module('meta')


setup(
    name='xmlsec',
    version=meta.version,
    description=meta.description,
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Cython',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Topic :: Text Processing :: Markup :: XML'
    ],
    author='Ryan Leckey',
    author_email='support@mehcode.com',
    url='https://github.com/mehcode/python-xmlsec',
    setup_requires=[
        'setuptools_cython',
        'pkgconfig',
        'lxml >= 3.0',
    ],
    install_requires=[
        'lxml >= 3.0',
    ],
    extras_require={
        'test': ['pytest']
    },
    package_dir={'xmlsec': 'src/xmlsec'},
    packages=['xmlsec'],
    ext_modules=[
        make_extension('xmlsec.constants'),
        make_extension('xmlsec.utils'),
        make_extension('xmlsec.tree'),
        make_extension('xmlsec.key'),
        make_extension('xmlsec.ds'),
        make_extension('xmlsec.enc'),
        make_extension('xmlsec.template'),
    ]
)
