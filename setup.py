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

        class LazyProxy(object):

            def __init__(self, function, args, kwargs):
                self._function = function
                self._args = args
                self._kwargs = kwargs
                self._result = None

            def __getattribute__(self, name):
                if name in ['_function', '_args', '_kwargs', '_result']:
                    return super(LazyProxy, self).__getattribute__(name)

                if self._result is None:
                    self._result = self._function(*self._args, **self._kwargs)

                return object.__getattribute__(self._result, name)

            def __setattr__(self, name, value):
                if name in ['_function', '_args', '_kwargs', '_result']:
                    super(LazyProxy, self).__setattr__(name, value)
                    return

                if self._result is None:
                    self._result = self._function(*self._args, **self._kwargs)

                setattr(self._result, name, value)

        return LazyProxy(function, args, kwargs)

    return wrapped


class Extension(Extension, object):

    lxml_extended = False

    @property
    def include_dirs(self):
        dirs = self.__dict__['include_dirs']
        if self.lxml_extended:
            return dirs

        # Resolve lxml include directories.
        import lxml
        lxml_base = path.dirname(lxml.__file__)
        lxml_include = path.join(lxml_base, 'includes')

        dirs.insert(0, lxml_include)
        dirs.insert(0, lxml_base)

        self.lxml_extended = True
        return dirs

    @include_dirs.setter
    def include_dirs(self, dirs):
        self.__dict__['include_dirs'] = dirs


@lazy
def make_extension(name, cython=True):
    from pkgconfig import parse

    # Declare the crypto implementation.
    XMLSEC_CRYPTO = 'openssl'

    # Process the `pkg-config` utility and discover include and library
    # directories.
    config = {}
    for lib in ['libxml-2.0', 'xmlsec1-%s' % XMLSEC_CRYPTO]:
        config.update(parse(lib))

    # List-ify config for setuptools.
    for key in config:
        config[key] = list(config[key])

    # Add the source directories for inclusion.
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
        'Programming Language :: Python :: 3.3',
        'Topic :: Text Processing :: Markup :: XML'
    ],
    author='Concordus Applications',
    author_email='support@concordusapps.com',
    url='https://github.com/concordusapps/python-xmlsec',
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
        make_extension('xmlsec.template'),
    ]
)
