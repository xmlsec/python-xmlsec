#! /usr/bin/env python
import sys
import subprocess
from os import path
from collections import defaultdict
from distutils.core import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext


PKGCONFIG_TOKEN_MAP = {
    '-D': 'define_macros',
    '-I': 'include_dirs',
    '-L': 'library_dirs',
    '-l': 'libraries'
}

def pkgconfig(*packages):
    """
    Run the `pkg-config` utility to determine locations of includes,
    libraries, etc. for dependencies.
    """
    config = defaultdict(set)

    # Execute the command in a subprocess and communicate the output.
    command = "pkg-config --libs --cflags %s" % ' '.join(packages)
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
    out, _ = process.communicate()

    # Clean the output.
    out = out.decode('utf8')
    out = out.replace('\\\"', "")

    # Iterate throught the tokens of the output.
    for token in out.split():
        key = PKGCONFIG_TOKEN_MAP.get(token[:2])
        if key:
            config[key].add(token[2:].strip())

    # Convert sets to lists.
    for name in config:
        config[name] = list(config[name])

    # Iterate and resolve define macros.
    macros = []
    for declaration in config['define_macros']:
        macros.append(tuple(declaration.split('=')))

    config['define_macros'] = macros

    # Return discovered configuration.
    return config


# we must extend our cflags once `lxml` is installed.
#  To this end, we override `Extension`
class Extension(Extension):

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


# Declare the crypto implementation.
XMLSEC_CRYPTO = 'openssl'

# Process the `pkg-config` utility and discover include and library
# directories.
config = pkgconfig('libxml-2.0', 'xmlsec1-%s' % XMLSEC_CRYPTO)
config['include_dirs'].insert(0, 'src')  # Prepend 'src' as an include dir.


setup(
    name='xmlsec',
    version='0.1.0',
    description='Python bindings for the XML Security Library.',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3.3',
        'Topic :: Text Processing :: Markup :: XML'
    ],
    author='Concordus Applications',
    author_email='support@concordusapps.com',
    setup_requires=[
        'lxml >= 3.0',
    ],
    install_requires=[
        'lxml >= 3.0',
    ],
    extras_require={
        'test': ['pytest']
    },
    cmdclass = {'build_ext': build_ext},
    ext_modules=[Extension('xmlsec', ['src/xmlsec.pyx'], **config)]
)
