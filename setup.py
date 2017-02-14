from __future__ import print_function

import glob
import os
from setuptools import setup
from setuptools import Extension
from setuptools.command import build_ext


__name__ = "xmlsec"
__version__ = os.getenv("TRAVIS_TAG", "1.0.2")  # publish on tag is used
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


def add_to_list(target, up):
    if up is None:
        return target

    value = set(target)
    value.update(up)
    target[:] = list(value)


def find_sources(path):
    return glob.glob(os.path.join(path, "*.c"))


def parse_requirements(filename, __cache={}):
    try:
        return __cache[filename]
    except KeyError:
        with open(filename) as stream:
            result = __cache[filename] = [x for x in (y.strip() for y in stream) if x and not x.startswith('#')]
            return result


class BuildExt(build_ext.build_ext):
    def run(self):
        self.patch_xmlsec()
        build_ext.build_ext.run(self)

    def patch_xmlsec(self):
        # at this moment all setup_requires are installed and we can safety import them
        pkgconfig = __import__("pkgconfig")
        lxml = __import__("lxml")

        ext = self.ext_map[__name__]
        config = pkgconfig.parse("xmlsec1")
        # added build flags from pkg-config
        for item in ('define_macros', 'libraries', 'library_dirs', 'include_dirs'):
            add_to_list(getattr(ext, item), config.get(item))

        add_to_list(ext.include_dirs, lxml.get_include())


_xmlsec = Extension(
    __name__,
    sources=find_sources("./src"),
    extra_compile_args=cflags,
    libraries=[],
    library_dirs=[],
    include_dirs=[],
    define_macros=macroses
)

setup(
    name=__name__,
    version=__version__,
    description=__description__,
    ext_modules=[_xmlsec],
    cmdclass={'build_ext': BuildExt},
    setup_requires=parse_requirements('requirements.txt'),
    install_requires=parse_requirements('requirements.txt'),
    author="Bulat Gaifullin",
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
