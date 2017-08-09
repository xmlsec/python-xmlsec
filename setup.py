from setuptools import setup
from setuptools import Extension
from setuptools.command import build_ext

import setupinfo


class BuildExt(build_ext.build_ext):
    def run(self):
        # at this moment all setup_requires are installed and we can safety import them
        self.patch_options()
        build_ext.build_ext.run(self)

    def patch_options(self):
        ext = self.ext_map[setupinfo.name()]
        ext.define_macros.extend(setupinfo.define_macros())
        ext.include_dirs.extend(setupinfo.include_dirs())
        ext.libraries.extend(setupinfo.libraries())
        ext.library_dirs.extend(setupinfo.library_dirs())


_xmlsec = Extension(
    setupinfo.name(),
    sources=setupinfo.sources(),
    extra_compile_args=setupinfo.cflags(),
    libraries=[],
    library_dirs=[],
    include_dirs=[],
    define_macros=[],
)

setup(
    name=setupinfo.name(),
    version=setupinfo.version(),
    description=setupinfo.description(),
    ext_modules=[_xmlsec],
    cmdclass={'build_ext': BuildExt},
    setup_requires=setupinfo.requirements(),
    install_requires=setupinfo.requirements(),
    author="Bulat Gaifullin",
    author_email='support@mehcode.com',
    maintainer='Bulat Gaifullin',
    maintainer_email='gaifullinbf@gmail.com',
    url='https://github.com/mehcode/python-xmlsec',
    download_url="https://github.com/mehcode/python-xmlsec/archive/v%s.tar.gz" % setupinfo.version(),
    license='MIT',
    keywords=["xmlsec"],
    classifiers=[
        setupinfo.dev_status(),
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: C',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Text Processing :: Markup :: XML'
    ],
)
