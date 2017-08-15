from setuptools import setup
from setuptools import Extension
from setuptools.command import build_ext

import xmlsec_setupinfo


class BuildExt(build_ext.build_ext):
    def run(self):
        # at this moment all setup_requires are installed and we can safety import them
        self.patch_options()
        build_ext.build_ext.run(self)

    def patch_options(self):
        ext = self.ext_map[xmlsec_setupinfo.name()]
        ext.define_macros.extend(xmlsec_setupinfo.define_macros())
        ext.include_dirs.extend(xmlsec_setupinfo.include_dirs())
        ext.libraries.extend(xmlsec_setupinfo.libraries())
        ext.library_dirs.extend(xmlsec_setupinfo.library_dirs())


_xmlsec = Extension(
    xmlsec_setupinfo.name(),
    sources=xmlsec_setupinfo.sources(),
    extra_compile_args=xmlsec_setupinfo.cflags(),
    libraries=[],
    library_dirs=[],
    include_dirs=[],
    define_macros=[],
)

setup(
    name=xmlsec_setupinfo.name(),
    version=xmlsec_setupinfo.version(),
    description=xmlsec_setupinfo.description(),
    ext_modules=[_xmlsec],
    cmdclass={'build_ext': BuildExt},
    setup_requires=xmlsec_setupinfo.requirements(),
    install_requires=xmlsec_setupinfo.requirements(),
    author="Bulat Gaifullin",
    author_email='support@mehcode.com',
    maintainer='Bulat Gaifullin',
    maintainer_email='gaifullinbf@gmail.com',
    url='https://github.com/mehcode/python-xmlsec',
    download_url="https://github.com/mehcode/python-xmlsec/archive/v%s.tar.gz" % xmlsec_setupinfo.version(),
    license='MIT',
    keywords=["xmlsec"],
    classifiers=[
        xmlsec_setupinfo.dev_status(),
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
