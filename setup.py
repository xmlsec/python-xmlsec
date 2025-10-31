from pathlib import Path

from setuptools import Extension, setup

from build_support.build_ext import build_ext

src_root = Path(__file__).parent / 'src'
sources = [str(path.absolute()) for path in src_root.rglob('*.c')]
pyxmlsec = Extension('xmlsec', sources=sources)
setup_reqs = ['setuptools_scm[toml]>=3.4', 'pkgconfig>=1.5.1', 'lxml>=3.8']


with open('README.md', encoding='utf-8') as readme:
    long_desc = readme.read()


setup(
    name='xmlsec',
    use_scm_version=True,
    description='Python bindings for the XML Security Library',
    long_description=long_desc,
    long_description_content_type='text/markdown',
    ext_modules=[pyxmlsec],
    cmdclass={'build_ext': build_ext},
    python_requires='>=3.9',
    setup_requires=setup_reqs,
    install_requires=['lxml>=3.8'],
    author='Bulat Gaifullin',
    author_email='support@mehcode.com',
    maintainer='Oleg Hoefling',
    maintainer_email='oleg.hoefling@gmail.com',
    url='https://github.com/mehcode/python-xmlsec',
    project_urls={
        'Documentation': 'https://xmlsec.readthedocs.io',
        'Source': 'https://github.com/mehcode/python-xmlsec',
        'Changelog': 'https://github.com/mehcode/python-xmlsec/releases',
    },
    license='MIT',
    keywords=['xmlsec'],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: C',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: Python :: 3.13',
        'Programming Language :: Python :: 3.14',
        'Topic :: Text Processing :: Markup :: XML',
        'Typing :: Typed',
    ],
    zip_safe=False,
    packages=['xmlsec'],
    package_dir={'': 'src'},
    package_data={'xmlsec': ['py.typed', '*.pyi']},
)
