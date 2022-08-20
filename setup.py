import contextlib
import html.parser
import io
import json
import multiprocessing
import os
import re
import subprocess
import sys
import tarfile
import zipfile
from distutils import log
from distutils.errors import DistutilsError
from distutils.version import StrictVersion as Version
from pathlib import Path
from urllib.request import urlcleanup, urljoin, urlopen, urlretrieve

from setuptools import Extension, setup
from setuptools.command.build_ext import build_ext as build_ext_orig


class HrefCollector(html.parser.HTMLParser):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.hrefs = []

    def handle_starttag(self, tag, attrs):
        if tag == 'a':
            for name, value in attrs:
                if name == 'href':
                    self.hrefs.append(value)


def latest_release_from_html(url, matcher):
    with contextlib.closing(urlopen(url)) as r:
        charset = r.headers.get_content_charset() or 'utf-8'
        content = r.read().decode(charset)
        collector = HrefCollector()
        collector.feed(content)
        hrefs = collector.hrefs

        def comp(text):
            try:
                return Version(matcher.match(text).groupdict()['version'])
            except (AttributeError, ValueError):
                return Version('0.0')

        latest = max(hrefs, key=comp)
        return '{}/{}'.format(url, latest)


def latest_release_from_gnome_org_cache(url, lib_name):
    cache_url = '{}/cache.json'.format(url)
    with contextlib.closing(urlopen(cache_url)) as r:
        cache = json.load(r)
        latest_version = cache[2][lib_name][-1]
        latest_source = cache[1][lib_name][latest_version]['tar.xz']
        return '{}/{}'.format(url, latest_source)


def latest_zlib_release():
    return latest_release_from_html('https://zlib.net/fossils', re.compile('zlib-(?P<version>.*).tar.gz'))


def latest_libiconv_release():
    return latest_release_from_html('https://ftp.gnu.org/pub/gnu/libiconv', re.compile('libiconv-(?P<version>.*).tar.gz'))


def latest_libxml2_release():
    return latest_release_from_gnome_org_cache('https://download.gnome.org/sources/libxml2', 'libxml2')


def latest_libxslt_release():
    return latest_release_from_gnome_org_cache('https://download.gnome.org/sources/libxslt', 'libxslt')


def latest_xmlsec_release():
    return latest_release_from_html('https://www.aleksey.com/xmlsec/download/', re.compile('xmlsec1-(?P<version>.*).tar.gz'))


class build_ext(build_ext_orig):
    def info(self, message):
        self.announce(message, level=log.INFO)

    def run(self):
        ext = self.ext_map['xmlsec']
        self.debug = os.environ.get('PYXMLSEC_ENABLE_DEBUG', False)
        self.static = os.environ.get('PYXMLSEC_STATIC_DEPS', False)

        if self.static or sys.platform == 'win32':
            self.info('starting static build on {}'.format(sys.platform))
            buildroot = Path('build', 'tmp')

            self.prefix_dir = buildroot / 'prefix'
            self.prefix_dir.mkdir(parents=True, exist_ok=True)
            self.prefix_dir = self.prefix_dir.absolute()

            self.build_libs_dir = buildroot / 'libs'
            self.build_libs_dir.mkdir(exist_ok=True)

            self.libs_dir = Path(os.environ.get('PYXMLSEC_LIBS_DIR', 'libs'))
            self.libs_dir.mkdir(exist_ok=True)
            self.info('{:20} {}'.format('Lib sources in:', self.libs_dir.absolute()))

            if sys.platform == 'win32':
                self.prepare_static_build_win()
            elif 'linux' in sys.platform:
                self.prepare_static_build_linux()
        else:
            import pkgconfig

            try:
                config = pkgconfig.parse('xmlsec1')
            except EnvironmentError:
                raise DistutilsError('Unable to invoke pkg-config.')
            except pkgconfig.PackageNotFoundError:
                raise DistutilsError('xmlsec1 is not installed or not in path.')

            if config is None or not config.get('libraries'):
                raise DistutilsError('Bad or incomplete result returned from pkg-config.')

            ext.define_macros.extend(config['define_macros'])
            ext.include_dirs.extend(config['include_dirs'])
            ext.library_dirs.extend(config['library_dirs'])
            ext.libraries.extend(config['libraries'])

        import lxml

        ext.include_dirs.extend(lxml.get_include())

        ext.define_macros.extend(
            [('MODULE_NAME', self.distribution.metadata.name), ('MODULE_VERSION', self.distribution.metadata.version)]
        )
        # escape the XMLSEC_CRYPTO macro value, see mehcode/python-xmlsec#141
        for (key, value) in ext.define_macros:
            if key == 'XMLSEC_CRYPTO' and not (value.startswith('"') and value.endswith('"')):
                ext.define_macros.remove((key, value))
                ext.define_macros.append((key, '"{0}"'.format(value)))
                break

        if sys.platform == 'win32':
            ext.extra_compile_args.append('/Zi')
        else:
            ext.extra_compile_args.extend(
                [
                    '-g',
                    '-std=c99',
                    '-fPIC',
                    '-fno-strict-aliasing',
                    '-Wno-error=declaration-after-statement',
                    '-Werror=implicit-function-declaration',
                ]
            )

        if self.debug:
            ext.extra_compile_args.append('-Wall')
            ext.extra_compile_args.append('-O0')
            ext.define_macros.append(('PYXMLSEC_ENABLE_DEBUG', '1'))
        else:
            ext.extra_compile_args.append('-Os')

        super(build_ext, self).run()

    def prepare_static_build_win(self):
        release_url = 'https://github.com/bgaifullin/libxml2-win-binaries/releases/download/v2018.08/'
        if sys.maxsize > 2147483647:
            suffix = 'win64'
        else:
            suffix = 'win32'

        libs = [
            'libxml2-2.9.4.{}.zip'.format(suffix),
            'libxslt-1.1.29.{}.zip'.format(suffix),
            'zlib-1.2.8.{}.zip'.format(suffix),
            'iconv-1.14.{}.zip'.format(suffix),
            'openssl-1.0.1.{}.zip'.format(suffix),
            'xmlsec-1.2.24.{}.zip'.format(suffix),
        ]

        for libfile in libs:
            url = urljoin(release_url, libfile)
            destfile = self.libs_dir / libfile
            if destfile.is_file():
                self.info('Using local copy of "{}"'.format(url))
            else:
                self.info('Retrieving "{}" to "{}"'.format(url, destfile))
                urlcleanup()  # work around FTP bug 27973 in Py2.7.12+
                urlretrieve(url, str(destfile))

        for p in self.libs_dir.glob('*.zip'):
            with zipfile.ZipFile(str(p)) as f:
                destdir = self.build_libs_dir
                f.extractall(path=str(destdir))

        ext = self.ext_map['xmlsec']
        ext.define_macros = [
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
        ]
        ext.libraries = [
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
        ]
        ext.library_dirs = [str(p.absolute()) for p in self.build_libs_dir.rglob('lib')]

        includes = [p for p in self.build_libs_dir.rglob('include') if p.is_dir()]
        includes.append(next(p / 'xmlsec' for p in includes if (p / 'xmlsec').is_dir()))
        ext.include_dirs = [str(p.absolute()) for p in includes]

    def prepare_static_build_linux(self):
        self.openssl_version = os.environ.get('PYXMLSEC_OPENSSL_VERSION', '1.1.1q')
        self.libiconv_version = os.environ.get('PYXMLSEC_LIBICONV_VERSION')
        self.libxml2_version = os.environ.get('PYXMLSEC_LIBXML2_VERSION')
        self.libxslt_version = os.environ.get('PYXMLSEC_LIBXSLT_VERSION')
        self.zlib_version = os.environ.get('PYXMLSEC_ZLIB_VERSION')
        self.xmlsec1_version = os.environ.get('PYXMLSEC_XMLSEC1_VERSION')

        # fetch openssl
        openssl_tar = next(self.libs_dir.glob('openssl*.tar.gz'), None)
        if openssl_tar is None:
            self.info('{:10}: {}'.format('OpenSSL', 'source tar not found, downloading ...'))
            openssl_tar = self.libs_dir / 'openssl.tar.gz'
            self.info('{:10}: {} {}'.format('OpenSSL', 'version', self.openssl_version))
            urlretrieve('https://www.openssl.org/source/openssl-{}.tar.gz'.format(self.openssl_version), str(openssl_tar))

        # fetch zlib
        zlib_tar = next(self.libs_dir.glob('zlib*.tar.gz'), None)
        if zlib_tar is None:
            self.info('{:10}: {}'.format('zlib', 'source not found, downloading ...'))
            zlib_tar = self.libs_dir / 'zlib.tar.gz'
            if self.zlib_version is None:
                url = latest_zlib_release()
                self.info('{:10}: {}'.format('zlib', 'PYXMLSEC_ZLIB_VERSION unset, downloading latest from {}'.format(url)))
            else:
                url = 'https://zlib.net/fossils/zlib-{}.tar.gz'.format(self.zlib_version)
                self.info(
                    '{:10}: {}'.format('zlib', 'PYXMLSEC_ZLIB_VERSION={}, downloading from {}'.format(self.zlib_version, url))
                )
            urlretrieve(url, str(zlib_tar))

        # fetch libiconv
        libiconv_tar = next(self.libs_dir.glob('libiconv*.tar.gz'), None)
        if libiconv_tar is None:
            self.info('{:10}: {}'.format('libiconv', 'source not found, downloading ...'))
            libiconv_tar = self.libs_dir / 'libiconv.tar.gz'
            if self.libiconv_version is None:
                url = latest_libiconv_release()
                self.info('{:10}: {}'.format('zlib', 'PYXMLSEC_LIBICONV_VERSION unset, downloading latest from {}'.format(url)))
            else:
                url = 'https://ftp.gnu.org/pub/gnu/libiconv/libiconv-{}.tar.gz'.format(self.libiconv_version)
                self.info(
                    '{:10}: {}'.format(
                        'zlib', 'PYXMLSEC_LIBICONV_VERSION={}, downloading from {}'.format(self.libiconv_version, url)
                    )
                )
            urlretrieve(url, str(libiconv_tar))

        # fetch libxml2
        libxml2_tar = next(self.libs_dir.glob('libxml2*.tar.xz'), None)
        if libxml2_tar is None:
            self.info('{:10}: {}'.format('libxml2', 'source tar not found, downloading ...'))
            if self.libxml2_version is None:
                url = latest_libxml2_release()
                self.info('{:10}: {}'.format('libxml2', 'PYXMLSEC_LIBXML2_VERSION unset, downloading latest from {}'.format(url)))
            else:
                version_prefix, _ = self.libxml2_version.rsplit('.', 1)
                url = 'https://download.gnome.org/sources/libxml2/{}/libxml2-{}.tar.xz'.format(
                    version_prefix, self.libxml2_version
                )
                self.info(
                    '{:10}: {}'.format(
                        'libxml2', 'PYXMLSEC_LIBXML2_VERSION={}, downloading from {}'.format(self.libxml2_version, url)
                    )
                )
            libxml2_tar = self.libs_dir / 'libxml2.tar.xz'
            urlretrieve(url, str(libxml2_tar))

        # fetch libxslt
        libxslt_tar = next(self.libs_dir.glob('libxslt*.tar.gz'), None)
        if libxslt_tar is None:
            self.info('{:10}: {}'.format('libxslt', 'source tar not found, downloading ...'))
            if self.libxslt_version is None:
                url = latest_libxslt_release()
                self.info('{:10}: {}'.format('libxslt', 'PYXMLSEC_LIBXSLT_VERSION unset, downloading latest from {}'.format(url)))
            else:
                version_prefix, _ = self.libxslt_version.rsplit('.', 1)
                url = 'https://download.gnome.org/sources/libxslt/{}/libxslt-{}.tar.xz'.format(
                    version_prefix, self.libxslt_version
                )
                self.info(
                    '{:10}: {}'.format(
                        'libxslt', 'PYXMLSEC_LIBXSLT_VERSION={}, downloading from {}'.format(self.libxslt_version, url)
                    )
                )
            libxslt_tar = self.libs_dir / 'libxslt.tar.gz'
            urlretrieve(url, str(libxslt_tar))

        # fetch xmlsec1
        xmlsec1_tar = next(self.libs_dir.glob('xmlsec1*.tar.gz'), None)
        if xmlsec1_tar is None:
            self.info('{:10}: {}'.format('xmlsec1', 'source tar not found, downloading ...'))
            if self.xmlsec1_version is None:
                url = latest_xmlsec_release()
                self.info('{:10}: {}'.format('xmlsec1', 'PYXMLSEC_XMLSEC1_VERSION unset, downloading latest from {}'.format(url)))
            else:
                url = 'https://www.aleksey.com/xmlsec/download/xmlsec1-{}.tar.gz'.format(self.xmlsec1_version)
                self.info(
                    '{:10}: {}'.format(
                        'xmlsec1', 'PYXMLSEC_XMLSEC1_VERSION={}, downloading from {}'.format(self.xmlsec1_version, url)
                    )
                )
            xmlsec1_tar = self.libs_dir / 'xmlsec1.tar.gz'
            urlretrieve(url, str(xmlsec1_tar))

        for file in (openssl_tar, zlib_tar, libiconv_tar, libxml2_tar, libxslt_tar, xmlsec1_tar):
            self.info('Unpacking {}'.format(file.name))
            try:
                with tarfile.open(str(file)) as tar:
                    tar.extractall(path=str(self.build_libs_dir))
            except EOFError:
                raise DistutilsError('Bad {} downloaded; remove it and try again.'.format(file.name))

        prefix_arg = '--prefix={}'.format(self.prefix_dir)

        cflags = ['-fPIC']
        env = os.environ.copy()
        if 'CFLAGS' in env:
            env['CFLAGS'].append(' '.join(cflags))
        else:
            env['CFLAGS'] = ' '.join(cflags)

        self.info('Building OpenSSL')
        openssl_dir = next(self.build_libs_dir.glob('openssl-*'))
        subprocess.check_output(['./config', prefix_arg, 'no-shared', '-fPIC'], cwd=str(openssl_dir), env=env)
        subprocess.check_output(['make', '-j{}'.format(multiprocessing.cpu_count() + 1)], cwd=str(openssl_dir), env=env)
        subprocess.check_output(
            ['make', '-j{}'.format(multiprocessing.cpu_count() + 1), 'install_sw'], cwd=str(openssl_dir), env=env
        )

        self.info('Building zlib')
        zlib_dir = next(self.build_libs_dir.glob('zlib-*'))
        subprocess.check_output(['./configure', prefix_arg], cwd=str(zlib_dir), env=env)
        subprocess.check_output(['make', '-j{}'.format(multiprocessing.cpu_count() + 1)], cwd=str(zlib_dir), env=env)
        subprocess.check_output(['make', '-j{}'.format(multiprocessing.cpu_count() + 1), 'install'], cwd=str(zlib_dir), env=env)

        self.info('Building libiconv')
        libiconv_dir = next(self.build_libs_dir.glob('libiconv-*'))
        subprocess.check_output(
            ['./configure', prefix_arg, '--disable-dependency-tracking', '--disable-shared'], cwd=str(libiconv_dir), env=env
        )
        subprocess.check_output(['make', '-j{}'.format(multiprocessing.cpu_count() + 1)], cwd=str(libiconv_dir), env=env)
        subprocess.check_output(
            ['make', '-j{}'.format(multiprocessing.cpu_count() + 1), 'install'], cwd=str(libiconv_dir), env=env
        )

        self.info('Building LibXML2')
        libxml2_dir = next(self.build_libs_dir.glob('libxml2-*'))
        subprocess.check_output(
            [
                './configure',
                prefix_arg,
                '--disable-dependency-tracking',
                '--disable-shared',
                '--enable-rebuild-docs=no',
                '--without-lzma',
                '--without-python',
                '--with-iconv={}'.format(self.prefix_dir),
                '--with-zlib={}'.format(self.prefix_dir),
            ],
            cwd=str(libxml2_dir),
            env=env,
        )
        subprocess.check_output(['make', '-j{}'.format(multiprocessing.cpu_count() + 1)], cwd=str(libxml2_dir), env=env)
        subprocess.check_output(
            ['make', '-j{}'.format(multiprocessing.cpu_count() + 1), 'install'], cwd=str(libxml2_dir), env=env
        )

        self.info('Building libxslt')
        libxslt_dir = next(self.build_libs_dir.glob('libxslt-*'))
        subprocess.check_output(
            [
                './configure',
                prefix_arg,
                '--disable-dependency-tracking',
                '--disable-shared',
                '--without-python',
                '--without-crypto',
                '--with-libxml-prefix={}'.format(self.prefix_dir),
            ],
            cwd=str(libxslt_dir),
            env=env,
        )
        subprocess.check_output(['make', '-j{}'.format(multiprocessing.cpu_count() + 1)], cwd=str(libxslt_dir), env=env)
        subprocess.check_output(
            ['make', '-j{}'.format(multiprocessing.cpu_count() + 1), 'install'], cwd=str(libxslt_dir), env=env
        )

        self.info('Building xmlsec1')
        if 'LDFLAGS' in env:
            env['LDFLAGS'].append(' -lpthread')
        else:
            env['LDFLAGS'] = '-lpthread'
        xmlsec1_dir = next(self.build_libs_dir.glob('xmlsec1-*'))
        subprocess.check_output(
            [
                './configure',
                prefix_arg,
                '--disable-shared',
                '--disable-gost',
                '--disable-crypto-dl',
                '--enable-static=yes',
                '--enable-shared=no',
                '--enable-static-linking=yes',
                '--with-default-crypto=openssl',
                '--with-openssl={}'.format(self.prefix_dir),
                '--with-libxml={}'.format(self.prefix_dir),
                '--with-libxslt={}'.format(self.prefix_dir),
            ],
            cwd=str(xmlsec1_dir),
            env=env,
        )
        subprocess.check_output(
            ['make', '-j{}'.format(multiprocessing.cpu_count() + 1)]
            + ['-I{}'.format(str(self.prefix_dir / 'include')), '-I{}'.format(str(self.prefix_dir / 'include' / 'libxml'))],
            cwd=str(xmlsec1_dir),
            env=env,
        )
        subprocess.check_output(
            ['make', '-j{}'.format(multiprocessing.cpu_count() + 1), 'install'], cwd=str(xmlsec1_dir), env=env
        )

        ext = self.ext_map['xmlsec']
        ext.define_macros = [
            ('__XMLSEC_FUNCTION__', '__func__'),
            ('XMLSEC_NO_SIZE_T', None),
            ('XMLSEC_NO_GOST', '1'),
            ('XMLSEC_NO_GOST2012', '1'),
            ('XMLSEC_NO_XKMS', '1'),
            ('XMLSEC_CRYPTO', '\\"openssl\\"'),
            ('XMLSEC_NO_CRYPTO_DYNAMIC_LOADING', '1'),
            ('XMLSEC_CRYPTO_OPENSSL', '1'),
            ('LIBXML_ICONV_ENABLED', 1),
            ('LIBXML_STATIC', '1'),
            ('LIBXSLT_STATIC', '1'),
            ('XMLSEC_STATIC', '1'),
            ('inline', '__inline'),
            ('UNICODE', '1'),
            ('_UNICODE', '1'),
        ]

        ext.include_dirs.append(str(self.prefix_dir / 'include'))
        ext.include_dirs.extend([str(p.absolute()) for p in (self.prefix_dir / 'include').iterdir() if p.is_dir()])

        ext.library_dirs = []
        ext.libraries = ['m', 'rt']
        extra_objects = [
            'libxmlsec1.a',
            'libxslt.a',
            'libxml2.a',
            'libz.a',
            'libxmlsec1-openssl.a',
            'libcrypto.a',
            'libiconv.a',
            'libxmlsec1.a',
        ]
        ext.extra_objects = [str(self.prefix_dir / 'lib' / o) for o in extra_objects]


src_root = Path(__file__).parent / 'src'
sources = [str(p.absolute()) for p in src_root.rglob('*.c')]
pyxmlsec = Extension('xmlsec', sources=sources)
setup_reqs = ['setuptools_scm[toml]>=3.4', 'pkgconfig>=1.5.1', 'lxml>=3.8']


with io.open('README.rst', encoding='utf-8') as f:
    long_desc = f.read()


setup(
    name='xmlsec',
    use_scm_version=True,
    description='Python bindings for the XML Security Library',
    long_description=long_desc,
    ext_modules=[pyxmlsec],
    cmdclass={'build_ext': build_ext},
    python_requires='>=3.5',
    setup_requires=setup_reqs,
    install_requires=['lxml>=3.8'],
    author="Bulat Gaifullin",
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
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Topic :: Text Processing :: Markup :: XML',
        'Typing :: Typed',
    ],
    zip_safe=False,
    packages=['xmlsec'],
    package_dir={'': 'src'},
    package_data={'xmlsec': ['py.typed', '*.pyi']},
)
