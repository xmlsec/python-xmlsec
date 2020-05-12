import multiprocessing
import os
import subprocess
import sys
import tarfile
import zipfile
from distutils import log

from setuptools import Extension, setup
from setuptools.command.build_ext import build_ext as build_ext_orig

if sys.version_info >= (3, 4):
    from pathlib import Path
    from urllib.request import urlcleanup, urljoin, urlretrieve
else:
    from urllib import urlcleanup, urljoin, urlretrieve
    from pathlib2 import Path


class build_ext(build_ext_orig):
    def info(self, message):
        self.announce(message, level=log.INFO)

    def run(self):
        if os.environ.get('STATIC_DEPS', False) or sys.platform == 'win32':
            self.info('STATIC_DEPS is set; starting build of static deps on {}'.format(sys.platform))
            buildroot = Path('build', 'tmp')

            self.prefix_dir = buildroot / 'prefix'
            self.prefix_dir.mkdir(parents=True, exist_ok=True)
            self.prefix_dir = self.prefix_dir.absolute()

            self.build_libs_dir = buildroot / 'libs'
            self.build_libs_dir.mkdir(exist_ok=True)

            self.libs_dir = Path(os.environ.get('LIBS_DIR', 'libs'))
            self.libs_dir.mkdir(exist_ok=True)

            if sys.platform == 'win32':
                self.prepare_static_build_win()
            elif 'linux' in sys.platform:
                self.prepare_static_build_linux()
        super(build_ext, self).run()

    def prepare_static_build_win(self):
        release_url = 'https://github.com/bgaifullin/libxml2-win-binaries/releases/download/v2018.08/'
        if sys.version_info < (3, 5):
            if sys.maxsize > 2147483647:
                suffix = 'vs2008.win64'
            else:
                suffix = "vs2008.win32"
        else:
            if sys.maxsize > 2147483647:
                suffix = "win64"
            else:
                suffix = "win32"

        libs = {
            'libxml2': 'libxml2-2.9.4.{}.zip'.format(suffix),
            'libxslt': 'libxslt-1.1.29.{}.zip'.format(suffix),
            'zlib': 'zlib-1.2.8.{}.zip'.format(suffix),
            'iconv': 'iconv-1.14.{}.zip'.format(suffix),
            'openssl': 'openssl-1.0.1.{}.zip'.format(suffix),
            'xmlsec': 'xmlsec-1.2.24.{}.zip'.format(suffix),
        }

        for lib, file in libs.items():
            url = urljoin(release_url, file)
            destfile = self.libs_dir / file
            if destfile.is_file():
                self.info('Using local copy of "{}"'.format(url))
            else:
                self.info('Retrieving "{}" to "{}"'.format(url, destfile))
                urlcleanup()  # work around FTP bug 27973 in Py2.7.12+
                urlretrieve(url, destfile)

        for p in self.libs_dir.glob('*.zip'):
            with zipfile.ZipFile(p) as f:
                destdir = self.build_libs_dir
                f.extractall(path=destdir)

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

        includes = [p for p in self.build_libs_dir.rglob('include') if p.is_dir()]
        includes.append(next(p / 'xmlsec' for p in includes if (p / 'xmlsec').is_dir()))
        ext.include_dirs = [str(p.absolute()) for p in includes]
        ext.library_dirs = [str(p.absolute()) for p in self.build_libs_dir.rglob('lib')]

    def prepare_static_build_linux(self):
        self.debug = os.environ.get('DEBUG', False)
        self.openssl_version = '1.1.1g'
        self.libiconv_version = os.environ.get('LIBICONV_VERSION', '1.16')
        self.libxml2_version = os.environ.get('LIBXML2_VERSION', None)
        self.libxslt_version = os.environ.get('LIBXLST_VERSION', None)
        self.zlib_version = os.environ.get('ZLIB_VERSION', '1.2.11')
        self.xmlsec1_version = os.environ.get('XMLSEC1_VERSION', '1.2.30')

        self.info('Settings:')
        self.info('{:20} {}'.format('Lib sources in:', self.libs_dir.absolute()))
        self.info('{:20} {}'.format('zlib version:', self.zlib_version))
        self.info('{:20} {}'.format('libiconv version:', self.libiconv_version))
        self.info('{:20} {}'.format('libxml2 version:', self.libxml2_version))
        self.info('{:20} {}'.format('libxslt version:', self.libxslt_version))
        self.info('{:20} {}'.format('xmlsec1 version:', self.xmlsec1_version))

        # fetch openssl
        openssl_tar = next(self.libs_dir.glob('openssl*.tar.gz'), None)
        if openssl_tar is None:
            self.info('OpenSSL source tar not found, downloading ...')
            openssl_tar = self.libs_dir / 'openssl.tar.gz'
            urlretrieve('https://www.openssl.org/source/openssl-{}.tar.gz'.format(self.openssl_version), openssl_tar)

        # fetch zlib
        zlib_tar = next(self.libs_dir.glob('zlib*.tar.gz'), None)
        if zlib_tar is None:
            self.info('zlib source tar not found, downloading ...')
            zlib_tar = self.libs_dir / 'zlib.tar.gz'
            urlretrieve('https://zlib.net/zlib-{}.tar.gz'.format(self.zlib_version), zlib_tar)

        # fetch libiconv
        libiconv_tar = next(self.libs_dir.glob('libiconv*.tar.gz'), None)
        if libiconv_tar is None:
            self.info('libiconv source tar not found, downloading ...')
            libiconv_tar = self.libs_dir / 'libiconv.tar.gz'
            urlretrieve('https://ftp.gnu.org/pub/gnu/libiconv/libiconv-{}.tar.gz'.format(self.libiconv_version), libiconv_tar)

        # fetch libxml2
        libxml2_tar = next(self.libs_dir.glob('libxml2*.tar.gz'), None)
        if libxml2_tar is None:
            self.info('Libxml2 source tar not found, downloading ...')
            if self.libxml2_version is None:
                url = 'http://xmlsoft.org/sources/LATEST_LIBXML2'
            else:
                url = 'http://xmlsoft.org/sources/libxml2-{}.tar.gz'.format(self.libxml2_version)
            libxml2_tar = self.libs_dir / 'libxml2.tar.gz'
            urlretrieve(url, libxml2_tar)

        # fetch libxslt
        libxslt_tar = next(self.libs_dir.glob('libxslt*.tar.gz'), None)
        if libxslt_tar is None:
            self.info('libxslt source tar not found, downloading ...')
            if self.libxslt_version is None:
                url = 'http://xmlsoft.org/sources/LATEST_LIBXSLT'
            else:
                url = 'http://xmlsoft.org/sources/libxslt-{}.tar.gz'.format(self.libxslt_version)
            libxslt_tar = self.libs_dir / 'libxslt.tar.gz'
            urlretrieve(url, libxslt_tar)

        # fetch xmlsec1
        xmlsec1_tar = next(self.libs_dir.glob('xmlsec1*.tar.gz'), None)
        if xmlsec1_tar is None:
            self.info('xmlsec1 source tar not found, downloading ...')
            url = 'http://www.aleksey.com/xmlsec/download/xmlsec1-{}.tar.gz'.format(self.xmlsec1_version)
            xmlsec1_tar = self.libs_dir / 'xmlsec1.tar.gz'
            urlretrieve(url, xmlsec1_tar)

        for file in (openssl_tar, zlib_tar, libiconv_tar, libxml2_tar, libxslt_tar, xmlsec1_tar):
            self.info('Unpacking {}'.format(file.name))
            with tarfile.open(file) as tar:
                tar.extractall(path=self.build_libs_dir)

        prefix_arg = '--prefix={}'.format(prefix_dir)

        cflags = ['-fPIC']
        env = os.environ.copy()
        if 'CFLAGS' in env:
            env['CFLAGS'].append(' '.join(cflags))
        else:
            env['CFLAGS'] = ' '.join(cflags)

        self.info('Building OpenSSL')
        openssl_dir = next(self.build_libs_dir.glob('openssl-*'))
        subprocess.run(['./config', prefix_arg, 'no-shared', '-fPIC'], cwd=openssl_dir, env=env)
        subprocess.run(['make', '-j{}'.format(multiprocessing.cpu_count() + 1)], cwd=openssl_dir, env=env)
        subprocess.run(['make', '-j{}'.format(multiprocessing.cpu_count() + 1), 'install_sw'], cwd=openssl_dir, env=env)

        self.info('Building zlib')
        zlib_dir = next(self.build_libs_dir.glob('zlib-*'))
        subprocess.run(['./configure', prefix_arg], cwd=zlib_dir, env=env)
        subprocess.run(['make', '-j{}'.format(multiprocessing.cpu_count() + 1)], cwd=zlib_dir, env=env)
        subprocess.run(['make', '-j{}'.format(multiprocessing.cpu_count() + 1), 'install'], cwd=zlib_dir, env=env)

        self.info('Building libiconv')
        libiconv_dir = next(self.build_libs_dir.glob('libiconv-*'))
        subprocess.run(
            ['./configure', prefix_arg, '--disable-dependency-tracking', '--disable-shared'], cwd=libiconv_dir, env=env
        )
        subprocess.run(['make', '-j{}'.format(multiprocessing.cpu_count() + 1)], cwd=libiconv_dir, env=env)
        subprocess.run(['make', '-j{}'.format(multiprocessing.cpu_count() + 1), 'install'], cwd=libiconv_dir, env=env)

        self.info('Building LibXML2')
        libxml2_dir = next(self.build_libs_dir.glob('libxml2-*'))
        subprocess.run(
            [
                './configure',
                prefix_arg,
                '--without-python',
                '--with-iconv={}'.format(self.prefix_dir),
                '--with-zlib={}'.format(self.prefix_dir),
            ],
            cwd=libxml2_dir,
            env=env,
        )
        subprocess.run(['make', '-j{}'.format(multiprocessing.cpu_count() + 1)], cwd=libxml2_dir, env=env)
        subprocess.run(['make', '-j{}'.format(multiprocessing.cpu_count() + 1), 'install'], cwd=libxml2_dir, env=env)

        self.info('Building libxslt')
        libxslt_dir = next(self.build_libs_dir.glob('libxslt-*'))
        subprocess.run(
            [
                './configure',
                prefix_arg,
                '--without-python',
                '--with-libxml-prefix={}'.format(self.prefix_dir),
                '--without-crypto',
            ],
            cwd=libxslt_dir,
            env=env,
        )
        subprocess.run(['make', '-j{}'.format(multiprocessing.cpu_count() + 1)], cwd=libxslt_dir, env=env)
        subprocess.run(['make', '-j{}'.format(multiprocessing.cpu_count() + 1), 'install'], cwd=libxslt_dir, env=env)

        self.info('Building xmlsec1')
        if 'LDFLAGS' in env:
            env['LDFLAGS'].append(' -lpthread')
        else:
            env['LDFLAGS'] = '-lpthread'
        xmlsec1_dir = next(self.build_libs_dir.glob('xmlsec1-*'))
        subprocess.run(
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
            cwd=xmlsec1_dir,
            env=env,
        )
        subprocess.run(
            ['make', '-j{}'.format(multiprocessing.cpu_count() + 1)]
            + ['-I{}'.format(str(self.prefix_dir / 'include')), '-I{}'.format(str(self.prefix_dir / 'include' / 'libxml'))],
            cwd=xmlsec1_dir,
            env=env,
        )
        subprocess.run(['make', '-j{}'.format(multiprocessing.cpu_count() + 1), 'install'], cwd=xmlsec1_dir, env=env)

        ext = self.ext_map['xmlsec']
        ext.define_macros = [
            ('MODULE_NAME', self.distribution.metadata.name),
            ('MODULE_VERSION', self.distribution.metadata.version),
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

        if self.debug:
            ext.define_macros.append(('PYXMLSEC_ENABLE_DEBUG', '1'))

        ext.extra_compile_args.extend(
            [
                '-O0',
                '-g',
                '-std=c99',
                '-fPIC',
                '-fno-strict-aliasing',
                '-Wno-error=declaration-after-statement',
                '-Werror=implicit-function-declaration',
            ]
        )

        ext.include_dirs.append(str(self.prefix_dir / 'include'))
        ext.include_dirs.extend([str(p.absolute()) for p in (self.prefix_dir / 'include').iterdir() if p.is_dir()])
        import lxml

        ext.include_dirs.extend(lxml.get_include())

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


src_root = Path('src')
sources = [str(p.absolute()) for p in src_root.rglob('*.c')]
pyxmlsec = Extension('xmlsec', sources=sources)
setup_reqs = ['setuptools_scm[toml]>=3.4', 'pkgconfig', 'lxml>=3.8']

if sys.version_info < (3,):
    setup_reqs.append('pathlib2')


setup(
    name='xmlsec',
    use_scm_version=True,
    description='Python bindings for the XML Security Library',
    ext_modules=[pyxmlsec],
    cmdclass={'build_ext': build_ext},
    setup_requires=setup_reqs,
    install_requires=['lxml>=3.8'],
    author="Bulat Gaifullin",
    author_email='support@mehcode.com',
    maintainer='Oleg Hoefling',
    maintainer_email='oleg.hoefling@gmail.com',
    url='https://github.com/mehcode/python-xmlsec',
    license='MIT',
    keywords=['xmlsec'],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: C',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Topic :: Text Processing :: Markup :: XML',
    ],
)
