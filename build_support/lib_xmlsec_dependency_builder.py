import multiprocessing
import os
import platform
import subprocess
import sys
import tarfile
import zipfile
from dataclasses import dataclass
from distutils.errors import DistutilsError
from pathlib import Path
from typing import ClassVar
from urllib.parse import urljoin
from urllib.request import urlcleanup

from .network import download_lib
from .releases import (
    latest_libiconv_release,
    latest_libxml2_release,
    latest_libxslt_release,
    latest_openssl_release,
    latest_xmlsec_release,
    latest_zlib_release,
)


@dataclass
class CrossCompileInfo:
    host: str
    arch: str
    compiler: str

    @property
    def triplet(self) -> str:
        return f'{self.host}-{self.arch}-{self.compiler}'


class LibXmlsecDependencyBuilder:
    WINDOWS_LIBS_DOWNLOAD_RELEASE_URL = 'https://github.com/mxamin/python-xmlsec-win-binaries/releases/download/2025.07.10/'
    LIB_VERSION_ENV_VARS: ClassVar[dict[str, str]] = {
        'libiconv_version': 'PYXMLSEC_LIBICONV_VERSION',
        'libxml2_version': 'PYXMLSEC_LIBXML2_VERSION',
        'libxslt_version': 'PYXMLSEC_LIBXSLT_VERSION',
        'openssl_version': 'PYXMLSEC_OPENSSL_VERSION',
        'xmlsec1_version': 'PYXMLSEC_XMLSEC1_VERSION',
        'zlib_version': 'PYXMLSEC_ZLIB_VERSION',
    }
    UNIX_DEFAULT_LIB_VERSIONS: ClassVar[dict[str, str]] = {
        'libiconv_version': '1.18',
        'libxml2_version': '2.14.6',  # Make sure it matches with lxml
        'libxslt_version': '1.1.43',
        'openssl_version': '3.6.0',
        'xmlsec1_version': '1.3.9',
        'zlib_version': '1.3.1',
    }
    WINDOWS_DEFAULT_LIB_VERSIONS: ClassVar[dict[str, str]] = {
        'libiconv_version': '1.18-1',
        'libxml2_version': '2.11.9-3',  # Make sure it matches with lxml
        'libxslt_version': '1.1.39',
        'openssl_version': '3.0.16.pl1',
        'xmlsec1_version': '1.3.7',
        'zlib_version': '1.3.1',
    }

    def __init__(self, platform_name, info=None, libs_dir=None, buildroot=None, plat_name=None):
        self.platform_name = platform_name
        self.info = info or print
        self.plat_name = plat_name

        self._prepare_directories(libs_dir=libs_dir, buildroot=buildroot)
        self._set_library_versions(build_platform=platform_name)

    @property
    def versions(self):
        return {attr: getattr(self, attr) for attr in self.LIB_VERSION_ENV_VARS}

    def prepare(self, download_only=False):
        self.info(f'preparing dependency build on {self.platform_name}')
        if self.platform_name == 'win32':
            self._prepare_windows_build(download_only=download_only)
        elif 'linux' in self.platform_name or 'darwin' in self.platform_name:
            self._prepare_unix_build(build_platform=self.platform_name, download_only=download_only)
        else:
            raise DistutilsError(f'Unsupported static build platform: {self.platform_name}')

    def _prepare_directories(self, libs_dir=None, buildroot=None):
        buildroot_path = Path(buildroot) if buildroot else Path('build', 'tmp')

        prefix_dir = buildroot_path / 'prefix'
        prefix_dir.mkdir(parents=True, exist_ok=True)
        self.prefix_dir = prefix_dir.absolute()

        build_libs_dir = buildroot_path / 'libs'
        build_libs_dir.mkdir(parents=True, exist_ok=True)
        self.build_libs_dir = build_libs_dir

        libs_root = libs_dir if libs_dir is not None else os.environ.get('PYXMLSEC_LIBS_DIR', 'libs')
        libs_dir_path = Path(libs_root)
        libs_dir_path.mkdir(parents=True, exist_ok=True)
        self.libs_dir = libs_dir_path

        self.info('{:20} {}'.format('Lib sources in:', self.libs_dir.absolute()))

    def _set_library_versions(self, build_platform):
        defaults = self.UNIX_DEFAULT_LIB_VERSIONS
        if build_platform == 'win32':
            defaults = self.WINDOWS_DEFAULT_LIB_VERSIONS

        for version_attr, env_var in self.LIB_VERSION_ENV_VARS.items():
            setattr(self, version_attr, os.environ.get(env_var, defaults[version_attr]))

    def _prepare_windows_build(self, download_only=False):
        if platform.machine() == 'ARM64':
            suffix = 'win-arm64'
        elif sys.maxsize > 2**32:
            suffix = 'win64'
        else:
            suffix = 'win32'

        libs = [
            f'libxml2-{self.libxml2_version}.{suffix}.zip',
            f'libxslt-{self.libxslt_version}.{suffix}.zip',
            f'zlib-{self.zlib_version}.{suffix}.zip',
            f'iconv-{self.libiconv_version}.{suffix}.zip',
            f'openssl-{self.openssl_version}.{suffix}.zip',
            f'xmlsec-{self.xmlsec1_version}.{suffix}.zip',
        ]

        for libfile in libs:
            url = urljoin(self.WINDOWS_LIBS_DOWNLOAD_RELEASE_URL, libfile)
            destfile = self.libs_dir / libfile
            if destfile.is_file():
                self.info(f'Using local copy of "{url}"')
            else:
                self.info(f'Retrieving "{url}" to "{destfile}"')
                urlcleanup()
                download_lib(url, str(destfile))

        if download_only:
            return

        for package in self.libs_dir.glob('*.zip'):
            with zipfile.ZipFile(str(package)) as archive:
                archive.extractall(path=str(self.build_libs_dir))

    def _prepare_unix_build(self, build_platform, download_only=False):
        archives = self._ensure_source_archives()
        if download_only:
            return

        self._extract_archives(archives)

        env, prefix_arg, ldflags, cross_compile = self._prepare_build_environment(build_platform)
        self._build_dependencies(env, prefix_arg, ldflags, cross_compile)

    def _ensure_source_archives(self):
        return [
            self._ensure_source(
                name='OpenSSL',
                glob='openssl*.tar.gz',
                filename='openssl.tar.gz',
                version=self.openssl_version,
                env_label='PYXMLSEC_OPENSSL_VERSION',
                default_url=latest_openssl_release,
                version_url=lambda v: f'https://api.github.com/repos/openssl/openssl/tarball/openssl-{v}',
            ),
            self._ensure_source(
                name='zlib',
                glob='zlib*.tar.gz',
                filename='zlib.tar.gz',
                version=self.zlib_version,
                env_label='PYXMLSEC_ZLIB_VERSION',
                default_url=latest_zlib_release,
                version_url=lambda v: f'https://zlib.net/fossils/zlib-{v}.tar.gz',
            ),
            self._ensure_source(
                name='libiconv',
                glob='libiconv*.tar.gz',
                filename='libiconv.tar.gz',
                version=self.libiconv_version,
                env_label='PYXMLSEC_LIBICONV_VERSION',
                default_url=latest_libiconv_release,
                version_url=lambda v: f'https://ftpmirror.gnu.org/libiconv/libiconv-{v}.tar.gz',
            ),
            self._ensure_source(
                name='libxml2',
                glob='libxml2*.tar.xz',
                filename='libxml2.tar.xz',
                version=self.libxml2_version,
                env_label='PYXMLSEC_LIBXML2_VERSION',
                default_url=latest_libxml2_release,
                version_url=lambda v: self._libxml_related_url('libxml2', v),
            ),
            self._ensure_source(
                name='libxslt',
                glob='libxslt*.tar.xz',
                filename='libxslt.tar.xz',
                version=self.libxslt_version,
                env_label='PYXMLSEC_LIBXSLT_VERSION',
                default_url=latest_libxslt_release,
                version_url=lambda v: self._libxml_related_url('libxslt', v),
            ),
            self._ensure_source(
                name='xmlsec1',
                glob='xmlsec1*.tar.gz',
                filename='xmlsec1.tar.gz',
                version=self.xmlsec1_version,
                env_label='PYXMLSEC_XMLSEC1_VERSION',
                default_url=latest_xmlsec_release,
                version_url=lambda v: f'https://github.com/lsh123/xmlsec/releases/download/{v}/xmlsec1-{v}.tar.gz',
            ),
        ]

    def _ensure_source(self, name, glob, filename, version, env_label, default_url, version_url):
        archive = next(self.libs_dir.glob(glob), None)
        if archive is not None:
            return archive

        self.info('{:10}: {}'.format(name, 'source tar not found, downloading ...'))
        archive = self.libs_dir / filename
        if version is None:
            url = default_url()
            self.info('{:10}: {}'.format(name, f'{env_label} unset, downloading latest from {url}'))
        else:
            url = version_url(version)
            self.info('{:10}: {}'.format(name, f'{env_label}={version}, downloading from {url}'))
        download_lib(url, str(archive))
        return archive

    def _libxml_related_url(self, lib_name, version):
        version_prefix, _ = version.rsplit('.', 1)
        return f'https://download.gnome.org/sources/{lib_name}/{version_prefix}/{lib_name}-{version}.tar.xz'

    def _extract_archives(self, archives):
        for archive in archives:
            self.info(f'Unpacking {archive.name}')
            try:
                with tarfile.open(str(archive)) as tar:
                    if sys.version_info >= (3, 12):
                        tar.extractall(path=str(self.build_libs_dir), filter='data')
                    else:
                        tar.extractall(path=str(self.build_libs_dir))
            except EOFError as error:
                raise DistutilsError(f'Bad {archive.name} downloaded; remove it and try again.') from error

    def _prepare_build_environment(self, build_platform):
        prefix_arg = f'--prefix={self.prefix_dir}'
        env = os.environ.copy()

        cflags = []
        if env.get('CFLAGS'):
            cflags.append(env['CFLAGS'])
        cflags.append('-fPIC')

        ldflags = []
        if env.get('LDFLAGS'):
            ldflags.append(env['LDFLAGS'])

        cross_compile = None
        if build_platform == 'darwin':
            if self.plat_name:
                arch = self.plat_name.rsplit('-', 1)[1]
                if arch != platform.machine() and arch in ('x86_64', 'arm64'):
                    self.info(f'Cross-compiling for {arch}')
                    cflags.append(f'-arch {arch}')
                    ldflags.append(f'-arch {arch}')
                    cross_compile = CrossCompileInfo('darwin64', arch, 'cc')
            major_version, _ = tuple(map(int, platform.mac_ver()[0].split('.')[:2]))
            if major_version >= 11 and 'MACOSX_DEPLOYMENT_TARGET' not in env:
                env['MACOSX_DEPLOYMENT_TARGET'] = '11.0'

        env['CFLAGS'] = ' '.join(cflags)
        env['LDFLAGS'] = ' '.join(ldflags)
        return env, prefix_arg, ldflags, cross_compile

    def _build_dependencies(self, env, prefix_arg, ldflags, cross_compile):
        self._build_openssl(env, prefix_arg, cross_compile)
        self._build_zlib(env, prefix_arg)

        host_arg = [f'--host={cross_compile.arch}'] if cross_compile else []
        self._build_libiconv(env, prefix_arg, host_arg)
        self._build_libxml2(env, prefix_arg, host_arg)
        self._build_libxslt(env, prefix_arg, host_arg)

        ldflags.append('-lpthread')
        env['LDFLAGS'] = ' '.join(ldflags)
        self._build_xmlsec1(env, prefix_arg, host_arg)

    def _build_openssl(self, env, prefix_arg, cross_compile):
        self.info('Building OpenSSL')
        openssl_dir = next(self.build_libs_dir.glob('openssl-*'))
        openssl_config_cmd = [prefix_arg, 'no-shared', '-fPIC', '--libdir=lib']
        if platform.machine() == 'riscv64':
            # openssl(riscv64): disable ASM to avoid R_RISCV_JAL relocation failure on 3.5.2
            # OpenSSL 3.5.2 enables RISC-V64 AES assembly by default. When we statically
            # link libcrypto alongside xmlsec, the AES asm path triggers a link-time error:
            #   relocation truncated to fit: R_RISCV_JAL against symbol `AES_set_encrypt_key'
            #   in .../libcrypto.a(libcrypto-lib-aes-riscv64.o)
            # This appears to stem from a long-range jump emitted by the AES asm generator
            # (see aes-riscv64.pl around L1069), which can exceed the JAL reach when objects
            # end up far apart in the final static link.
            # As a pragmatic workaround, disable ASM on riscv64 (pass `no-asm`) so the
            # portable C implementation is used. This unblocks the build at the cost of
            # some crypto performance on riscv64 only.
            # Refs:
            # - https://github.com/openssl/openssl/blob/0893a62/crypto/aes/asm/aes-riscv64.pl#L1069
            openssl_config_cmd.append('no-asm')
        if cross_compile:
            openssl_config_cmd.insert(0, './Configure')
            openssl_config_cmd.append(cross_compile.triplet)
        else:
            openssl_config_cmd.insert(0, './config')
        subprocess.check_call(openssl_config_cmd, cwd=str(openssl_dir), env=env)
        subprocess.check_call(['make', f'-j{multiprocessing.cpu_count() + 1}'], cwd=str(openssl_dir), env=env)
        subprocess.check_call(['make', f'-j{multiprocessing.cpu_count() + 1}', 'install_sw'], cwd=str(openssl_dir), env=env)

    def _build_zlib(self, env, prefix_arg):
        self.info('Building zlib')
        zlib_dir = next(self.build_libs_dir.glob('zlib-*'))
        subprocess.check_call(['./configure', prefix_arg], cwd=str(zlib_dir), env=env)
        subprocess.check_call(['make', f'-j{multiprocessing.cpu_count() + 1}'], cwd=str(zlib_dir), env=env)
        subprocess.check_call(['make', f'-j{multiprocessing.cpu_count() + 1}', 'install'], cwd=str(zlib_dir), env=env)

    def _build_libiconv(self, env, prefix_arg, host_arg):
        self.info('Building libiconv')
        libiconv_dir = next(self.build_libs_dir.glob('libiconv-*'))
        subprocess.check_call(
            [
                './configure',
                prefix_arg,
                '--disable-dependency-tracking',
                '--disable-shared',
                *host_arg,
            ],
            cwd=str(libiconv_dir),
            env=env,
        )
        subprocess.check_call(['make', f'-j{multiprocessing.cpu_count() + 1}'], cwd=str(libiconv_dir), env=env)
        subprocess.check_call(['make', f'-j{multiprocessing.cpu_count() + 1}', 'install'], cwd=str(libiconv_dir), env=env)

    def _build_libxml2(self, env, prefix_arg, host_arg):
        self.info('Building LibXML2')
        libxml2_dir = next(self.build_libs_dir.glob('libxml2-*'))
        subprocess.check_call(
            [
                './configure',
                prefix_arg,
                '--disable-dependency-tracking',
                '--disable-shared',
                '--without-lzma',
                '--without-python',
                f'--with-iconv={self.prefix_dir}',
                f'--with-zlib={self.prefix_dir}',
                *host_arg,
            ],
            cwd=str(libxml2_dir),
            env=env,
        )
        subprocess.check_call(['make', f'-j{multiprocessing.cpu_count() + 1}'], cwd=str(libxml2_dir), env=env)
        subprocess.check_call(['make', f'-j{multiprocessing.cpu_count() + 1}', 'install'], cwd=str(libxml2_dir), env=env)

    def _build_libxslt(self, env, prefix_arg, host_arg):
        self.info('Building libxslt')
        libxslt_dir = next(self.build_libs_dir.glob('libxslt-*'))
        subprocess.check_call(
            [
                './configure',
                prefix_arg,
                '--disable-dependency-tracking',
                '--disable-shared',
                '--without-python',
                '--without-crypto',
                f'--with-libxml-prefix={self.prefix_dir}',
                *host_arg,
            ],
            cwd=str(libxslt_dir),
            env=env,
        )
        subprocess.check_call(['make', f'-j{multiprocessing.cpu_count() + 1}'], cwd=str(libxslt_dir), env=env)
        subprocess.check_call(['make', f'-j{multiprocessing.cpu_count() + 1}', 'install'], cwd=str(libxslt_dir), env=env)

    def _build_xmlsec1(self, env, prefix_arg, host_arg):
        self.info('Building xmlsec1')
        xmlsec1_dir = next(self.build_libs_dir.glob('xmlsec1-*'))
        subprocess.check_call(
            [
                './configure',
                prefix_arg,
                '--disable-shared',
                '--disable-gost',
                '--enable-md5',
                '--enable-ripemd160',
                '--disable-crypto-dl',
                '--enable-static=yes',
                '--enable-shared=no',
                '--enable-static-linking=yes',
                '--with-default-crypto=openssl',
                f'--with-openssl={self.prefix_dir}',
                f'--with-libxml={self.prefix_dir}',
                f'--with-libxslt={self.prefix_dir}',
                *host_arg,
            ],
            cwd=str(xmlsec1_dir),
            env=env,
        )
        include_flags = [
            f'-I{self.prefix_dir / "include"}',
            f'-I{self.prefix_dir / "include" / "libxml"}',
        ]
        subprocess.check_call(
            ['make', f'-j{multiprocessing.cpu_count() + 1}', *include_flags],
            cwd=str(xmlsec1_dir),
            env=env,
        )
        subprocess.check_call(['make', f'-j{multiprocessing.cpu_count() + 1}', 'install'], cwd=str(xmlsec1_dir), env=env)


__all__ = ('CrossCompileInfo', 'LibXmlsecDependencyBuilder')
