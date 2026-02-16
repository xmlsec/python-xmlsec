import sys
from distutils.errors import DistutilsError

from .lib_xmlsec_dependency_builder import CrossCompileInfo, LibXmlsecDependencyBuilder


class StaticBuildHelper:
    def __init__(self, builder):
        self.builder = builder
        self.ext = builder.ext_map['xmlsec']
        self.info = builder.info

    def prepare(self, platform_name):
        self.info(f'starting static build on {sys.platform}')
        deps_builder = LibXmlsecDependencyBuilder(
            platform_name=platform_name,
            info=self.info,
            plat_name=getattr(self.builder, 'plat_name', None),
        )
        deps_builder.prepare()

        self.prefix_dir = deps_builder.prefix_dir
        self.build_libs_dir = deps_builder.build_libs_dir
        self.libs_dir = deps_builder.libs_dir

        self.builder.prefix_dir = self.prefix_dir
        self.builder.build_libs_dir = self.build_libs_dir
        self.builder.libs_dir = self.libs_dir

        for version_attr, value in deps_builder.versions.items():
            setattr(self.builder, version_attr, value)

        if platform_name == 'win32':
            self._configure_windows_extension_for_static()
        elif 'linux' in platform_name or 'darwin' in platform_name:
            self._configure_unix_extension_for_static(platform_name)
        else:
            raise DistutilsError(f'Unsupported static build platform: {platform_name}')

    def _configure_windows_extension_for_static(self):
        self.ext.define_macros = [
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
            ('LIBXSLT_STATIC', 1),
            ('XMLSEC_STATIC', 1),
            ('inline', '__inline'),
        ]
        self.ext.libraries = [
            'libxmlsec_a',
            'libxmlsec-openssl_a',
            'libcrypto',
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
        self.ext.library_dirs = [str(path.absolute()) for path in self.build_libs_dir.rglob('lib')]

        includes = [path for path in self.build_libs_dir.rglob('include') if path.is_dir()]
        includes.append(next(path / 'xmlsec' for path in includes if (path / 'xmlsec').is_dir()))
        self.ext.include_dirs = [str(path.absolute()) for path in includes]

    def _configure_unix_extension_for_static(self, build_platform):
        self.ext.define_macros = [
            ('__XMLSEC_FUNCTION__', '__func__'),
            ('XMLSEC_NO_SIZE_T', None),
            ('XMLSEC_NO_GOST', '1'),
            ('XMLSEC_NO_GOST2012', '1'),
            ('XMLSEC_NO_XKMS', '1'),
            ('XMLSEC_CRYPTO', '\\"openssl\\"'),
            ('XMLSEC_NO_CRYPTO_DYNAMIC_LOADING', '1'),
            ('XMLSEC_CRYPTO_OPENSSL', '1'),
            ('LIBXML_ICONV_ENABLED', 1),
            ('LIBXML_STATIC', 1),
            ('LIBXSLT_STATIC', 1),
            ('XMLSEC_STATIC', 1),
            ('inline', '__inline'),
            ('UNICODE', '1'),
            ('_UNICODE', '1'),
        ]

        self.ext.include_dirs.append(str(self.prefix_dir / 'include'))
        self.ext.include_dirs.extend([str(path.absolute()) for path in (self.prefix_dir / 'include').iterdir() if path.is_dir()])

        self.ext.library_dirs = []
        if build_platform == 'linux':
            self.ext.libraries = ['m', 'rt']
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
        self.ext.extra_objects = [str(self.prefix_dir / 'lib' / obj) for obj in extra_objects]


__all__ = ('CrossCompileInfo', 'StaticBuildHelper')
