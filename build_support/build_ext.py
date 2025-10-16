import os
import sys
from distutils import log
from distutils.errors import DistutilsError

from setuptools.command.build_ext import build_ext as build_ext_orig

from .static_build import CrossCompileInfo, StaticBuildHelper


class build_ext(build_ext_orig):
    def info(self, message):
        self.announce(message, level=log.INFO)

    def run(self):
        ext = self.ext_map['xmlsec']
        self.debug = os.environ.get('PYXMLSEC_ENABLE_DEBUG', False)
        self.static = os.environ.get('PYXMLSEC_STATIC_DEPS', False)
        self.size_opt = os.environ.get('PYXMLSEC_OPTIMIZE_SIZE', True)

        if self.static or sys.platform == 'win32':
            helper = StaticBuildHelper(self)
            helper.prepare(sys.platform)
        else:
            import pkgconfig

            try:
                config = pkgconfig.parse('xmlsec1')
            except OSError as error:
                raise DistutilsError('Unable to invoke pkg-config.') from error
            except pkgconfig.PackageNotFoundError as error:
                raise DistutilsError('xmlsec1 is not installed or not in path.') from error

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
        for key, value in ext.define_macros:
            if key == 'XMLSEC_CRYPTO' and not (value.startswith('"') and value.endswith('"')):
                ext.define_macros.remove((key, value))
                ext.define_macros.append((key, f'"{value}"'))
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
            ext.define_macros.append(('PYXMLSEC_ENABLE_DEBUG', '1'))
            if sys.platform == 'win32':
                ext.extra_compile_args.append('/Od')
            else:
                ext.extra_compile_args.append('-Wall')
                ext.extra_compile_args.append('-O0')
        else:
            if self.size_opt:
                if sys.platform == 'win32':
                    ext.extra_compile_args.append('/Os')
                else:
                    ext.extra_compile_args.append('-Os')

        super().run()


__all__ = ('CrossCompileInfo', 'build_ext')
