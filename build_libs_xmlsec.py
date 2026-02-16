import argparse
import os
import sys
from pathlib import Path

from build_support.lib_xmlsec_dependency_builder import LibXmlsecDependencyBuilder


def _console_info(message):
    print(message)


def main(argv=None):
    parser = argparse.ArgumentParser(description='Download and build static dependency libraries for python-xmlsec.')
    parser.add_argument(
        '--platform',
        default=sys.platform,
        help='Target platform (default: current interpreter platform).',
    )
    parser.add_argument(
        '--plat-name',
        default=os.environ.get('PYXMLSEC_PLAT_NAME'),
        help='Target platform tag for cross-compiling (for example macosx-11.0-arm64).',
    )
    parser.add_argument(
        '--libs-dir',
        default=os.environ.get('PYXMLSEC_LIBS_DIR', 'libs'),
        help='Directory where source/binary archives are stored.',
    )
    parser.add_argument(
        '--buildroot',
        default=Path('build', 'tmp'),
        type=Path,
        help='Build root for extracted/build artifacts.',
    )
    parser.add_argument(
        '--download-only',
        action='store_true',
        help='Only download dependency archives; do not extract/build.',
    )

    args = parser.parse_args(argv)
    builder = LibXmlsecDependencyBuilder(
        platform_name=args.platform,
        info=_console_info,
        libs_dir=Path(args.libs_dir),
        buildroot=args.buildroot,
        plat_name=args.plat_name,
    )
    builder.prepare(download_only=args.download_only)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
