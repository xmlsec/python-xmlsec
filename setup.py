from pathlib import Path

from setuptools import Extension, setup

from build_support.build_ext import build_ext

src_root = Path(__file__).parent / 'src'
sources = [str(path.absolute()) for path in src_root.rglob('*.c')]
pyxmlsec = Extension('xmlsec', sources=sources)


setup(
    ext_modules=[pyxmlsec],
    cmdclass={'build_ext': build_ext},
)
