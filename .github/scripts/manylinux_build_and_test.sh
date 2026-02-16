#!/bin/sh
set -eu

: "${PY_ABI:?PY_ABI is required}"
: "${MANYLINUX_IMAGE:?MANYLINUX_IMAGE is required}"

# Make local build helpers importable for isolated PEP 517 backend subprocesses.
export PYTHONPATH="$PWD${PYTHONPATH:+:${PYTHONPATH}}"
# Ensure dependency archives are read from the restored workspace cache even in isolated builds.
export PYXMLSEC_LIBS_DIR="$PWD/libs"

# Step: Install system build dependencies (manylinux only)
echo "== [container] Step: Install system build dependencies (manylinux only) =="
case "$MANYLINUX_IMAGE" in
  manylinux*)
    yum install -y perl-core
    ;;
esac

# Step: Install python build dependencies
echo "== [container] Step: Install python build dependencies =="
/opt/python/${PY_ABI}/bin/pip install --upgrade pip setuptools wheel build 'setuptools_scm>=8'

# Step: Set environment variables
echo "== [container] Step: Set environment variables =="
PKGVER=$(/opt/python/${PY_ABI}/bin/python setup.py --version)
echo "PKGVER=$PKGVER"

# Step: Build linux_x86_64 wheel
echo "== [container] Step: Build linux_x86_64 wheel =="
/opt/python/${PY_ABI}/bin/python -m build

# Step: Label manylinux wheel
echo "== [container] Step: Label manylinux wheel =="
ls -la dist/
auditwheel show dist/xmlsec-${PKGVER}-${PY_ABI}-linux_x86_64.whl
auditwheel repair dist/xmlsec-${PKGVER}-${PY_ABI}-linux_x86_64.whl
ls -la wheelhouse/
auditwheel show wheelhouse/xmlsec-${PKGVER}-${PY_ABI}-*${MANYLINUX_IMAGE}*.whl

# Step: Install test dependencies
echo "== [container] Step: Install test dependencies =="
/opt/python/${PY_ABI}/bin/pip install --upgrade -r requirements-test.txt
/opt/python/${PY_ABI}/bin/pip install xmlsec --only-binary=xmlsec --no-index --find-links=wheelhouse/

# Step: Run tests
echo "== [container] Step: Run tests =="
/opt/python/${PY_ABI}/bin/pytest -v --color=yes

# Step: Fix mounted workspace file ownership on host
echo "== [container] Step: Fix mounted workspace file ownership on host =="
chown -R "${HOST_UID}:${HOST_GID}" dist wheelhouse build libs || true
