#!/bin/sh
set -eu

: "${PY_ABI:?PY_ABI is required}"
: "${MANYLINUX_IMAGE:?MANYLINUX_IMAGE is required}"

# Make local build helpers importable for isolated PEP 517 backend subprocesses.
export PYTHONPATH="$PWD${PYTHONPATH:+:${PYTHONPATH}}"
# Ensure dependency archives are read from the restored workspace cache even in isolated builds.
export PYXMLSEC_LIBS_DIR="$PWD/libs"

# Step: Allow Git access to the mounted workspace for SCM version discovery
echo "== [container] Step: Configure Git safe.directory =="
if command -v git >/dev/null 2>&1; then
  if [ -n "${PWD:-}" ]; then
    git config --global --add safe.directory "$PWD"
    echo "GIT_SAFE_DIRECTORY=$PWD"
  fi
fi

# Step: Install system build dependencies (manylinux only)
echo "== [container] Step: Install system build dependencies (manylinux only) =="
case "$MANYLINUX_IMAGE" in
  manylinux*)
    yum install -y perl-core
    ;;
esac
# libiconv >= 1.19 needs GNU make >= 4.0 (po/Makefile uses '!='); CentOS 7 ships 3.82.
case "$MANYLINUX_IMAGE" in
  manylinux2014_*)
    yum install -y devtoolset-10-make
    make --version | head -n 1
    ;;
esac

# Step: Build lxml from source with static deps (temporary)
# TODO: remove once lxml publishes cp315 manylinux2014_x86_64 wheels.
echo "== [container] Step: Configure lxml static build (cp315 manylinux2014 only) =="
case "$PY_ABI/$MANYLINUX_IMAGE" in
  cp315-*/manylinux2014_*)
    export STATIC_DEPS=true
    export LIBXML2_VERSION="${LIBXML2_VERSION:?}" LIBXSLT_VERSION="${LIBXSLT_VERSION:?}"
    # lxml links its static deps into a shared extension, so they need -fPIC.
    export CFLAGS="${CFLAGS:+$CFLAGS }-fPIC"
    echo "STATIC_DEPS=$STATIC_DEPS LIBXML2_VERSION=$LIBXML2_VERSION LIBXSLT_VERSION=$LIBXSLT_VERSION CFLAGS=$CFLAGS"
    ;;
esac

# Step: Install uv
echo "== [container] Step: Install uv =="
PYTHON="/opt/python/${PY_ABI}/bin/python"
"$PYTHON" -m pip install --upgrade uv
UV="/opt/python/${PY_ABI}/bin/uv"
# Use the image's interpreter, and keep root-owned files out of the mounted workspace.
export UV_PYTHON_PREFERENCE=only-system
export UV_PROJECT_ENVIRONMENT=/tmp/venv

# Step: Build linux_x86_64 wheel
echo "== [container] Step: Build linux_x86_64 wheel =="
"$UV" build --python "$PYTHON"

# Step: Label manylinux wheel
echo "== [container] Step: Label manylinux wheel =="
ls -la dist/
auditwheel show dist/xmlsec-*-${PY_ABI}-linux_x86_64.whl
auditwheel repair dist/xmlsec-*-${PY_ABI}-linux_x86_64.whl
ls -la wheelhouse/
auditwheel show wheelhouse/xmlsec-*-${PY_ABI}-*${MANYLINUX_IMAGE}*.whl

# Step: Install test dependencies
echo "== [container] Step: Install test dependencies =="
"$UV" sync --python "$PYTHON" --locked --no-default-groups --group test --no-install-project
"$UV" pip install --python /tmp/venv/bin/python xmlsec --only-binary xmlsec --no-index --find-links wheelhouse/

# Step: Run tests
echo "== [container] Step: Run tests =="
/tmp/venv/bin/pytest -v --color=yes

# Step: Fix mounted workspace file ownership on host
echo "== [container] Step: Fix mounted workspace file ownership on host =="
chown -R "${HOST_UID}:${HOST_GID}" dist wheelhouse build libs || true
