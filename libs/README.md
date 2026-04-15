# Dependency archive cache

This directory is used as the local cache for third-party libraries needed by
the static build tooling.

## How it works

`build_libs_xmlsec.py` and `LibXmlsecDependencyBuilder` look in `libs/` first.
If a matching archive is already present here, that file is reused. If not, the
build tooling downloads the archive into this directory and then continues.

The default lookup path is:

```bash
libs/
```

You can override it with either:

```bash
python build_libs_xmlsec.py --libs-dir /path/to/cache
```

or:

```bash
export PYXMLSEC_LIBS_DIR=/path/to/cache
```

## What belongs here

Store downloaded source or binary archives here, for example:

- `openssl*.tar.gz`
- `zlib*.tar.gz`
- `libiconv*.tar.gz`
- `libxml2*.tar.xz`
- `libxslt*.tar.xz`
- `xmlsec1*.tar.gz`
- Windows binary archives such as `libxml2-<version>.<suffix>.zip`

Extracted build artifacts do not belong in this directory. Those are created
under `build/tmp/libs/`.

## Why keep this directory

- Speeds up local rebuilds by reusing previously downloaded archives.
- Matches the CI cache strategy in `.github/workflows/cache_libs.yml`.
- Makes it possible to pre-populate dependency archives for offline or
  repeatable builds.
