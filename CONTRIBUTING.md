# Contributing to python-xmlsec

This guide takes you from a fresh clone to a working development environment
with passing tests. The project uses [uv](https://docs.astral.sh/uv/) to manage
Python, dependencies and builds.

## Quick start

On macOS or Linux with a C compiler installed:

```bash
git clone https://github.com/xmlsec/python-xmlsec.git
cd python-xmlsec
export PYXMLSEC_STATIC_DEPS=true
uv sync
uv run pytest
```

The first `uv sync` takes a few minutes because it compiles OpenSSL, libxml2,
xmlsec1 and their dependencies. See [Choose how to get the native
libraries](#2-choose-how-to-get-the-native-libraries) for what that variable
does and for the alternative.

## 1. Install the prerequisites

- **uv 0.13 or newer**. See the [installation
  guide](https://docs.astral.sh/uv/getting-started/installation/), or run:

  ```bash
  curl -LsSf https://astral.sh/uv/install.sh | sh
  ```

- **Python** does not need installing. uv downloads the version pinned in
  [`.python-version`](.python-version) (the latest stable 3.14 release at the
  time it was pinned) the first time you run `uv sync`.

- **A C toolchain**:

  | OS            | Install                                                 |
  | ------------- | ------------------------------------------------------- |
  | macOS         | `xcode-select --install`                                |
  | Debian/Ubuntu | `sudo apt-get install build-essential perl`             |
  | Fedora/CentOS | `sudo dnf install gcc make perl-core`                   |
  | Alpine        | `apk add build-base perl`                               |
  | Windows       | Visual Studio with the "Desktop development with C++" workload |

## 2. Choose how to get the native libraries

`xmlsec` is a C extension that links against `libxmlsec1`, `libxml2` and
OpenSSL. It also exchanges XML nodes with `lxml`, so **`xmlsec` and `lxml` must
use the same `libxml2` version at runtime**. Both options below guarantee that.

| | Static libraries | System libraries |
| ---------------------- | ------------------------------ | ------------------------------------ |
| Choose it when         | You want the simplest setup    | You're changing the C code often     |
| System packages needed | Only a C toolchain             | `libxmlsec1`, `libxml2`, `pkg-config` |
| First `uv sync`        | A few minutes                  | Under a minute                       |
| Rebuild after C edits  | Over a minute                  | A couple of seconds                  |
| Matches release wheels | Yes                            | No                                   |

Whichever you choose, **keep its environment variables set whenever you run
`uv`** in this project, because any `uv sync` or `uv run` may need to rebuild the
extension. Add them to your shell profile or use a tool like
[direnv](https://direnv.net/).

### Option A: static libraries (recommended)

This builds the same library versions as the release wheels and uses `lxml`'s
prebuilt wheel:

```bash
export PYXMLSEC_STATIC_DEPS=true
uv sync
```

Downloaded archives are cached in [`libs/`](libs/README.md) and build output
goes to `build/`, which can reach about 2 GB.

### Option B: system libraries

This builds both `xmlsec` and `lxml` from source against your system's
`libxml2`.

Install the libraries for your OS:

```bash
# Debian/Ubuntu
sudo apt-get install pkg-config libxml2-dev libxslt1-dev libxmlsec1-dev libxmlsec1-openssl

# Fedora/CentOS
sudo dnf install pkgconf-pkg-config libxml2-devel libxslt-devel xmlsec1-devel xmlsec1-openssl-devel libtool-ltdl-devel

# Alpine
apk add build-base pkgconf openssl-dev libffi-dev libxslt-dev libxml2-dev xmlsec-dev xmlsec

# macOS
brew install libxml2 libxslt libxmlsec1 pkgconf
```

Then build:

```bash
# macOS only: Homebrew's libxml2 isn't on the default search path
export PKG_CONFIG_PATH="$(brew --prefix)/opt/libxml2/lib/pkgconfig"

export UV_NO_BINARY_PACKAGE=lxml
uv sync
```

### Windows

Windows builds always use prebuilt static libraries, which are downloaded
automatically, so you don't need to choose an option or set any variables. Run
`uv sync` from a Developer Command Prompt or PowerShell.

### Switching between options

Change your environment variables, then force both packages to rebuild:

```bash
uv sync --reinstall-package xmlsec --reinstall-package lxml
```

## 3. Check that it works

```bash
uv run python -c "import xmlsec; print(xmlsec.get_libxmlsec_version())"
uv run pytest
```

A few tests are skipped unless the optional PKCS#11 tooling is installed
(`softhsm2`, `opensc` and `libengine-pkcs11-openssl` on Debian/Ubuntu).

## 4. Everyday commands

`uv run` keeps the environment in sync and rebuilds the extension when a file in
`src/` or `build_support/` changes, so you don't need to activate a virtual
environment.

| Task                             | Command                                                         |
| -------------------------------- | --------------------------------------------------------------- |
| Run all tests                    | `uv run pytest`                                                 |
| Run one test file                | `uv run pytest tests/test_ds.py -v`                             |
| Check for memory leaks           | `PYXMLSEC_TEST_ITERATIONS=50 uv run pytest`                     |
| Test on another Python           | `uv run --isolated --python 3.10 pytest`                        |
| Install the git hooks (once)     | `uv run pre-commit install`                                     |
| Run all linters and type checks  | `uv run pre-commit run --all-files`                             |
| Lint / format only               | `uv run ruff check --fix .` / `uv run ruff format .`            |
| Build the docs                   | `uv run --group docs make -C doc html`                          |
| Build an sdist and wheel         | `uv build`                                                      |
| Force a rebuild of the extension | `uv sync --reinstall-package xmlsec`                            |

The pre-commit hooks reject commits made directly to `master`, so work on a
branch. For more on the docs, see [doc/README.md](doc/README.md).

`--isolated` uses a temporary environment and leaves `.venv` alone. With static
libraries, each run on a different Python rebuilds them, which takes over a
minute.

## 5. Manage dependencies

Runtime and build requirements are in `[project]` and `[build-system]` in
[`pyproject.toml`](pyproject.toml). Development tools are in
`[dependency-groups]`:

| Group      | Contents                                  | Installed by                  |
| ---------- | ----------------------------------------- | ----------------------------- |
| `test`     | pytest and test dependencies              | `dev`, CI, cibuildwheel       |
| `lint`     | ruff and pre-commit                       | `dev`                         |
| `coverage` | coverage.py                               | `dev`, macOS CI               |
| `dev`      | All of the above                          | `uv sync` by default          |
| `docs`     | Sphinx and its theme (Python 3.12+ only)  | `--group docs`, Read the Docs |

```bash
uv add --group test some-package          # add a dependency
uv lock --upgrade-package some-package    # upgrade one locked package
```

Commit `uv.lock` together with any change to dependencies. Three versions need
keeping in step by hand:

- The `test` group is pinned exactly because cibuildwheel installs it from
  `pyproject.toml` and doesn't read `uv.lock`.
- `lxml` must have the same pin in the `test` and `docs` groups.
- `ruff` must match the version in
  [`.pre-commit-config.yaml`](.pre-commit-config.yaml).

To move to a newer Python for development, update `.python-version`.
Supported Python versions for users are set separately, by `requires-python` and
the classifiers in `pyproject.toml` and the CI matrices.

## 6. Build settings

These environment variables affect how the extension is built. After changing
one, run `uv sync --reinstall-package xmlsec` so that it takes effect.

| Variable                 | Effect                                                                            |
| ------------------------ | --------------------------------------------------------------------------------- |
| `PYXMLSEC_STATIC_DEPS`   | Build and link the native libraries statically                                    |
| `PYXMLSEC_ENABLE_DEBUG`  | Enable debug logging and turn off optimizations                                   |
| `PYXMLSEC_OPTIMIZE_SIZE` | Optimize for size (default); set to `false` to turn off                           |
| `PYXMLSEC_LIBS_DIR`      | Directory for cached archives (default: `libs/`)                                  |
| `PYXMLSEC_XMLSEC1_VERSION`, `PYXMLSEC_LIBXML2_VERSION`, `PYXMLSEC_LIBXSLT_VERSION`, `PYXMLSEC_OPENSSL_VERSION`, `PYXMLSEC_ZLIB_VERSION`, `PYXMLSEC_LIBICONV_VERSION` | Override the versions used for a static build |
| `GH_TOKEN`               | GitHub token for release lookups during static builds, to avoid API rate limits   |

## Troubleshooting

### `error: Unable to invoke pkg-config` or `xmlsec1 is not installed or not in path`

uv tried to build against system libraries. If you're using static libraries,
`PYXMLSEC_STATIC_DEPS` isn't set in this shell, so set it again. If you're using
system libraries, install them, and on macOS also set `PKG_CONFIG_PATH`, as shown
in [Option B](#option-b-system-libraries).

### `lxml & xmlsec libxml2 library version mismatch`

`xmlsec` and `lxml` loaded different versions of `libxml2`. This usually means
`xmlsec` was built against system libraries while `lxml` came from a wheel. Set
the variables for your chosen option, then rebuild both packages as described in
[Switching between options](#switching-between-options).

### C changes don't seem to take effect

Force a rebuild with `uv sync --reinstall-package xmlsec`. This also refreshes
the version number that `xmlsec` reports, which doesn't update on its own when
you commit or switch branches unless tracked source files changed.

### `warning: Ignoring unsupported Python request` for `.python-version`

An older checkout may have had a local `.python-version` containing a virtual
environment name. Restore the tracked file with
`git checkout -- .python-version`.

## Reporting an issue

Please include:

- your version of `xmlsec`
- your version of `libxmlsec1`
- your version of `libxml2`
- the output of:

  ```bash
  pkg-config --cflags xmlsec1
  ```
