# Documentation and Read the Docs

This project publishes its documentation on Read the Docs (RTD):

- Public site: <https://xmlsec.readthedocs.io/>
- RTD config: [../.readthedocs.yaml](../.readthedocs.yaml)
- Sphinx config: [source/conf.py](source/conf.py)
- Docs source: [source/](source/)

## How Read the Docs works in this repo

Read the Docs does not usually require you to upload files manually.
Instead, it watches the GitHub repository and builds the docs from the latest pushed commit.

For this repository, RTD is configured to:

- use config version `2`
- build on `ubuntu-24.04`
- use the Python version pinned in `.python-version`
- build with Sphinx using `doc/source/conf.py`
- install `uv`, then install the project and the `docs` dependency group from `uv.lock` with `uv sync`

That means every successful RTD build uses the repository contents plus the settings in `.readthedocs.yaml`.

## Before you publish

If you changed the docs, or changed code that affects autodoc output, validate locally first.

### 1. Set up the development environment

Follow [CONTRIBUTING.md](../CONTRIBUTING.md) to install `uv` and choose how to get the native libraries. Autodoc imports `xmlsec` to render the API pages, so the package has to build.

### 2. Keep your build settings

Keep the environment variables for the option you chose, such as `PYXMLSEC_STATIC_DEPS=true`, set in your shell. The docs dependencies are in the `docs` dependency group, and `uv run` installs them in the next step. That group needs Python `3.12+` because of Sphinx `9.1.0`; the project's default development Python already meets this.

### 3. Build the docs locally

```bash
uv run --group docs make -C doc html
```

Built HTML will be placed in:

```text
doc/build/html/
```

Open `doc/build/html/index.html` in a browser and check the pages you changed.

## How to publish the latest docs

### Normal flow

If the RTD project is already connected to GitHub, this is the normal deployment path:

1. Edit the docs or code.
2. Commit the changes.
3. Push the branch to GitHub.
4. RTD receives the webhook event.
5. RTD rebuilds the matching version and publishes it.

For this repository, the current Git branch is `master`, and `latest` on RTD commonly tracks the repository default branch.

Example:

```bash
git add doc/source .readthedocs.yaml README.md
git commit -m "Update documentation"
git push origin master
```

If you changed files outside those paths, add the correct files instead of using the sample `git add` command above.

### Manual rebuild from the RTD dashboard

If you already pushed your changes but the site did not update:

1. Open the Read the Docs project for `xmlsec`.
2. Go to the build/version page.
3. Trigger a build for the version you want, usually `latest`.
4. Wait for the build to finish and review the logs if it fails.

Typical reasons a manual rebuild is needed:

- GitHub integration/webhook is missing or broken
- the target branch/version is inactive on RTD
- a previous build failed and you want to rebuild after fixing the branch

## First-time setup in Read the Docs

If RTD has not been connected yet, an admin needs to set it up once:

1. Sign in to Read the Docs with a GitHub account that has access to `xmlsec/python-xmlsec`.
2. Import the repository.
3. Confirm RTD is using the repository root `.readthedocs.yaml`.
4. Make sure the GitHub integration/webhook is enabled.
5. Make sure the `latest` version is active.

After that, pushes to GitHub should trigger builds automatically.

## Troubleshooting

### Build fails locally on `uv sync` or `uv run`

The Python package needs native `xmlsec` and `libxml2` libraries. Check the environment variables and packages for your option in [CONTRIBUTING.md](../CONTRIBUTING.md), then retry.

### RTD build fails after a push

Check:

- the build logs in RTD
- whether `.readthedocs.yaml` is valid
- whether `doc/source/conf.py` still builds cleanly
- whether the target branch/version is active

### RTD is building the wrong version

Read the Docs manages versions from Git branches and tags. Verify which branch `latest` points to, and whether `stable` is mapped to a branch or tag you expect.
