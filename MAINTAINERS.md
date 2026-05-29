# Maintainer Notes

Internal procedures for repository maintainers. End users and ordinary
contributors do not need any of the steps documented here — these all
require GitHub repository admin rights, PyPI account ownership, or
Read the Docs project ownership.

## Deploying the Documentation

The `docs/` MkDocs site can be hosted in two places. Both targets are
configured in this repository but require a one-time, account-scoped
enablement step before the public URLs start serving content.

### GitHub Pages

- **URL once enabled:** <https://pgiralt.github.io/axltoolkit/>
- **Workflow:** [`.github/workflows/docs.yml`](.github/workflows/docs.yml)
- **What the workflow does:** Builds the MkDocs site on every PR
  (sanity check) and deploys to GitHub Pages on every push to
  `master` / `main`.
- **One-time enablement steps** (must be performed once after the
  workflow lands on the default branch):
    1. Go to the repository on GitHub.
    2. **Settings → Pages**.
    3. Under **Build and deployment → Source**, choose
       **"GitHub Actions"** (do *not* pick the legacy "Deploy from a
       branch" option).
    4. The next push to `master` will publish, and subsequent pushes
       will overwrite the deployed site.

If the `deploy` job fails with a permissions error, double-check
**Settings → Actions → General → Workflow permissions** and confirm
"Read and write permissions" is selected (or that the workflow itself
declares the needed `pages: write` and `id-token: write` permissions —
this repo's workflow does, so the org-level toggle usually isn't
necessary).

### Read the Docs

- **URL once enabled:** <https://axltoolkit.readthedocs.io/>
- **Config file:** [`.readthedocs.yaml`](.readthedocs.yaml)
- **One-time enablement steps:**
    1. Sign in at <https://readthedocs.org/> with the GitHub account
       that owns the repo.
    2. Go to
       <https://readthedocs.org/dashboard/import/> and pick
       `pgiralt/axltoolkit` from the connected-repo list. (If the
       repo isn't listed, click **Refresh** or **Import Manually**.)
    3. Accept the defaults. RTD will detect `.readthedocs.yaml`
       automatically.
    4. RTD will build on every push to a branch you configure (default
       is the repo's default branch). The first build can take a few
       minutes.

## Publishing to PyPI

### Building distributions

```bash
pip install --upgrade build twine
rm -rf dist/ build/
python -m build       # produces dist/*.tar.gz and dist/*.whl
twine check --strict dist/*    # validates metadata and README rendering
```

Both files must be **PASSED** before you upload anywhere. The sdist
should be approximately 2.3 MB and the wheel approximately 2.4 MB
(most of the size is the bundled AXL schemas under
`axltoolkit/schema/`).

### Test PyPI dry-run (always do this first)

Before publishing to the real index, validate on
[Test PyPI](https://test.pypi.org/). The repository ships a manual
workflow at [`.github/workflows/test-pypi.yml`](.github/workflows/test-pypi.yml)
that automates this.

**One-time setup**

1. Create an account at <https://test.pypi.org/account/register/>
   (separate from production PyPI). Enable 2FA.
2. Generate an API token at
   <https://test.pypi.org/manage/account/token/>. The token value
   starts with `pypi-`.
3. In the GitHub repository, go to
   **Settings → Secrets and variables → Actions → New repository
   secret** and add a secret named `TEST_PYPI_API_TOKEN` with the
   token value.

**Each release candidate**

1. Bump the version in `pyproject.toml` to a pre-release identifier —
   Test PyPI (like real PyPI) refuses to overwrite a version that has
   already been uploaded. Use PEP 440 pre-release suffixes:
   `2.0.0.dev1`, `2.0.0rc1`, `2.1.0a1`, etc.
2. Push the commit. From the **Actions** tab, run
   *"Publish to Test PyPI (manual)"* via **Run workflow**.
3. After the workflow completes, install from Test PyPI in a clean
   virtual environment:

    ```bash
    python -m venv /tmp/axltk-test
    source /tmp/axltk-test/bin/activate
    pip install \
        --index-url https://test.pypi.org/simple/ \
        --extra-index-url https://pypi.org/simple/ \
        axltoolkit==2.0.0rc1
    python -c "import axltoolkit; print(axltoolkit.__version__)"
    ```

    The `--extra-index-url` to real PyPI is required so runtime
    dependencies (`zeep`, `requests`, `lxml`, …) resolve from the
    index that actually hosts them.

4. Confirm the project page at
   <https://test.pypi.org/project/axltoolkit/> looks correct — README
   rendered, classifiers right, license shown.

### Publishing to production PyPI

When the Test PyPI artifact looks good:

1. Reset the version in `pyproject.toml` to the final release string
   (e.g., `2.0.0`).
2. Commit the version bump and tag the release:

    ```bash
    git tag -a v2.0.0 -m "Release 2.0.0"
    git push --tags
    ```

3. Build and upload manually:

    ```bash
    rm -rf dist/ build/
    python -m build
    twine check --strict dist/*
    twine upload dist/*    # uses ~/.pypirc or prompts for credentials
    ```

    You will need a real PyPI account and either an API token
    (`__token__` username, `pypi-…` password) configured in
    `~/.pypirc` or entered interactively.

### Publishing rules to remember

- **Releases are immutable.** Once `2.0.0` is uploaded, you cannot
  replace it — you have to publish `2.0.1`. If you find a regression
  immediately after upload, you can *yank* the release (hidden from
  new installs, existing installs continue to work) but you cannot
  delete it from the index.
- **Test PyPI is also immutable per version.** Use pre-release
  suffixes (`.dev1`, `rc1`, …) to iterate.
- **Two-factor auth is mandatory** on both PyPI and Test PyPI as of
  2024. Use an authenticator app or a hardware key.
- **Project-scoped tokens beat account-scoped tokens.** After the
  first upload to a new project, replace the account-wide token with
  one scoped to just `axltoolkit`.
