# Local Development

This guide covers everything you need to develop against axltoolkit
locally: a `.env`-backed credentials workflow for samples and integration
tests, running the unit and live-UCM test suites, and the coverage tools
that keep the WSDL ↔ Python wrapper surface in sync.

## Editable Install

Clone the repository and install the package in **editable** mode with
the development extras:

```bash
git clone https://github.com/pgiralt/axltoolkit.git
cd axltoolkit
pip install -e ".[dev]"
```

The `dev` extra adds:

- `pytest` / `pytest-cov` — unit & integration test runner
- `ruff` — linter and formatter
- `python-dotenv` — loads the local `.env` file
- `pip-audit` — CVE scanner for the dependency tree
- `mypy` — static type checking

To also build the documentation locally, install the `docs` extra:

```bash
pip install -e ".[docs]"
mkdocs serve     # http://127.0.0.1:8000
```

## Credentials via `.env`

The samples (`samples/*.py`) and the integration suite
(`tests/integration/`) both read UCM credentials from environment
variables. To keep them out of your shell history (and out of Git), put
them in a `.env` file at the repository root.

### Step 1 — Copy the template

```bash
cp .env.example .env
```

The repository's `.gitignore` includes `.env`, so accidentally
committing it isn't possible without removing the rule.

### Step 2 — Fill in the values

```ini title=".env"
# UCM publisher hostname or IP
UCM_ADDRESS=ucm-pub.example.com

# AXL application-user credentials
UCM_USERNAME=axladmin
UCM_PASSWORD=replace-me

# Platform / OS admin credentials (PAWS, LogCollection)
UCM_PLATFORM_USERNAME=administrator
UCM_PLATFORM_PASSWORD=replace-me

# AXL schema version (10.0–15.0)
UCM_AXL_VERSION=15.0

# TLS verification:
#   true              — verify against system CA store (recommended)
#   /path/to/ca.pem   — verify against a specific CA bundle
#   false             — disable (LAB ONLY)
UCM_TLS_VERIFY=true

# Request timeouts in seconds
UCM_TIMEOUT=30
UCM_LOG_TIMEOUT=120
```

!!! warning "TLS verify defaults"
    `.env.example` defaults `UCM_TLS_VERIFY=true` (recommended for any
    real environment). The integration-test `conftest.py` defaults to
    `false` if the variable is **unset**, because most labs use the
    self-signed Tomcat certificate that ships with UCM. Set it
    explicitly to `true` (or a CA bundle path) in your `.env` whenever
    you have a trusted chain available.

### Step 3 — Sample scripts read it automatically

`samples/_env.py` is a small helper that calls
`dotenv.load_dotenv()` and exports the variables as Python constants.
Every sample script imports from it:

```python title="samples/sample1_axl.py" hl_lines="1-3"
from _env import (
    UCM_ADDRESS, UCM_USERNAME, UCM_PASSWORD,
    UCM_AXL_VERSION, UCM_TLS_VERIFY, UCM_TIMEOUT,
)
from axltoolkit import AXLClient

client = AXLClient(
    username=UCM_USERNAME,
    password=UCM_PASSWORD,
    server_ip=UCM_ADDRESS,
    version=UCM_AXL_VERSION,
    tls_verify=UCM_TLS_VERIFY,
    timeout=UCM_TIMEOUT,
)
```

Run any sample with no extra arguments:

```bash
cd samples
python sample1_axl.py
```

## Running Tests

### Unit tests

The fast, **offline** unit suite under `tests/` mocks every SOAP call
and runs in seconds:

```bash
pytest tests/ -v
```

### Integration tests (live UCM)

`tests/integration/` connects to the cluster specified in your `.env`
and exercises real AXL/SXML operations. The suite is **destructive on
itself** — it creates, modifies, and removes objects prefixed with
`AXTK_T_`. It does **not** touch anything else, but you should still
run it against a lab cluster.

```bash
# Verbose run with short tracebacks
pytest tests/integration/ -v --tb=short

# Just the smoke subset (connectivity + version)
pytest tests/integration/test_axl_integration.py::test_axl_smoke -v

# Skip the suite if env vars are missing (default behavior)
pytest tests/integration/
```

If `UCM_ADDRESS`, `UCM_USERNAME`, or `UCM_PASSWORD` is missing, the
fixture raises `pytest.skip` and the suite turns into a no-op — handy
in CI environments where there's no live UCM.

!!! note "Session recovery"
    The integration suite is long-running. The `RISPortClient` automatically
    re-establishes its session if UCM returns `Error Code = 7` (session
    stale) mid-run, so RISPort tests no longer fail intermittently
    after several minutes of AXL traffic.

## Coverage Scripts

Two scripts keep the project honest about API coverage.

### `scripts/check_coverage.py` — WSDL ↔ client parity

Compares every SOAP operation declared by the bundled WSDLs against the
`self._service.<operation>(...)` call sites in each client module.
Used as a CI gate (`coverage-check` job in `.github/workflows/ci.yml`):

```bash
# Default — AXL 15.0 only
python scripts/check_coverage.py

# All AXL schema versions
python scripts/check_coverage.py --all-versions

# Include the SXML/PAWS/Webdialer WSDL snapshots
python scripts/check_coverage.py --all-versions --include-sxml

# Strict mode also fails on "extra" wrappers
python scripts/check_coverage.py --strict
```

Exit codes:

- `0` — every WSDL operation has a Python wrapper
- `1` — coverage gap detected
- `2` — usage error (missing schema/client file)

### `scripts/check_test_coverage.py` — test ↔ client parity

The complement of the previous check: enumerates every public method on
each client class and asks *"how many of these are exercised by the
integration suite?"*. It understands parametrized indirect dispatch
(`getattr(axl, f"add_{type_key}")(...)`) so the numbers reflect the
real coverage, not just the literal text in the test files.

```bash
# Human-readable per-verb breakdown
python scripts/check_test_coverage.py

# Just the AXL client, with the full uncovered list
python scripts/check_test_coverage.py --client axl --verbose

# Machine-readable output for a dashboard
python scripts/check_test_coverage.py --client all --json > coverage.json

# CI gate — fail if AXL coverage drops below 60%
python scripts/check_test_coverage.py --strict --min 60
```

This script is a **reporting tool**, not a default CI gate — coverage
of update/apply/reset/restart methods is intentionally partial because
those operations have side effects on the live cluster.

### `scripts/snapshot_wsdls.py` — refresh SXML WSDLs

The SXML/PAWS/Webdialer WSDLs are not redistributable with this
package, so the project snapshots them under
`tests/fixtures/wsdls/` for coverage checks. Refresh them whenever your
UCM is upgraded:

```bash
python scripts/snapshot_wsdls.py
```

The script reads `UCM_ADDRESS` / `UCM_USERNAME` / `UCM_PASSWORD` from
your `.env`, so no command-line arguments are required.

### `scripts/generate_models.py` — regenerate TypedDicts and Enums

The `_generated_models.py` and `_generated_enums.py` modules are built
from the AXL XSD via this script. If you update the bundled schemas (or
change the generator), regenerate both files in one shot:

```bash
python scripts/generate_models.py
```

The generator emits a `_AxlStrEnum` base class for every string enum so
that SOAP serialization continues to work on Python 3.11+ (where the
default `str(EnumMember)` representation changed).

## Code Quality

```bash
# Lint
ruff check axltoolkit/ tests/

# Format check
ruff format --check axltoolkit/ tests/

# Apply formatting in-place
ruff format axltoolkit/ tests/

# Static type checking
mypy axltoolkit/
```

## Dependency Vulnerability Scan

The CI workflow runs `pip-audit --strict --desc` on every push. To run
the same scan locally before pushing:

```bash
pip install pip-audit
pip-audit --strict --desc
```

A non-zero exit means at least one dependency has a known CVE — bump
the constraint in `pyproject.toml` and re-run.

## Continuous Integration

`.github/workflows/ci.yml` defines four jobs:

| Job | What it does |
|-----|--------------|
| `test` | Runs `pytest tests/` on Python 3.9–3.13 with coverage |
| `lint` | `ruff check` + `ruff format --check` on Python 3.12 |
| `coverage-check` | Runs `scripts/check_coverage.py --all-versions --include-sxml` |
| `dependency-audit` | Runs `pip-audit --strict --desc` against installed deps |

All four must pass before a PR is merged.

## Publishing to PyPI

### Building distributions

```bash
pip install --upgrade build twine
rm -rf dist/ build/
python -m build       # produces dist/*.tar.gz and dist/*.whl
twine check dist/*    # validates metadata and README rendering
```

Both files must be **PASSED** before you upload anywhere. The sdist
should be approximately 2.3 MB and the wheel approximately 2.4 MB (most
of the size is the bundled AXL schemas under `axltoolkit/schema/`).

### Test PyPI dry-run (recommended)

Before publishing to the real index, always validate on
[Test PyPI](https://test.pypi.org/). The repository ships a manual
workflow at `.github/workflows/test-pypi.yml` that automates this:

**One-time setup**

1. Create an account at <https://test.pypi.org/account/register/>
   (separate from production PyPI). Enable 2FA.
2. Generate a project-scoped API token at
   <https://test.pypi.org/manage/account/token/>. The token value
   starts with `pypi-`.
3. In the GitHub repository, go to
   **Settings → Secrets and variables → Actions → New repository
   secret** and add a secret named `TEST_PYPI_API_TOKEN` with the token
   value.

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
dependencies (`zeep`, `requests`, `lxml`, …) resolve from the index
that actually hosts them.

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
twine check dist/*
twine upload dist/*    # uses ~/.pypirc or prompts for credentials
```

You will need a real PyPI account and either an API token
(`__token__` username, `pypi-…` password) configured in `~/.pypirc` or
entered interactively.

### Publishing rules to remember

- **Releases are immutable.** Once `2.0.0` is uploaded, you cannot
  replace it — you have to publish `2.0.1`. If you find a regression
  immediately after upload, you can *yank* the release (hidden from new
  installs, existing installs continue to work) but you cannot delete
  it from the index.
- **Test PyPI is also immutable per version.** Use pre-release
  suffixes (`.dev1`, `rc1`, …) to iterate.
- **Two-factor auth is mandatory** on both PyPI and Test PyPI as of
  2024. Use an authenticator app or a hardware key.
- **Project-scoped tokens beat account-scoped tokens.** After the
  first upload to a new project, replace the account-wide token with
  one scoped to just `axltoolkit`.
