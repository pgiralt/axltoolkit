# Changelog

## Unreleased

### Security Hardening

- **SOAP envelope redaction** — `last_request_debug()` now redacts
  secret-bearing elements inside the SOAP body (e.g. `<password>`,
  `<ldapPassword>`, `<token>`, `<apiKey>`, `<snmpPassword>`,
  `<authProtocolPassword>`, `<privProtocolPassword>`), not just the
  `Authorization` / `Cookie` headers. The match is case-insensitive on
  the element's local name, so namespace prefixes are irrelevant.
- **DTD parsing forbidden** — `zeep` is now constructed with
  `Settings(forbid_dtd=True)`, blocking DOCTYPE declarations and the
  XXE / Billion Laughs / parameter-entity attack classes that depend on
  them.
- **Legacy `requirements.txt` removed** — the file pinned
  `zeep==3.4.0` (known XXE issues) and `defusedxml==0.6.0` (known
  CVEs). `pyproject.toml` is now the single source of truth, pinning
  modern, patched versions.
- **`pip-audit --strict` in CI** — a new `dependency-audit` job runs
  on every push and fails the build if any installed dependency has a
  known CVE.
- **`UCM_TLS_VERIFY` default flipped to `true`** in `.env.example` and
  `samples/_env.py`, with explicit warnings that `false` is for lab use
  only.
- **SNMP enum warnings** — `SNMPAuthenticationProtocol` and
  `SNMPPrivacyProtocol` carry generated docstrings advising against
  insecure `MD5` / `DES` values in favor of `SHA` and `AES*`.
- **Sample scripts** use generic placeholders (`jsmith`,
  `SEP001122334455`) instead of real userids/MACs.

### Reliability Improvements

- **RISPort session recovery** — `RISPortClient` now detects the
  *"Cisco RISDC needs SOAP clients to start a new session"*
  fault (`Error Code = 7`), clears its cookies, rebinds the service
  proxy, and retries the operation once. Long-running scripts and the
  integration suite no longer fail intermittently after the RIS
  session expires.
- **`_AxlStrEnum` base class** — `scripts/generate_models.py` now
  emits a `str`-subclassing base for every generated enum that
  preserves the pre-Python-3.11 `str()` representation. Fixes a
  serialization break on 3.11+ where the SOAP envelope contained
  `EnumClass.MEMBER` instead of the bare member name.

### New Features

- **`.env`-backed credentials workflow** — `python-dotenv` is now part
  of the `dev` extras. `samples/_env.py` and
  `tests/integration/conftest.py` load `.env` from the repo root
  automatically; `.env.example` documents every variable.
- **Integration test suite** — `tests/integration/` exercises 376+
  AXL/SXML operations against a live UCM cluster, including
  parametrized add/get/update/remove cycles for 50+ object types.
- **WebdialerClient documentation** — the previously-merged
  `WebdialerClient` is now covered in the API reference and Quick Start
  guide.
- **Coverage scripts**:
    - `scripts/check_coverage.py` (CI gate) — verifies every WSDL
      operation has a Python wrapper. Now also covers the SXML, PAWS,
      and Webdialer WSDLs via `--include-sxml`.
    - `scripts/check_test_coverage.py` (reporting tool) — measures
      how much of the public client surface is exercised by the
      integration suite, with parametrized indirect-dispatch
      awareness.
    - `scripts/snapshot_wsdls.py` — refreshes the SXML/PAWS/Webdialer
      WSDL snapshots from a live UCM.
- **Local Development guide** — new
  [`docs/guide/local-development.md`](guide/local-development.md) page
  collects `.env` setup, the integration test runner, the coverage
  scripts, CI job descriptions, and the **PyPI publishing workflow**
  (including a Test PyPI dry-run path) in one place.
- **Test PyPI workflow** — `.github/workflows/test-pypi.yml` provides
  a manual `workflow_dispatch` job that builds the sdist and wheel,
  runs `twine check --strict`, and uploads to
  [test.pypi.org](https://test.pypi.org) using a repository-scoped
  `TEST_PYPI_API_TOKEN` secret. Lets you verify metadata, README
  rendering, and clean-install behavior before claiming the version on
  production PyPI.

### Code Quality

- **AXL method dedup** — 14 duplicate methods removed from
  `axltoolkit/axl.py`; 3 orphaned section headers re-labelled to
  match the methods underneath them.
- **`add_remote_destination` refactored** for consistency with the
  rest of the `add_*` method family.

### Packaging

- **PEP 639 license metadata** — `pyproject.toml` now declares the
  license via the modern SPDX-style expression
  (`license = "LicenseRef-Cisco-Sample-Code-License-1.1"` with
  `license-files = ["LICENSE"]`). The deprecated
  `License :: Other/Proprietary License` classifier and the
  `license = {file = "..."}` table form (both scheduled for removal
  by setuptools in Feb 2027) are gone. Built distributions now emit
  `License-Expression:` and `License-File:` headers, no
  deprecation warnings.
- **`LICENSE` file at the repo root** — the full Cisco Sample Code
  License v1.1 text is now a top-level file (was previously only
  embedded in `README.md`), so PyPI, GitHub, and license-scanning
  tools all detect it automatically.
- **`[project.urls]`** — PyPI metadata now includes Homepage,
  Documentation, Repository, Issues, and Changelog links for richer
  project pages.
- **PyPI keywords and classifiers** added for discoverability
  (`cisco`, `ucm`, `callmanager`, `axl`, `sxml`, …;
  `Topic :: Communications :: Telephony`,
  `Topic :: System :: Systems Administration`, …).
- **`setuptools>=77.0` build requirement** — needed for PEP 639
  `LicenseRef-*` expression support.

## v2.0.0

### New Features

- **Modular client architecture** — Separate clients for each API:
  `AXLClient`, `RISPortClient`, `PerfMonClient`, `ServiceabilityClient`,
  `LogCollectionClient`, `DimeGetFileClient`, `PAWSClient`, `WebdialerClient`
- **Full PAWS coverage** — `PAWSClient` now wraps all 20 PAWS services
  (22 methods) including deployment mode, hardware model, upgrade lifecycle
  (prepare, start, cancel, filter, validate, stage, progress, type),
  restart system, and switch version operations
- **Full AXL WSDL coverage** — All 1,068 AXL operations wrapped as
  snake_case methods
- **Fluent builders** — `PhoneBuilder`, `SipTrunkBuilder`, `CssBuilder`
  for constructing complex payloads
- **TypedDict models** — IDE-friendly type annotations for common AXL objects
- **Auto-generated TypedDict models** — Schema-driven `TypedDict` classes for
  all `add_*` (174 models) and `update_*` (201 models) method payloads,
  generated from the AXL XSD via `scripts/generate_models.py`
- **Auto-generated enum types** — 170 `str, Enum` classes for constrained AXL
  fields (e.g. `ProtocolSide`, `ClockReference`) that serialize naturally
- **Typed `update_*` kwargs** — `Unpack[UpdatePhone]` etc. provide IDE
  autocompletion and type checking for all update method keyword arguments
- **Typed exception hierarchy** — Granular error handling with
  `AXLNotFoundError`, `AXLDuplicateError`, `AXLSQLError`, etc.
- **SQL injection protection** — Pattern detection and value escaping for
  Thin AXL queries
- **Session cookie caching** — JSESSIONID reuse across requests for better
  performance
- **Configurable retry logic** — Automatic exponential back-off on transient
  HTTP errors
- **Request/response history** — Built-in debug helper with credential
  redaction
- **Comprehensive documentation** — MkDocs Material site with user guide,
  API reference, and recipes

### Security Improvements

- TLS verification enabled by default (`tls_verify=True`)
- WSDL cache stored in user-scoped directory (`~/.cache/axltoolkit/`) with
  restricted permissions
- `server_ip` validated at construction time to prevent SSRF
- `Authorization` header redacted in debug output
- HTTPS-only retry adapter (no HTTP fallback)
- All documentation examples use FQDNs and `tls_verify=True`

### Breaking Changes

- Legacy class names (`AxlToolkit`, `UcmRisPortToolkit`, etc.) are deprecated
  and emit `DeprecationWarning`.  They will be removed in a future major
  release.
- `get_cisco_cloud_onboarding()` removed — the underlying
  `getCiscoCloudOnboarding` AXL operation does not exist in any WSDL schema
  version.  Use `list_cisco_cloud_onboarding()` instead.
- `add_user_phone_association()` → `associate_user_devices()` — the old
  method was a convenience wrapper around `updateUser`.  The name
  `add_user_phone_association()` now wraps the actual AXL
  `addUserPhoneAssociation` WSDL operation.
- `run_sql_query()` → `sql_query()`, `run_sql_update()` → `sql_update()`
- `get_service()` replaced by `.service` property
- Various method renames — see the [Migration Guide](migration.md) for the
  full list

### Dependencies

- `zeep>=4.2.1,<5`
- `requests>=2.32.0,<3`
- `lxml>=4.9.0,<7`
- `urllib3>=2.0.0,<3`
- `typing_extensions>=4.1` (Python &lt; 3.12 only — provides `Unpack`,
  `Required`, `NotRequired`)
- Python 3.9+ required
