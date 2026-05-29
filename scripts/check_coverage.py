#!/usr/bin/env python3
"""Verify that ``axltoolkit`` wraps every operation in its source WSDLs.

This script implements the AXL/SXML coverage check described in
``docs/migration.md`` and the v2 README. It compares the set of SOAP
operations declared by the bundled AXL WSDL(s) (and optionally
snapshotted SXML/PAWS/Webdialer WSDLs in ``tests/fixtures/wsdls/``)
against the set of ``self._service.<operation>(…)`` calls in the
matching Python client modules. Any operation that exists in the WSDL
but has no Python wrapper — or vice versa — is reported.

Usage::

    python scripts/check_coverage.py [--axl-version 15.0] [--strict]
    python scripts/check_coverage.py --include-sxml
    python scripts/check_coverage.py --all-versions

Exit codes:

* ``0`` — no missing or extra wrappers detected.
* ``1`` — coverage gap detected (use ``--strict`` to fail on extras too).
* ``2`` — usage error (e.g., schema/client file missing).

This script is intended to be run in CI to prevent regressions whenever
``axltoolkit/axl.py`` or the bundled WSDLs are modified.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from lxml import etree

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DIR = REPO_ROOT / "axltoolkit" / "schema"
SXML_FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "wsdls"

WSDL_NS = "http://schemas.xmlsoap.org/wsdl/"

# Operations that intentionally have no Python wrapper. Add an entry here
# (with a justification) only when removing the wrapper is the right
# call. The current AXL surface wraps every documented operation, so the
# list is empty.
INTENTIONAL_SKIPS: Dict[str, Set[str]] = {
    "axl": set(),
    "risport": set(),
    "perfmon": set(),
    "serviceability": set(),
    "log_collection": set(),
    "webdialer": set(),
    "paws": set(),
}


@dataclass
class CoverageResult:
    """Per-service coverage outcome."""

    name: str
    wsdl_path: Path
    client_path: Path
    wsdl_ops: Set[str] = field(default_factory=set)
    client_calls: Set[str] = field(default_factory=set)

    @property
    def missing(self) -> Set[str]:
        """Operations in the WSDL with no wrapper in the client."""
        return self.wsdl_ops - self.client_calls - INTENTIONAL_SKIPS.get(self.name, set())

    @property
    def extras(self) -> Set[str]:
        """Operations called by the client that are not in the WSDL.

        These are almost always false positives caused by helper methods
        whose names happen to match the regex, but it is still worth
        printing them so a human can spot real mistakes (e.g., typos).
        """
        return self.client_calls - self.wsdl_ops


# ── WSDL parsing ────────────────────────────────────────────────────


def extract_wsdl_operations(wsdl_path: Path) -> Set[str]:
    """Return every ``operation`` name in the ``portType`` of a WSDL.

    Uses ``lxml`` with safe defaults (no DTDs, no external entities, no
    network access) to harden against XXE — see the project's XML
    hardening rules.
    """
    parser = etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
        dtd_validation=False,
        huge_tree=False,
    )
    tree = etree.parse(str(wsdl_path), parser)
    root = tree.getroot()
    operations: Set[str] = set()
    for port_type in root.findall(f"{{{WSDL_NS}}}portType"):
        for op in port_type.findall(f"{{{WSDL_NS}}}operation"):
            name = op.get("name")
            if name:
                operations.add(name)
    return operations


# ── Client parsing ──────────────────────────────────────────────────


_SERVICE_CALL_RE = re.compile(r"self\._service\.(\w+)\s*\(")


def extract_client_service_calls(client_path: Path) -> Set[str]:
    """Return every ``self._service.<name>(`` call in a client module."""
    text = client_path.read_text(encoding="utf-8")
    return set(_SERVICE_CALL_RE.findall(text))


# ── Top-level checks ────────────────────────────────────────────────


def check_axl(version: str) -> CoverageResult:
    wsdl = SCHEMA_DIR / version / "AXLAPI.wsdl"
    client = REPO_ROOT / "axltoolkit" / "axl.py"
    if not wsdl.exists():
        raise FileNotFoundError(f"AXL WSDL not found: {wsdl}")
    if not client.exists():
        raise FileNotFoundError(f"AXL client not found: {client}")
    return CoverageResult(
        name="axl",
        wsdl_path=wsdl,
        client_path=client,
        wsdl_ops=extract_wsdl_operations(wsdl),
        client_calls=extract_client_service_calls(client),
    )


SXML_CHECKS: List[Tuple[str, str, str]] = [
    # (service_key, wsdl_filename, client_filename)
    ("risport", "RISService70.wsdl", "risport.py"),
    ("perfmon", "PerfmonService.wsdl", "perfmon.py"),
    ("serviceability", "ControlCenterServices.wsdl", "serviceability.py"),
    ("log_collection", "LogCollectionService.wsdl", "log_collection.py"),
    ("webdialer", "wd70.wsdl", "webdialer.py"),
    # PAWS is intentionally not added here — it has multiple per-service
    # WSDLs; the PAWS client wraps all of them via ``_PAWS_SERVICES`` and
    # is covered by its own dedicated tests in tests/test_paws_client.py.
]


def check_sxml(service_key: str, wsdl_filename: str, client_filename: str) -> Optional[CoverageResult]:
    """Run a coverage check against a snapshotted SXML WSDL.

    Returns ``None`` if no snapshot is available (this is not a failure
    — CI runs this in best-effort mode for SXML, since the WSDLs must be
    fetched from a live UCM via ``snapshot_wsdls.py``).
    """
    wsdl = SXML_FIXTURE_DIR / wsdl_filename
    client = REPO_ROOT / "axltoolkit" / client_filename
    if not wsdl.exists():
        return None
    if not client.exists():
        raise FileNotFoundError(f"SXML client not found: {client}")
    return CoverageResult(
        name=service_key,
        wsdl_path=wsdl,
        client_path=client,
        wsdl_ops=extract_wsdl_operations(wsdl),
        client_calls=extract_client_service_calls(client),
    )


# ── Reporting ───────────────────────────────────────────────────────


def format_report(result: CoverageResult) -> str:
    lines = []
    lines.append(f"\n[{result.name}]")
    lines.append(f"  WSDL:   {result.wsdl_path.relative_to(REPO_ROOT)}")
    lines.append(f"  Client: {result.client_path.relative_to(REPO_ROOT)}")
    lines.append(f"  WSDL operations: {len(result.wsdl_ops)}")
    lines.append(f"  Client calls:    {len(result.client_calls)}")
    if result.missing:
        lines.append(f"  MISSING ({len(result.missing)}):")
        for op in sorted(result.missing):
            lines.append(f"    - {op}")
    if result.extras:
        lines.append(f"  Extras ({len(result.extras)}, may be helper calls):")
        for op in sorted(result.extras):
            lines.append(f"    + {op}")
    if not result.missing and not result.extras:
        lines.append("  OK — 100% coverage")
    return "\n".join(lines)


# ── CLI ─────────────────────────────────────────────────────────────


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--axl-version",
        default="15.0",
        help="AXL schema version directory to check (default: 15.0)",
    )
    parser.add_argument(
        "--all-versions",
        action="store_true",
        help="Check every AXL version under axltoolkit/schema/",
    )
    parser.add_argument(
        "--include-sxml",
        action="store_true",
        help="Also check SXML/Webdialer WSDLs from tests/fixtures/wsdls/",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Also fail when the client calls names not present in the WSDL",
    )
    args = parser.parse_args(argv)

    results: List[CoverageResult] = []

    versions = (
        sorted(p.name for p in SCHEMA_DIR.iterdir() if p.is_dir())
        if args.all_versions
        else [args.axl_version]
    )

    try:
        for v in versions:
            results.append(check_axl(v))
            # Rename so the report identifies which version
            results[-1].name = f"axl-{v}"
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if args.include_sxml:
        for key, wsdl_name, client_name in SXML_CHECKS:
            result = check_sxml(key, wsdl_name, client_name)
            if result is None:
                print(
                    f"[{key}] SKIPPED — no WSDL snapshot at "
                    f"{(SXML_FIXTURE_DIR / wsdl_name).relative_to(REPO_ROOT)}. "
                    "Run scripts/snapshot_wsdls.py against a live UCM to create one.",
                    file=sys.stderr,
                )
            else:
                results.append(result)

    failed = False
    for result in results:
        print(format_report(result))
        if result.missing:
            failed = True
        if args.strict and result.extras:
            failed = True

    if failed:
        print(
            "\nFAIL: coverage gap detected. Add the missing wrappers to the "
            "corresponding client module (or update INTENTIONAL_SKIPS with a "
            "justification).",
            file=sys.stderr,
        )
        return 1

    print("\nOK: all checked services have 100% coverage")
    return 0


if __name__ == "__main__":
    sys.exit(main())
