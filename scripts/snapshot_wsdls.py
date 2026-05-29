#!/usr/bin/env python3
"""Snapshot SXML / Webdialer / PAWS WSDLs from a live Cisco UCM into the repo.

This script fetches the WSDL files served by the various non-AXL Cisco
UCM SOAP endpoints (RISPort70, PerfMon, ControlCenter, LogCollection,
Webdialer, PAWS) and writes them to ``tests/fixtures/wsdls/``. Those
snapshots are then used by ``scripts/check_coverage.py`` to enforce
that ``axltoolkit`` keeps wrapping every operation defined by each
service.

The intent is for a maintainer to run this once against a fresh UCM
release (or whenever Cisco updates the WSDLs) and commit the resulting
files. CI does not call this script — it only consumes the snapshots.

Security notes:

* TLS verification is **on** by default. Use ``--insecure`` to opt out
  (lab environments only).
* Credentials are never logged.
* WSDL contents are parsed with safe ``lxml`` settings (no DTDs / no
  external entities / no network access during parsing) to avoid XXE.
* Each fetched WSDL is parsed and validated before being written to
  disk — malformed responses are rejected without overwriting an
  existing snapshot.

Usage::

    python scripts/snapshot_wsdls.py \\
        --ucm ucm-pub.example.com \\
        --username AXLAdmin

    # Insecure (lab only)
    python scripts/snapshot_wsdls.py --ucm 10.0.0.1 -u admin --insecure

Exit codes:

* ``0`` — all WSDLs fetched and saved successfully
* ``1`` — one or more fetches failed
* ``2`` — usage error or invalid response
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

import requests
import urllib3
from lxml import etree
from requests.auth import HTTPBasicAuth

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "wsdls"

# (label, url_template, output_filename)
# Each url_template uses ``{server}`` which is replaced at runtime.
WSDL_ENDPOINTS: List[Tuple[str, str, str]] = [
    ("RISPort70", "https://{server}:8443/realtimeservice2/services/RISService70?wsdl", "RISService70.wsdl"),
    ("PerfMon", "https://{server}:8443/perfmonservice2/services/PerfmonService?wsdl", "PerfmonService.wsdl"),
    ("ControlCenter", "https://{server}:8443/controlcenterservice2/services/ControlCenterServices?wsdl", "ControlCenterServices.wsdl"),
    ("LogCollection", "https://{server}:8443/logcollectionservice2/services/LogCollectionPortTypeService?wsdl", "LogCollectionPortTypeService.wsdl"),
    ("DimeGetFileService", "https://{server}:8443/logcollectionservice/services/DimeGetFileService?wsdl", "DimeGetFileService.wsdl"),
    ("Webdialer", "https://{server}/webdialer/wsdl/wd70.wsdl", "wd70.wsdl"),
    # PAWS — Cisco serves one WSDL per service. The list mirrors
    # axltoolkit/paws_client.py::_PAWS_SERVICES.
    ("PAWS-Version", "https://{server}:8443/platform-services/services/VersionService?wsdl", "paws_VersionService.wsdl"),
    ("PAWS-HardwareInformation", "https://{server}:8443/platform-services/services/HardwareInformationService?wsdl", "paws_HardwareInformationService.wsdl"),
    ("PAWS-ClusterNodes", "https://{server}:8443/platform-services/services/ClusterNodesService?wsdl", "paws_ClusterNodesService.wsdl"),
    ("PAWS-CertificateService", "https://{server}:8443/platform-services/services/CertificateService?wsdl", "paws_CertificateService.wsdl"),
]


@dataclass
class FetchResult:
    label: str
    url: str
    output_path: Path
    success: bool
    error: Optional[str] = None


def _validate_wsdl_bytes(payload: bytes) -> None:
    """Parse the response body with hardened settings; raise on error."""
    parser = etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
        dtd_validation=False,
        huge_tree=False,
    )
    root = etree.fromstring(payload, parser=parser)
    # Look for ``<wsdl:definitions>`` or ``<definitions>`` as a sanity
    # check that the response really is a WSDL (and not, e.g., an HTML
    # error page).
    tag = etree.QName(root.tag).localname
    if tag.lower() != "definitions":
        raise ValueError(
            f"Response root element is <{root.tag}>, expected <definitions>"
        )


def fetch_one(
    label: str,
    url: str,
    output_path: Path,
    auth: HTTPBasicAuth,
    tls_verify: bool,
    timeout: int,
) -> FetchResult:
    try:
        response = requests.get(
            url,
            auth=auth,
            verify=tls_verify,
            timeout=timeout,
            headers={"Accept": "text/xml, application/xml, */*"},
        )
        response.raise_for_status()
    except requests.exceptions.RequestException as exc:
        # Avoid leaking auth header — exc may include the URL but not
        # the credentials thanks to requests' built-in redaction.
        return FetchResult(label, url, output_path, False, str(exc))

    try:
        _validate_wsdl_bytes(response.content)
    except (etree.XMLSyntaxError, ValueError) as exc:
        return FetchResult(label, url, output_path, False, f"Invalid WSDL: {exc}")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    # Write atomically so that an interrupted run cannot leave a partial
    # file behind that later confuses the coverage checker.
    tmp_path = output_path.with_suffix(output_path.suffix + ".part")
    tmp_path.write_bytes(response.content)
    tmp_path.replace(output_path)
    return FetchResult(label, url, output_path, True)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--ucm",
        required=True,
        help="UCM publisher hostname or IP",
    )
    parser.add_argument(
        "-u", "--username",
        required=True,
        help="AXL/CCMAdministrator username",
    )
    parser.add_argument(
        "--password-env",
        default="UCM_PASSWORD",
        help=(
            "Name of the environment variable holding the password "
            "(default: UCM_PASSWORD). If unset, prompts interactively."
        ),
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS verification (lab environments only)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="HTTP timeout in seconds (default: 30)",
    )
    parser.add_argument(
        "--output-dir",
        default=str(FIXTURE_DIR),
        help=f"Output directory (default: {FIXTURE_DIR.relative_to(REPO_ROOT)})",
    )
    args = parser.parse_args(argv)

    password = os.environ.get(args.password_env)
    if not password:
        password = getpass.getpass(f"Password for {args.username}@{args.ucm}: ")
    if not password:
        print("ERROR: password is required", file=sys.stderr)
        return 2

    if args.insecure:
        # User explicitly opted out. Suppress the noisy InsecureRequestWarning
        # to keep the report readable but DO NOT silently downgrade the
        # default — verification stays on unless --insecure is passed.
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        print(
            "WARNING: TLS verification disabled (--insecure). Use only in "
            "isolated lab environments.",
            file=sys.stderr,
        )

    auth = HTTPBasicAuth(args.username, password)
    output_dir = Path(args.output_dir)

    results: List[FetchResult] = []
    for label, url_template, filename in WSDL_ENDPOINTS:
        url = url_template.format(server=args.ucm)
        output_path = output_dir / filename
        print(f"Fetching {label}… ", end="", flush=True)
        result = fetch_one(
            label=label,
            url=url,
            output_path=output_path,
            auth=auth,
            tls_verify=not args.insecure,
            timeout=args.timeout,
        )
        if result.success:
            size = result.output_path.stat().st_size
            print(f"OK ({size:,} bytes -> {result.output_path.relative_to(REPO_ROOT)})")
        else:
            print(f"FAIL: {result.error}")
        results.append(result)

    failures = [r for r in results if not r.success]
    print()
    if failures:
        print(f"{len(failures)} of {len(results)} fetches failed:")
        for r in failures:
            print(f"  - {r.label}: {r.error}")
        return 1

    print(f"All {len(results)} WSDLs saved to {output_dir.relative_to(REPO_ROOT)}/")
    print(
        "\nNext step: run `python scripts/check_coverage.py --include-sxml` "
        "to verify the client modules wrap every operation."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
