#!/usr/bin/env python3
"""Report integration-test coverage of the AXL / SXML client surface.

This script is a complement to :mod:`scripts.check_coverage` — that one
asks *"does every WSDL operation have a Python wrapper?"*, this one asks
*"does every Python wrapper have an integration test?"*.

It works by:

1. Parsing each ``axltoolkit/<client>.py`` module to enumerate the
   public methods exposed on the client class.
2. Parsing ``tests/integration/*.py`` to enumerate every method call
   on an ``axl``/``ris``/``perfmon``/etc. client variable, including
   indirect dispatches through ``getattr(axl, f"verb_{type_key}")``
   inside parametrized tests.
3. Diffing the two sets, broken down by CRUD verb prefix.

The script never fails the build (exit ``0`` always) unless ``--strict``
is passed with a ``--min`` threshold — it's a reporting tool, not a
gate. Coverage of update/apply/reset/restart/do methods is partial by
design (those operations have real side effects on the live cluster).

Usage::

    python scripts/check_test_coverage.py
    python scripts/check_test_coverage.py --client axl --verbose
    python scripts/check_test_coverage.py --client all --json > cov.json
    python scripts/check_test_coverage.py --strict --min 60     # CI gate
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
TESTS_DIR = REPO_ROOT / "tests" / "integration"
CLIENT_DIR = REPO_ROOT / "axltoolkit"

CRUD_VERBS = [
    "add",
    "get",
    "update",
    "remove",
    "list",
    "apply",
    "reset",
    "restart",
    "do",
]

# Map a client key to (module file, test variable names that bind it)
CLIENTS: Dict[str, Tuple[str, Tuple[str, ...]]] = {
    "axl": ("axl.py", ("axl", "client")),
    "risport": ("risport.py", ("ris",)),
    "perfmon": ("perfmon.py", ("perfmon", "pm")),
    "serviceability": ("serviceability.py", ("svc",)),
    "paws_client": ("paws_client.py", ("paws",)),
    "webdialer": ("webdialer.py", ("webdialer", "wd")),
    "log_collection": ("log_collection.py", ("log_client", "dime_client")),
}


# ── Helpers ───────────────────────────────────────────────────────────


def _public_methods(client_file: Path) -> Set[str]:
    """Return the set of public method names defined on the client class."""
    src = client_file.read_text()
    names = set()
    for m in re.finditer(r"^    def ([a-z_][a-zA-Z0-9_]*)\(", src, re.MULTILINE):
        name = m.group(1)
        if not name.startswith("_"):
            names.add(name)
    return names


def _direct_calls(test_src: str, client_vars: Tuple[str, ...]) -> Set[str]:
    """Find ``var.method(…)`` calls where var is a known client variable."""
    calls = set()
    var_alt = "|".join(re.escape(v) for v in client_vars)
    pattern = rf"\b(?:{var_alt})\.([a-z_][a-zA-Z0-9_]*)\("
    for m in re.finditer(pattern, test_src):
        calls.add(m.group(1))
    return calls


def _extract_list_keys(node: ast.AST) -> List[str]:
    """Extract string ``type_key`` values from a list-of-tuples-or-strings literal."""
    if not isinstance(node, ast.List):
        return []
    keys: List[str] = []
    for elt in node.elts:
        # Plain string literal in the list
        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
            keys.append(elt.value)
        # Tuple/list literal — take the first string element
        elif isinstance(elt, (ast.Tuple, ast.List)) and elt.elts:
            first = elt.elts[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                keys.append(first.value)
    return keys


def _dynamic_calls(test_src: str, client_vars: Tuple[str, ...]) -> Set[str]:
    """Resolve dynamic method dispatches in parametrized tests.

    The integration suite uses two patterns to call methods whose name is
    not known statically:

    1. Inline f-string in :func:`getattr` / :func:`hasattr`::

           update_fn = getattr(axl, f"update_{type_key}")

    2. f-string assigned to a local first, then dispatched::

           update_method_name = f"update_{obj_key}"
           if hasattr(axl, update_method_name):
               update_method = getattr(axl, update_method_name)

    Both forms produce an f-string literal ``f"verb_{var}"`` somewhere in
    the function body. We just scan for those f-strings — any verb that
    appears alongside a parametrize-referenced list is counted as
    exercising every ``verb_<type_key>`` combination.

    Strategy:
      1. Collect module-level ``_LIST = [...]`` lists of type keys.
      2. For each ``FunctionDef`` decorated with
         ``@pytest.mark.parametrize(..., _LIST, ...)``, find all f-string
         literals matching ``f"verb_{any_var}"`` in the body and pair the
         resulting verbs with the referenced list's type keys.
    """
    tree = ast.parse(test_src)

    # Step 1 — collect lists of keys
    list_keys: Dict[str, List[str]] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and tgt.id.startswith("_"):
                    keys = _extract_list_keys(node.value)
                    if keys:
                        list_keys[tgt.id] = keys

    # Match f"verb_{var}" anywhere in the function body (covers both
    # inline-getattr and intermediate-variable patterns).
    verb_pat = re.compile(r'f["\']([a-z_]+)_\{[A-Za-z_][A-Za-z0-9_]*\}["\']')

    resolved: Set[str] = set()
    src_lines = test_src.splitlines(keepends=True)
    line_offsets = [0]
    for line in src_lines:
        line_offsets.append(line_offsets[-1] + len(line))

    def _slice(node: ast.AST) -> str:
        start = line_offsets[node.lineno - 1]
        end = line_offsets[node.end_lineno] if node.end_lineno else len(test_src)
        return test_src[start:end]

    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        ref_lists: List[str] = []
        for dec in node.decorator_list:
            if not isinstance(dec, ast.Call):
                continue
            for arg in dec.args:
                if isinstance(arg, ast.Name) and arg.id in list_keys:
                    ref_lists.append(arg.id)
        if not ref_lists:
            continue
        body_src = _slice(node)
        verbs = set(verb_pat.findall(body_src))
        # Restrict to the verbs we care about (filters out f-strings that
        # happen to share the shape but aren't method dispatches, like
        # f"failed_{x}" in error messages).
        verbs &= set(CRUD_VERBS) | {"check", "search", "find"}
        for list_name in ref_lists:
            for type_key in list_keys[list_name]:
                for verb in verbs:
                    resolved.add(f"{verb}_{type_key}")
    return resolved


def _collect_calls(client_vars: Tuple[str, ...]) -> Set[str]:
    """Aggregate all direct and dynamic calls across the integration test dir."""
    calls: Set[str] = set()
    for test_file in sorted(TESTS_DIR.glob("*.py")):
        if test_file.name == "__init__.py":
            continue
        src = test_file.read_text()
        calls |= _direct_calls(src, client_vars)
        calls |= _dynamic_calls(src, client_vars)
    return calls


# ── Report ────────────────────────────────────────────────────────────


@dataclass
class CoverageResult:
    """Per-client coverage summary used for printing and JSON output."""
    client: str
    defined: Set[str]
    covered: Set[str]
    by_verb: Dict[str, Tuple[int, int]] = field(default_factory=dict)
    update_gaps_with_addget: List[str] = field(default_factory=list)


def _compute(client: str) -> Optional[CoverageResult]:
    """Compute a :class:`CoverageResult` for a single client key."""
    if client not in CLIENTS:
        return None
    rel, vars_ = CLIENTS[client]
    client_file = CLIENT_DIR / rel
    if not client_file.exists():
        return None
    defined = _public_methods(client_file)
    covered = _collect_calls(vars_) & defined

    by_verb: Dict[str, Tuple[int, int]] = {}
    other_def = set(defined)
    other_cov = set(covered)
    for verb in CRUD_VERBS:
        d = {m for m in defined if m.startswith(f"{verb}_")}
        c = d & covered
        by_verb[verb] = (len(c), len(d))
        other_def -= d
        other_cov -= c
    by_verb["other"] = (len(other_cov), len(other_def))

    # Object types where add/get are covered but update is not (low-effort gaps)
    add_cov = {m[4:] for m in covered if m.startswith("add_")}
    get_cov = {m[4:] for m in covered if m.startswith("get_")}
    upd_def = {m[7:] for m in defined if m.startswith("update_")}
    upd_cov = {m[7:] for m in covered if m.startswith("update_")}
    gaps = sorted((add_cov & get_cov & upd_def) - upd_cov)

    return CoverageResult(
        client=client,
        defined=defined,
        covered=covered,
        by_verb=by_verb,
        update_gaps_with_addget=gaps,
    )


def _format_text(result: CoverageResult, *, verbose: bool) -> str:
    """Pretty-print a coverage result as a human-readable text report."""
    lines: List[str] = []
    n_def = len(result.defined)
    n_cov = len(result.covered)
    pct = (n_cov / n_def * 100) if n_def else 0.0
    lines.append(f"[{result.client}]")
    lines.append(f"  Public methods defined: {n_def}")
    lines.append(f"  Methods exercised:      {n_cov}  ({pct:.1f}%)")
    lines.append("")
    lines.append(f"  {'Verb':<10} {'Defined':>8} {'Tested':>8} {'Pct':>7}")
    lines.append("  " + "-" * 38)
    for verb in CRUD_VERBS + ["other"]:
        c, d = result.by_verb.get(verb, (0, 0))
        if d == 0:
            continue
        verb_pct = (c / d * 100) if d else 0.0
        lines.append(f"  {verb:<10} {d:>8} {c:>8} {verb_pct:>6.1f}%")
    lines.append("")
    if result.update_gaps_with_addget:
        lines.append(
            f"  Object types with add_* AND get_* covered but update_* missing "
            f"({len(result.update_gaps_with_addget)}):"
        )
        for name in result.update_gaps_with_addget:
            lines.append(f"    - {name}")
        lines.append("")
    if verbose:
        missing = sorted(result.defined - result.covered)
        if missing:
            lines.append(f"  Uncovered methods ({len(missing)}):")
            for name in missing:
                lines.append(f"    {name}")
            lines.append("")
    return "\n".join(lines)


def _format_json(results: List[CoverageResult]) -> str:
    payload = []
    for r in results:
        payload.append({
            "client": r.client,
            "defined": len(r.defined),
            "covered": len(r.covered),
            "coverage_pct": round((len(r.covered) / len(r.defined) * 100) if r.defined else 0, 2),
            "by_verb": {
                v: {"defined": d, "covered": c, "pct": round((c / d * 100) if d else 0, 2)}
                for v, (c, d) in r.by_verb.items()
            },
            "uncovered": sorted(r.defined - r.covered),
            "update_gaps_with_addget": r.update_gaps_with_addget,
        })
    return json.dumps(payload, indent=2)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--client",
        choices=["all", *CLIENTS.keys()],
        default="all",
        help="Which client surface to report on (default: all).",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="List every uncovered method name (can be long).",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Emit a machine-readable JSON report instead of text.",
    )
    parser.add_argument(
        "--strict", action="store_true",
        help="Exit non-zero if coverage falls below --min for any client.",
    )
    parser.add_argument(
        "--min", type=float, default=0.0,
        help="Minimum acceptable coverage percent when --strict is set.",
    )
    args = parser.parse_args(argv)

    targets = list(CLIENTS) if args.client == "all" else [args.client]
    results: List[CoverageResult] = []
    for c in targets:
        r = _compute(c)
        if r is not None:
            results.append(r)

    if args.json:
        print(_format_json(results))
    else:
        for r in results:
            print(_format_text(r, verbose=args.verbose))

    if args.strict:
        for r in results:
            n_def = len(r.defined)
            n_cov = len(r.covered)
            pct = (n_cov / n_def * 100) if n_def else 0.0
            if pct < args.min:
                print(
                    f"FAIL: [{r.client}] coverage {pct:.1f}% is below --min {args.min}%",
                    file=sys.stderr,
                )
                return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
