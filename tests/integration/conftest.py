"""
Integration test fixtures for axltoolkit against a live UCM cluster.

Required environment variables
------------------------------
UCM_ADDRESS      FQDN or IP address of the UCM publisher
UCM_USERNAME     AXL application-user username
UCM_PASSWORD     AXL application-user password

Optional environment variables
------------------------------
UCM_AXL_VERSION           AXL schema version (default: "14.0")
UCM_TLS_VERIFY            "true" or path to CA bundle (default: "false")
UCM_TIMEOUT               Request timeout in seconds (default: "30")
UCM_LOG_TIMEOUT           Timeout for LogCollection/DimeGetFile (default: "120")
UCM_PLATFORM_USERNAME     Platform/OS admin username (default: UCM_USERNAME)
UCM_PLATFORM_PASSWORD     Platform/OS admin password (default: UCM_PASSWORD)

These values may be supplied either as shell exports or through a ``.env``
file at the repository root (gitignored — see ``.env.example``). The
``.env`` file is loaded automatically below via ``python-dotenv`` when
the package is installed; if it isn't, only real shell exports are used.

Running
-------
    # Option 1 — explicit exports
    UCM_ADDRESS=ucm.example.com UCM_USERNAME=admin UCM_PASSWORD=secret \\
        pytest tests/integration/ -v --tb=short

    # Option 2 — populate ``.env`` at the repo root, then simply
    pytest tests/integration/ -v --tb=short
"""

from __future__ import annotations

import contextlib
import os
from pathlib import Path
from typing import Any, Dict, Generator

import pytest

# ── Load credentials from .env at the repo root (best-effort) ─────────
#
# Existing ``os.environ`` values win over anything in the .env file, so
# shell exports remain authoritative for CI / overrides. python-dotenv
# is declared in the dev extras (pyproject.toml) but treated as
# optional here so the suite still runs in minimal environments where
# only the shell env is available.
try:
    from dotenv import load_dotenv as _load_dotenv
except ImportError:  # pragma: no cover - optional dependency
    pass
else:
    _REPO_ROOT = Path(__file__).resolve().parents[2]
    _load_dotenv(_REPO_ROOT / ".env", override=False)

from axltoolkit import (
    AXLClient,
    AXLDuplicateError,
    AXLError,
    PAWSClient,
    PerfMonClient,
    RISPortClient,
    ServiceabilityClient,
    WebdialerClient,
)
from axltoolkit._generated_enums import ProtocolSide
from axltoolkit.log_collection import DimeGetFileClient, LogCollectionClient

# ── Unique prefix for every object created by the test suite ──────────
PREFIX = "AXTK_T_"


def _username() -> str:
    """Return AXL application-user username."""
    return os.environ["UCM_USERNAME"]


def _password() -> str:
    """Return AXL application-user password."""
    return os.environ["UCM_PASSWORD"]


def _server_ip() -> str:
    """Return UCM server address."""
    return os.environ["UCM_ADDRESS"]


def _timeout() -> int:
    """Return default request timeout in seconds."""
    return int(os.environ.get("UCM_TIMEOUT", "30"))


def _platform_username() -> str:
    """Return platform/OS admin username (PAWS/LogCollection require platform creds)."""
    return os.environ.get("UCM_PLATFORM_USERNAME", _username())


def _platform_password() -> str:
    """Return platform/OS admin password."""
    return os.environ.get("UCM_PLATFORM_PASSWORD", _password())


# ======================================================================
#  Helpers
# ======================================================================


def _safe_debug(client) -> str:
    """Return last_request_debug() as a formatted string, or '' on error."""
    try:
        dbg = client.last_request_debug()
        if not dbg:
            return "  (no SOAP history captured)"
        lines = []
        req = dbg.get("request", {})
        resp = dbg.get("response", {})
        if req:
            env = req.get("envelope", b"")
            env_str = env.decode("utf-8", errors="replace") if isinstance(env, bytes) else str(env)
            lines.append(f"  REQUEST HEADERS: {req.get('headers', 'N/A')}")
            lines.append(f"  REQUEST ENVELOPE: {env_str[:2000]}")
        if resp:
            env = resp.get("envelope", b"")
            env_str = env.decode("utf-8", errors="replace") if isinstance(env, bytes) else str(env)
            lines.append(f"  RESPONSE HEADERS: {resp.get('headers', 'N/A')}")
            lines.append(f"  RESPONSE ENVELOPE: {env_str[:2000]}")
        return "\n".join(lines) if lines else "  (no request/response data)"
    except Exception as exc:
        return f"  (debug info unavailable: {exc})"


def _tls_verify():
    """Parse UCM_TLS_VERIFY env var into the value expected by clients."""
    val = os.environ.get("UCM_TLS_VERIFY", "false")
    if val.lower() in ("true", "1", "yes"):
        return True
    if val.lower() in ("false", "0", "no"):
        return False
    return val  # treat as path to CA bundle


def _skip_if_missing():
    """Skip the entire test session if connection env vars are absent."""
    required = ["UCM_ADDRESS", "UCM_USERNAME", "UCM_PASSWORD"]
    missing = [v for v in required if not os.environ.get(v)]
    if missing:
        pytest.skip(f"Integration tests skipped — missing env vars: {', '.join(missing)}")


# ======================================================================
#  Client fixtures (session-scoped)
# ======================================================================


@pytest.fixture(scope="session")
def axl() -> AXLClient:
    """AXL client connected to the live UCM cluster."""
    _skip_if_missing()
    return AXLClient(
        username=_username(),
        password=_password(),
        server_ip=_server_ip(),
        version=os.environ.get("UCM_AXL_VERSION", "14.0"),
        tls_verify=_tls_verify(),
        timeout=_timeout(),
    )


@pytest.fixture(scope="session")
def ris() -> RISPortClient:
    _skip_if_missing()
    return RISPortClient(
        username=_username(),
        password=_password(),
        server_ip=_server_ip(),
        tls_verify=_tls_verify(),
        timeout=_timeout(),
    )


@pytest.fixture(scope="session")
def perfmon() -> PerfMonClient:
    _skip_if_missing()
    return PerfMonClient(
        username=_username(),
        password=_password(),
        server_ip=_server_ip(),
        tls_verify=_tls_verify(),
        timeout=_timeout(),
    )


@pytest.fixture(scope="session")
def svc() -> ServiceabilityClient:
    _skip_if_missing()
    return ServiceabilityClient(
        username=_username(),
        password=_password(),
        server_ip=_server_ip(),
        tls_verify=_tls_verify(),
        timeout=_timeout(),
    )


@pytest.fixture(scope="session")
def paws() -> PAWSClient:
    _skip_if_missing()
    return PAWSClient(
        username=_platform_username(),
        password=_platform_password(),
        server_ip=_server_ip(),
        tls_verify=_tls_verify(),
        timeout=_timeout(),
    )


@pytest.fixture(scope="session")
def webdialer() -> WebdialerClient:
    _skip_if_missing()
    return WebdialerClient(
        username=_username(),
        password=_password(),
        server_ip=_server_ip(),
        tls_verify=_tls_verify(),
        timeout=_timeout(),
    )


@pytest.fixture(scope="session")
def log_client() -> LogCollectionClient:
    _skip_if_missing()
    return LogCollectionClient(
        username=_platform_username(),
        password=_platform_password(),
        server_ip=_server_ip(),
        tls_verify=_tls_verify(),
        timeout=int(os.environ.get("UCM_LOG_TIMEOUT", "120")),
        max_retries=0,
    )


@pytest.fixture(scope="session")
def dime_client() -> DimeGetFileClient:
    _skip_if_missing()
    return DimeGetFileClient(
        username=_platform_username(),
        password=_platform_password(),
        server_ip=_server_ip(),
        tls_verify=_tls_verify(),
        timeout=int(os.environ.get("UCM_LOG_TIMEOUT", "120")),
    )


# ======================================================================
#  Dependency fixtures — shared prerequisite objects
#
#  These are created once per session and torn down in reverse order.
#  CRUD tests create their *own* objects for testing; these fixtures
#  exist solely to satisfy foreign-key requirements.
# ======================================================================


@pytest.fixture(scope="session")
def dep_partition(axl) -> Generator[str, None, None]:
    """Route Partition used as a dependency by many tests."""
    name = f"{PREFIX}Dep_PT"
    try:
        axl.add_route_partition(name, description="Integration dependency")
    except AXLDuplicateError:
        pass
    except Exception as exc:
        pytest.fail(f"Failed to create dependency partition '{name}': {exc}\n{_safe_debug(axl)}")
    yield name
    with contextlib.suppress(Exception):
        axl.remove_route_partition(name)


@pytest.fixture(scope="session")
def dep_partition_2(axl) -> Generator[str, None, None]:
    """Second route partition (for CSS with multiple members)."""
    name = f"{PREFIX}Dep_PT2"
    try:
        axl.add_route_partition(name, description="Integration dependency 2")
    except AXLDuplicateError:
        pass
    except Exception as exc:
        pytest.fail(f"Failed to create dependency partition '{name}': {exc}\n{_safe_debug(axl)}")
    yield name
    with contextlib.suppress(Exception):
        axl.remove_route_partition(name)


@pytest.fixture(scope="session")
def dep_device_pool(axl) -> Generator[str, None, None]:
    """Device Pool — discovers actual CMG/Region names from the server."""
    name = f"{PREFIX}Dep_DP"
    try:
        # Discover actual CMG and Region names via SQL
        cmg = axl.sql_query("SELECT name FROM callmanagergroup LIMIT 1")
        region = axl.sql_query("SELECT name FROM region LIMIT 1")
        if not cmg.get("rows") or not region.get("rows"):
            pytest.skip("Server missing CallManager Group or Region")
        cmg_name = cmg["rows"][0]["name"]
        region_name = region["rows"][0]["name"]
        try:
            axl.add_device_pool(
                {
                    "name": name,
                    "dateTimeSettingName": "CMLocal",
                    "callManagerGroupName": cmg_name,
                    "regionName": region_name,
                    "srstName": "Disable",
                }
            )
        except AXLDuplicateError:
            pass  # reuse leftover from a previous run
    except Exception as exc:
        pytest.fail(f"Failed to create dependency device pool '{name}': {exc}\n{_safe_debug(axl)}")
    yield name
    with contextlib.suppress(Exception):
        axl.remove_device_pool(name)


@pytest.fixture(scope="session")
def dep_css(axl, dep_partition, dep_partition_2) -> Generator[str, None, None]:
    """Calling Search Space containing the two dependency partitions."""
    name = f"{PREFIX}Dep_CSS"
    try:
        axl.add_css(name, "Integration dependency CSS", [dep_partition, dep_partition_2])
    except AXLDuplicateError:
        pass
    except Exception as exc:
        pytest.fail(f"Failed to create dependency CSS '{name}': {exc}\n{_safe_debug(axl)}")
    yield name
    with contextlib.suppress(Exception):
        axl.remove_css(name)


@pytest.fixture(scope="session")
def dep_line(axl, dep_partition) -> Generator[str, None, None]:
    """Directory number in dep_partition."""
    pattern = "19999"
    try:
        axl.add_line(
            {
                "pattern": pattern,
                "routePartitionName": dep_partition,
                "description": "Integration dependency line",
                "usage": "Device",
            }
        )
    except AXLDuplicateError:
        pass
    except AXLError as exc:
        if "exists" in str(exc).lower():
            pass  # DN already exists (code 4052)
        else:
            pytest.fail(
                f"Failed to create dependency line '{pattern}' in '{dep_partition}': {exc}\n"
                f"{_safe_debug(axl)}"
            )
    except Exception as exc:
        pytest.fail(
            f"Failed to create dependency line '{pattern}' in '{dep_partition}': {exc}\n"
            f"{_safe_debug(axl)}"
        )
    yield pattern
    with contextlib.suppress(Exception):
        axl.remove_line(pattern, dep_partition)


@pytest.fixture(scope="session")
def dep_sip_trunk_sec_profile(axl) -> Generator[str, None, None]:
    """SIP Trunk Security Profile for trunk tests."""
    name = f"{PREFIX}Dep_STSP"
    try:
        axl.add_sip_trunk_security_profile(name, description="Integration dependency")
    except AXLDuplicateError:
        pass
    except Exception as exc:
        pytest.fail(
            f"Failed to create dependency SIP trunk sec profile '{name}': {exc}\n{_safe_debug(axl)}"
        )
    yield name
    with contextlib.suppress(Exception):
        axl.remove_sip_trunk_security_profile(name)


@pytest.fixture(scope="session")
def dep_sip_trunk(axl, dep_device_pool, dep_sip_trunk_sec_profile) -> Generator[str, None, None]:
    """SIP Trunk for route group tests."""
    name = f"{PREFIX}Dep_Trunk"
    try:
        axl.add_sip_trunk(
            {
                "name": name,
                "product": "SIP Trunk",
                "class": "Trunk",
                "protocol": "SIP",
                "protocolSide": ProtocolSide.NETWORK,
                "devicePoolName": dep_device_pool,
                "securityProfileName": dep_sip_trunk_sec_profile,
                "sipProfileName": "Standard SIP Profile",
                "locationName": "Hub_None",
                "presenceGroupName": "Standard Presence group",
            }
        )
    except AXLDuplicateError:
        pass
    except Exception as exc:
        pytest.fail(f"Failed to create dependency SIP trunk '{name}': {exc}\n{_safe_debug(axl)}")
    yield name
    with contextlib.suppress(Exception):
        axl.remove_sip_trunk(name)


@pytest.fixture(scope="session")
def dep_line_group(axl, dep_line, dep_partition) -> Generator[str, None, None]:
    """Line Group containing dep_line."""
    name = f"{PREFIX}Dep_LG"
    try:
        axl.add_line_group(
            name,
            members=[
                {
                    "lineSelectionOrder": 1,
                    "directoryNumber": {
                        "pattern": dep_line,
                        "routePartitionName": dep_partition,
                    },
                }
            ],
        )
    except AXLDuplicateError:
        pass
    except Exception as exc:
        pytest.fail(f"Failed to create dependency line group '{name}': {exc}\n{_safe_debug(axl)}")
    yield name
    with contextlib.suppress(Exception):
        axl.remove_line_group(name)


@pytest.fixture(scope="session")
def dep_hunt_list(axl, dep_line_group) -> Generator[str, None, None]:
    """Hunt List referencing dep_line_group."""
    name = f"{PREFIX}Dep_HL"
    try:
        cmg = axl.sql_query("SELECT name FROM callmanagergroup LIMIT 1")
        if not cmg.get("rows"):
            pytest.skip("No CallManager Group found on server")
        cmg_name = cmg["rows"][0]["name"]
        axl.add_hunt_list(
            name,
            description="Integration dependency",
            call_manager_group_name=cmg_name,
            line_groups=[dep_line_group],
        )
    except AXLDuplicateError:
        pass
    except Exception as exc:
        pytest.fail(f"Failed to create dependency hunt list '{name}': {exc}\n{_safe_debug(axl)}")
    yield name
    with contextlib.suppress(Exception):
        axl.remove_hunt_list(name)


@pytest.fixture(scope="session")
def dep_route_group(axl, dep_sip_trunk) -> Generator[str, None, None]:
    """Route Group referencing dep_sip_trunk."""
    name = f"{PREFIX}Dep_RG"
    try:
        axl.add_route_group(name, "Top Down", [dep_sip_trunk])
    except AXLDuplicateError:
        pass
    except Exception as exc:
        pytest.fail(f"Failed to create dependency route group '{name}': {exc}\n{_safe_debug(axl)}")
    yield name
    with contextlib.suppress(Exception):
        axl.remove_route_group(name)


@pytest.fixture(scope="session")
def dep_route_list(axl, dep_route_group) -> Generator[str, None, None]:
    """Route List referencing dep_route_group."""
    name = f"{PREFIX}Dep_RL"
    try:
        axl.add_route_list(
            name,
            description="Integration dependency",
            call_manager_group_name="Default",
            route_list_enabled=True,
            run_on_every_node=False,
            route_groups=[dep_route_group],
        )
    except AXLDuplicateError:
        pass
    except Exception as exc:
        pytest.fail(f"Failed to create dependency route list '{name}': {exc}\n{_safe_debug(axl)}")
    yield name
    with contextlib.suppress(Exception):
        axl.remove_route_list(name)


# ======================================================================
#  Pytest hook — dump AXL debug info on test failure
# ======================================================================

# Store references to the live clients so the hook can access them.
_session_clients: Dict[str, Any] = {}


@pytest.fixture(scope="session", autouse=True)
def _register_clients(axl):
    """Make the AXL client available to the failure hook."""
    _session_clients["axl"] = axl
    yield
    _session_clients.clear()


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """Append AXL last-request debug info to the report when a test fails."""
    outcome = yield
    report = outcome.get_result()
    if report.when in ("call", "setup") and report.failed:
        client = _session_clients.get("axl")
        if client is not None:
            debug_text = _safe_debug(client)
            if debug_text:
                report.sections.append(("AXL Last Request Debug", debug_text))


# ======================================================================
#  Emergency cleanup — find and remove any orphaned AXTK_T_ objects
# ======================================================================


@pytest.fixture(scope="session", autouse=True)
def emergency_cleanup(axl):
    """After all tests, attempt to clean up any orphaned test objects."""
    yield
    try:
        result = axl.sql_query(f"SELECT name FROM device WHERE name LIKE '{PREFIX}%'")
        for row in result.get("rows", []):
            with contextlib.suppress(Exception):
                axl.remove_phone(row["name"])
    except Exception:
        pass
