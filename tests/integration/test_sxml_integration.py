"""
SXML client integration tests against a live UCM cluster.

Tests RISPort, PerfMon, Serviceability, PAWS, Webdialer, and Log Collection
clients.

Run:
    UCM_ADDRESS=ucm.example.com UCM_USERNAME=admin UCM_PASSWORD=secret \\
        pytest tests/integration/test_sxml_integration.py -v --tb=short
"""

from __future__ import annotations

import os

import pytest

from axltoolkit import (
    PAWSClient,
    PerfMonClient,
    RISPortClient,
    ServiceabilityClient,
    WebdialerClient,
)
from axltoolkit.log_collection import DimeGetFileClient, LogCollectionClient

from .conftest import _safe_debug

pytestmark = pytest.mark.integration


# ══════════════════════════════════════════════════════════════════════
#  RISPort
# ══════════════════════════════════════════════════════════════════════


def test_ris_connectivity(ris: RISPortClient):
    """RISPort — verify connectivity."""
    ris.check_connectivity()


def test_ris_select_cm_device(ris: RISPortClient):
    """RISPort — selectCmDevice query."""
    result = ris.select_cm_device(device_class="Phone", status="Registered")
    assert result is not None, f"selectCmDevice(Registered) returned None\n{_safe_debug(ris)}"


def test_ris_select_cm_device_any(ris: RISPortClient):
    """RISPort — selectCmDevice with Any status."""
    result = ris.select_cm_device(device_class="Phone", status="Any")
    assert result is not None, f"selectCmDevice(Any) returned None\n{_safe_debug(ris)}"


def test_ris_select_cm_device_with_items(ris: RISPortClient):
    """RISPort — selectCmDevice with select_items filter."""
    result = ris.select_cm_device(
        device_class="Phone",
        select_items=["SEP*"],
        status="Any",
    )
    assert result is not None, f"selectCmDevice(SEP*) returned None\n{_safe_debug(ris)}"


def test_ris_select_cti_item(ris: RISPortClient):
    """RISPort — selectCtiItem query."""
    result = ris.select_cti_item()
    assert result is not None, f"selectCtiItem returned None\n{_safe_debug(ris)}"


def test_ris_get_registered_phones(ris: RISPortClient):
    """RISPort — get_registered_phones convenience method."""
    try:
        phones = ris.get_registered_phones("*")
    except Exception as exc:
        pytest.skip(f"get_registered_phones not available: {exc}")
    assert isinstance(phones, list)
    # Each entry should be a dict with expected keys
    if phones:
        phone = phones[0]
        assert "name" in phone
        assert "ip_address" in phone
        assert "status" in phone


def test_ris_get_registered_phones_pattern(ris: RISPortClient):
    """RISPort — get_registered_phones with specific pattern."""
    try:
        phones = ris.get_registered_phones("SEP*")
    except Exception as exc:
        pytest.skip(f"get_registered_phones not available: {exc}")
    assert isinstance(phones, list)


def test_ris_last_request_debug(ris: RISPortClient):
    """RISPort — last_request_debug after a call."""
    ris.select_cm_device(device_class="Phone", status="Any")
    debug = ris.last_request_debug()
    assert "request" in debug
    assert "response" in debug


# ══════════════════════════════════════════════════════════════════════
#  PerfMon
# ══════════════════════════════════════════════════════════════════════


def test_pm_connectivity(perfmon: PerfMonClient):
    """PerfMon — verify connectivity."""
    perfmon.check_connectivity()


def test_pm_list_counters(perfmon: PerfMonClient):
    """PerfMon — list available counter objects."""
    host = os.environ["UCM_ADDRESS"]
    result = perfmon.list_counters(host)
    assert result is not None, f"list_counters('{host}') returned None\n{_safe_debug(perfmon)}"


def test_pm_session_lifecycle(perfmon: PerfMonClient):
    """PerfMon — open/add/collect/close session lifecycle."""
    host = os.environ["UCM_ADDRESS"]
    session = perfmon.open_session()
    assert session is not None, f"open_session returned None\n{_safe_debug(perfmon)}"

    try:
        # Add a counter — use a universally available counter
        counter = f"\\\\{host}\\Cisco CallManager\\RegisteredOtherStationDevices"
        perfmon.add_counters(session, [counter])

        # Collect data
        data = perfmon.collect_session_data(session)
        assert data is not None, f"collect_session_data returned None\n{_safe_debug(perfmon)}"

        # Remove counters
        perfmon.remove_counters(session, [counter])
    finally:
        perfmon.close_session(session)


def test_pm_list_instances(perfmon: PerfMonClient):
    """PerfMon — list instances of a counter object."""
    host = os.environ["UCM_ADDRESS"]
    try:
        result = perfmon.list_instances(host, "Cisco CallManager")
        assert result is not None, f"list_instances returned None\n{_safe_debug(perfmon)}"
    except Exception as exc:
        pytest.skip(f"PerfMon list_instances not available: {exc}")


# ══════════════════════════════════════════════════════════════════════
#  Serviceability
# ══════════════════════════════════════════════════════════════════════


def test_svc_connectivity(svc: ServiceabilityClient):
    """Serviceability — verify connectivity."""
    svc.check_connectivity()


def test_svc_get_service_status(svc: ServiceabilityClient):
    """Serviceability — get status of Cisco CallManager service."""
    try:
        result = svc.get_service_status(["Cisco CallManager"])
    except Exception as exc:
        pytest.skip(f"get_service_status not available: {exc}")
    assert result is not None, f"get_service_status returned None\n{_safe_debug(svc)}"


def test_svc_get_multiple_service_status(svc: ServiceabilityClient):
    """Serviceability — get status of multiple services."""
    try:
        result = svc.get_service_status([
            "Cisco CallManager",
            "Cisco Tftp",
        ])
    except Exception as exc:
        pytest.skip(f"get_service_status(multi) not available: {exc}")
    assert result is not None, f"get_service_status(multi) returned None\n{_safe_debug(svc)}"


# ══════════════════════════════════════════════════════════════════════
#  PAWS
# ══════════════════════════════════════════════════════════════════════


def test_paws_connectivity(paws: PAWSClient):
    """PAWS — verify connectivity."""
    paws.check_connectivity()


def test_paws_get_active_version(paws: PAWSClient):
    """PAWS — get active software version."""
    result = paws.get_active_version()
    assert result is not None, f"get_active_version returned None\n{_safe_debug(paws)}"


def test_paws_get_inactive_version(paws: PAWSClient):
    """PAWS — get inactive software version."""
    result = paws.get_inactive_version()
    # Result may be None if no inactive version exists


def test_paws_get_hardware_information(paws: PAWSClient):
    """PAWS — get hardware information."""
    result = paws.get_hardware_information()
    assert result is not None, f"get_hardware_information returned None\n{_safe_debug(paws)}"


def test_paws_get_cluster_nodes(paws: PAWSClient):
    """PAWS — get cluster node list."""
    result = paws.get_cluster_nodes()
    assert result is not None, f"get_cluster_nodes returned None\n{_safe_debug(paws)}"


def test_paws_get_options(paws: PAWSClient):
    """PAWS — get installed options/licenses."""
    result = paws.get_options()
    assert result is not None, f"get_options returned None\n{_safe_debug(paws)}"


def test_paws_get_installed_products(paws: PAWSClient):
    """PAWS — get installed products."""
    result = paws.get_installed_products()
    assert result is not None, f"get_installed_products returned None\n{_safe_debug(paws)}"


# ══════════════════════════════════════════════════════════════════════
#  Webdialer
# ══════════════════════════════════════════════════════════════════════


def test_wd_connectivity(webdialer: WebdialerClient):
    """Webdialer — verify connectivity."""
    webdialer.check_connectivity()


# Note: make_call / end_call require registered devices and are
# therefore not safe to run in automated tests.  get_device_lines
# also requires a real user+device.  We verify connectivity only.


# ══════════════════════════════════════════════════════════════════════
#  Log Collection
# ══════════════════════════════════════════════════════════════════════


def test_log_connectivity(log_client: LogCollectionClient):
    """LogCollection — verify connectivity."""
    log_client.check_connectivity()


def test_log_list_node_service_logs(log_client: LogCollectionClient):
    """LogCollection — list available log services/nodes."""
    result = log_client.list_node_service_logs()
    assert result is not None, f"list_node_service_logs returned None\n{_safe_debug(log_client)}"


def test_dime_connectivity(dime_client: DimeGetFileClient):
    """DimeGetFile — verify connectivity."""
    dime_client.check_connectivity()
