"""Tests for PerfMonClient with mocked zeep service."""

import pytest
from unittest.mock import MagicMock, patch
from zeep.exceptions import Fault

from axltoolkit.perfmon import PerfMonClient
from axltoolkit.exceptions import PerfMonError


@pytest.fixture
def pm():
    """Create a PerfMonClient with a mocked zeep service."""
    with patch.object(PerfMonClient, "__init__", lambda self, *a, **kw: None):
        client = PerfMonClient.__new__(PerfMonClient)
        client._service = MagicMock()
        client._server_ip = "10.0.0.1"
        client._log = MagicMock()
    return client


class TestSessionManagement:
    def test_open_session(self, pm):
        pm._service.perfmonOpenSession.return_value = "session-handle-123"
        handle = pm.open_session()
        assert handle == "session-handle-123"
        pm._service.perfmonOpenSession.assert_called_once()

    def test_open_session_fault(self, pm):
        pm._service.perfmonOpenSession.side_effect = Fault("Cannot open session")
        with pytest.raises(PerfMonError, match="Failed to open perfmon session"):
            pm.open_session()

    def test_close_session(self, pm):
        pm.close_session("session-handle-123")
        pm._service.perfmonCloseSession.assert_called_once_with(
            SessionHandle="session-handle-123"
        )

    def test_close_session_fault(self, pm):
        pm._service.perfmonCloseSession.side_effect = Fault("Invalid session")
        with pytest.raises(PerfMonError, match="Failed to close perfmon session"):
            pm.close_session("bad-handle")


class TestCounterManagement:
    def test_add_counters_list(self, pm):
        counters = [
            r"\\cm-pub\Cisco CallManager\CallsCompleted",
            r"\\cm-pub\Cisco CallManager\CallsActive",
        ]
        pm.add_counters("session-123", counters)
        call_args = pm._service.perfmonAddCounter.call_args
        assert call_args[1]["SessionHandle"] == "session-123"
        counter_data = call_args[1]["ArrayOfCounter"]
        assert len(counter_data[0]["Counter"]) == 2

    def test_add_counters_single_string(self, pm):
        pm.add_counters("session-123", r"\\cm-pub\Cisco CallManager\CallsCompleted")
        call_args = pm._service.perfmonAddCounter.call_args
        counter_data = call_args[1]["ArrayOfCounter"]
        assert len(counter_data[0]["Counter"]) == 1

    def test_add_counters_fault(self, pm):
        pm._service.perfmonAddCounter.side_effect = Fault("Invalid counter")
        with pytest.raises(PerfMonError, match="Failed to add counters"):
            pm.add_counters("session-123", [r"\\bad\counter"])

    def test_remove_counters(self, pm):
        counters = [r"\\cm-pub\Cisco CallManager\CallsCompleted"]
        pm.remove_counters("session-123", counters)
        pm._service.perfmonRemoveCounter.assert_called_once()

    def test_remove_counters_fault(self, pm):
        pm._service.perfmonRemoveCounter.side_effect = Fault("Counter not in session")
        with pytest.raises(PerfMonError, match="Failed to remove counters"):
            pm.remove_counters("session-123", ["bad"])


class TestCollectSessionData:
    def test_collect_with_single_instance_data(self, pm):
        pm._service.perfmonCollectSessionData.return_value = [
            {
                "Name": {"_value_1": r"\\cm-pub\Cisco CallManager\CallsCompleted"},
                "Value": 42,
                "CStatus": 0,
            },
            {
                "Name": {"_value_1": r"\\cm-pub\Cisco CallManager\CallsActive"},
                "Value": 5,
                "CStatus": 0,
            },
        ]

        result = pm.collect_session_data("session-123")
        assert result is not None
        assert "cm-pub" in result
        assert "Cisco CallManager" in result["cm-pub"]
        cm = result["cm-pub"]["Cisco CallManager"]
        assert cm["multi_instance"] is False
        assert cm["counters"]["CallsCompleted"] == 42
        assert cm["counters"]["CallsActive"] == 5

    def test_collect_with_multi_instance_data(self, pm):
        pm._service.perfmonCollectSessionData.return_value = [
            {
                "Name": {"_value_1": r"\\cm-pub\Cisco Lines(1000)\Active"},
                "Value": 1,
                "CStatus": 0,
            },
            {
                "Name": {"_value_1": r"\\cm-pub\Cisco Lines(2000)\Active"},
                "Value": 0,
                "CStatus": 0,
            },
        ]

        result = pm.collect_session_data("session-123")
        lines = result["cm-pub"]["Cisco Lines"]
        assert lines["multi_instance"] is True
        assert lines["instances"]["1000"]["Active"] == 1
        assert lines["instances"]["2000"]["Active"] == 0

    def test_collect_skips_nonzero_status(self, pm):
        pm._service.perfmonCollectSessionData.return_value = [
            {
                "Name": {"_value_1": r"\\cm-pub\Cisco CallManager\CallsCompleted"},
                "Value": 42,
                "CStatus": 0,
            },
            {
                "Name": {"_value_1": r"\\cm-pub\Cisco CallManager\CallsFailed"},
                "Value": -1,
                "CStatus": 1,  # error status, should be skipped
            },
        ]

        result = pm.collect_session_data("session-123")
        cm = result["cm-pub"]["Cisco CallManager"]
        assert "CallsCompleted" in cm["counters"]
        assert "CallsFailed" not in cm.get("counters", {})

    def test_collect_no_data(self, pm):
        pm._service.perfmonCollectSessionData.return_value = None
        result = pm.collect_session_data("session-123")
        assert result is None

    def test_collect_empty_list(self, pm):
        # An empty list is falsy, so collect_session_data returns None
        pm._service.perfmonCollectSessionData.return_value = []
        result = pm.collect_session_data("session-123")
        assert result is None

    def test_collect_fault(self, pm):
        pm._service.perfmonCollectSessionData.side_effect = Fault("Session expired")
        with pytest.raises(PerfMonError, match="Failed to collect session data"):
            pm.collect_session_data("expired-handle")


class TestOneShot:
    def test_list_counters(self, pm):
        pm._service.perfmonListCounter.return_value = [
            {
                "Name": {"_value_1": "Cisco CallManager"},
                "MultiInstance": False,
                "ArrayOfCounter": {
                    "item": [
                        {"Name": {"_value_1": "CallsCompleted"}},
                        {"Name": {"_value_1": "CallsActive"}},
                    ]
                },
            }
        ]

        result = pm.list_counters("cm-pub")
        pm._service.perfmonListCounter.assert_called_once_with(Host="cm-pub")
        assert "Cisco CallManager" in result
        assert result["Cisco CallManager"]["multi_instance"] is False
        assert "CallsCompleted" in result["Cisco CallManager"]["counters"]

    def test_list_counters_none(self, pm):
        pm._service.perfmonListCounter.return_value = None
        result = pm.list_counters("cm-pub")
        assert result is None

    def test_list_counters_fault(self, pm):
        pm._service.perfmonListCounter.side_effect = Fault("Host unreachable")
        with pytest.raises(PerfMonError, match="Failed to list counters"):
            pm.list_counters("bad-host")

    def test_list_instances(self, pm):
        pm._service.perfmonListInstance.return_value = [
            {"Name": {"_value_1": "1000"}},
            {"Name": {"_value_1": "2000"}},
            {"Name": {"_value_1": "3000"}},
        ]

        result = pm.list_instances("cm-pub", "Cisco Lines")
        pm._service.perfmonListInstance.assert_called_once_with(
            Host="cm-pub", Object="Cisco Lines"
        )
        assert result == ["1000", "2000", "3000"]

    def test_list_instances_none(self, pm):
        pm._service.perfmonListInstance.return_value = None
        result = pm.list_instances("cm-pub", "Cisco Lines")
        assert result is None

    def test_list_instances_fault(self, pm):
        pm._service.perfmonListInstance.side_effect = Fault("Object not found")
        with pytest.raises(PerfMonError, match="Failed to list instances"):
            pm.list_instances("cm-pub", "Fake Object")

    def test_collect_counter_data(self, pm):
        pm._service.perfmonCollectCounterData.return_value = [
            {
                "Name": {"_value_1": r"\\cm-pub\Cisco CallManager\CallsCompleted"},
                "Value": 42,
                "CStatus": 0,
            },
            {
                "Name": {"_value_1": r"\\cm-pub\Cisco CallManager\CallsActive"},
                "Value": 3,
                "CStatus": 0,
            },
        ]
        result = pm.collect_counter_data("cm-pub", "Cisco CallManager")
        pm._service.perfmonCollectCounterData.assert_called_once_with(
            Host="cm-pub", Object="Cisco CallManager"
        )
        assert result is not None
        assert len(result) == 2
        assert result[0]["name"].endswith("CallsCompleted")
        assert result[0]["value"] == 42
        assert result[0]["cstatus"] == 0

    def test_collect_counter_data_none(self, pm):
        pm._service.perfmonCollectCounterData.return_value = None
        result = pm.collect_counter_data("cm-pub", "Cisco CallManager")
        assert result is None

    def test_collect_counter_data_empty_list(self, pm):
        pm._service.perfmonCollectCounterData.return_value = []
        result = pm.collect_counter_data("cm-pub", "Cisco CallManager")
        assert result is None

    def test_collect_counter_data_fault(self, pm):
        pm._service.perfmonCollectCounterData.side_effect = Fault("Object not found")
        with pytest.raises(PerfMonError, match="Failed to collect counter data"):
            pm.collect_counter_data("cm-pub", "Fake Object")


class TestDecodeCounterName:
    def test_single_instance(self):
        result = PerfMonClient.decode_counter_name(
            r"\\cm-pub\Cisco CallManager\CallsCompleted"
        )
        assert result == {
            "host": "cm-pub",
            "object": "Cisco CallManager",
            "instance": None,
            "counter": "CallsCompleted",
        }

    def test_multi_instance(self):
        result = PerfMonClient.decode_counter_name(
            r"\\cm-pub\Cisco Locations LBM(Hub_None)\BandwidthAvailable"
        )
        assert result == {
            "host": "cm-pub",
            "object": "Cisco Locations LBM",
            "instance": "Hub_None",
            "counter": "BandwidthAvailable",
        }

    def test_instance_with_arrow(self):
        result = PerfMonClient.decode_counter_name(
            r"\\cm-pub\Cisco Locations LBM(Branch->Hub_None)\CallsInProgress"
        )
        assert result is not None
        assert result["instance"] == "Branch->Hub_None"

    def test_invalid_string(self):
        assert PerfMonClient.decode_counter_name("garbage") is None
        assert PerfMonClient.decode_counter_name("") is None
        assert PerfMonClient.decode_counter_name("\\single") is None
