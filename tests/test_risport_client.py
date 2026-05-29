"""Tests for RISPortClient with mocked zeep service."""

import pytest
from unittest.mock import MagicMock, patch
from zeep.exceptions import Fault

from axltoolkit.risport import RISPortClient
from axltoolkit.exceptions import RISPortError


@pytest.fixture
def ris():
    """Create a RISPortClient with a mocked zeep service."""
    with patch.object(RISPortClient, "__init__", lambda self, *a, **kw: None):
        client = RISPortClient.__new__(RISPortClient)
        client._service = MagicMock()
        client._server_ip = "10.0.0.1"
        client._log = MagicMock()
    return client


class TestSelectCmDevice:
    def test_default_parameters(self, ris):
        ris._service.selectCmDevice.return_value = {
            "SelectCmDeviceResult": {
                "TotalDevicesFound": 0,
                "CmNodes": {"item": []},
            },
            "StateInfo": "",
        }
        result = ris.select_cm_device()
        call_args = ris._service.selectCmDevice.call_args
        criteria = call_args[1]["CmSelectionCriteria"]
        assert criteria["DeviceClass"] == "Any"
        assert criteria["SelectBy"] == "Name"
        assert criteria["MaxReturnedDevices"] == "1000"
        assert criteria["Model"] == 255
        assert criteria["Status"] == "Any"
        assert criteria["SelectItems"] == [{"item": ["*"]}]

    def test_custom_parameters(self, ris):
        ris._service.selectCmDevice.return_value = {"SelectCmDeviceResult": {}, "StateInfo": ""}
        ris.select_cm_device(
            device_class="Phone",
            select_by="Name",
            max_returned_devices=500,
            model=100,
            status="Registered",
            select_items=["SEP*", "CSF*"],
        )
        call_args = ris._service.selectCmDevice.call_args
        criteria = call_args[1]["CmSelectionCriteria"]
        assert criteria["DeviceClass"] == "Phone"
        assert criteria["MaxReturnedDevices"] == "500"
        assert criteria["Model"] == 100
        assert criteria["Status"] == "Registered"
        assert criteria["SelectItems"] == [{"item": ["SEP*", "CSF*"]}]

    def test_fault_raises_risport_error(self, ris):
        ris._service.selectCmDevice.side_effect = Fault("Service unavailable")
        with pytest.raises(RISPortError, match="selectCmDevice failed"):
            ris.select_cm_device()

    def test_fault_preserves_original(self, ris):
        fault = Fault("test error")
        ris._service.selectCmDevice.side_effect = fault
        with pytest.raises(RISPortError) as exc_info:
            ris.select_cm_device()
        assert exc_info.value.original_exception is fault


class TestSelectCmDeviceExt:
    def test_default_parameters(self, ris):
        ris._service.selectCmDeviceExt.return_value = {
            "SelectCmDeviceResult": {
                "TotalDevicesFound": 0,
                "CmNodes": {"item": []},
            },
            "StateInfo": "",
        }
        ris.select_cm_device_ext()
        call_args = ris._service.selectCmDeviceExt.call_args
        criteria = call_args[1]["CmSelectionCriteria"]
        assert criteria["DeviceClass"] == "Any"
        assert criteria["SelectBy"] == "Name"
        assert criteria["MaxReturnedDevices"] == 1000
        assert criteria["Status"] == "Any"
        assert criteria["SelectItems"] == {"item": [{"Item": "*"}]}

    def test_custom_parameters(self, ris):
        ris._service.selectCmDeviceExt.return_value = {"SelectCmDeviceResult": {}, "StateInfo": ""}
        ris.select_cm_device_ext(
            device_class="Phone",
            max_returned_devices=200,
            status="Registered",
            select_items=["SEP*", "CSF*"],
            state_info="prev-state",
        )
        call_args = ris._service.selectCmDeviceExt.call_args
        assert call_args[1]["StateInfo"] == "prev-state"
        criteria = call_args[1]["CmSelectionCriteria"]
        assert criteria["DeviceClass"] == "Phone"
        assert criteria["Status"] == "Registered"
        assert criteria["MaxReturnedDevices"] == 200
        assert criteria["SelectItems"] == {
            "item": [{"Item": "SEP*"}, {"Item": "CSF*"}]
        }

    def test_fault_raises_risport_error(self, ris):
        ris._service.selectCmDeviceExt.side_effect = Fault("Service unavailable")
        with pytest.raises(RISPortError, match="selectCmDeviceExt failed"):
            ris.select_cm_device_ext()

    def test_fault_preserves_original(self, ris):
        fault = Fault("ext error")
        ris._service.selectCmDeviceExt.side_effect = fault
        with pytest.raises(RISPortError) as exc_info:
            ris.select_cm_device_ext()
        assert exc_info.value.original_exception is fault


class TestSelectCtiItem:
    def test_default_parameters(self, ris):
        ris._service.selectCtiItem.return_value = {}
        ris.select_cti_item()
        call_args = ris._service.selectCtiItem.call_args
        criteria = call_args[1]["CtiSelectionCriteria"]
        assert criteria["CtiMgrClass"] == "Device"
        assert criteria["MaxReturnedItems"] == 2000
        assert criteria["Status"] == "Any"
        assert criteria["NodeName"] == ""
        assert criteria["SelectAppBy"] == "AppId"
        assert criteria["DevNames"] == {"item": []}
        assert criteria["AppItems"] == {"item": []}
        assert criteria["DirNumbers"] == {"item": []}

    def test_custom_parameters(self, ris):
        ris._service.selectCtiItem.return_value = {}
        ris.select_cti_item(
            cti_mgr_class="Line",
            max_returned_items=100,
            status="Open",
            device_names=["CTI*"],
        )
        call_args = ris._service.selectCtiItem.call_args
        criteria = call_args[1]["CtiSelectionCriteria"]
        assert criteria["CtiMgrClass"] == "Line"
        assert criteria["DevNames"] == {"item": [{"DevName": "CTI*"}]}

    def test_with_app_items(self, ris):
        ris._service.selectCtiItem.return_value = {}
        ris.select_cti_item(app_items=["CTIApp1", "CTIApp2"])
        call_args = ris._service.selectCtiItem.call_args
        criteria = call_args[1]["CtiSelectionCriteria"]
        assert criteria["AppItems"] == {
            "item": [{"AppItem": "CTIApp1"}, {"AppItem": "CTIApp2"}]
        }

    def test_with_dir_numbers(self, ris):
        ris._service.selectCtiItem.return_value = {}
        ris.select_cti_item(dir_numbers=["1001", "1002"])
        call_args = ris._service.selectCtiItem.call_args
        criteria = call_args[1]["CtiSelectionCriteria"]
        assert criteria["DirNumbers"] == {
            "item": [{"DirNumber": "1001"}, {"DirNumber": "1002"}]
        }

    def test_fault_raises_risport_error(self, ris):
        ris._service.selectCtiItem.side_effect = Fault("CTI service error")
        with pytest.raises(RISPortError, match="selectCtiItem failed"):
            ris.select_cti_item()


class TestGetRegisteredPhones:
    def test_returns_flat_list(self, ris):
        ris._service.selectCmDevice.return_value = {
            "SelectCmDeviceResult": {
                "TotalDevicesFound": 2,
                "CmNodes": {
                    "item": [
                        {
                            "Name": "cm-pub",
                            "CmDevices": {
                                "item": [
                                    {
                                        "Name": "SEP001122334455",
                                        "IPAddress": {"item": [{"IP": "10.0.0.5"}]},
                                        "Status": "Registered",
                                        "Model": 684,
                                    },
                                    {
                                        "Name": "SEP665544332211",
                                        "IPAddress": {"item": [{"IP": "10.0.0.6"}]},
                                        "Status": "Registered",
                                        "Model": 684,
                                    },
                                ]
                            },
                        }
                    ]
                },
            },
            "StateInfo": "",
        }

        phones = ris.get_registered_phones("SEP*")
        assert len(phones) == 2
        assert phones[0]["name"] == "SEP001122334455"
        assert phones[0]["ip_address"] == "10.0.0.5"
        assert phones[0]["node"] == "cm-pub"
        assert phones[1]["name"] == "SEP665544332211"

    def test_handles_no_ip(self, ris):
        ris._service.selectCmDevice.return_value = {
            "SelectCmDeviceResult": {
                "TotalDevicesFound": 1,
                "CmNodes": {
                    "item": [
                        {
                            "Name": "cm-pub",
                            "CmDevices": {
                                "item": [
                                    {
                                        "Name": "SEP000000000000",
                                        "IPAddress": None,
                                        "Status": "Registered",
                                        "Model": 684,
                                    }
                                ]
                            },
                        }
                    ]
                },
            },
            "StateInfo": "",
        }

        phones = ris.get_registered_phones()
        assert len(phones) == 1
        assert phones[0]["ip_address"] is None

    def test_handles_empty_nodes(self, ris):
        ris._service.selectCmDevice.return_value = {
            "SelectCmDeviceResult": {
                "TotalDevicesFound": 0,
                "CmNodes": {"item": []},
            },
            "StateInfo": "",
        }
        phones = ris.get_registered_phones()
        assert phones == []


# ── Session-recovery (Error Code 7) tests ────────────────────────────────


@pytest.fixture
def ris_with_session():
    """RIS client whose mocked session/client supports rebuild on recovery."""
    with patch.object(RISPortClient, "__init__", lambda self, *a, **kw: None):
        client = RISPortClient.__new__(RISPortClient)
        client._service = MagicMock(name="initial_service")
        client._server_ip = "10.0.0.1"
        client._log = MagicMock()
        # Mock attributes needed by _reset_session
        client._session = MagicMock(name="session")
        client._session.cookies = MagicMock()
        client._client = MagicMock(name="zeep_client")
        # When recovery rebuilds the service, hand back a brand-new mock
        client._client.create_service.return_value = MagicMock(name="rebuilt_service")
    return client


class TestIsSessionError:
    def test_error_code_7(self):
        fault = Fault("Error Code = 7 Following error needs soap clients to start a new session")
        assert RISPortClient._is_session_error(fault) is True

    def test_error_code_7_case_insensitive(self):
        fault = Fault("ERROR CODE = 7")
        assert RISPortClient._is_session_error(fault) is True

    def test_session_phrase_alone(self):
        fault = Fault("Some prefix - Needs soap clients to start a new session")
        assert RISPortClient._is_session_error(fault) is True

    def test_other_fault_returns_false(self):
        fault = Fault("Internal Server Error")
        assert RISPortClient._is_session_error(fault) is False

    def test_authentication_fault_returns_false(self):
        fault = Fault("Authentication failed for user")
        assert RISPortClient._is_session_error(fault) is False


class TestResetSession:
    def test_clears_cookies_and_rebuilds_service(self, ris_with_session):
        original_service = ris_with_session._service
        ris_with_session._reset_session()
        ris_with_session._session.cookies.clear.assert_called_once()
        ris_with_session._client.create_service.assert_called_once_with(
            RISPortClient._BINDING,
            RISPortClient._ENDPOINT.format(server="10.0.0.1"),
        )
        assert ris_with_session._service is not original_service


class TestCallRecovery:
    def test_passthrough_on_success(self, ris_with_session):
        ris_with_session._service.someOp.return_value = "ok"
        result = ris_with_session._call("someOp", arg="value")
        assert result == "ok"
        ris_with_session._service.someOp.assert_called_once_with(arg="value")
        ris_with_session._client.create_service.assert_not_called()

    def test_non_session_fault_is_wrapped_without_retry(self, ris_with_session):
        ris_with_session._service.someOp.side_effect = Fault("Service unavailable")
        with pytest.raises(RISPortError, match="someOp failed:"):
            ris_with_session._call("someOp")
        assert ris_with_session._service.someOp.call_count == 1
        ris_with_session._client.create_service.assert_not_called()

    def test_session_error_triggers_one_retry(self, ris_with_session):
        # First call: session error. Second call (on rebuilt service): success.
        initial_service = ris_with_session._service
        initial_service.someOp.side_effect = Fault(
            "Error Code = 7 Following error needs soap clients to start a new session"
        )
        rebuilt_service = ris_with_session._client.create_service.return_value
        rebuilt_service.someOp.return_value = "recovered"

        result = ris_with_session._call("someOp", arg="value")

        assert result == "recovered"
        initial_service.someOp.assert_called_once_with(arg="value")
        rebuilt_service.someOp.assert_called_once_with(arg="value")
        ris_with_session._session.cookies.clear.assert_called_once()
        ris_with_session._client.create_service.assert_called_once()

    def test_session_error_on_retry_raises(self, ris_with_session):
        initial_service = ris_with_session._service
        initial_service.someOp.side_effect = Fault("Error Code = 7")
        rebuilt_service = ris_with_session._client.create_service.return_value
        rebuilt_service.someOp.side_effect = Fault("Error Code = 7")

        with pytest.raises(RISPortError, match="someOp failed after session reset"):
            ris_with_session._call("someOp")

        initial_service.someOp.assert_called_once()
        rebuilt_service.someOp.assert_called_once()

    def test_select_cm_device_inherits_recovery(self, ris_with_session):
        """End-to-end: an Error Code 7 on selectCmDevice triggers recovery."""
        initial_service = ris_with_session._service
        initial_service.selectCmDevice.side_effect = Fault(
            "Error Code = 7 Following error needs soap clients to start a new session"
        )
        rebuilt_service = ris_with_session._client.create_service.return_value
        rebuilt_service.selectCmDevice.return_value = {
            "SelectCmDeviceResult": {"TotalDevicesFound": 0, "CmNodes": {"item": []}},
            "StateInfo": "",
        }

        result = ris_with_session.select_cm_device()

        assert "SelectCmDeviceResult" in result
        rebuilt_service.selectCmDevice.assert_called_once()
