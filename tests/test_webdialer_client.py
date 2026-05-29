"""Tests for WebdialerClient with mocked zeep service."""

import pytest
from unittest.mock import MagicMock, patch
from zeep.exceptions import Fault

from axltoolkit.webdialer import WebdialerClient
from axltoolkit.exceptions import WebdialerError


@pytest.fixture
def wd():
    """Create a WebdialerClient with a mocked zeep service."""
    with patch.object(WebdialerClient, "__init__", lambda self, *a, **kw: None):
        client = WebdialerClient.__new__(WebdialerClient)
        client._service = MagicMock()
        client._server_ip = "10.0.0.1"
        client._username = "wduser"
        client._log = MagicMock()
        # Mock the session auth for _build_credential
        client._session = MagicMock()
        client._session.auth.password = "wdpass"
    return client


class TestBuildHelpers:
    def test_build_credential(self, wd):
        cred = wd._build_credential()
        assert cred == {"userID": "wduser", "password": "wdpass"}

    def test_build_user_profile_defaults(self, wd):
        profile = wd._build_user_profile("jsmith", "SEP001122334455", "1001")
        assert profile["user"] == "jsmith"
        assert profile["deviceName"] == "SEP001122334455"
        assert profile["lineNumber"] == "1001"
        assert profile["supportEM"] is False
        assert profile["dontAutoClose"] is True
        assert profile["dontShowCallConf"] is True

    def test_build_user_profile_custom(self, wd):
        profile = wd._build_user_profile(
            "jsmith", "SEP001122334455", "1001",
            support_em=True, locale="German Germany",
        )
        assert profile["supportEM"] is True
        assert profile["locale"] == "German Germany"


class TestMakeCall:
    def test_success(self, wd):
        wd._service.makeCallSoap.return_value = {"responseCode": 0, "responseDescription": "OK"}
        result = wd.make_call(
            user="jsmith",
            device="SEP001122334455",
            line="1001",
            destination="1002",
        )
        wd._service.makeCallSoap.assert_called_once()
        call_args = wd._service.makeCallSoap.call_args
        assert call_args[1]["in0"]["userID"] == "wduser"
        assert call_args[1]["in1"] == "1002"
        assert call_args[1]["in2"]["user"] == "jsmith"
        assert result["responseCode"] == 0

    def test_with_profile_kwargs(self, wd):
        wd._service.makeCallSoap.return_value = {"responseCode": 0}
        wd.make_call(
            user="jsmith",
            device="SEP001122334455",
            line="1001",
            destination="1002",
            support_em=True,
        )
        call_args = wd._service.makeCallSoap.call_args
        assert call_args[1]["in2"]["supportEM"] is True

    def test_fault_raises_error(self, wd):
        wd._service.makeCallSoap.side_effect = Fault("Call failed")
        with pytest.raises(WebdialerError, match="Failed to make call to 1002"):
            wd.make_call("jsmith", "SEP001122334455", "1001", "1002")

    def test_fault_preserves_original(self, wd):
        fault = Fault("test")
        wd._service.makeCallSoap.side_effect = fault
        with pytest.raises(WebdialerError) as exc_info:
            wd.make_call("jsmith", "SEP001122334455", "1001", "1002")
        assert exc_info.value.original_exception is fault


class TestEndCall:
    def test_success(self, wd):
        wd._service.endCallSoap.return_value = {"responseCode": 0}
        result = wd.end_call(
            user="jsmith",
            device="SEP001122334455",
            line="1001",
        )
        wd._service.endCallSoap.assert_called_once()
        call_args = wd._service.endCallSoap.call_args
        assert call_args[1]["in0"]["userID"] == "wduser"
        assert call_args[1]["in1"]["user"] == "jsmith"

    def test_fault_raises_error(self, wd):
        wd._service.endCallSoap.side_effect = Fault("End call failed")
        with pytest.raises(WebdialerError, match="Failed to end call on"):
            wd.end_call("jsmith", "SEP001122334455", "1001")


class TestGetDeviceLines:
    def test_success(self, wd):
        wd._service.getDeviceLinesSoap.return_value = {
            "lines": [{"lineNumber": "1001"}, {"lineNumber": "1002"}]
        }
        result = wd.get_device_lines("jsmith", "SEP001122334455")
        wd._service.getDeviceLinesSoap.assert_called_once()
        call_args = wd._service.getDeviceLinesSoap.call_args
        assert call_args[1]["in1"]["user"] == "jsmith"
        assert call_args[1]["in1"]["deviceName"] == "SEP001122334455"
        assert len(result["lines"]) == 2

    def test_fault_raises_error(self, wd):
        wd._service.getDeviceLinesSoap.side_effect = Fault("Device not found")
        with pytest.raises(WebdialerError, match="Failed to get device lines"):
            wd.get_device_lines("jsmith", "BADDEVICE")


class TestGetPortNumber:
    def test_success(self, wd):
        wd._service.getPortNumberSoap.return_value = {"portNumber": "8443"}
        result = wd.get_port_number()
        wd._service.getPortNumberSoap.assert_called_once_with()
        assert result["portNumber"] == "8443"

    def test_fault_raises_error(self, wd):
        wd._service.getPortNumberSoap.side_effect = Fault("Port query failed")
        with pytest.raises(WebdialerError, match="Failed to get port number"):
            wd.get_port_number()

    def test_fault_preserves_original(self, wd):
        fault = Fault("network error")
        wd._service.getPortNumberSoap.side_effect = fault
        with pytest.raises(WebdialerError) as exc_info:
            wd.get_port_number()
        assert exc_info.value.original_exception is fault


class TestGetCallStatus:
    def test_success(self, wd):
        wd._service.getCallStatusSoap.return_value = {"callState": "Connected"}
        result = wd.get_call_status(
            user="jsmith",
            device="SEP001122334455",
            line="1001",
        )
        wd._service.getCallStatusSoap.assert_called_once()
        call_args = wd._service.getCallStatusSoap.call_args
        assert call_args[1]["in0"]["userID"] == "wduser"
        assert call_args[1]["in1"]["user"] == "jsmith"
        assert call_args[1]["in1"]["deviceName"] == "SEP001122334455"
        assert call_args[1]["in1"]["lineNumber"] == "1001"
        assert result["callState"] == "Connected"

    def test_with_profile_kwargs(self, wd):
        wd._service.getCallStatusSoap.return_value = {"callState": "Idle"}
        wd.get_call_status(
            user="jsmith",
            device="SEP001122334455",
            line="1001",
            support_em=True,
        )
        call_args = wd._service.getCallStatusSoap.call_args
        assert call_args[1]["in1"]["supportEM"] is True

    def test_fault_raises_error(self, wd):
        wd._service.getCallStatusSoap.side_effect = Fault("Status query failed")
        with pytest.raises(WebdialerError, match="Failed to get call status"):
            wd.get_call_status("jsmith", "SEP001122334455", "1001")
