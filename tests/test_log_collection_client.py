"""Tests for LogCollectionClient and DimeGetFileClient with mocked zeep service."""

from unittest.mock import MagicMock, patch

import pytest
from zeep.exceptions import Fault

from axltoolkit.exceptions import LogCollectionError
from axltoolkit.log_collection import DimeGetFileClient, LogCollectionClient

# ── LogCollectionClient ───────────────────────────────────────────────


@pytest.fixture
def log_client():
    with patch.object(LogCollectionClient, "__init__", lambda self, *a, **kw: None):
        client = LogCollectionClient.__new__(LogCollectionClient)
        client._service = MagicMock()
        client._server_ip = "10.0.0.1"
        client._log = MagicMock()
    return client


class TestListNodeServiceLogs:
    def test_success(self, log_client):
        log_client._service.listNodeServiceLogs.return_value = {
            "ServiceList": [{"ServiceName": "Cisco CallManager"}]
        }
        result = log_client.list_node_service_logs()
        log_client._service.listNodeServiceLogs.assert_called_once()
        assert "ServiceList" in result

    def test_fault_raises_error(self, log_client):
        log_client._service.listNodeServiceLogs.side_effect = Fault("Service error")
        with pytest.raises(LogCollectionError, match="Failed to list node service logs"):
            log_client.list_node_service_logs()

    def test_fault_preserves_original(self, log_client):
        fault = Fault("test")
        log_client._service.listNodeServiceLogs.side_effect = fault
        with pytest.raises(LogCollectionError) as exc_info:
            log_client.list_node_service_logs()
        assert exc_info.value.original_exception is fault


class TestSelectLogFiles:
    def test_success(self, log_client):
        criteria = {"ServiceName": "Cisco CallManager", "TimeZone": "UTC"}
        log_client._service.selectLogFiles.return_value = {"FileList": []}
        result = log_client.select_log_files(criteria)
        log_client._service.selectLogFiles.assert_called_once_with(FileSelectionCriteria=criteria)

    def test_fault_raises_error(self, log_client):
        log_client._service.selectLogFiles.side_effect = Fault("Selection failed")
        with pytest.raises(LogCollectionError, match="Failed to select log files"):
            log_client.select_log_files({"ServiceName": "Bad"})


# ── DimeGetFileClient ─────────────────────────────────────────────────


@pytest.fixture
def dime_client():
    with patch.object(DimeGetFileClient, "__init__", lambda self, *a, **kw: None):
        client = DimeGetFileClient.__new__(DimeGetFileClient)
        client._service = MagicMock()
        client._server_ip = "10.0.0.1"
        client._log = MagicMock()
    return client


class TestGetOneFile:
    def test_success(self, dime_client):
        dime_client._service.getOneFile.return_value = {"fileData": b"log content"}
        result = dime_client.get_one_file("/var/log/active/cm/trace/ccm/sdl/test.log")
        dime_client._service.getOneFile.assert_called_once_with(
            fileName="/var/log/active/cm/trace/ccm/sdl/test.log"
        )
        assert result["fileData"] == b"log content"

    def test_fault_raises_error(self, dime_client):
        dime_client._service.getOneFile.side_effect = Fault("File not found")
        with pytest.raises(LogCollectionError, match="Failed to get file"):
            dime_client.get_one_file("/bad/path.log")

    def test_fault_preserves_original(self, dime_client):
        fault = Fault("test")
        dime_client._service.getOneFile.side_effect = fault
        with pytest.raises(LogCollectionError) as exc_info:
            dime_client.get_one_file("/path.log")
        assert exc_info.value.original_exception is fault
