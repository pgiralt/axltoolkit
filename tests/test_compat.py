"""Tests for backward-compatible legacy class aliases."""

import pytest
import warnings
from unittest.mock import MagicMock, patch


class TestAxlToolkitCompat:
    """Test that the legacy AxlToolkit shim delegates correctly."""

    def _make_instance(self):
        from axltoolkit._compat import AxlToolkit
        from axltoolkit.axl import AXLClient

        with patch.object(AXLClient, "__init__", lambda self, *a, **kw: None):
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                obj = AxlToolkit.__new__(AxlToolkit)
                obj._service = MagicMock()
                obj._server_ip = "10.0.0.1"
                obj._version = "15.0"
                obj._log = MagicMock()
        return obj

    def test_emits_deprecation_warning(self):
        from axltoolkit._compat import AxlToolkit
        from axltoolkit.axl import AXLClient

        with patch.object(AXLClient, "__init__", return_value=None):
            with pytest.warns(DeprecationWarning, match="AxlToolkit is deprecated"):
                AxlToolkit("u", "p", "127.0.0.1")

    def test_run_sql_query_delegates(self):
        obj = self._make_instance()
        obj._service.executeSQLQuery.return_value = {"return": None}
        result = obj.run_sql_query("SELECT 1")
        obj._service.executeSQLQuery.assert_called_once()

    def test_run_sql_update_delegates(self):
        obj = self._make_instance()
        obj._service.executeSQLUpdate.return_value = {"return": None}
        result = obj.run_sql_update("UPDATE device SET description='X'")
        obj._service.executeSQLUpdate.assert_called_once()

    def test_get_user_delegates(self):
        obj = self._make_instance()
        obj._service.getUser.return_value = {"return": {"user": {}}}
        obj.get_user("jsmith")
        obj._service.getUser.assert_called_once_with(userid="jsmith")

    def test_list_phone_delegates(self):
        obj = self._make_instance()
        obj._service.listPhone.return_value = {"return": {"phone": []}}
        obj.list_phone(name="SEP%")
        obj._service.listPhone.assert_called_once()

    def test_get_service_returns_service(self):
        obj = self._make_instance()
        assert obj.get_service() is obj._service

    def test_get_cfb_delegates(self):
        obj = self._make_instance()
        obj._service.getConferenceBridge.return_value = {"return": {}}
        obj.get_cfb("CFB_1")
        obj._service.getConferenceBridge.assert_called_once_with(name="CFB_1")

    def test_get_mrg_delegates(self):
        obj = self._make_instance()
        obj._service.getMediaResourceGroup.return_value = {"return": {}}
        obj.get_mrg("MRG_1")
        obj._service.getMediaResourceGroup.assert_called_once_with(name="MRG_1")

    def test_add_partition_delegates(self):
        obj = self._make_instance()
        obj._service.addRoutePartition.return_value = {"return": "ok"}
        obj.add_partition("PT_Test", "desc")
        obj._service.addRoutePartition.assert_called_once()

    def test_inherits_new_methods(self):
        """Legacy class inherits all new AXL methods."""
        obj = self._make_instance()
        assert hasattr(obj, "get_gateway")
        assert hasattr(obj, "list_route_plan")
        assert hasattr(obj, "wipe_phone")
        assert hasattr(obj, "get_smart_license_status")


class TestUcmRisPortToolkitCompat:
    def test_emits_deprecation_warning(self):
        from axltoolkit._compat import UcmRisPortToolkit
        from axltoolkit.risport import RISPortClient

        with patch.object(RISPortClient, "__init__", return_value=None):
            with pytest.warns(DeprecationWarning, match="UcmRisPortToolkit is deprecated"):
                UcmRisPortToolkit("u", "p", "127.0.0.1")

    def test_get_service_returns_service(self):
        from axltoolkit._compat import UcmRisPortToolkit
        from axltoolkit.risport import RISPortClient

        with patch.object(RISPortClient, "__init__", return_value=None):
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                obj = UcmRisPortToolkit("u", "p", "127.0.0.1")
                obj._service = MagicMock()
                assert obj.get_service() is obj._service


class TestUcmPerfMonToolkitCompat:
    def _make_instance(self):
        from axltoolkit._compat import UcmPerfMonToolkit
        from axltoolkit.perfmon import PerfMonClient

        with patch.object(PerfMonClient, "__init__", return_value=None):
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                obj = UcmPerfMonToolkit("u", "p", "127.0.0.1")
                obj._service = MagicMock()
        return obj

    def test_emits_deprecation_warning(self):
        from axltoolkit._compat import UcmPerfMonToolkit
        from axltoolkit.perfmon import PerfMonClient

        with patch.object(PerfMonClient, "__init__", return_value=None):
            with pytest.warns(DeprecationWarning, match="UcmPerfMonToolkit is deprecated"):
                UcmPerfMonToolkit("u", "p", "127.0.0.1")

    def test_perfmon_open_session(self):
        obj = self._make_instance()
        obj._service.perfmonOpenSession.return_value = "handle-1"
        result = obj.perfmonOpenSession()
        assert result == "handle-1"

    def test_perfmon_add_counter_success(self):
        obj = self._make_instance()
        result = obj.perfmonAddCounter("handle-1", [r"\\host\Object\Counter"])
        assert result is True

    def test_perfmon_add_counter_failure(self):
        from zeep.exceptions import Fault
        obj = self._make_instance()
        obj._service.perfmonAddCounter.side_effect = Fault("error")
        result = obj.perfmonAddCounter("handle-1", ["bad"])
        assert result is False

    def test_perfmon_close_session(self):
        obj = self._make_instance()
        obj.perfmonCloseSession("handle-1")
        obj._service.perfmonCloseSession.assert_called_once()

    def test_perfmon_list_instance(self):
        obj = self._make_instance()
        obj._service.perfmonListInstance.return_value = [
            {"Name": {"_value_1": "1000"}},
        ]
        result = obj.perfmonListInstance(host="cm-pub", object_name="Cisco Lines")
        assert result == ["1000"]


class TestPawsToolkitCompat:
    def test_emits_deprecation_warning(self):
        from axltoolkit._compat import PawsToolkit
        from axltoolkit.paws_client import PAWSClient

        with patch.object(PAWSClient, "__init__", return_value=None):
            with pytest.warns(DeprecationWarning, match="PawsToolkit is deprecated"):
                PawsToolkit("u", "p", "127.0.0.1", "VersionService")

    def test_service_param_ignored(self):
        from axltoolkit._compat import PawsToolkit
        from axltoolkit.paws_client import PAWSClient

        with patch.object(PAWSClient, "__init__", return_value=None):
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                obj = PawsToolkit("u", "p", "127.0.0.1", "VersionService")
                assert obj.get_service() is None


class TestWebdialerToolkitCompat:
    def test_emits_deprecation_warning(self):
        from axltoolkit._compat import WebdialerToolkit
        from axltoolkit.webdialer import WebdialerClient

        with patch.object(WebdialerClient, "__init__", return_value=None):
            with pytest.warns(DeprecationWarning, match="WebdialerToolkit is deprecated"):
                WebdialerToolkit("u", "p", "127.0.0.1")
