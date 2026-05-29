"""Tests for PAWSClient with mocked PAWS services."""

from unittest.mock import MagicMock, patch

import pytest
from zeep.exceptions import Fault

from axltoolkit.exceptions import PAWSError
from axltoolkit.paws_client import PAWSClient


@pytest.fixture
def paws():
    """Create a PAWSClient with mocked lazy-init services."""
    with patch.object(PAWSClient, "__init__", lambda self, *a, **kw: None):
        client = PAWSClient.__new__(PAWSClient)
        client._server_ip = "10.0.0.1"
        client._services = {}
        client._log = MagicMock()
        # Pre-populate service mocks so _get_paws_service returns them
        for svc_name in [
            "HardwareInformationService",
            "VersionService",
            "OptionsService",
            "ProductService",
            "ClusterNodesService",
            "APIVersionService",
            "CancelUpgradeService",
            "DeploymentModeService",
            "HardwareModelService",
            "PrepareRemoteUpgradeService",
            "RestartSystemService",
            "RestartSystemStatusService",
            "StartUpgradeService",
            "SwitchVersionService",
            "SwitchVersionStatusService",
            "UpgradeFilterService",
            "UpgradeProgressStageService",
            "UpgradeStageService",
            "UpgradeTypeService",
            "UpgradeValidService",
        ]:
            client._services[svc_name] = MagicMock()
    return client


class TestGetHardwareInformation:
    def test_success(self, paws):
        paws._services["HardwareInformationService"].getHardwareInformation.return_value = {
            "Processors": "8",
            "Memory": "16384 MB",
        }
        result = paws.get_hardware_information()
        paws._services["HardwareInformationService"].getHardwareInformation.assert_called_once()
        assert result["Processors"] == "8"

    def test_fault_raises_error(self, paws):
        paws._services["HardwareInformationService"].getHardwareInformation.side_effect = Fault(
            "HW service error"
        )
        with pytest.raises(PAWSError, match="Failed to get hardware information"):
            paws.get_hardware_information()


class TestGetActiveVersion:
    def test_success(self, paws):
        paws._services["VersionService"].getActiveVersion.return_value = {
            "activeServerVersion": "15.0.1.10000-1"
        }
        result = paws.get_active_version()
        assert result["activeServerVersion"] == "15.0.1.10000-1"

    def test_fault_raises_error(self, paws):
        paws._services["VersionService"].getActiveVersion.side_effect = Fault("Version error")
        with pytest.raises(PAWSError, match="Failed to get active version"):
            paws.get_active_version()

    def test_fault_preserves_original(self, paws):
        fault = Fault("test")
        paws._services["VersionService"].getActiveVersion.side_effect = fault
        with pytest.raises(PAWSError) as exc_info:
            paws.get_active_version()
        assert exc_info.value.original_exception is fault


class TestGetInactiveVersion:
    def test_success(self, paws):
        paws._services["VersionService"].getInactiveVersion.return_value = {
            "inactiveServerVersion": "14.0.1.10000-1"
        }
        result = paws.get_inactive_version()
        assert result["inactiveServerVersion"] == "14.0.1.10000-1"

    def test_fault_raises_error(self, paws):
        paws._services["VersionService"].getInactiveVersion.side_effect = Fault("error")
        with pytest.raises(PAWSError, match="Failed to get inactive version"):
            paws.get_inactive_version()


class TestGetOptions:
    def test_success(self, paws):
        paws._services["OptionsService"].getActiveOptions.return_value = {
            "options": ["Enhanced Security"]
        }
        result = paws.get_options()
        paws._services["OptionsService"].getActiveOptions.assert_called_once()
        assert "options" in result

    def test_fault_raises_error(self, paws):
        paws._services["OptionsService"].getActiveOptions.side_effect = Fault("Options error")
        with pytest.raises(PAWSError, match="Failed to get options"):
            paws.get_options()


class TestGetInstalledProducts:
    def test_success(self, paws):
        paws._services["ProductService"].getInstalledProducts.return_value = {
            "products": [{"name": "Cisco Unified CM"}]
        }
        result = paws.get_installed_products()
        assert result["products"][0]["name"] == "Cisco Unified CM"

    def test_fault_raises_error(self, paws):
        paws._services["ProductService"].getInstalledProducts.side_effect = Fault("error")
        with pytest.raises(PAWSError, match="Failed to get installed products"):
            paws.get_installed_products()


class TestGetClusterNodes:
    def test_success(self, paws):
        paws._services["ClusterNodesService"].getClusterNodes.return_value = {
            "nodes": [{"name": "cm-pub"}, {"name": "cm-sub1"}]
        }
        result = paws.get_cluster_nodes()
        assert len(result["nodes"]) == 2

    def test_fault_raises_error(self, paws):
        paws._services["ClusterNodesService"].getClusterNodes.side_effect = Fault("error")
        with pytest.raises(PAWSError, match="Failed to get cluster nodes"):
            paws.get_cluster_nodes()


class TestGetInactiveOptions:
    def test_success(self, paws):
        paws._services["OptionsService"].getInactiveOptions.return_value = {"options": ["Security"]}
        result = paws.get_inactive_options()
        paws._services["OptionsService"].getInactiveOptions.assert_called_once()
        assert "options" in result

    def test_fault_raises_error(self, paws):
        paws._services["OptionsService"].getInactiveOptions.side_effect = Fault("error")
        with pytest.raises(PAWSError, match="Failed to get inactive options"):
            paws.get_inactive_options()


class TestGetProductName:
    def test_success(self, paws):
        paws._services["ProductService"].getProductName.return_value = {
            "productName": "Cisco Unified Communications Manager"
        }
        result = paws.get_product_name()
        assert result["productName"] == "Cisco Unified Communications Manager"

    def test_fault_raises_error(self, paws):
        paws._services["ProductService"].getProductName.side_effect = Fault("error")
        with pytest.raises(PAWSError, match="Failed to get product name"):
            paws.get_product_name()


class TestGetMyClusterNode:
    def test_success(self, paws):
        paws._services["ClusterNodesService"].getMyClusterNode.return_value = {
            "name": "cm-pub",
            "ip": "10.0.0.1",
        }
        result = paws.get_my_cluster_node()
        assert result["name"] == "cm-pub"

    def test_fault_raises_error(self, paws):
        paws._services["ClusterNodesService"].getMyClusterNode.side_effect = Fault("error")
        with pytest.raises(PAWSError, match="Failed to get my cluster node"):
            paws.get_my_cluster_node()


class TestGetAPIVersion:
    def test_success(self, paws):
        paws._services["APIVersionService"].getAPIVersion.return_value = {"apiVersion": "1.0"}
        result = paws.get_api_version()
        assert result["apiVersion"] == "1.0"

    def test_fault_raises_error(self, paws):
        paws._services["APIVersionService"].getAPIVersion.side_effect = Fault("error")
        with pytest.raises(PAWSError, match="Failed to get API version"):
            paws.get_api_version()


class TestDeploymentMode:
    def test_get_success(self, paws):
        paws._services["DeploymentModeService"].getDeploymentMode.return_value = {
            "result": "internal.request.complete",
            "deploymentMode": "Enterprise",
        }
        result = paws.get_deployment_mode()
        assert result["deploymentMode"] == "Enterprise"

    def test_get_fault_raises_error(self, paws):
        paws._services["DeploymentModeService"].getDeploymentMode.side_effect = Fault("error")
        with pytest.raises(PAWSError, match="Failed to get deployment mode"):
            paws.get_deployment_mode()

    def test_set_success(self, paws):
        paws._services["DeploymentModeService"].setDeploymentMode.return_value = {
            "result": "internal.request.complete"
        }
        result = paws.set_deployment_mode("Enterprise")
        paws._services["DeploymentModeService"].setDeploymentMode.assert_called_once_with(
            "Enterprise"
        )
        assert result["result"] == "internal.request.complete"

    def test_set_fault_raises_error(self, paws):
        paws._services["DeploymentModeService"].setDeploymentMode.side_effect = Fault("error")
        with pytest.raises(PAWSError, match="Failed to set deployment mode"):
            paws.set_deployment_mode("HCS")


class TestGetHardwareModel:
    def test_success(self, paws):
        paws._services["HardwareModelService"].getHardwareModel.return_value = {
            "hardwareModel": "VMware Virtual Platform",
            "isVirtualMachine": True,
        }
        result = paws.get_hardware_model()
        assert result["isVirtualMachine"] is True

    def test_fault_raises_error(self, paws):
        paws._services["HardwareModelService"].getHardwareModel.side_effect = Fault("error")
        with pytest.raises(PAWSError, match="Failed to get hardware model"):
            paws.get_hardware_model()


class TestCancelUpgrade:
    def test_success(self, paws):
        paws._services["CancelUpgradeService"].cancelUpgrade.return_value = {
            "result": "internal.request.complete"
        }
        result = paws.cancel_upgrade("session123")
        paws._services["CancelUpgradeService"].cancelUpgrade.assert_called_once_with("session123")
        assert result["result"] == "internal.request.complete"

    def test_fault_raises_error(self, paws):
        paws._services["CancelUpgradeService"].cancelUpgrade.side_effect = Fault("error")
        with pytest.raises(PAWSError, match="Failed to cancel upgrade"):
            paws.cancel_upgrade("session123")


class TestPrepareRemoteUpgrade:
    def test_success(self, paws):
        upgrade_file = {"name": "test.iso", "server": "ftp.example.com"}
        paws._services["PrepareRemoteUpgradeService"].prepareRemoteUpgrade.return_value = {
            "result": "internal.request.complete"
        }
        result = paws.prepare_remote_upgrade(upgrade_file, "sess1")
        paws._services["PrepareRemoteUpgradeService"].prepareRemoteUpgrade.assert_called_once_with(
            upgrade_file, "sess1", False
        )
        assert result["result"] == "internal.request.complete"

    def test_fault_raises_error(self, paws):
        paws._services["PrepareRemoteUpgradeService"].prepareRemoteUpgrade.side_effect = Fault(
            "error"
        )
        with pytest.raises(PAWSError, match="Failed to prepare remote upgrade"):
            paws.prepare_remote_upgrade({}, "sess1")


class TestStartUpgrade:
    def test_success(self, paws):
        paws._services["StartUpgradeService"].startUpgrade.return_value = {
            "result": "internal.request.complete"
        }
        result = paws.start_upgrade("sess1", override_session=True, auto_switch=True)
        paws._services["StartUpgradeService"].startUpgrade.assert_called_once_with(
            "sess1", True, True
        )
        assert result["result"] == "internal.request.complete"

    def test_fault_raises_error(self, paws):
        paws._services["StartUpgradeService"].startUpgrade.side_effect = Fault("error")
        with pytest.raises(PAWSError, match="Failed to start upgrade"):
            paws.start_upgrade("sess1")


class TestGetUpgradeStage:
    def test_success(self, paws):
        paws._services["UpgradeStageService"].getUpgradeStage.return_value = {
            "upgradeStage": "upgrade.stage.none"
        }
        result = paws.get_upgrade_stage()
        assert result["upgradeStage"] == "upgrade.stage.none"

    def test_fault_raises_error(self, paws):
        paws._services["UpgradeStageService"].getUpgradeStage.side_effect = Fault("error")
        with pytest.raises(PAWSError, match="Failed to get upgrade stage"):
            paws.get_upgrade_stage()


class TestGetCurrentUpgradeProgressStage:
    def test_success(self, paws):
        paws._services[
            "UpgradeProgressStageService"
        ].getCurrentUpgradeProgressStage.return_value = {
            "upgradeStage": "upgrade.progress.application.installation"
        }
        result = paws.get_current_upgrade_progress_stage()
        assert result["upgradeStage"] == "upgrade.progress.application.installation"

    def test_fault_raises_error(self, paws):
        paws._services[
            "UpgradeProgressStageService"
        ].getCurrentUpgradeProgressStage.side_effect = Fault("error")
        with pytest.raises(PAWSError, match="Failed to get upgrade progress stage"):
            paws.get_current_upgrade_progress_stage()


class TestGetUpgradeType:
    def test_success(self, paws):
        paws._services["UpgradeTypeService"].getUpgradeType.return_value = {"upgradeType": "L2"}
        result = paws.get_upgrade_type()
        assert result["upgradeType"] == "L2"

    def test_fault_raises_error(self, paws):
        paws._services["UpgradeTypeService"].getUpgradeType.side_effect = Fault("error")
        with pytest.raises(PAWSError, match="Failed to get upgrade type"):
            paws.get_upgrade_type()


class TestIsUpgradeValid:
    def test_success(self, paws):
        paws._services["UpgradeValidService"].isUpgradeValid.return_value = {"upgradeValid": True}
        result = paws.is_upgrade_valid("test.iso")
        paws._services["UpgradeValidService"].isUpgradeValid.assert_called_once_with("test.iso")
        assert result["upgradeValid"] is True

    def test_fault_raises_error(self, paws):
        paws._services["UpgradeValidService"].isUpgradeValid.side_effect = Fault("error")
        with pytest.raises(PAWSError, match="Failed to validate upgrade file"):
            paws.is_upgrade_valid("test.iso")


class TestUpgradeFilter:
    def test_success(self, paws):
        paws._services["UpgradeFilterService"].upgradeFilter.return_value = {
            "upgradeFiles": ["valid.iso"]
        }
        result = paws.upgrade_filter("patch", ["valid.iso", "bad.iso"])
        paws._services["UpgradeFilterService"].upgradeFilter.assert_called_once_with(
            "patch", ["valid.iso", "bad.iso"]
        )
        assert result["upgradeFiles"] == ["valid.iso"]

    def test_fault_raises_error(self, paws):
        paws._services["UpgradeFilterService"].upgradeFilter.side_effect = Fault("error")
        with pytest.raises(PAWSError, match="Failed to filter upgrade files"):
            paws.upgrade_filter("patch", ["test.iso"])


class TestRestartSystem:
    def test_success(self, paws):
        paws._services["RestartSystemService"].restartSystem.return_value = {
            "result": "internal.request.complete"
        }
        result = paws.restart_system()
        assert result["result"] == "internal.request.complete"

    def test_fault_raises_error(self, paws):
        paws._services["RestartSystemService"].restartSystem.side_effect = Fault("error")
        with pytest.raises(PAWSError, match="Failed to restart system"):
            paws.restart_system()


class TestGetRestartSystemStatus:
    def test_success(self, paws):
        paws._services["RestartSystemStatusService"].getRestartSystemStatus.return_value = {
            "restartSystemStatus": "internal.request.complete"
        }
        result = paws.get_restart_system_status()
        assert result["restartSystemStatus"] == "internal.request.complete"

    def test_fault_raises_error(self, paws):
        paws._services["RestartSystemStatusService"].getRestartSystemStatus.side_effect = Fault(
            "error"
        )
        with pytest.raises(PAWSError, match="Failed to get restart system status"):
            paws.get_restart_system_status()


class TestSwitchVersions:
    def test_success(self, paws):
        paws._services["SwitchVersionService"].switchVersions.return_value = {
            "result": "internal.request.complete"
        }
        result = paws.switch_versions()
        assert result["result"] == "internal.request.complete"

    def test_fault_raises_error(self, paws):
        paws._services["SwitchVersionService"].switchVersions.side_effect = Fault("error")
        with pytest.raises(PAWSError, match="Failed to switch versions"):
            paws.switch_versions()


class TestGetSwitchVersionStatus:
    def test_success(self, paws):
        paws._services["SwitchVersionStatusService"].getSwitchVersionStatus.return_value = {
            "switchVersionStatus": "internal.request.complete"
        }
        result = paws.get_switch_version_status()
        assert result["switchVersionStatus"] == "internal.request.complete"

    def test_fault_raises_error(self, paws):
        paws._services["SwitchVersionStatusService"].getSwitchVersionStatus.side_effect = Fault(
            "error"
        )
        with pytest.raises(PAWSError, match="Failed to get switch version status"):
            paws.get_switch_version_status()


class TestLazyInit:
    def test_unknown_service_raises(self):
        with patch.object(PAWSClient, "__init__", lambda self, *a, **kw: None):
            client = PAWSClient.__new__(PAWSClient)
            client._services = {}
        with pytest.raises(ValueError, match="Unknown PAWS service"):
            client._get_paws_service("FakeService")

    def test_caches_service(self):
        with patch.object(PAWSClient, "__init__", lambda self, *a, **kw: None):
            client = PAWSClient.__new__(PAWSClient)
            client._services = {}
        mock_svc = MagicMock()
        client._services["VersionService"] = mock_svc
        assert client._get_paws_service("VersionService") is mock_svc
