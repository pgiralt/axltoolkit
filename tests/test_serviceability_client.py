"""Tests for ServiceabilityClient with mocked zeep service."""

from unittest.mock import MagicMock, patch

import pytest
from zeep.exceptions import Fault

from axltoolkit.exceptions import ServiceabilityError
from axltoolkit.serviceability import ServiceabilityClient


@pytest.fixture
def svc():
    """Create a ServiceabilityClient with a mocked zeep service."""
    with patch.object(ServiceabilityClient, "__init__", lambda self, *a, **kw: None):
        client = ServiceabilityClient.__new__(ServiceabilityClient)
        client._service = MagicMock()
        client._server_ip = "10.0.0.1"
        client._log = MagicMock()
    return client


class TestGetServiceStatus:
    def test_with_service_names(self, svc):
        svc._service.soapGetServiceStatus.return_value = {
            "ServiceInfoList": [
                {"ServiceName": "Cisco CallManager", "ServiceStatus": "Started"},
            ]
        }
        result = svc.get_service_status(["Cisco CallManager"])
        svc._service.soapGetServiceStatus.assert_called_once_with(
            ServiceStatus=["Cisco CallManager"]
        )
        assert "ServiceInfoList" in result

    def test_without_service_names(self, svc):
        svc._service.soapGetServiceStatus.return_value = {"ServiceInfoList": []}
        result = svc.get_service_status()
        svc._service.soapGetServiceStatus.assert_called_once_with(ServiceStatus="")

    def test_fault_raises_error(self, svc):
        svc._service.soapGetServiceStatus.side_effect = Fault("Service unavailable")
        with pytest.raises(ServiceabilityError, match="Failed to get service status"):
            svc.get_service_status(["Cisco CallManager"])

    def test_fault_preserves_original(self, svc):
        fault = Fault("error")
        svc._service.soapGetServiceStatus.side_effect = fault
        with pytest.raises(ServiceabilityError) as exc_info:
            svc.get_service_status()
        assert exc_info.value.original_exception is fault


class TestServiceDeployment:
    def test_deploy(self, svc):
        svc._service.soapDoServiceDeployment.return_value = {"status": "ok"}
        result = svc.do_service_deployment("Cisco CallManager", "Deploy")
        call_args = svc._service.soapDoServiceDeployment.call_args
        info = call_args[1]["DeploymentInfo"]
        assert info["ServiceName"] == "Cisco CallManager"
        assert info["DeployAction"] == "Deploy"

    def test_undeploy(self, svc):
        svc._service.soapDoServiceDeployment.return_value = {"status": "ok"}
        svc.do_service_deployment("Cisco Tomcat", "UnDeploy")
        call_args = svc._service.soapDoServiceDeployment.call_args
        assert call_args[1]["DeploymentInfo"]["DeployAction"] == "UnDeploy"

    def test_fault_raises_error(self, svc):
        svc._service.soapDoServiceDeployment.side_effect = Fault("Cannot deploy")
        with pytest.raises(ServiceabilityError, match="Failed to deploy service"):
            svc.do_service_deployment("BadService", "Deploy")


class TestServiceControl:
    def test_restart(self, svc):
        svc._service.soapDoControlServices.return_value = {"status": "ok"}
        svc.restart_service("Cisco CallManager")
        call_args = svc._service.soapDoControlServices.call_args
        info = call_args[1]["ControlServiceInfo"]
        assert info["ServiceName"] == "Cisco CallManager"
        assert info["ControlAction"] == "Restart"

    def test_start(self, svc):
        svc._service.soapDoControlServices.return_value = {"status": "ok"}
        svc.start_service("Cisco Tomcat")
        call_args = svc._service.soapDoControlServices.call_args
        assert call_args[1]["ControlServiceInfo"]["ControlAction"] == "Start"

    def test_stop(self, svc):
        svc._service.soapDoControlServices.return_value = {"status": "ok"}
        svc.stop_service("Cisco Tomcat")
        call_args = svc._service.soapDoControlServices.call_args
        assert call_args[1]["ControlServiceInfo"]["ControlAction"] == "Stop"

    def test_restart_fault_raises_error(self, svc):
        svc._service.soapDoControlServices.side_effect = Fault("Restart failed")
        with pytest.raises(ServiceabilityError, match="Failed to restart"):
            svc.restart_service("Cisco CallManager")

    def test_start_fault_raises_error(self, svc):
        svc._service.soapDoControlServices.side_effect = Fault("Start failed")
        with pytest.raises(ServiceabilityError, match="Failed to start"):
            svc.start_service("Cisco CallManager")

    def test_stop_fault_raises_error(self, svc):
        svc._service.soapDoControlServices.side_effect = Fault("Stop failed")
        with pytest.raises(ServiceabilityError, match="Failed to stop"):
            svc.stop_service("Cisco CallManager")


class TestStaticServiceList:
    def test_get_static_service_list(self, svc):
        svc._service.soapGetStaticServiceList.return_value = {
            "ServiceInformationResponse": [
                {"ServiceName": "Cisco CallManager", "IsFeature": True},
                {"ServiceName": "Cisco Tomcat", "IsFeature": False},
            ]
        }
        result = svc.get_static_service_list()
        svc._service.soapGetStaticServiceList.assert_called_once_with(ServiceInformation="")
        assert "ServiceInformationResponse" in result

    def test_get_static_service_list_fault(self, svc):
        svc._service.soapGetStaticServiceList.side_effect = Fault("Service unavailable")
        with pytest.raises(ServiceabilityError, match="Failed to get static service list"):
            svc.get_static_service_list()

    def test_get_static_service_list_fault_preserves_original(self, svc):
        fault = Fault("internal error")
        svc._service.soapGetStaticServiceList.side_effect = fault
        with pytest.raises(ServiceabilityError) as exc_info:
            svc.get_static_service_list()
        assert exc_info.value.original_exception is fault


class TestProductInformationList:
    def test_get_product_information_list(self, svc):
        svc._service.getProductInformationList.return_value = {
            "ProductInformationResponse": [
                {"Name": "Cisco Unified Communications Manager", "Version": "15.0"},
            ]
        }
        result = svc.get_product_information_list()
        svc._service.getProductInformationList.assert_called_once_with(ServiceInfo="")
        assert "ProductInformationResponse" in result

    def test_get_product_information_list_fault(self, svc):
        svc._service.getProductInformationList.side_effect = Fault("Cannot read product info")
        with pytest.raises(ServiceabilityError, match="Failed to get product information list"):
            svc.get_product_information_list()
