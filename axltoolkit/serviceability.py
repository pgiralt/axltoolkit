"""
Serviceability (ControlCenter) client for Cisco UCM.

Provides access to the ControlCenter SXML API for managing UCM services.

Usage::

    from axltoolkit import ServiceabilityClient

    client = ServiceabilityClient(
        username="admin",
        password="secret",
        server_ip="ucm-pub.example.com",
        tls_verify=True,
    )

    status = client.get_service_status(["Cisco CallManager"])
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Sequence, Union

from zeep.exceptions import Fault

from ._base import BaseClient
from .exceptions import ServiceabilityError

logger = logging.getLogger("axltoolkit.serviceability")


class ServiceabilityClient(BaseClient):
    """Client for the Cisco UCM ControlCenter (Serviceability) SXML API.

    Provides methods to query and manage UCM services (start, stop, restart,
    query status).

    Args:
        username: Platform/OS Administration user name.
        password: Password.
        server_ip: UCM server IP address or FQDN.
        tls_verify: TLS verification setting (default ``True``).
        timeout: Request timeout in seconds (default 30).
        max_retries: Retry count for transient failures (default 3).
    """

    _WSDL_PATH = (
        "https://{server}:8443/controlcenterservice2/services/"
        "ControlCenterServices?wsdl"
    )

    def __init__(
        self,
        username: str,
        password: str,
        server_ip: str,
        *,
        tls_verify: Union[bool, str] = True,
        timeout: int = 30,
        max_retries: int = 3,
    ):
        super().__init__(
            username=username,
            password=password,
            server_ip=server_ip,
            tls_verify=tls_verify,
            timeout=timeout,
            max_retries=max_retries,
        )

        wsdl = self._WSDL_PATH.format(server=server_ip)
        self._client = self._create_zeep_client(wsdl)
        self._service = self._client.service
        # Override the endpoint — the WSDL may advertise localhost
        endpoint = (
            f"https://{server_ip}:8443/controlcenterservice2/"
            "services/ControlCenterServices"
        )
        self._service._binding_options["address"] = endpoint

    @property
    def service(self):
        """Direct access to the underlying zeep service proxy."""
        return self._service

    def get_service_status(
        self,
        service_names: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        """Get the status of one or more UCM services.

        Args:
            service_names: List of service names to query.  If ``None``,
                queries all services.

        Returns:
            The raw SOAP response dict from ``soapGetServiceStatus``.

        Raises:
            ServiceabilityError: If the query fails.

        Example::

            status = client.get_service_status(["Cisco CallManager"])
        """
        try:
            if service_names:
                return self._service.soapGetServiceStatus(
                    ServiceStatus=service_names
                )
            return self._service.soapGetServiceStatus(ServiceStatus="")
        except Fault as fault:
            raise ServiceabilityError(
                f"Failed to get service status: {fault}",
                original_exception=fault,
            ) from fault

    def do_service_deployment(
        self,
        service_name: str,
        deploy_action: str,
    ) -> Dict[str, Any]:
        """Deploy (activate/deactivate) a UCM service.

        Args:
            service_name: The name of the service to deploy.
            deploy_action: ``"Deploy"`` to activate, ``"UnDeploy"``
                to deactivate.

        Returns:
            The raw SOAP response dict.

        Raises:
            ServiceabilityError: If the deployment fails.
        """
        try:
            return self._service.soapDoServiceDeployment(
                DeploymentInfo={
                    "ServiceName": service_name,
                    "DeployAction": deploy_action,
                }
            )
        except Fault as fault:
            raise ServiceabilityError(
                f"Failed to deploy service '{service_name}': {fault}",
                original_exception=fault,
            ) from fault

    def restart_service(self, service_name: str) -> Dict[str, Any]:
        """Restart a UCM service.

        Args:
            service_name: The name of the service to restart.

        Returns:
            The raw SOAP response dict.

        Raises:
            ServiceabilityError: If the restart fails.
        """
        try:
            return self._service.soapDoControlServices(
                ControlServiceInfo={
                    "ServiceName": service_name,
                    "ControlAction": "Restart",
                }
            )
        except Fault as fault:
            raise ServiceabilityError(
                f"Failed to restart service '{service_name}': {fault}",
                original_exception=fault,
            ) from fault

    def start_service(self, service_name: str) -> Dict[str, Any]:
        """Start a UCM service.

        Args:
            service_name: The name of the service to start.

        Returns:
            The raw SOAP response dict.

        Raises:
            ServiceabilityError: If the start fails.
        """
        try:
            return self._service.soapDoControlServices(
                ControlServiceInfo={
                    "ServiceName": service_name,
                    "ControlAction": "Start",
                }
            )
        except Fault as fault:
            raise ServiceabilityError(
                f"Failed to start service '{service_name}': {fault}",
                original_exception=fault,
            ) from fault

    def stop_service(self, service_name: str) -> Dict[str, Any]:
        """Stop a UCM service.

        Args:
            service_name: The name of the service to stop.

        Returns:
            The raw SOAP response dict.

        Raises:
            ServiceabilityError: If the stop fails.
        """
        try:
            return self._service.soapDoControlServices(
                ControlServiceInfo={
                    "ServiceName": service_name,
                    "ControlAction": "Stop",
                }
            )
        except Fault as fault:
            raise ServiceabilityError(
                f"Failed to stop service '{service_name}': {fault}",
                original_exception=fault,
            ) from fault

    def get_static_service_list(self) -> Dict[str, Any]:
        """Get the static list of services available on the node.

        Returns the catalog of services that can be managed via this
        Serviceability endpoint, including display name and whether each
        service is a feature service or a network service.

        Returns:
            The raw SOAP response dict from ``soapGetStaticServiceList``.
            The service catalog is in the ``ServiceInformationResponse``
            field.

        Raises:
            ServiceabilityError: If the query fails.

        Example::

            catalog = client.get_static_service_list()
            for svc in catalog["ServiceInformationResponse"]:
                print(svc["ServiceName"], svc["IsFeature"])
        """
        try:
            return self._service.soapGetStaticServiceList(ServiceInformation="")
        except Fault as fault:
            raise ServiceabilityError(
                f"Failed to get static service list: {fault}",
                original_exception=fault,
            ) from fault

    def get_product_information_list(self) -> Dict[str, Any]:
        """Get the product information list for the UCM node.

        Returns product metadata for the cluster (version, edition,
        product name, etc.) as reported by the ControlCenter service.

        Returns:
            The raw SOAP response dict from ``getProductInformationList``.

        Raises:
            ServiceabilityError: If the query fails.

        Example::

            info = client.get_product_information_list()
            for product in info["ProductInformationResponse"]:
                print(product["Name"], product["Version"])
        """
        try:
            return self._service.getProductInformationList(ServiceInfo="")
        except Fault as fault:
            raise ServiceabilityError(
                f"Failed to get product information list: {fault}",
                original_exception=fault,
            ) from fault
