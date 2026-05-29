"""
PAWS (Platform Administrative Web Services) client for Cisco UCM.

Provides access to platform-level APIs including hardware details,
software versions, cluster nodes, installed options, deployment mode,
and upgrade/restart/switch-version operations.

Usage::

    from axltoolkit import PAWSClient

    client = PAWSClient(
        username="admin",         # Platform/OS admin credentials
        password="secret",
        server_ip="ucm-pub.example.com",
        tls_verify=True,
    )

    version = client.get_active_version()
    hw_info = client.get_hardware_information()
    nodes = client.get_cluster_nodes()
    model = client.get_hardware_model()
    mode = client.get_deployment_mode()
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Union

from zeep.exceptions import Fault

from ._base import BaseClient
from .exceptions import PAWSError

logger = logging.getLogger("axltoolkit.paws")

# Map of PAWS service names to (binding, endpoint_path) tuples.
# WSDLs are fetched from the server at runtime.
_PAWS_SERVICES = {
    "HardwareInformationService": {
        "binding": "{http://services.api.platform.vos.cisco.com}HardwareInformationServiceSoap12Binding",
        "endpoint": "/platform-services/services/HardwareInformationService.HardwareInformationServiceHttpsSoap12Endpoint/",
        "wsdl_path": "/platform-services/services/HardwareInformationService?wsdl",
    },
    "VersionService": {
        "binding": "{http://services.api.platform.vos.cisco.com}VersionServiceSoap12Binding",
        "endpoint": "/platform-services/services/VersionService.VersionServiceHttpsSoap12Endpoint/",
        "wsdl_path": "/platform-services/services/VersionService?wsdl",
    },
    "OptionsService": {
        "binding": "{http://services.api.platform.vos.cisco.com}OptionsServiceSoap12Binding",
        "endpoint": "/platform-services/services/OptionsService.OptionsServiceHttpsSoap12Endpoint/",
        "wsdl_path": "/platform-services/services/OptionsService?wsdl",
    },
    "ProductService": {
        "binding": "{http://services.api.platform.vos.cisco.com}ProductServiceSoap12Binding",
        "endpoint": "/platform-services/services/ProductService.ProductServiceHttpsSoap12Endpoint/",
        "wsdl_path": "/platform-services/services/ProductService?wsdl",
    },
    "ClusterNodesService": {
        "binding": "{http://services.api.platform.vos.cisco.com}ClusterNodesServiceSoap12Binding",
        "endpoint": "/platform-services/services/ClusterNodesService.ClusterNodesServiceHttpsSoap12Endpoint/",
        "wsdl_path": "/platform-services/services/ClusterNodesService?wsdl",
    },
    "APIVersionService": {
        "binding": "{http://services.api.platform.vos.cisco.com}APIVersionServiceSoap12Binding",
        "endpoint": "/platform-services/services/APIVersionService.APIVersionServiceHttpsSoap12Endpoint/",
        "wsdl_path": "/platform-services/services/APIVersionService?wsdl",
    },
    "CancelUpgradeService": {
        "binding": "{http://services.api.platform.vos.cisco.com}CancelUpgradeServiceSoap12Binding",
        "endpoint": "/platform-services/services/CancelUpgradeService.CancelUpgradeServiceHttpsSoap12Endpoint/",
        "wsdl_path": "/platform-services/services/CancelUpgradeService?wsdl",
    },
    "DeploymentModeService": {
        "binding": "{http://services.api.platform.vos.cisco.com}DeploymentModeServiceSoap12Binding",
        "endpoint": "/platform-services/services/DeploymentModeService.DeploymentModeServiceHttpsSoap12Endpoint/",
        "wsdl_path": "/platform-services/services/DeploymentModeService?wsdl",
    },
    "HardwareModelService": {
        "binding": "{http://services.api.platform.vos.cisco.com}HardwareModelServiceSoap12Binding",
        "endpoint": "/platform-services/services/HardwareModelService.HardwareModelServiceHttpsSoap12Endpoint/",
        "wsdl_path": "/platform-services/services/HardwareModelService?wsdl",
    },
    "PrepareRemoteUpgradeService": {
        "binding": "{http://services.api.platform.vos.cisco.com}PrepareRemoteUpgradeServiceSoap12Binding",
        "endpoint": "/platform-services/services/PrepareRemoteUpgradeService.PrepareRemoteUpgradeServiceHttpsSoap12Endpoint/",
        "wsdl_path": "/platform-services/services/PrepareRemoteUpgradeService?wsdl",
    },
    "RestartSystemService": {
        "binding": "{http://services.api.platform.vos.cisco.com}RestartSystemServiceSoap12Binding",
        "endpoint": "/platform-services/services/RestartSystemService.RestartSystemServiceHttpsSoap12Endpoint/",
        "wsdl_path": "/platform-services/services/RestartSystemService?wsdl",
    },
    "RestartSystemStatusService": {
        "binding": "{http://services.api.platform.vos.cisco.com}RestartSystemStatusServiceSoap12Binding",
        "endpoint": "/platform-services/services/RestartSystemStatusService.RestartSystemStatusServiceHttpsSoap12Endpoint/",
        "wsdl_path": "/platform-services/services/RestartSystemStatusService?wsdl",
    },
    "StartUpgradeService": {
        "binding": "{http://services.api.platform.vos.cisco.com}StartUpgradeServiceSoap12Binding",
        "endpoint": "/platform-services/services/StartUpgradeService.StartUpgradeServiceHttpsSoap12Endpoint/",
        "wsdl_path": "/platform-services/services/StartUpgradeService?wsdl",
    },
    "SwitchVersionService": {
        "binding": "{http://services.api.platform.vos.cisco.com}SwitchVersionServiceSoap12Binding",
        "endpoint": "/platform-services/services/SwitchVersionService.SwitchVersionServiceHttpsSoap12Endpoint/",
        "wsdl_path": "/platform-services/services/SwitchVersionService?wsdl",
    },
    "SwitchVersionStatusService": {
        "binding": "{http://services.api.platform.vos.cisco.com}SwitchVersionStatusServiceSoap12Binding",
        "endpoint": "/platform-services/services/SwitchVersionStatusService.SwitchVersionStatusServiceHttpsSoap12Endpoint/",
        "wsdl_path": "/platform-services/services/SwitchVersionStatusService?wsdl",
    },
    "UpgradeFilterService": {
        "binding": "{http://services.api.platform.vos.cisco.com}UpgradeFilterServiceSoap12Binding",
        "endpoint": "/platform-services/services/UpgradeFilterService.UpgradeFilterServiceHttpsSoap12Endpoint/",
        "wsdl_path": "/platform-services/services/UpgradeFilterService?wsdl",
    },
    "UpgradeProgressStageService": {
        "binding": "{http://services.api.platform.vos.cisco.com}UpgradeProgressStageServiceSoap12Binding",
        "endpoint": "/platform-services/services/UpgradeProgressStageService.UpgradeProgressStageServiceHttpsSoap12Endpoint/",
        "wsdl_path": "/platform-services/services/UpgradeProgressStageService?wsdl",
    },
    "UpgradeStageService": {
        "binding": "{http://services.api.platform.vos.cisco.com}UpgradeStageServiceSoap12Binding",
        "endpoint": "/platform-services/services/UpgradeStageService.UpgradeStageServiceHttpsSoap12Endpoint/",
        "wsdl_path": "/platform-services/services/UpgradeStageService?wsdl",
    },
    "UpgradeTypeService": {
        "binding": "{http://services.api.platform.vos.cisco.com}UpgradeTypeServiceSoap12Binding",
        "endpoint": "/platform-services/services/UpgradeTypeService.UpgradeTypeServiceHttpsSoap12Endpoint/",
        "wsdl_path": "/platform-services/services/UpgradeTypeService?wsdl",
    },
    "UpgradeValidService": {
        "binding": "{http://services.api.platform.vos.cisco.com}UpgradeValidServiceSoap12Binding",
        "endpoint": "/platform-services/services/UpgradeValidService.UpgradeValidServiceHttpsSoap12Endpoint/",
        "wsdl_path": "/platform-services/services/UpgradeValidService?wsdl",
    },
}


class PAWSClient(BaseClient):
    """Client for Cisco UCM Platform Administrative Web Services (PAWS).

    This client provides access to platform-level APIs that return
    information about the hardware, software, cluster topology, and
    installed options on UCM servers.

    Unlike the AXL and SXML APIs which use a single WSDL, PAWS consists
    of multiple independent SOAP services.  This client lazily initializes
    each service on first use, so only the services you call will have
    their WSDLs fetched.

    Args:
        username: Platform/OS Administration user name.
        password: Platform password.
        server_ip: UCM server IP address or FQDN.
        tls_verify: TLS verification setting (default ``True``).
        timeout: Request timeout in seconds (default 30).
        max_retries: Retry count for transient failures (default 3).

    Note:
        PAWS uses **platform credentials** (OS Administration), not AXL
        application user credentials.
    """

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
        self._services: Dict[str, Any] = {}

    def _get_paws_service(self, service_name: str):
        """Lazily initialize and return a PAWS service proxy."""
        if service_name in self._services:
            return self._services[service_name]

        if service_name not in _PAWS_SERVICES:
            raise ValueError(
                f"Unknown PAWS service: {service_name}. "
                f"Available: {', '.join(_PAWS_SERVICES.keys())}"
            )

        config = _PAWS_SERVICES[service_name]

        wsdl = f"https://{self._server_ip}:8443{config['wsdl_path']}"

        endpoint = f"https://{self._server_ip}:8443{config['endpoint']}"

        client = self._create_zeep_client(wsdl)
        service = client.create_service(config["binding"], endpoint)
        self._services[service_name] = service
        return service

    # ── Hardware Information ───────────────────────────────────────────

    def get_hardware_information(self) -> Dict[str, Any]:
        """Retrieve hardware information from the UCM server.

        Returns:
            A dict containing hardware details (CPU, memory, disk, etc.).

        Raises:
            PAWSError: If the query fails.

        Example::

            hw = client.get_hardware_information()
            print(hw)
        """
        svc = self._get_paws_service("HardwareInformationService")
        try:
            return svc.getHardwareInformation()
        except Fault as fault:
            raise PAWSError(
                f"Failed to get hardware information: {fault}",
                original_exception=fault,
            ) from fault

    # ── Version Information ────────────────────────────────────────────

    def get_active_version(self) -> Dict[str, Any]:
        """Retrieve the active software version of the UCM server.

        Returns:
            A dict with version information (activeServerVersion, etc.).

        Raises:
            PAWSError: If the query fails.

        Example::

            version = client.get_active_version()
            print(version)
        """
        svc = self._get_paws_service("VersionService")
        try:
            return svc.getActiveVersion()
        except Fault as fault:
            raise PAWSError(
                f"Failed to get active version: {fault}",
                original_exception=fault,
            ) from fault

    def get_inactive_version(self) -> Dict[str, Any]:
        """Retrieve the inactive software version of the UCM server.

        Returns:
            A dict with inactive version information.

        Raises:
            PAWSError: If the query fails.
        """
        svc = self._get_paws_service("VersionService")
        try:
            return svc.getInactiveVersion()
        except Fault as fault:
            raise PAWSError(
                f"Failed to get inactive version: {fault}",
                original_exception=fault,
            ) from fault

    # ── Options / Installed Products ───────────────────────────────────

    def get_options(self) -> Dict[str, Any]:
        """Retrieve installed options/features on the UCM server.

        Returns:
            A dict with installed option information.

        Raises:
            PAWSError: If the query fails.
        """
        svc = self._get_paws_service("OptionsService")
        try:
            return svc.getActiveOptions()
        except Fault as fault:
            raise PAWSError(
                f"Failed to get options: {fault}",
                original_exception=fault,
            ) from fault

    def get_installed_products(self) -> Dict[str, Any]:
        """Retrieve installed product information.

        Returns:
            A dict with installed product details.

        Raises:
            PAWSError: If the query fails.
        """
        svc = self._get_paws_service("ProductService")
        try:
            return svc.getInstalledProducts()
        except Fault as fault:
            raise PAWSError(
                f"Failed to get installed products: {fault}",
                original_exception=fault,
            ) from fault

    def get_inactive_options(self) -> Dict[str, Any]:
        """Retrieve installed options on the inactive partition.

        Returns:
            A dict with inactive option information.

        Raises:
            PAWSError: If the query fails.
        """
        svc = self._get_paws_service("OptionsService")
        try:
            return svc.getInactiveOptions()
        except Fault as fault:
            raise PAWSError(
                f"Failed to get inactive options: {fault}",
                original_exception=fault,
            ) from fault

    def get_product_name(self) -> Dict[str, Any]:
        """Retrieve the product name of the UCM server.

        Returns:
            A dict with product name information.

        Raises:
            PAWSError: If the query fails.
        """
        svc = self._get_paws_service("ProductService")
        try:
            return svc.getProductName()
        except Fault as fault:
            raise PAWSError(
                f"Failed to get product name: {fault}",
                original_exception=fault,
            ) from fault

    # ── Cluster Nodes ──────────────────────────────────────────────────

    def get_cluster_nodes(self) -> Dict[str, Any]:
        """Retrieve the list of nodes in the UCM cluster.

        Returns:
            A dict with cluster node information.

        Raises:
            PAWSError: If the query fails.

        Example::

            nodes = client.get_cluster_nodes()
            print(nodes)
        """
        svc = self._get_paws_service("ClusterNodesService")
        try:
            return svc.getClusterNodes()
        except Fault as fault:
            raise PAWSError(
                f"Failed to get cluster nodes: {fault}",
                original_exception=fault,
            ) from fault

    def get_my_cluster_node(self) -> Dict[str, Any]:
        """Retrieve information about the cluster node being contacted.

        Returns:
            A dict with the current node's details (IP, hostname, etc.).

        Raises:
            PAWSError: If the query fails.
        """
        svc = self._get_paws_service("ClusterNodesService")
        try:
            return svc.getMyClusterNode()
        except Fault as fault:
            raise PAWSError(
                f"Failed to get my cluster node: {fault}",
                original_exception=fault,
            ) from fault

    # ── API Version ────────────────────────────────────────────────────

    def get_api_version(self) -> Dict[str, Any]:
        """Retrieve the PAWS API version.

        Returns:
            A dict with the API version information.

        Raises:
            PAWSError: If the query fails.
        """
        svc = self._get_paws_service("APIVersionService")
        try:
            return svc.getAPIVersion()
        except Fault as fault:
            raise PAWSError(
                f"Failed to get API version: {fault}",
                original_exception=fault,
            ) from fault

    # ── Deployment Mode ────────────────────────────────────────────────

    def get_deployment_mode(self) -> Dict[str, Any]:
        """Retrieve the deployment mode (Enterprise, HCS, or HCS-LE).

        Returns:
            A dict with the deployment mode and result code.

        Raises:
            PAWSError: If the query fails.
        """
        svc = self._get_paws_service("DeploymentModeService")
        try:
            return svc.getDeploymentMode()
        except Fault as fault:
            raise PAWSError(
                f"Failed to get deployment mode: {fault}",
                original_exception=fault,
            ) from fault

    def set_deployment_mode(self, mode: str) -> Dict[str, Any]:
        """Set the deployment mode.

        Args:
            mode: One of ``'Enterprise'``, ``'HCS'``, or ``'HCS-LE'``.

        Returns:
            A dict with the result code.

        Raises:
            PAWSError: If the operation fails.
        """
        svc = self._get_paws_service("DeploymentModeService")
        try:
            return svc.setDeploymentMode(mode)
        except Fault as fault:
            raise PAWSError(
                f"Failed to set deployment mode: {fault}",
                original_exception=fault,
            ) from fault

    # ── Hardware Model ─────────────────────────────────────────────────

    def get_hardware_model(self) -> Dict[str, Any]:
        """Retrieve the hardware model, serial number, and VM status.

        Returns:
            A dict with hardware model details.

        Raises:
            PAWSError: If the query fails.
        """
        svc = self._get_paws_service("HardwareModelService")
        try:
            return svc.getHardwareModel()
        except Fault as fault:
            raise PAWSError(
                f"Failed to get hardware model: {fault}",
                original_exception=fault,
            ) from fault

    # ── Upgrade Operations ─────────────────────────────────────────────

    def prepare_remote_upgrade(
        self,
        upgrade_file: Dict[str, Any],
        session_id: str,
        override_session: bool = False,
    ) -> Dict[str, Any]:
        """Download and prepare an upgrade or COP file for installation.

        This call should always be made asynchronously.

        Args:
            upgrade_file: A dict with keys ``name``, ``path``, ``password``,
                ``server``, ``upgradeLocation``, ``upgradeType``, ``user``.
            session_id: Unique session ID provided by the client.
            override_session: If ``True``, overrides an existing session.

        Returns:
            A dict with the result, remote messages, and upgrade file info.

        Raises:
            PAWSError: If the operation fails.
        """
        svc = self._get_paws_service("PrepareRemoteUpgradeService")
        try:
            return svc.prepareRemoteUpgrade(
                upgrade_file, session_id, override_session
            )
        except Fault as fault:
            raise PAWSError(
                f"Failed to prepare remote upgrade: {fault}",
                original_exception=fault,
            ) from fault

    def start_upgrade(
        self,
        session_id: str,
        override_session: bool = False,
        auto_switch: bool = False,
    ) -> Dict[str, Any]:
        """Start an upgrade or COP file installation.

        This call should always be made asynchronously.

        Args:
            session_id: Unique session ID provided by the client.
            override_session: If ``True``, overrides an existing session.
            auto_switch: If ``True``, auto-switch to the new version on
                successful upgrade.

        Returns:
            A dict with the result and any remote messages.

        Raises:
            PAWSError: If the operation fails.
        """
        svc = self._get_paws_service("StartUpgradeService")
        try:
            return svc.startUpgrade(session_id, override_session, auto_switch)
        except Fault as fault:
            raise PAWSError(
                f"Failed to start upgrade: {fault}",
                original_exception=fault,
            ) from fault

    def cancel_upgrade(self, session_id: str) -> Dict[str, Any]:
        """Cancel an in-progress upgrade or COP file installation.

        This call should always be made asynchronously.

        Args:
            session_id: The session ID associated with the upgrade.

        Returns:
            A dict with the result and any remote messages.

        Raises:
            PAWSError: If the operation fails.
        """
        svc = self._get_paws_service("CancelUpgradeService")
        try:
            return svc.cancelUpgrade(session_id)
        except Fault as fault:
            raise PAWSError(
                f"Failed to cancel upgrade: {fault}",
                original_exception=fault,
            ) from fault

    def get_upgrade_stage(self) -> Dict[str, Any]:
        """Retrieve the current overall upgrade/COP installation stage.

        Returns:
            A dict with the current upgrade stage (e.g. downloading,
            validating, installing).

        Raises:
            PAWSError: If the query fails.
        """
        svc = self._get_paws_service("UpgradeStageService")
        try:
            return svc.getUpgradeStage()
        except Fault as fault:
            raise PAWSError(
                f"Failed to get upgrade stage: {fault}",
                original_exception=fault,
            ) from fault

    def get_current_upgrade_progress_stage(self) -> Dict[str, Any]:
        """Retrieve detailed progress for an in-progress upgrade.

        Must be called after :meth:`start_upgrade` has been initiated.

        Returns:
            A dict with the detailed upgrade progress stage.

        Raises:
            PAWSError: If the query fails.
        """
        svc = self._get_paws_service("UpgradeProgressStageService")
        try:
            return svc.getCurrentUpgradeProgressStage()
        except Fault as fault:
            raise PAWSError(
                f"Failed to get upgrade progress stage: {fault}",
                original_exception=fault,
            ) from fault

    def get_upgrade_type(self) -> Dict[str, Any]:
        """Retrieve the type of the current upgrade (L2 or RU).

        Can only be called after an upgrade has started.

        Returns:
            A dict with the upgrade type information.

        Raises:
            PAWSError: If the query fails.
        """
        svc = self._get_paws_service("UpgradeTypeService")
        try:
            return svc.getUpgradeType()
        except Fault as fault:
            raise PAWSError(
                f"Failed to get upgrade type: {fault}",
                original_exception=fault,
            ) from fault

    def is_upgrade_valid(self, filename: str) -> Dict[str, Any]:
        """Determine if the specified upgrade file is valid.

        Args:
            filename: The upgrade file name to validate.

        Returns:
            A dict with the result and ``upgradeValid`` boolean.

        Raises:
            PAWSError: If the query fails.
        """
        svc = self._get_paws_service("UpgradeValidService")
        try:
            return svc.isUpgradeValid(filename)
        except Fault as fault:
            raise PAWSError(
                f"Failed to validate upgrade file: {fault}",
                original_exception=fault,
            ) from fault

    def upgrade_filter(
        self, upgrade_type: str, filenames: List[str]
    ) -> Dict[str, Any]:
        """Return a list of valid upgrade files from the provided list.

        Args:
            upgrade_type: The upgrade type (e.g. ``'patch'``).
            filenames: A list of upgrade file names to filter.

        Returns:
            A dict with the result and valid upgrade files.

        Raises:
            PAWSError: If the query fails.
        """
        svc = self._get_paws_service("UpgradeFilterService")
        try:
            return svc.upgradeFilter(upgrade_type, filenames)
        except Fault as fault:
            raise PAWSError(
                f"Failed to filter upgrade files: {fault}",
                original_exception=fault,
            ) from fault

    # ── Restart / Switch Version ───────────────────────────────────────

    def restart_system(self) -> Optional[Dict[str, Any]]:
        """Reboot the system without switching partitions.

        The server may reboot before the SOAP response can be returned,
        so the response may be ``None`` or incomplete.  Use
        :meth:`get_restart_system_status` to check the reboot status.

        Returns:
            A dict with the result and remote messages, or ``None``
            if the server rebooted before responding.

        Raises:
            PAWSError: If the operation fails before reboot initiates.
        """
        svc = self._get_paws_service("RestartSystemService")
        try:
            return svc.restartSystem()
        except Fault as fault:
            raise PAWSError(
                f"Failed to restart system: {fault}",
                original_exception=fault,
            ) from fault

    def get_restart_system_status(self) -> Dict[str, Any]:
        """Retrieve the status of the last restart system call.

        Returns:
            A dict with the result and ``restartSystemStatus``
            (``internal.request.processing`` or
            ``internal.request.complete``).

        Raises:
            PAWSError: If the query fails.
        """
        svc = self._get_paws_service("RestartSystemStatusService")
        try:
            return svc.getRestartSystemStatus()
        except Fault as fault:
            raise PAWSError(
                f"Failed to get restart system status: {fault}",
                original_exception=fault,
            ) from fault

    def switch_versions(self) -> Optional[Dict[str, Any]]:
        """Switch the running software version to the upgrade version.

        The server reboots as part of this operation; the response may
        not be received.  Use :meth:`get_switch_version_status` to
        check the status.

        Returns:
            A dict with the result and remote messages, or ``None``
            if the server rebooted before responding.

        Raises:
            PAWSError: If the operation fails.
        """
        svc = self._get_paws_service("SwitchVersionService")
        try:
            return svc.switchVersions()
        except Fault as fault:
            raise PAWSError(
                f"Failed to switch versions: {fault}",
                original_exception=fault,
            ) from fault

    def get_switch_version_status(self) -> Dict[str, Any]:
        """Retrieve the status of the last switch version call.

        Returns:
            A dict with the result and ``switchVersionStatus``
            (``internal.request.processing`` or
            ``internal.request.complete``).

        Raises:
            PAWSError: If the query fails.
        """
        svc = self._get_paws_service("SwitchVersionStatusService")
        try:
            return svc.getSwitchVersionStatus()
        except Fault as fault:
            raise PAWSError(
                f"Failed to get switch version status: {fault}",
                original_exception=fault,
            ) from fault
