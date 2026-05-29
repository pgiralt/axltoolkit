"""
Log Collection and DimeGetFile clients for Cisco UCM.

Provides access to the LogCollection and DimeGetFile SXML APIs for
retrieving log files and traces from the UCM cluster.

Usage::

    from axltoolkit import LogCollectionClient

    client = LogCollectionClient(
        username="admin",
        password="secret",
        server_ip="ucm-pub.example.com",
        tls_verify=True,
    )

    files = client.list_log_files(service_logs=["Cisco CallManager"])
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Union

from zeep.exceptions import Fault

from ._base import BaseClient
from .exceptions import LogCollectionError

logger = logging.getLogger("axltoolkit.log_collection")


class LogCollectionClient(BaseClient):
    """Client for the Cisco UCM Log Collection SXML API.

    Provides methods to list and retrieve log files and traces from the
    UCM cluster.

    Args:
        username: Platform/OS Administration user name.
        password: Password.
        server_ip: UCM server IP address or FQDN.
        tls_verify: TLS verification setting (default ``True``).
        timeout: Request timeout in seconds (default 60, as log operations
            can be slow).
        max_retries: Retry count for transient failures (default 3).
    """

    _WSDL_PATH = (
        "https://{server}:8443/logcollectionservice2/services/LogCollectionPortTypeService?wsdl"
    )

    def __init__(
        self,
        username: str,
        password: str,
        server_ip: str,
        *,
        tls_verify: Union[bool, str] = True,
        timeout: int = 60,
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
            f"https://{server_ip}:8443/logcollectionservice2/services/LogCollectionPortTypeService"
        )
        self._service._binding_options["address"] = endpoint

    @property
    def service(self):
        """Direct access to the underlying zeep service proxy."""
        return self._service

    def list_node_service_logs(self) -> Dict[str, Any]:
        """List available service logs on this node.

        Returns:
            The raw SOAP response dict from ``listNodeServiceLogs``.

        Raises:
            LogCollectionError: If the query fails.
        """
        try:
            return self._service.listNodeServiceLogs(ListRequest="")
        except Fault as fault:
            raise LogCollectionError(
                f"Failed to list node service logs: {fault}",
                original_exception=fault,
            ) from fault

    def select_log_files(
        self,
        file_selection_criteria: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Select log files matching criteria.

        Args:
            file_selection_criteria: A dict describing the log file
                selection criteria.  Refer to UCM Serviceability API
                documentation for the full schema.

        Returns:
            The raw SOAP response dict from ``selectLogFiles``.

        Raises:
            LogCollectionError: If the query fails.
        """
        try:
            return self._service.selectLogFiles(FileSelectionCriteria=file_selection_criteria)
        except Fault as fault:
            raise LogCollectionError(
                f"Failed to select log files: {fault}",
                original_exception=fault,
            ) from fault


class DimeGetFileClient(BaseClient):
    """Client for the Cisco UCM DimeGetFile SXML API.

    Provides direct file retrieval from UCM servers.

    Args:
        username: Platform/OS Administration user name.
        password: Password.
        server_ip: UCM server IP address or FQDN.
        tls_verify: TLS verification setting (default ``True``).
        timeout: Request timeout in seconds (default 120).
        max_retries: Retry count for transient failures (default 3).
    """

    _WSDL_PATH = "https://{server}:8443/logcollectionservice/services/DimeGetFileService?wsdl"

    def __init__(
        self,
        username: str,
        password: str,
        server_ip: str,
        *,
        tls_verify: Union[bool, str] = True,
        timeout: int = 120,
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

    @property
    def service(self):
        """Direct access to the underlying zeep service proxy."""
        return self._service

    def get_one_file(self, file_name: str) -> Dict[str, Any]:
        """Retrieve a single file from the UCM server.

        Args:
            file_name: The full path to the file on the UCM server.

        Returns:
            The raw SOAP response containing the file data.

        Raises:
            LogCollectionError: If the file retrieval fails.
        """
        try:
            return self._service.getOneFile(fileName=file_name)
        except Fault as fault:
            raise LogCollectionError(
                f"Failed to get file '{file_name}': {fault}",
                original_exception=fault,
            ) from fault
