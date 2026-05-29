"""
Backward-compatible aliases for the legacy axltoolkit class names.

This module provides the old class names (``AxlToolkit``, ``UcmRisPortToolkit``,
etc.) as thin wrappers around the new client classes.  They preserve the old
constructor signatures so existing code continues to work without changes.

.. deprecated:: 2.0.0
    Use :class:`~axltoolkit.AXLClient`, :class:`~axltoolkit.RISPortClient`,
    etc. instead.  These compatibility shims will be removed in a future
    major release.

Migration guide::

    # Old
    from axltoolkit import AxlToolkit
    axl = AxlToolkit(username="admin", password="pw", server_ip="ucm-pub.example.com",
                     version="12.5")
    result = axl.get_user("jsmith")

    # New
    from axltoolkit import AXLClient
    axl = AXLClient(username="admin", password="pw", server_ip="ucm-pub.example.com",
                    version="12.5")
    result = axl.get_user(userid="jsmith")
"""

from __future__ import annotations

import warnings
from typing import Any, Dict, Union

from .axl import AXLClient
from .log_collection import DimeGetFileClient, LogCollectionClient
from .paws_client import PAWSClient
from .perfmon import PerfMonClient
from .risport import RISPortClient
from .serviceability import ServiceabilityClient
from .webdialer import WebdialerClient


def _deprecation_warning(old_name: str, new_name: str) -> None:
    warnings.warn(
        f"{old_name} is deprecated, use {new_name} instead.",
        DeprecationWarning,
        stacklevel=3,
    )


class AxlToolkit(AXLClient):
    """Backward-compatible wrapper for :class:`AXLClient`.

    .. deprecated:: 2.0.0
        Use :class:`AXLClient` instead.
    """

    def __init__(
        self,
        username: str,
        password: str,
        server_ip: str,
        version: str = "12.5",
        tls_verify: Union[bool, str] = True,
        timeout: int = 10,
        logging_enabled: bool = False,
    ):
        _deprecation_warning("AxlToolkit", "AXLClient")
        super().__init__(
            username=username,
            password=password,
            server_ip=server_ip,
            version=version,
            tls_verify=tls_verify,
            timeout=timeout,
        )
        if logging_enabled:
            import logging

            logging.getLogger("axltoolkit").setLevel(logging.DEBUG)
            logging.basicConfig(level=logging.DEBUG)

    # Legacy method aliases that maintain the old signatures

    def get_service(self):
        return self.service

    def run_sql_query(self, query: str) -> Dict[str, Any]:
        return self.sql_query(query)

    def run_sql_update(self, query: str) -> Dict[str, Any]:
        return self.sql_update(query)

    def get_ucm_group(self, name: str):
        return self.get_call_manager_group(name)

    def update_ucm_group_members(self, name: str, members):
        return self.update_call_manager_group_members(name, members)

    def add_ucm_group(self, name: str, members):
        return self.add_call_manager_group(name, members)

    def remove_ucm_group(self, name: str):
        return self.remove_call_manager_group(name)

    def get_user(self, userid: str):
        return super().get_user(userid=userid)

    def list_users(self, **kwargs):
        return super().list_users(**kwargs)

    def update_user(self, user_data: dict):
        return super().update_user(**user_data)

    def get_line(self, dn: str, partition: str):
        return super().get_line(pattern=dn, route_partition_name=partition)

    def add_line(self, line_data: dict):
        return super().add_line(line_data)

    def update_line(self, line_data: dict):
        return super().update_line(**line_data)

    def add_partition(self, name: str, description: str = ""):
        return self.add_route_partition(name, description)

    def add_partitions(self, partition_list):
        return self.add_route_partitions(partition_list)

    def get_partition(self, name: str, returned_tags=None):
        return self.get_route_partition(name, returned_tags)

    def remove_partition(self, name: str):
        return self.remove_route_partition(name)

    def add_css(self, name, description, partition_list):
        return super().add_css(name, description, partition_list)

    def get_css(self, name):
        return super().get_css(name)

    def remove_css(self, name):
        return super().remove_css(name)

    def update_css(self, css_name, description, partition_list):
        return super().update_css(css_name, description, partition_list)

    def add_cfb(self, cfb_data):
        return self.add_conference_bridge(cfb_data)

    def add_cfb_cms(
        self,
        name,
        description,
        cfb_prefix,
        sip_trunk,
        security_icon_control,
        override_dest,
        addresses,
        username,
        password,
        port,
    ):
        return self.add_conference_bridge_cms(
            name,
            description,
            cfb_prefix,
            sip_trunk,
            security_icon_control,
            override_dest,
            addresses,
            username,
            password,
            port,
        )

    def get_cfb(self, name):
        return self.get_conference_bridge(name)

    def remove_cfb(self, name):
        return self.remove_conference_bridge(name)

    def update_cfb(self, **kwargs):
        return self.update_conference_bridge(**kwargs)

    def get_mrg(self, name):
        return self.get_media_resource_group(name)

    def get_mrgl(self, name):
        return self.get_media_resource_list(name)

    def list_phone(self, **kwargs):
        return self.list_phones(**kwargs)

    def add_phone(self, phone_data, line_data=None):
        return super().add_phone(phone_data, line_data)

    def update_phone(self, phone_data, line_data=None):
        return super().update_phone(line_data=line_data, **phone_data)

    def do_reset_restart_device(self, device, is_hard_reset, is_mgcp):
        try:
            return self._service.doDeviceReset(
                deviceName=device, isHardReset=is_hard_reset, isMGCP=is_mgcp
            )
        except Exception:
            return None

    def reset_device(self, device):
        return super().reset_device(device)

    def restart_device(self, device):
        return super().restart_device(device)

    def reset_mgcp(self, device):
        return self.reset_mgcp_device(device)

    def restart_mgcp(self, device):
        return self.restart_mgcp_device(device)

    def sql_update_service_parameter(self, name, value):
        return super().sql_update_service_parameter(name, value)

    def sql_get_service_parameter(self, name):
        return super().sql_get_service_parameter(name)

    def sql_associate_device_to_user(self, device, userid, association_type="1"):
        return super().sql_associate_device_to_user(device, userid, association_type)


class UcmServiceabilityToolkit(ServiceabilityClient):
    """Backward-compatible wrapper for :class:`ServiceabilityClient`.

    .. deprecated:: 2.0.0
    """

    def __init__(self, username, password, server_ip, tls_verify=True):
        _deprecation_warning("UcmServiceabilityToolkit", "ServiceabilityClient")
        super().__init__(
            username=username,
            password=password,
            server_ip=server_ip,
            tls_verify=tls_verify,
        )

    def get_service(self):
        return self.service


class UcmRisPortToolkit(RISPortClient):
    """Backward-compatible wrapper for :class:`RISPortClient`.

    .. deprecated:: 2.0.0
    """

    def __init__(self, username, password, server_ip, tls_verify=True):
        _deprecation_warning("UcmRisPortToolkit", "RISPortClient")
        super().__init__(
            username=username,
            password=password,
            server_ip=server_ip,
            tls_verify=tls_verify,
        )

    def get_service(self):
        return self.service


class UcmPerfMonToolkit(PerfMonClient):
    """Backward-compatible wrapper for :class:`PerfMonClient`.

    .. deprecated:: 2.0.0
    """

    def __init__(self, username, password, server_ip, tls_verify=True):
        _deprecation_warning("UcmPerfMonToolkit", "PerfMonClient")
        super().__init__(
            username=username,
            password=password,
            server_ip=server_ip,
            tls_verify=tls_verify,
        )

    def get_service(self):
        return self.service

    # Legacy method name aliases (camelCase → kept for compatibility)
    def perfmonOpenSession(self):
        return self.open_session()

    def perfmonAddCounter(self, session_handle, counters):
        try:
            self.add_counters(session_handle, counters)
            return True
        except Exception:
            return False

    def perfmonRemoveCounter(self, session_handle, counters):
        try:
            self.remove_counters(session_handle, counters)
            return True
        except Exception:
            return False

    def perfmonCollectSessionData(self, session_handle):
        return self.collect_session_data(session_handle)

    def perfmonCloseSession(self, session_handle):
        try:
            self.close_session(session_handle)
        except Exception:
            pass

    def perfmonListCounter(self, host):
        return self.list_counters(host)

    def perfmonListInstance(self, host, object_name):
        return self.list_instances(host, object_name)


class UcmLogCollectionToolkit(LogCollectionClient):
    """Backward-compatible wrapper for :class:`LogCollectionClient`.

    .. deprecated:: 2.0.0
    """

    def __init__(self, username, password, server_ip, tls_verify=True):
        _deprecation_warning("UcmLogCollectionToolkit", "LogCollectionClient")
        super().__init__(
            username=username,
            password=password,
            server_ip=server_ip,
            tls_verify=tls_verify,
        )

    def get_service(self):
        return self.service


class UcmDimeGetFileToolkit(DimeGetFileClient):
    """Backward-compatible wrapper for :class:`DimeGetFileClient`.

    .. deprecated:: 2.0.0
    """

    def __init__(self, username, password, server_ip, tls_verify=True):
        _deprecation_warning("UcmDimeGetFileToolkit", "DimeGetFileClient")
        super().__init__(
            username=username,
            password=password,
            server_ip=server_ip,
            tls_verify=tls_verify,
        )

    def get_service(self):
        return self.service


class PawsToolkit(PAWSClient):
    """Backward-compatible wrapper for :class:`PAWSClient`.

    .. deprecated:: 2.0.0

    Note: The old constructor accepted a ``service`` string parameter to
    select which PAWS service to connect to.  The new :class:`PAWSClient`
    lazily initializes all services, so this parameter is ignored.
    """

    def __init__(self, username, password, server_ip, service=None, tls_verify=True):
        _deprecation_warning("PawsToolkit", "PAWSClient")
        super().__init__(
            username=username,
            password=password,
            server_ip=server_ip,
            tls_verify=tls_verify,
        )

    def get_service(self):
        # Legacy callers used to pick a service at init time; no direct equiv.
        return None


class WebdialerToolkit(WebdialerClient):
    """Backward-compatible wrapper for :class:`WebdialerClient`.

    .. deprecated:: 2.0.0
    """

    def __init__(self, username, password, server_ip, tls_verify=True, timeout=5):
        _deprecation_warning("WebdialerToolkit", "WebdialerClient")
        super().__init__(
            username=username,
            password=password,
            server_ip=server_ip,
            tls_verify=tls_verify,
            timeout=timeout,
        )

    def get_service(self):
        return self.service
