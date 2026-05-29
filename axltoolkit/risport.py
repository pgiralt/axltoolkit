"""
RISPort70 (Real-time Information Service) client for Cisco UCM.

Provides access to real-time device registration status, CTI manager
information, and other runtime data from the UCM cluster.

Usage::

    from axltoolkit import RISPortClient

    client = RISPortClient(
        username="axladmin",
        password="secret",
        server_ip="ucm-pub.example.com",
        tls_verify=True,
    )

    devices = client.select_cm_device(device_class="Phone", select_by="Name",
                                       select_items=["SEP*"])
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Sequence, Union

from zeep.helpers import serialize_object

from zeep.exceptions import Fault

from ._base import BaseClient
from .exceptions import RISPortError

logger = logging.getLogger("axltoolkit.risport")


class RISPortClient(BaseClient):
    """Client for the Cisco UCM RISPort70 SXML API.

    The RISPort70 service provides real-time information about registered
    devices, CTI connections, and other runtime state.

    Args:
        username: AXL/CCMAdministrator user name.
        password: Password.
        server_ip: UCM publisher IP address or FQDN.
        tls_verify: TLS verification setting (default ``True``).
        timeout: Request timeout in seconds (default 30).
        max_retries: Retry count for transient failures (default 3).
    """

    _WSDL_PATH = "https://{server}:8443/realtimeservice2/services/RISService70?wsdl"
    _BINDING = "{http://schemas.cisco.com/ast/soap}RisBinding"
    _ENDPOINT = "https://{server}:8443/realtimeservice2/services/RISService70"

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
        self._service = self._client.create_service(
            self._BINDING,
            self._ENDPOINT.format(server=server_ip),
        )

    @property
    def service(self):
        """Direct access to the underlying zeep service proxy.

        Useful for calling RISPort operations that do not yet have a
        dedicated wrapper method.
        """
        return self._service

    # ── Session recovery helpers ──────────────────────────────────────────

    @staticmethod
    def _is_session_error(fault: Fault) -> bool:
        """Return ``True`` if the fault means RIS wants a brand-new session.

        UCM's RISPort70 module enforces a soft idle-timeout on each SOAP
        session. When that timeout expires it returns:

            Error Code = 7
            "Following error needs soap clients to start a new session"

        The fault is recoverable — clients are expected to drop their
        current session credentials (cookies) and reconnect.
        """
        msg = str(fault).lower()
        return (
            "error code = 7" in msg
            or "needs soap clients to start a new session" in msg
        )

    def _reset_session(self) -> None:
        """Clear cached cookies and rebuild the zeep service proxy.

        Drops the cached ``JSESSIONID`` (and any other server-side
        cookies) so UCM allocates a fresh RIS session on the next call,
        then rebinds the zeep service against the same endpoint.
        """
        self._log.debug(
            "Resetting RISPort session (clearing cookies, rebuilding service)"
        )
        self._session.cookies.clear()
        self._service = self._client.create_service(
            self._BINDING,
            self._ENDPOINT.format(server=self._server_ip),
        )

    def _call(self, op_name: str, **kwargs: Any) -> Any:
        """Invoke a RISPort operation with one-shot session recovery.

        On Error Code 7 ("start a new session"), drops the current
        cookie jar, rebuilds the service binding, and retries once.
        Any other :class:`zeep.exceptions.Fault` — and a second Code 7
        on the retry — is wrapped in :class:`RISPortError`.
        """
        op = getattr(self._service, op_name)
        try:
            return op(**kwargs)
        except Fault as fault:
            if not self._is_session_error(fault):
                raise RISPortError(
                    f"{op_name} failed: {fault}",
                    original_exception=fault,
                ) from fault

            self._log.info(
                "RISPort %s returned 'start new session' (Error Code 7); "
                "resetting session and retrying once",
                op_name,
            )
            self._reset_session()
            op = getattr(self._service, op_name)
            try:
                return op(**kwargs)
            except Fault as retry_fault:
                raise RISPortError(
                    f"{op_name} failed after session reset: {retry_fault}",
                    original_exception=retry_fault,
                ) from retry_fault

    def select_cm_device(
        self,
        *,
        device_class: str = "Any",
        select_by: str = "Name",
        max_returned_devices: int = 1000,
        model: int = 255,
        status: str = "Any",
        select_items: Sequence[str] = ("*",),
        state_info: str = "",
    ) -> Dict[str, Any]:
        """Query registered device information from the cluster.

        Args:
            device_class: ``"Any"``, ``"Phone"``, ``"Gateway"``,
                ``"H323"``, ``"Cti"``, ``"VoiceMail"``, ``"MediaResources"``,
                ``"HuntList"``, ``"SIPTrunk"``, or ``"Unknown"``.
            select_by: ``"Name"``, ``"IPV4Address"``, ``"IPV6Address"``,
                ``"DirNumber"``, or ``"Description"``.
            max_returned_devices: Maximum number of devices to return
                (default 1000).
            model: Phone model number (255 = any model).
            status: ``"Any"``, ``"Registered"``, ``"UnRegistered"``,
                ``"Rejected"``, ``"PartiallyRegistered"``, or ``"Unknown"``.
            select_items: List of device name patterns (supports ``*``
                wildcards).  E.g. ``["SEP*"]`` for all SEP phones.
            state_info: State information from a previous query for
                change-tracking.  Empty string for initial query.

        Returns:
            The full ``selectCmDevice`` response as a dict.  Key structure::

                {
                    "SelectCmDeviceResult": {
                        "TotalDevicesFound": 42,
                        "CmNodes": {
                            "item": [
                                {
                                    "Name": "cm-pub.example.com",
                                    "CmDevices": {
                                        "item": [
                                            {
                                                "Name": "SEP001122334455",
                                                "IPAddress": {"item": [{"IP": "10.0.0.5"}]},
                                                "Status": "Registered",
                                                ...
                                            }
                                        ]
                                    }
                                }
                            ]
                        }
                    },
                    "StateInfo": "..."
                }

        Raises:
            RISPortError: If the query fails.

        Example::

            result = client.select_cm_device(
                device_class="Phone",
                select_items=["SEP*"],
                status="Registered",
            )
            for node in result['SelectCmDeviceResult']['CmNodes']['item']:
                for dev in node['CmDevices']['item']:
                    print(dev['Name'], dev.get('IPAddress'))
        """
        selection_criteria = {
            "DeviceClass": device_class,
            "SelectBy": select_by,
            "MaxReturnedDevices": str(max_returned_devices),
            "Model": model,
            "Status": status,
            "SelectItems": [{"item": list(select_items)}],
        }

        return self._call(
            "selectCmDevice",
            StateInfo=state_info,
            CmSelectionCriteria=selection_criteria,
        )

    def select_cm_device_ext(
        self,
        *,
        max_returned_devices: int = 1000,
        device_class: str = "Any",
        select_by: str = "Name",
        status: str = "Any",
        select_items: Sequence[str] = ("*",),
        state_info: str = "",
    ) -> Dict[str, Any]:
        """Query registered device information using the extended selection.

        ``selectCmDeviceExt`` is the extended sibling of
        :meth:`select_cm_device`. It accepts a simpler selection criteria
        structure (no model filter) and returns the same
        ``SelectCmDeviceResult`` payload. Use it when you want a leaner
        request and don't need to filter by model.

        Args:
            max_returned_devices: Maximum number of devices to return
                (default 1000).
            device_class: ``"Any"``, ``"Phone"``, ``"Gateway"``,
                ``"H323"``, ``"Cti"``, ``"VoiceMail"``, ``"MediaResources"``,
                ``"HuntList"``, ``"SIPTrunk"``, or ``"Unknown"``.
            select_by: ``"Name"``, ``"IPV4Address"``, ``"IPV6Address"``,
                ``"DirNumber"``, or ``"Description"``.
            status: ``"Any"``, ``"Registered"``, ``"UnRegistered"``,
                ``"Rejected"``, ``"PartiallyRegistered"``, or ``"Unknown"``.
            select_items: List of device name patterns (supports ``*``
                wildcards). E.g. ``["SEP*"]`` for all SEP phones.
            state_info: State information from a previous query for
                change-tracking. Empty string for initial query.

        Returns:
            The full ``selectCmDeviceExt`` response as a dict, with the
            same shape as :meth:`select_cm_device`.

        Raises:
            RISPortError: If the query fails.

        Example::

            result = client.select_cm_device_ext(
                device_class="Phone",
                select_items=["SEP*"],
                status="Registered",
            )
        """
        selection_criteria = {
            "MaxReturnedDevices": max_returned_devices,
            "DeviceClass": device_class,
            "SelectBy": select_by,
            "Status": status,
            "SelectItems": {"item": [{"Item": s} for s in select_items]},
        }

        return self._call(
            "selectCmDeviceExt",
            StateInfo=state_info,
            CmSelectionCriteria=selection_criteria,
        )

    def select_cti_item(
        self,
        *,
        cti_mgr_class: str = "Device",
        max_returned_items: int = 2000,
        status: str = "Any",
        node_name: str = "",
        select_app_by: str = "AppId",
        app_items: Optional[Sequence[str]] = None,
        device_names: Optional[Sequence[str]] = None,
        dir_numbers: Optional[Sequence[str]] = None,
        state_info: str = "",
    ) -> Dict[str, Any]:
        """Query CTI manager item information from the cluster.

        Args:
            cti_mgr_class: ``"Device"``, ``"Line"``, or ``"Provider"``.
            max_returned_items: Maximum items to return (default 2000).
            status: ``"Any"``, ``"Open"``, ``"Closed"``, or ``"OpenFailed"``.
            node_name: Restrict to a specific UCM node (empty = all nodes).
            select_app_by: ``"AppId"`` or ``"UserId"``.
            app_items: List of application name patterns.
            device_names: List of device name patterns (supports ``*``
                wildcards).
            dir_numbers: List of directory number patterns.
            state_info: State info from a previous query.

        Returns:
            The full ``selectCtiItem`` response as a dict.

        Raises:
            RISPortError: If the query fails.
        """
        selection_criteria: Dict[str, Any] = {
            "CtiMgrClass": cti_mgr_class,
            "MaxReturnedItems": max_returned_items,
            "Status": status,
            "NodeName": node_name,
            "SelectAppBy": select_app_by,
            "AppItems": {"item": []},
            "DevNames": {"item": []},
            "DirNumbers": {"item": []},
        }

        if app_items:
            selection_criteria["AppItems"] = {
                "item": [{"AppItem": a} for a in app_items]
            }
        if device_names:
            selection_criteria["DevNames"] = {
                "item": [{"DevName": d} for d in device_names]
            }
        if dir_numbers:
            selection_criteria["DirNumbers"] = {
                "item": [{"DirNumber": d} for d in dir_numbers]
            }

        return self._call(
            "selectCtiItem",
            StateInfo=state_info,
            CtiSelectionCriteria=selection_criteria,
        )

    def get_registered_phones(
        self,
        name_pattern: str = "SEP*",
        max_devices: int = 1000,
    ) -> List[Dict[str, Any]]:
        """Convenience method: get a flat list of registered phone devices.

        Args:
            name_pattern: Device name pattern (default ``"SEP*"``).
            max_devices: Maximum number of devices to return.

        Returns:
            A list of dicts, each with ``name``, ``ip_address``, ``status``,
            ``model``, and ``node`` keys.

        Raises:
            RISPortError: If the query fails.

        Example::

            for phone in client.get_registered_phones("CSF*"):
                print(f"{phone['name']}: {phone['ip_address']}")
        """
        result = self.select_cm_device(
            device_class="Phone",
            select_items=[name_pattern],
            max_returned_devices=max_devices,
            status="Registered",
        )

        phones: List[Dict[str, Any]] = []
        data = serialize_object(result, dict)
        cm_result = data.get("SelectCmDeviceResult") or {}
        nodes = cm_result.get("CmNodes", {}).get("item", [])

        for node in nodes:
            node_name = node.get("Name", "Unknown")
            devices = node.get("CmDevices", {}).get("item", [])
            for device in devices:
                ip = None
                ip_data = device.get("IPAddress")
                if ip_data and ip_data.get("item"):
                    ip = ip_data["item"][0].get("IP")

                phones.append({
                    "name": device.get("Name"),
                    "ip_address": ip,
                    "status": device.get("Status"),
                    "model": device.get("Model"),
                    "node": node_name,
                })

        return phones
