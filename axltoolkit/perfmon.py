"""
PerfMon (Performance Monitoring) client for Cisco UCM.

Provides session-based performance counter collection from the UCM cluster.

Usage::

    from axltoolkit import PerfMonClient

    client = PerfMonClient(
        username="axladmin",
        password="secret",
        server_ip="ucm-pub.example.com",
        tls_verify=True,
    )

    # Session-based counter collection
    session = client.open_session()
    client.add_counters(session, [
        r"\\\\cm-pub\\Cisco CallManager\\CallsCompleted",
    ])
    data = client.collect_session_data(session)
    client.close_session(session)

    # One-shot counter listing
    counters = client.list_counters("cm-pub.example.com")
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Sequence, Union

from zeep.exceptions import Fault

from ._base import BaseClient
from .exceptions import PerfMonError

logger = logging.getLogger("axltoolkit.perfmon")

# Regex for parsing perfmon counter name strings:
#   \\host\ObjectName(Instance)\CounterName
_COUNTER_RE = re.compile(r"""\\\\([^\\]*)\\([^()\\]*)(\(([^\\]*)\))?\\([^\\]*)""")


class PerfMonClient(BaseClient):
    """Client for the Cisco UCM PerfMon SXML API.

    The PerfMon service provides performance counter data from UCM servers.
    Counters can be collected in two modes:

    1. **Session-based**: Open a session, add counters, collect data
       periodically, then close the session.
    2. **One-shot**: List available counters or instances.

    Args:
        username: AXL/CCMAdministrator user name.
        password: Password.
        server_ip: UCM publisher IP address or FQDN.
        tls_verify: TLS verification setting (default ``True``).
        timeout: Request timeout in seconds (default 30).
        max_retries: Retry count for transient failures (default 3).
    """

    _WSDL_PATH = "https://{server}:8443/perfmonservice2/services/PerfmonService?wsdl"
    _BINDING = "{http://schemas.cisco.com/ast/soap}PerfmonBinding"
    _ENDPOINT = "https://{server}:8443/perfmonservice2/services/PerfmonService"

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
        """Direct access to the underlying zeep service proxy."""
        return self._service

    # ── Counter Name Parsing ───────────────────────────────────────────

    @staticmethod
    def decode_counter_name(counter_name_string: str) -> Optional[Dict[str, Optional[str]]]:
        """Parse a perfmon counter name string into components.

        Converts a string like
        ``\\\\\\\\host\\\\ObjectName(Instance)\\\\CounterName``
        into a structured dict.

        Args:
            counter_name_string: The raw counter name from PerfMon.

        Returns:
            A dict with ``host``, ``object``, ``instance`` (may be ``None``
            for single-instance objects), and ``counter`` keys.
            Returns ``None`` if the string cannot be parsed.

        Example::

            result = PerfMonClient.decode_counter_name(
                r"\\\\cm-pub\\Cisco CallManager\\CallsCompleted"
            )
            # {'host': 'cm-pub', 'object': 'Cisco CallManager',
            #  'instance': None, 'counter': 'CallsCompleted'}
        """
        match = _COUNTER_RE.match(counter_name_string)
        if match is None:
            return None
        return {
            "host": match.group(1),
            "object": match.group(2),
            "instance": match.group(4),
            "counter": match.group(5),
        }

    # ── Session Management ─────────────────────────────────────────────

    def open_session(self) -> str:
        """Open a new PerfMon collection session.

        Returns:
            A session handle string to use with :meth:`add_counters`,
            :meth:`collect_session_data`, and :meth:`close_session`.

        Raises:
            PerfMonError: If the session cannot be opened.
        """
        try:
            return self._service.perfmonOpenSession()
        except Fault as fault:
            raise PerfMonError(
                f"Failed to open perfmon session: {fault}",
                original_exception=fault,
            ) from fault

    def close_session(self, session_handle: str) -> None:
        """Close a PerfMon collection session.

        Args:
            session_handle: The session handle from :meth:`open_session`.

        Raises:
            PerfMonError: If the session cannot be closed.
        """
        try:
            self._service.perfmonCloseSession(SessionHandle=session_handle)
        except Fault as fault:
            raise PerfMonError(
                f"Failed to close perfmon session: {fault}",
                original_exception=fault,
            ) from fault

    def add_counters(
        self,
        session_handle: str,
        counters: Union[str, Sequence[str]],
    ) -> None:
        """Add counters to a PerfMon session.

        Args:
            session_handle: The session handle from :meth:`open_session`.
            counters: A single counter name string or a list of counter
                name strings.  Each must be in the PerfMon format::

                    \\\\\\\\hostname\\\\ObjectName(Instance)\\\\CounterName

        Raises:
            PerfMonError: If the counters cannot be added.

        Example::

            client.add_counters(session, [
                r"\\\\cm-pub\\Cisco CallManager\\CallsCompleted",
                r"\\\\cm-pub\\Cisco CallManager\\CallsActive",
            ])
        """
        if isinstance(counters, str):
            counters = [counters]

        counter_data = [
            {"Counter": [{"Name": c} for c in counters]}
        ]

        try:
            self._service.perfmonAddCounter(
                SessionHandle=session_handle,
                ArrayOfCounter=counter_data,
            )
        except Fault as fault:
            raise PerfMonError(
                f"Failed to add counters: {fault}",
                original_exception=fault,
            ) from fault

    def remove_counters(
        self,
        session_handle: str,
        counters: Union[str, Sequence[str]],
    ) -> None:
        """Remove counters from a PerfMon session.

        Args:
            session_handle: The session handle from :meth:`open_session`.
            counters: A single counter name string or a list of counter
                name strings to remove.

        Raises:
            PerfMonError: If the counters cannot be removed.
        """
        if isinstance(counters, str):
            counters = [counters]

        counter_data = [
            {"Counter": [{"Name": c} for c in counters]}
        ]

        try:
            self._service.perfmonRemoveCounter(
                SessionHandle=session_handle,
                ArrayOfCounter=counter_data,
            )
        except Fault as fault:
            raise PerfMonError(
                f"Failed to remove counters: {fault}",
                original_exception=fault,
            ) from fault

    def collect_session_data(
        self,
        session_handle: str,
    ) -> Optional[Dict[str, Dict[str, Any]]]:
        """Collect current counter values from a PerfMon session.

        Args:
            session_handle: The session handle from :meth:`open_session`.

        Returns:
            A nested dict structured as::

                {
                    "hostname": {
                        "ObjectName": {
                            "multi_instance": True/False,
                            "counters": {"CounterName": value},  # single-instance
                            "instances": {                        # multi-instance
                                "InstanceName": {"CounterName": value}
                            }
                        }
                    }
                }

            Returns ``None`` if no data is available.

        Raises:
            PerfMonError: If data collection fails.
        """
        try:
            session_data = self._service.perfmonCollectSessionData(
                SessionHandle=session_handle
            )
        except Fault as fault:
            raise PerfMonError(
                f"Failed to collect session data: {fault}",
                original_exception=fault,
            ) from fault

        if not session_data:
            return None

        result_data: Dict[str, Dict[str, Any]] = {}

        for data in session_data:
            counter_info = self.decode_counter_name(data["Name"]["_value_1"])
            if counter_info is None:
                continue

            host = counter_info["host"]
            obj = counter_info["object"]
            instance = counter_info["instance"]
            counter = counter_info["counter"]
            value = data["Value"]
            status = data["CStatus"]

            if status != 0:
                logger.debug(
                    "Skipping counter with non-zero status %d: %s",
                    status, data["Name"]["_value_1"],
                )
                continue

            result_data.setdefault(host, {})
            result_data[host].setdefault(obj, {})

            if instance is None:
                result_data[host][obj]["multi_instance"] = False
                result_data[host][obj].setdefault("counters", {})
                result_data[host][obj]["counters"][counter] = value
            else:
                result_data[host][obj]["multi_instance"] = True
                result_data[host][obj].setdefault("instances", {})
                result_data[host][obj]["instances"].setdefault(instance, {})
                result_data[host][obj]["instances"][instance][counter] = value

        return result_data

    # ── One-shot Queries ───────────────────────────────────────────────

    def list_counters(self, host: str) -> Optional[Dict[str, Dict[str, Any]]]:
        """List all available PerfMon counters on a host.

        Args:
            host: The UCM server hostname or FQDN.

        Returns:
            A dict keyed by object name.  Each value has
            ``multi_instance`` (bool) and ``counters`` (list of counter
            name strings).  Returns ``None`` on failure.

        Raises:
            PerfMonError: If the query fails.

        Example::

            counters = client.list_counters("cm-pub.example.com")
            for obj_name, info in counters.items():
                print(f"{obj_name}: {len(info['counters'])} counters")
        """
        try:
            counter_data = self._service.perfmonListCounter(Host=host)
        except Fault as fault:
            raise PerfMonError(
                f"Failed to list counters on {host}: {fault}",
                original_exception=fault,
            ) from fault

        if not counter_data:
            return None

        counter_list: Dict[str, Dict[str, Any]] = {}
        for obj_data in counter_data:
            obj_name = obj_data["Name"]["_value_1"]
            counter_list[obj_name] = {
                "multi_instance": obj_data["MultiInstance"],
                "counters": [
                    c["Name"]["_value_1"]
                    for c in obj_data["ArrayOfCounter"]["item"]
                ],
            }

        return counter_list

    def list_instances(self, host: str, object_name: str) -> Optional[List[str]]:
        """List instances for a multi-instance PerfMon object.

        Args:
            host: The UCM server hostname or FQDN.
            object_name: The PerfMon object name
                (e.g. ``"Cisco Lines"``, ``"Cisco SIP"``).

        Returns:
            A list of instance name strings, or ``None`` if no instances.

        Raises:
            PerfMonError: If the query fails.

        Example::

            instances = client.list_instances("cm-pub", "Cisco Lines")
            for inst in instances:
                print(inst)
        """
        try:
            instance_data = self._service.perfmonListInstance(
                Host=host, Object=object_name
            )
        except Fault as fault:
            raise PerfMonError(
                f"Failed to list instances for {object_name} on {host}: {fault}",
                original_exception=fault,
            ) from fault

        if not instance_data:
            return None

        return [inst["Name"]["_value_1"] for inst in instance_data]

    def collect_counter_data(
        self,
        host: str,
        object_name: str,
    ) -> Optional[List[Dict[str, Any]]]:
        """Collect counter values for one PerfMon object without a session.

        ``perfmonCollectCounterData`` is the session-less alternative to
        :meth:`collect_session_data`. It returns the current values of
        every counter for a single PerfMon object on a single host.
        Useful for ad-hoc reads when you don't need change tracking or a
        long-lived collection session.

        Args:
            host: The UCM server hostname or FQDN.
            object_name: The PerfMon object name
                (e.g. ``"Cisco CallManager"``, ``"Cisco Lines"``).

        Returns:
            A list of dicts, each with ``name`` (full counter name string),
            ``value`` (numeric value), and ``cstatus`` (counter status,
            ``0`` = ok) keys. Returns ``None`` if no data is available.

        Raises:
            PerfMonError: If the query fails.

        Example::

            counters = client.collect_counter_data("cm-pub", "Cisco CallManager")
            for c in counters:
                print(c["name"], "=", c["value"])
        """
        try:
            counter_data = self._service.perfmonCollectCounterData(
                Host=host, Object=object_name
            )
        except Fault as fault:
            raise PerfMonError(
                f"Failed to collect counter data for {object_name} on {host}: {fault}",
                original_exception=fault,
            ) from fault

        if not counter_data:
            return None

        return [
            {
                "name": entry["Name"]["_value_1"],
                "value": entry["Value"],
                "cstatus": entry["CStatus"],
            }
            for entry in counter_data
        ]
