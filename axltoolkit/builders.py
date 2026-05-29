"""
Fluent builders for complex AXL configuration payloads.

Builders produce the nested dict structures required by AXL ``add*``
operations, reducing the chance of typos and structural errors.

Usage::

    from axltoolkit.builders import PhoneBuilder, SipTrunkBuilder

    phone = (
        PhoneBuilder("SEP001122334455", product="Cisco 8845")
        .device_pool("Default")
        .sip_profile("Standard SIP Profile")
        .security_profile("Cisco 8845 - Standard SIP Non-Secure Profile")
        .phone_template("Standard 8845 SIP")
        .common_phone_config("Standard Common Phone Profile")
        .location("Hub_None")
        .add_line(1, "1001", "Internal-PT", display="John Smith")
        .add_line(2, "1002", "Internal-PT")
        .owner("jsmith")
        .build()
    )

    client.add_phone(phone)
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


class PhoneBuilder:
    """Fluent builder for phone device payloads.

    Creates the nested dict structure required by
    :meth:`~axltoolkit.axl.AXLClient.add_phone`.

    Args:
        name: Device name (e.g. ``"SEP001122334455"``).
        product: Phone model (e.g. ``"Cisco 8845"``).
        protocol: ``"SIP"`` or ``"SCCP"`` (default ``"SIP"``).

    Example::

        phone = (
            PhoneBuilder("SEP001122334455", product="Cisco 8845")
            .device_pool("Default")
            .sip_profile("Standard SIP Profile")
            .security_profile("Cisco 8845 - Standard SIP Non-Secure Profile")
            .phone_template("Standard 8845 SIP")
            .add_line(1, "1001", "Internal-PT")
            .build()
        )
    """

    def __init__(
        self,
        name: str,
        *,
        product: str = "Cisco 8845",
        protocol: str = "SIP",
    ):
        self._data: Dict[str, Any] = {
            "name": name,
            "product": product,
            "class": "Phone",
            "protocol": protocol,
            "protocolSide": "User",
            "commonPhoneConfigName": "Standard Common Phone Profile",
            "locationName": "Hub_None",
        }
        self._lines: List[Dict[str, Any]] = []

    def device_pool(self, name: str) -> PhoneBuilder:
        """Set the device pool."""
        self._data["devicePoolName"] = name
        return self

    def calling_search_space(self, name: str) -> PhoneBuilder:
        """Set the calling search space."""
        self._data["callingSearchSpaceName"] = name
        return self

    def common_device_config(self, name: str) -> PhoneBuilder:
        """Set the common device configuration."""
        self._data["commonDeviceConfigName"] = name
        return self

    def common_phone_config(self, name: str) -> PhoneBuilder:
        """Set the common phone configuration profile."""
        self._data["commonPhoneConfigName"] = name
        return self

    def phone_template(self, name: str) -> PhoneBuilder:
        """Set the phone button template."""
        self._data["phoneTemplateName"] = name
        return self

    def location(self, name: str) -> PhoneBuilder:
        """Set the location."""
        self._data["locationName"] = name
        return self

    def security_profile(self, name: str) -> PhoneBuilder:
        """Set the security profile."""
        self._data["securityProfileName"] = name
        return self

    def sip_profile(self, name: str) -> PhoneBuilder:
        """Set the SIP profile."""
        self._data["sipProfileName"] = name
        return self

    def softkey_template(self, name: str) -> PhoneBuilder:
        """Set the softkey template."""
        self._data["softkeyTemplateName"] = name
        return self

    def description(self, desc: str) -> PhoneBuilder:
        """Set the description."""
        self._data["description"] = desc
        return self

    def owner(self, userid: str) -> PhoneBuilder:
        """Set the owner user ID."""
        self._data["ownerUserName"] = userid
        return self

    def user_locale(self, locale: str) -> PhoneBuilder:
        """Set the user locale."""
        self._data["userLocale"] = locale
        return self

    def network_locale(self, locale: str) -> PhoneBuilder:
        """Set the network locale."""
        self._data["networkLocale"] = locale
        return self

    def media_resource_list(self, name: str) -> PhoneBuilder:
        """Set the media resource list."""
        self._data["mediaResourceListName"] = name
        return self

    def load_information(self, firmware: str) -> PhoneBuilder:
        """Set the firmware load information."""
        self._data["loadInformation"] = firmware
        return self

    def set(self, key: str, value: Any) -> PhoneBuilder:
        """Set an arbitrary key-value pair on the phone payload."""
        self._data[key] = value
        return self

    def add_line(
        self,
        index: int,
        pattern: str,
        route_partition_name: str = "",
        *,
        display: str = "",
        display_ascii: str = "",
        label: str = "",
        e164_mask: str = "",
        max_num_calls: int = 4,
        busy_trigger: int = 2,
    ) -> PhoneBuilder:
        """Add a line association.

        Args:
            index: Line button index (1-based).
            pattern: Directory number pattern.
            route_partition_name: Route partition for the DN.
            display: Display name.
            display_ascii: ASCII display name.
            label: Line text label.
            e164_mask: E.164 alternate number mask.
            max_num_calls: Maximum simultaneous calls on this line.
            busy_trigger: Busy trigger threshold.
        """
        line: Dict[str, Any] = {
            "index": index,
            "dirn": {
                "pattern": pattern,
                "routePartitionName": route_partition_name,
            },
            "maxNumCalls": max_num_calls,
            "busyTrigger": busy_trigger,
        }
        if display:
            line["display"] = display
        if display_ascii:
            line["displayAscii"] = display_ascii
        if label:
            line["label"] = label
        if e164_mask:
            line["e164Mask"] = e164_mask
        self._lines.append(line)
        return self

    def build(self) -> Dict[str, Any]:
        """Build and return the phone data dict.

        Returns:
            A dict suitable for passing to
            :meth:`~axltoolkit.axl.AXLClient.add_phone`.

        Raises:
            ValueError: If required fields are missing.
        """
        required = ["name", "product", "devicePoolName"]
        missing = [k for k in required if k not in self._data]
        if missing:
            raise ValueError(f"PhoneBuilder missing required fields: {', '.join(missing)}")

        result = dict(self._data)
        if self._lines:
            result["lines"] = {"line": list(self._lines)}
        return result


class SipTrunkBuilder:
    """Fluent builder for SIP Trunk payloads.

    Creates the nested dict structure required by
    :meth:`~axltoolkit.axl.AXLClient.add_sip_trunk`.

    Args:
        name: Trunk name.

    Example::

        trunk = (
            SipTrunkBuilder("SIP-Trunk-ITSP")
            .device_pool("Default")
            .security_profile("Non Secure SIP Trunk Profile")
            .sip_profile("Standard SIP Profile")
            .add_destination("10.0.0.100", 5060)
            .calling_search_space("CSS-Trunk")
            .build()
        )
    """

    def __init__(self, name: str):
        self._data: Dict[str, Any] = {
            "name": name,
            "product": "SIP Trunk",
            "class": "Trunk",
            "protocol": "SIP",
            "protocolSide": "Network",
            "locationName": "Hub_None",
            "presenceGroupName": "Standard Presence group",
        }
        self._destinations: List[Dict[str, Any]] = []

    def device_pool(self, name: str) -> SipTrunkBuilder:
        """Set the device pool."""
        self._data["devicePoolName"] = name
        return self

    def calling_search_space(self, name: str) -> SipTrunkBuilder:
        """Set the calling search space."""
        self._data["callingSearchSpaceName"] = name
        return self

    def security_profile(self, name: str) -> SipTrunkBuilder:
        """Set the SIP trunk security profile."""
        self._data["securityProfileName"] = name
        return self

    def sip_profile(self, name: str) -> SipTrunkBuilder:
        """Set the SIP profile."""
        self._data["sipProfileName"] = name
        return self

    def description(self, desc: str) -> SipTrunkBuilder:
        """Set the description."""
        self._data["description"] = desc
        return self

    def media_resource_list(self, name: str) -> SipTrunkBuilder:
        """Set the media resource list."""
        self._data["mediaResourceListName"] = name
        return self

    def location(self, name: str) -> SipTrunkBuilder:
        """Set the location."""
        self._data["locationName"] = name
        return self

    def run_on_every_node(self, enabled: bool = True) -> SipTrunkBuilder:
        """Set whether the trunk runs on every node."""
        self._data["runOnEveryNode"] = enabled
        return self

    def trunk_type(self, trunk_type: str) -> SipTrunkBuilder:
        """Set the SIP trunk type (e.g. ``"None(Default)"``).

        Args:
            trunk_type: The trunk type string.
        """
        self._data["sipTrunkType"] = trunk_type
        return self

    def set(self, key: str, value: Any) -> SipTrunkBuilder:
        """Set an arbitrary key-value pair on the trunk payload."""
        self._data[key] = value
        return self

    def add_destination(
        self,
        address: str,
        port: int = 5060,
        *,
        sort_order: Optional[int] = None,
        ipv6: bool = False,
    ) -> SipTrunkBuilder:
        """Add a destination (SIP peer).

        Args:
            address: IP address or hostname of the SIP peer.
            port: SIP port (default 5060).
            sort_order: Route priority order.  If ``None``, auto-assigned
                based on insertion order.
            ipv6: If ``True``, the address is treated as IPv6.
        """
        dest: Dict[str, Any] = {"port": port}
        if ipv6:
            dest["addressIpv6"] = address
        else:
            dest["addressIpv4"] = address

        if sort_order is not None:
            dest["sortOrder"] = sort_order
        else:
            dest["sortOrder"] = len(self._destinations) + 1

        self._destinations.append(dest)
        return self

    def build(self) -> Dict[str, Any]:
        """Build and return the SIP trunk data dict.

        Returns:
            A dict suitable for passing to
            :meth:`~axltoolkit.axl.AXLClient.add_sip_trunk`.

        Raises:
            ValueError: If required fields are missing.
        """
        required = ["name", "devicePoolName", "securityProfileName", "sipProfileName"]
        missing = [k for k in required if k not in self._data]
        if missing:
            raise ValueError(f"SipTrunkBuilder missing required fields: {', '.join(missing)}")

        result = dict(self._data)
        if self._destinations:
            result["destinations"] = {"destination": list(self._destinations)}
        return result


class CssBuilder:
    """Fluent builder for Calling Search Space payloads.

    Example::

        css = (
            CssBuilder("CSS-Internal")
            .description("Internal dialing CSS")
            .add_partition("PT-Internal")
            .add_partition("PT-Local")
            .add_partition("PT-LD")
            .build()
        )
    """

    def __init__(self, name: str):
        self._name = name
        self._description = ""
        self._partitions: List[str] = []

    def description(self, desc: str) -> CssBuilder:
        """Set the CSS description."""
        self._description = desc
        return self

    def add_partition(self, partition_name: str) -> CssBuilder:
        """Append a route partition to the CSS (order matters)."""
        self._partitions.append(partition_name)
        return self

    def build(self) -> Dict[str, Any]:
        """Build and return the CSS data dict.

        Returns:
            A dict with ``name``, ``description``, and ``members`` keys.
        """
        members = [
            {"routePartitionName": p, "index": i} for i, p in enumerate(self._partitions, start=1)
        ]
        return {
            "name": self._name,
            "description": self._description,
            "members": {"member": members},
        }
