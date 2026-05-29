"""
Typed models for common AXL configuration objects.

These :class:`~typing.TypedDict` definitions document the most commonly used
fields for key AXL objects and improve IDE autocompletion.  They are *not*
enforced at runtime — AXL responses may include additional fields not listed
here.  Use these types for annotation and documentation.

Usage::

    from axltoolkit.models import PhoneData, LineData, UserData

    phone: PhoneData = {
        "name": "SEP001122334455",
        "product": "Cisco 8845",
        "class": "Phone",
        "protocol": "SIP",
        "protocolSide": "User",
        "devicePoolName": "Default",
    }
"""

from __future__ import annotations

import sys
from typing import Any, Dict, List, Optional, Sequence

if sys.version_info >= (3, 11):
    from typing import NotRequired, TypedDict
else:
    from typing_extensions import NotRequired, TypedDict


# ═══════════════════════════════════════════════════════════════════════
#  Line
# ═══════════════════════════════════════════════════════════════════════


class LineData(TypedDict, total=False):
    """Fields for a directory number (Line) object."""

    pattern: str
    routePartitionName: str
    description: str
    alertingName: str
    asciiAlertingName: str
    voiceMailProfileName: str
    shareLineAppearanceCssName: str
    callForwardAll: Dict[str, Any]
    callForwardBusy: Dict[str, Any]
    callForwardBusyInt: Dict[str, Any]
    callForwardNoAnswer: Dict[str, Any]
    callForwardNoAnswerInt: Dict[str, Any]
    callForwardNoCoverage: Dict[str, Any]
    callForwardNoCoverageInt: Dict[str, Any]
    callForwardOnFailure: Dict[str, Any]
    callForwardNotRegistered: Dict[str, Any]
    callForwardNotRegisteredInt: Dict[str, Any]


class LineAssociation(TypedDict, total=False):
    """Line association data for phone line entries."""

    index: int
    dirn: Dict[str, str]  # {"pattern": "...", "routePartitionName": "..."}
    display: str
    displayAscii: str
    label: str
    e164Mask: str
    maxNumCalls: int
    busyTrigger: int
    associatedEndusers: Dict[str, Any]


# ═══════════════════════════════════════════════════════════════════════
#  Phone
# ═══════════════════════════════════════════════════════════════════════


class PhoneData(TypedDict, total=False):
    """Fields for a Phone device object.

    Required keys for ``add_phone``: ``name``, ``product``, ``class``,
    ``protocol``, ``protocolSide``, ``devicePoolName``.
    """

    name: str
    product: str
    description: str
    # 'class' is a Python keyword so it must be set via dict literal syntax
    protocol: str
    protocolSide: str
    devicePoolName: str
    callingSearchSpaceName: str
    commonDeviceConfigName: str
    commonPhoneConfigName: str
    phoneTemplateName: str
    locationName: str
    mediaResourceListName: str
    networkLocation: str
    ownerUserName: str
    securityProfileName: str
    sipProfileName: str
    softkeyTemplateName: str
    userLocale: str
    networkLocale: str
    loadInformation: str
    lines: Dict[str, List[LineAssociation]]
    # Speed dials, BLFs, services, etc.
    speeddials: Dict[str, Any]
    services: Dict[str, Any]
    busyLampFields: Dict[str, Any]


# ═══════════════════════════════════════════════════════════════════════
#  User
# ═══════════════════════════════════════════════════════════════════════


class UserData(TypedDict, total=False):
    """Fields for an End User object."""

    userid: str
    firstName: str
    lastName: str
    middleName: str
    password: str
    pin: str
    mailid: str
    department: str
    telephoneNumber: str
    homeNumber: str
    mobileNumber: str
    manager: str
    userLocale: str
    associatedDevices: Dict[str, Any]
    associatedGroups: Dict[str, Any]
    primaryExtension: Dict[str, str]
    enableCti: bool
    enableMobility: bool
    enableEmcc: bool
    digestCredentials: str


# ═══════════════════════════════════════════════════════════════════════
#  SIP Trunk
# ═══════════════════════════════════════════════════════════════════════


class SipTrunkDestination(TypedDict, total=False):
    """A single SIP Trunk destination entry."""

    addressIpv4: str
    addressIpv6: str
    port: int
    sortOrder: int


class SipTrunkData(TypedDict, total=False):
    """Fields for a SIP Trunk object.

    Required keys for ``add_sip_trunk``: ``name``, ``product``, ``class``,
    ``protocol``, ``protocolSide``, ``devicePoolName``,
    ``securityProfileName``, ``sipProfileName``.
    """

    name: str
    product: str
    description: str
    # 'class' must be set via dict literal syntax
    protocol: str
    protocolSide: str
    devicePoolName: str
    callingSearchSpaceName: str
    securityProfileName: str
    sipProfileName: str
    destinations: Dict[str, List[SipTrunkDestination]]
    mediaResourceListName: str
    locationName: str
    runOnEveryNode: bool
    sipTrunkType: str
    connectCallBeforePlayingAnnouncement: bool


# ═══════════════════════════════════════════════════════════════════════
#  Route Partition / CSS
# ═══════════════════════════════════════════════════════════════════════


class RoutePartitionData(TypedDict, total=False):
    """Fields for a Route Partition object."""

    name: str
    description: str
    timeScheduleIdName: str
    useOriginatingDeviceTimeZone: bool


class CssMember(TypedDict, total=False):
    """A single CSS member entry."""

    routePartitionName: str
    index: int


class CssData(TypedDict, total=False):
    """Fields for a Calling Search Space object."""

    name: str
    description: str
    members: Dict[str, List[CssMember]]


# ═══════════════════════════════════════════════════════════════════════
#  Route Pattern / Translation Pattern
# ═══════════════════════════════════════════════════════════════════════


class RoutePatternData(TypedDict, total=False):
    """Fields for a Route Pattern object."""

    pattern: str
    routePartitionName: str
    description: str
    blockEnable: bool
    calledPartyTransformationMask: str
    callingPartyTransformationMask: str
    callingSearchSpaceName: str
    destination: Dict[str, str]  # routeListName or gatewayName, etc.
    digitDiscardInstructionName: str
    networkLocation: str
    patternUrgency: bool
    prefixDigitsOut: str
    provideOutsideDialtone: bool
    releaseClause: str
    routeFilterName: str
    useCallingPartyPhoneMask: str


class TranslationPatternData(TypedDict, total=False):
    """Fields for a Translation Pattern object."""

    pattern: str
    routePartitionName: str
    description: str
    calledPartyTransformationMask: str
    callingPartyTransformationMask: str
    callingSearchSpaceName: str
    digitDiscardInstructionName: str
    patternUrgency: bool
    prefixDigitsOut: str
    provideOutsideDialtone: bool
    useCallingPartyPhoneMask: str
    useOriginatorCss: bool


# ═══════════════════════════════════════════════════════════════════════
#  Device Pool
# ═══════════════════════════════════════════════════════════════════════


class DevicePoolData(TypedDict, total=False):
    """Fields for a Device Pool object."""

    name: str
    dateTimeSettingName: str
    callManagerGroupName: str
    mediaResourceListName: str
    regionName: str
    networkLocale: str
    srstName: str
    locationName: str
    callingSearchSpaceName: str
    connectionMonitorDuration: int
    automatedAlternateRoutingCssName: str
    aarNeighborhoodName: str
    reversionCssName: str
    localRouteGroupName: str


# ═══════════════════════════════════════════════════════════════════════
#  Hunt Group
# ═══════════════════════════════════════════════════════════════════════


class HuntPilotData(TypedDict, total=False):
    """Fields for a Hunt Pilot object."""

    pattern: str
    routePartitionName: str
    description: str
    huntListName: str
    callingSearchSpaceName: str
    patternUrgency: bool


class HuntListData(TypedDict, total=False):
    """Fields for a Hunt List object."""

    name: str
    description: str
    callManagerGroupName: str
    routeListEnabled: bool
    voiceMailUsage: bool
    members: Dict[str, Any]


class LineGroupData(TypedDict, total=False):
    """Fields for a Line Group object."""

    name: str
    distributionAlgorithm: str
    rnaReversionTimeOut: int
    huntAlgorithmNoAnswer: str
    huntAlgorithmBusy: str
    huntAlgorithmNotAvailable: str
    members: Dict[str, Any]


# ═══════════════════════════════════════════════════════════════════════
#  Gateway / H.323
# ═══════════════════════════════════════════════════════════════════════


class GatewayData(TypedDict, total=False):
    """Fields for a Gateway object."""

    domainName: str
    description: str
    product: str
    protocol: str
    callingSearchSpaceName: str
    devicePoolName: str
    locationName: str


class H323TrunkData(TypedDict, total=False):
    """Fields for an H.323 Trunk object."""

    name: str
    description: str
    product: str
    protocol: str
    devicePoolName: str
    callingSearchSpaceName: str
    sigDigits: Dict[str, Any]
    significantDigits: int
    runOnEveryNode: bool


# ═══════════════════════════════════════════════════════════════════════
#  Region / Location
# ═══════════════════════════════════════════════════════════════════════


class RegionData(TypedDict, total=False):
    """Fields for a Region object."""

    name: str
    relatedRegions: Dict[str, Any]


class LocationData(TypedDict, total=False):
    """Fields for a Location object."""

    name: str
    withinAudioBandwidth: int
    withinVideoBandwidth: int
    withinImmersiveKbits: int
    betweenLocations: Dict[str, Any]


# ═══════════════════════════════════════════════════════════════════════
#  SQL query/update results
# ═══════════════════════════════════════════════════════════════════════


class SQLQueryResult(TypedDict, total=False):
    """Result from :meth:`AXLClient.sql_query`."""

    num_rows: int
    query: str
    rows: List[Dict[str, Optional[str]]]


class SQLUpdateResult(TypedDict):
    """Result from :meth:`AXLClient.sql_update`."""

    rows_updated: int
    query: str


# ═══════════════════════════════════════════════════════════════════════
#  RISPort models
# ═══════════════════════════════════════════════════════════════════════


class RegisteredPhone(TypedDict, total=False):
    """Single device returned by :meth:`RISPortClient.get_registered_phones`."""

    name: str
    ip_address: Optional[str]
    status: str
    model: int
    node: str
