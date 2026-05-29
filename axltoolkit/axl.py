"""
AXL (Administrative XML) client for Cisco Unified Communications Manager.

Provides both Thick AXL (SOAP-based CRUD operations) and Thin AXL
(direct SQL queries) access to the UCM administration database.

Usage::

    from axltoolkit import AXLClient

    client = AXLClient(
        username="axladmin",
        password="secret",
        server_ip="ucm-pub.example.com",
        version="15.0",
        tls_verify=True,
    )

    # Thick AXL
    user = client.get_user(userid="jsmith")

    # Thin AXL
    result = client.sql_query("SELECT pkid, name FROM device WHERE name LIKE 'SEP%'")
"""

from __future__ import annotations

import logging
import os
import re
import sys
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Sequence, Union

if sys.version_info >= (3, 12):
    from typing import Unpack
else:
    from typing_extensions import Unpack

from zeep import xsd
from zeep.exceptions import Fault

from ._base import BaseClient
from .exceptions import (
    AXLDuplicateError,
    AXLError,
    AXLNotFoundError,
    AXLSQLError,
    AXLSQLInjectionError,
    AXLValidationError,
)

if TYPE_CHECKING:
    from ._generated_models import (
        AarGroup,
        AdvertisedPatterns,
        Announcement,
        AppServerInfo,
        AppUser,
        ApplicationDialRules,
        ApplicationServer,
        ApplicationToSoftKeyTemplate,
        ApplicationUserCapfProfile,
        AudioCodecPreferenceList,
        BillingServer,
        BlockedLearnedPatterns,
        CCAProfiles,
        CallPark,
        CallPickupGroup,
        CalledPartyTracing,
        CallerFilterList,
        CcdAdvertisingService,
        CcdHostedDN,
        CcdHostedDNGroup,
        CcdRequestingService,
        CiscoCatalyst600024PortFXSGateway,
        CiscoCatalyst6000E1VoIPGateway,
        CiscoCatalyst6000T1VoIPGatewayPri,
        CiscoCatalyst6000T1VoIPGatewayT1,
        CmcInfo,
        CommonDeviceConfig,
        CommonPhoneConfig,
        ConferenceBridge,
        ConferenceNow,
        CredentialPolicy,
        Css,
        CtiRoutePoint,
        CumaServerSecurityProfile,
        CustomUserField,
        Customer,
        DateTimeGroup,
        DefaultDeviceProfile,
        DeviceMobility,
        DeviceMobilityGroup,
        DevicePool,
        DeviceProfile,
        DhcpServer,
        DhcpSubnet,
        DirNumberAliasLookupandSync,
        DirectedCallPark,
        DirectoryLookupDialRules,
        ElinGroup,
        EndUserCapfProfile,
        EnterpriseFeatureAccessConfiguration,
        ExpresswayCConfiguration,
        ExternalCallControlProfile,
        FacInfo,
        FallbackProfile,
        FeatureControlPolicy,
        FeatureGroupTemplate,
        Gatekeeper,
        Gateway,
        GatewayEndpointAnalogAccess,
        GatewayEndpointDigitalAccessBri,
        GatewayEndpointDigitalAccessPri,
        GatewayEndpointDigitalAccessT1,
        GatewaySccpEndpoints,
        GatewaySubunits,
        GeoLocation,
        GeoLocationFilter,
        GeoLocationPolicy,
        H323Gateway,
        H323Phone,
        H323Trunk,
        HandoffConfiguration,
        HttpProfile,
        HuntList,
        HuntPilot,
        ImeClient,
        ImeE164Transformation,
        ImeEnrolledPattern,
        ImeEnrolledPatternGroup,
        ImeExclusionNumber,
        ImeExclusionNumberGroup,
        ImeFirewall,
        ImeRouteFilterElement,
        ImeRouteFilterGroup,
        ImeServer,
        ImportedDirectoryUriCatalogs,
        InfrastructureDevice,
        IpPhoneServices,
        IvrUserLocale,
        LbmGroup,
        LbmHubGroup,
        LdapDirectory,
        LdapFilter,
        LdapSyncCustomField,
        Line,
        LineGroup,
        LocalRouteGroup,
        Location,
        MediaResourceGroup,
        MediaResourceList,
        MeetMe,
        MessageWaiting,
        MlppDomain,
        MobileVoiceAccess,
        Mobility,
        MobilityProfile,
        MraServiceDomain,
        Mtp,
        NetworkAccessProfile,
        Phone,
        PhoneActivationCode,
        PhoneButtonTemplate,
        PhoneNtp,
        PhoneSecurityProfile,
        PhysicalLocation,
        PresenceGroup,
        PresenceRedundancyGroup,
        ProcessNode,
        RCommunityString,
        RSNMPUser,
        RecordingProfile,
        Region,
        RemoteCluster,
        RemoteDestination,
        RemoteDestinationProfile,
        ResourcePriorityNamespace,
        ResourcePriorityNamespaceList,
        RouteFilter,
        RouteGroup,
        RouteList,
        RoutePartition,
        RoutePattern,
        SIPNormalizationScript,
        SafCcdPurgeBlockLearnedRoutes,
        SafForwarder,
        SafSecurityProfile,
        SdpTransparencyProfile,
        ServiceProfile,
        SipDialRules,
        SipProfile,
        SipRealm,
        SipTrunk,
        SipRoutePattern,
        SipTrunkSecurityProfile,
        SoftKeyTemplate,
        Srst,
        TimePeriod,
        TimeSchedule,
        TodAccess,
        TransPattern,
        Transcoder,
        TransformationProfile,
        UcService,
        UnitsToGateway,
        UniversalDeviceTemplate,
        UniversalLineTemplate,
        User,
        UserGroup,
        UserPhoneAssociation,
        UserProfileProvision,
        Vg224,
        VmPilot,
        VohServer,
        VoiceMailPilot,
        VoiceMailPort,
        VoiceMailProfile,
        VpnGateway,
        VpnGroup,
        VpnProfile,
        WLANProfile,
        WifiHotspot,
        WirelessAccessPointControllers,
        WlanProfileGroup,
        UpdateAarGroup,
        UpdateAarGroupMatrix,
        UpdateAdvertisedPatterns,
        UpdateAnnouncement,
        UpdateAnnunciator,
        UpdateAppServerInfo,
        UpdateAppUser,
        UpdateApplicationDialRules,
        UpdateApplicationServer,
        UpdateApplicationUserCapfProfile,
        UpdateAudioCodecPreferenceList,
        UpdateBillingServer,
        UpdateBlockedLearnedPatterns,
        UpdateCCAProfiles,
        UpdateCallManager,
        UpdateCallPark,
        UpdateCallPickupGroup,
        UpdateCalledPartyTransformationPattern,
        UpdateCallerFilterList,
        UpdateCallingPartyTransformationPattern,
        UpdateCcdAdvertisingService,
        UpdateCcdFeatureConfig,
        UpdateCcdHostedDN,
        UpdateCcdHostedDNGroup,
        UpdateCcdRequestingService,
        UpdateCiscoCatalyst600024PortFXSGateway,
        UpdateCiscoCatalyst6000E1VoIPGateway,
        UpdateCiscoCatalyst6000T1VoIPGatewayPri,
        UpdateCiscoCatalyst6000T1VoIPGatewayT1,
        UpdateCiscoCloudOnboarding,
        UpdateCmcInfo,
        UpdateCommonDeviceConfig,
        UpdateCommonPhoneConfig,
        UpdateConferenceBridge,
        UpdateConferenceNow,
        UpdateCredentialPolicy,
        UpdateCredentialPolicyDefault,
        UpdateCtiRoutePoint,
        UpdateCumaServerSecurityProfile,
        UpdateCustomUserField,
        UpdateCustomer,
        UpdateDateTimeGroup,
        UpdateDefaultDeviceProfile,
        UpdateDeviceDefaults,
        UpdateDeviceMobility,
        UpdateDeviceMobilityGroup,
        UpdateDevicePool,
        UpdateDeviceProfile,
        UpdateDhcpServer,
        UpdateDhcpSubnet,
        UpdateDirNumberAliasLookupandSync,
        UpdateDirectedCallPark,
        UpdateDirectoryLookupDialRules,
        UpdateElinGroup,
        UpdateEmccFeatureConfig,
        UpdateEndUserCapfProfile,
        UpdateEnterpriseFeatureAccessConfiguration,
        UpdateEnterprisePhoneConfig,
        UpdateExpresswayCConfiguration,
        UpdateExternalCallControlProfile,
        UpdateFacInfo,
        UpdateFallbackFeatureConfig,
        UpdateFallbackProfile,
        UpdateFeatureControlPolicy,
        UpdateFeatureGroupTemplate,
        UpdateFixedMohAudioSource,
        UpdateGatekeeper,
        UpdateGateway,
        UpdateGatewayEndpointAnalogAccess,
        UpdateGatewayEndpointDigitalAccessBri,
        UpdateGatewayEndpointDigitalAccessPri,
        UpdateGatewayEndpointDigitalAccessT1,
        UpdateGatewaySccpEndpoints,
        UpdateGeoLocation,
        UpdateGeoLocationFilter,
        UpdateGeoLocationPolicy,
        UpdateH323Gateway,
        UpdateH323Phone,
        UpdateH323Trunk,
        UpdateHandoffConfiguration,
        UpdateHttpProfile,
        UpdateHuntList,
        UpdateHuntPilot,
        UpdateIlsConfig,
        UpdateImeClient,
        UpdateImeE164Transformation,
        UpdateImeEnrolledPattern,
        UpdateImeEnrolledPatternGroup,
        UpdateImeExclusionNumber,
        UpdateImeExclusionNumberGroup,
        UpdateImeFeatureConfig,
        UpdateImeFirewall,
        UpdateImeLearnedRoutes,
        UpdateImeRouteFilterElement,
        UpdateImeRouteFilterGroup,
        UpdateImeServer,
        UpdateImportedDirectoryUriCatalogs,
        UpdateInfrastructureDevice,
        UpdateInterClusterDirectoryUri,
        UpdateInterClusterServiceProfile,
        UpdateInteractiveVoiceResponse,
        UpdateIpPhoneServices,
        UpdateIvrUserLocale,
        UpdateLbmGroup,
        UpdateLbmHubGroup,
        UpdateLdapDirectory,
        UpdateLdapFilter,
        UpdateLdapSearch,
        UpdateLdapSyncCustomField,
        UpdateLine,
        UpdateLineGroup,
        UpdateLocalRouteGroup,
        UpdateLocation,
        UpdateMediaResourceGroup,
        UpdateMediaResourceList,
        UpdateMeetMe,
        UpdateMessageWaiting,
        UpdateMlppDomain,
        UpdateMobileVoiceAccess,
        UpdateMobility,
        UpdateMobilityProfile,
        UpdateMohAudioSource,
        UpdateMohServer,
        UpdateMraServiceDomain,
        UpdateMtp,
        UpdateNetworkAccessProfile,
        UpdatePageLayoutPreferences,
        UpdatePhone,
        UpdatePhoneButtonTemplate,
        UpdatePhoneNtp,
        UpdatePhoneSecurityProfile,
        UpdatePhysicalLocation,
        UpdatePresenceGroup,
        UpdatePresenceRedundancyGroup,
        UpdateProcessNode,
        UpdateProcessNodeService,
        UpdateRecordingProfile,
        UpdateRegion,
        UpdateRegionMatrix,
        UpdateRemoteCluster,
        UpdateRemoteDestination,
        UpdateRemoteDestinationProfile,
        UpdateResourcePriorityNamespace,
        UpdateResourcePriorityNamespaceList,
        UpdateRouteFilter,
        UpdateRouteList,
        UpdateRoutePartition,
        UpdateRoutePartitionsForLearnedPatterns,
        UpdateRoutePattern,
        UpdateSIPNormalizationScript,
        UpdateSNMPCommunityString,
        UpdateSNMPMIB2List,
        UpdateSNMPUser,
        UpdateSafCcdPurgeBlockLearnedRoutes,
        UpdateSafForwarder,
        UpdateSafSecurityProfile,
        UpdateSdpTransparencyProfile,
        UpdateSecureConfig,
        UpdateSelfProvisioning,
        UpdateServiceParameter,
        UpdateServiceProfile,
        UpdateSipDialRules,
        UpdateSipProfile,
        UpdateSipRealm,
        UpdateSipRoutePattern,
        UpdateSipTrunk,
        UpdateSipTrunkSecurityProfile,
        UpdateSoftKeySet,
        UpdateSoftKeyTemplate,
        UpdateSrst,
        UpdateSyslogConfiguration,
        UpdateTimePeriod,
        UpdateTimeSchedule,
        UpdateTodAccess,
        UpdateTransPattern,
        UpdateTranscoder,
        UpdateTransformationProfile,
        UpdateTvsCertificate,
        UpdateUcService,
        UpdateUniversalDeviceTemplate,
        UpdateUniversalLineTemplate,
        UpdateUser,
        UpdateUserGroup,
        UpdateUserProfileProvision,
        UpdateVg224,
        UpdateVohServer,
        UpdateVoiceMailPilot,
        UpdateVoiceMailPort,
        UpdateVoiceMailProfile,
        UpdateVpnGateway,
        UpdateVpnGroup,
        UpdateVpnProfile,
        UpdateWLANProfile,
        UpdateWifiHotspot,
        UpdateWirelessAccessPointControllers,
        UpdateWlanProfileGroup,
    )

logger = logging.getLogger("axltoolkit.axl")

# AXL error codes
_ERR_NOT_FOUND = 5007
_ERR_DUPLICATE = 11617

# Pattern for detecting obviously malicious SQL fragments
_SQL_INJECTION_PATTERN = re.compile(
    r"(?:--|;|/\*|\*/|xp_|exec\s|execute\s|drop\s+table|alter\s+table|"
    r"insert\s+into\s.*select|union\s+select)",
    re.IGNORECASE,
)

# Supported AXL schema versions
SUPPORTED_VERSIONS = ("10.0", "10.5", "11.0", "11.5", "12.0", "12.5", "14.0", "15.0")

def _sanitize_sql_value(value: str) -> str:
    """Escape single quotes in a SQL value to prevent injection.

    Args:
        value: A raw string value to be embedded in a SQL query.

    Returns:
        The value with single quotes doubled (``'`` → ``''``).

    Raises:
        AXLSQLInjectionError: If the value contains suspicious SQL patterns.
    """
    if _SQL_INJECTION_PATTERN.search(value):
        raise AXLSQLInjectionError(
            f"Potentially dangerous SQL detected in value: {value!r}"
        )
    return value.replace("'", "''")

def _axl_error_from_fault(fault: Fault) -> AXLError:
    """Convert a zeep Fault into the appropriate AXLError subclass."""
    fault_code = getattr(fault, "code", None)

    # Build a rich fault string that includes detail when available
    fault_string = str(fault)
    detail = getattr(fault, "detail", None)
    if detail is not None:
        try:
            if hasattr(detail, "tag"):
                # lxml element tree — serialise for readability
                from lxml import etree
                detail_text = etree.tostring(detail, pretty_print=True).decode()
            elif isinstance(detail, bytes):
                # Zeep may pass the detail as pre-serialised bytes
                # (e.g. when the server returns non-SOAP content like HTML)
                detail_text = detail.decode("utf-8", errors="replace")
            else:
                detail_text = str(detail)
            # Truncate very long details (e.g. full HTML pages)
            if len(detail_text) > 2000:
                detail_text = detail_text[:2000] + "…[truncated]"
            fault_string = f"{fault_string} | Detail: {detail_text}"
        except Exception:
            pass

    # Try to extract the numeric error code from the fault message
    axl_code = None
    match = re.search(r"(\d{4,5})", fault_string)
    if match:
        axl_code = int(match.group(1))

    if axl_code == _ERR_NOT_FOUND or "was not found" in fault_string.lower():
        return AXLNotFoundError(
            fault_string,
            fault_code=fault_code,
            fault_message=fault_string,
            axl_error_code=axl_code,
            original_exception=fault,
        )
    elif axl_code == _ERR_DUPLICATE or "duplicate" in fault_string.lower():
        return AXLDuplicateError(
            fault_string,
            fault_code=fault_code,
            fault_message=fault_string,
            axl_error_code=axl_code,
            original_exception=fault,
        )
    elif "invalid" in fault_string.lower() or "validation" in fault_string.lower():
        return AXLValidationError(
            fault_string,
            fault_code=fault_code,
            fault_message=fault_string,
            axl_error_code=axl_code,
            original_exception=fault,
        )
    else:
        return AXLError(
            fault_string,
            fault_code=fault_code,
            fault_message=fault_string,
            axl_error_code=axl_code,
            original_exception=fault,
        )

class AXLClient(BaseClient):
    """Client for the Cisco UCM AXL SOAP API.

    Wraps both **Thick AXL** (SOAP-based CRUD for configuration objects such
    as phones, users, route partitions, etc.) and **Thin AXL** (direct SQL
    queries and updates against the UCM Informix database).

    Args:
        username: AXL/CCMAdministrator user name.
        password: Password.
        server_ip: UCM publisher IP address or FQDN.
        version: AXL schema version.  Must be one of
            ``"10.0"``, ``"10.5"``, ``"11.0"``, ``"11.5"``,
            ``"12.0"``, ``"12.5"``, ``"14.0"``, ``"15.0"``.
            Defaults to ``"15.0``.
        tls_verify: ``True`` to verify the server certificate, ``False`` to
            skip verification, or a path to a custom CA bundle.
        timeout: Request timeout in seconds (default 30).
        max_retries: Retry count for transient failures (default 3).

    Example::

        client = AXLClient("admin", "password", "ucm-pub.example.com", version="15.0")
        phone = client.get_phone(name="SEP001122334455")
        print(phone['return']['phone']['name'])
    """

    def __init__(
        self,
        username: str,
        password: str,
        server_ip: str,
        *,
        version: str = "15.0",
        tls_verify: Union[bool, str] = True,
        timeout: int = 30,
        max_retries: int = 3,
    ):
        self._cache_key_suffix = f"v{version}"
        super().__init__(
            username=username,
            password=password,
            server_ip=server_ip,
            tls_verify=tls_verify,
            timeout=timeout,
            max_retries=max_retries,
        )

        if version not in SUPPORTED_VERSIONS:
            raise ValueError(
                f"Unsupported AXL version '{version}'. "
                f"Supported versions: {', '.join(SUPPORTED_VERSIONS)}"
            )
        self._version = version

        filedir = os.path.dirname(__file__)
        wsdl_path = os.path.join(filedir, "schema", version, "AXLAPI.wsdl")
        if not os.path.isfile(wsdl_path):
            raise FileNotFoundError(f"WSDL not found for version {version}: {wsdl_path}")

        self._client = self._create_zeep_client(wsdl_path)
        self._service = self._client.create_service(
            "{http://www.cisco.com/AXLAPIService/}AXLAPIBinding",
            f"https://{server_ip}:8443/axl/",
        )

    @property
    def version(self) -> str:
        """The AXL schema version this client is using."""
        return self._version

    @property
    def service(self):
        """Direct access to the underlying zeep service proxy.

        Useful for calling AXL operations that do not yet have a dedicated
        wrapper method::

            result = client.service.addAppUser(appUser={...})
        """
        return self._service

    # ═══════════════════════════════════════════════════════════════════
    #  Thin AXL — SQL Queries and Updates
    # ═══════════════════════════════════════════════════════════════════

    def sql_query(self, query: str) -> Dict[str, Any]:
        """Execute a read-only SQL query via Thin AXL.

        Args:
            query: A SQL SELECT statement to execute against the UCM
                Informix database.

        Returns:
            A dict with keys:

            - ``num_rows`` (int): Number of rows returned.
            - ``query`` (str): The original query string.
            - ``rows`` (list[dict]): List of row dicts (column name → value).
              Only present when ``num_rows > 0``.

        Raises:
            AXLSQLError: If the query fails.

        .. warning::
            This method sends the query string directly to the UCM Informix
            database with **no parameterization or escaping**.  Never build
            queries from untrusted input without sanitizing values first.
            Use :func:`_sanitize_sql_value` or the higher-level ``sql_get_*``
            helpers which sanitize automatically.

        Example::

            result = client.sql_query("SELECT name, description FROM device WHERE name LIKE 'SEP%'")
            for row in result.get('rows', []):
                print(row['name'], row['description'])
        """
        result: Dict[str, Any] = {"num_rows": 0, "query": query}

        try:
            sql_result = self._service.executeSQLQuery(sql=query)
        except Fault as fault:
            raise AXLSQLError(
                f"SQL query failed: {fault}",
                original_exception=fault,
            ) from fault

        rows: List[Dict[str, Optional[str]]] = []
        if sql_result is not None and sql_result["return"] is not None:
            for row in sql_result["return"]["row"]:
                row_dict: Dict[str, Optional[str]] = {}
                for column in row:
                    row_dict[column.tag] = column.text
                rows.append(row_dict)

        result["num_rows"] = len(rows)
        if rows:
            result["rows"] = rows

        return result

    def sql_update(self, query: str) -> Dict[str, Any]:
        """Execute a SQL INSERT, UPDATE, or DELETE via Thin AXL.

        Args:
            query: A SQL DML statement.

        Returns:
            A dict with keys:

            - ``rows_updated`` (int): Number of rows affected.
            - ``query`` (str): The original query string.

        Raises:
            AXLSQLError: If the update fails.

        .. warning::
            This method sends the query string directly to the UCM Informix
            database with **no parameterization or escaping**.  Never build
            queries from untrusted input without sanitizing values first.
            Use :func:`_sanitize_sql_value` or the higher-level ``sql_*``
            helpers which sanitize automatically.

        Example::

            result = client.sql_update(
                "UPDATE device SET description='Test' WHERE name='SEP001122334455'"
            )
            print(f"Updated {result['rows_updated']} rows")
        """
        result: Dict[str, Any] = {"rows_updated": 0, "query": query}

        try:
            sql_result = self._service.executeSQLUpdate(sql=query)
        except Fault as fault:
            raise AXLSQLError(
                f"SQL update failed: {fault}",
                original_exception=fault,
            ) from fault

        if sql_result is not None and sql_result["return"] is not None:
            result["rows_updated"] = sql_result["return"]["rowsUpdated"]

        return result

    # ═══════════════════════════════════════════════════════════════════
    #  Call Manager Group (UCM Group)
    # ═══════════════════════════════════════════════════════════════════

    def get_call_manager_group(self, name: str) -> Dict[str, Any]:
        """Retrieve a Call Manager Group by name.

        Args:
            name: The name of the Call Manager Group.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If the group does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getCallManagerGroup(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_call_manager_group(
        self,
        name: str,
        members: Sequence[str],
    ) -> Dict[str, Any]:
        """Add a new Call Manager Group.

        Args:
            name: Name for the new group.
            members: Ordered list of Call Manager (process node) names.
                The first entry gets priority 1, second gets priority 2, etc.

        Returns:
            The AXL response dict (contains the UUID of the created group).

        Raises:
            AXLDuplicateError: If a group with this name already exists.
            AXLError: On other AXL faults.

        Example::

            client.add_call_manager_group("CMGroup-1", ["cm1pub", "cm1sub1"])
        """
        member_data = [
            {"priority": idx, "callManagerName": m}
            for idx, m in enumerate(members, start=1)
        ]
        try:
            return self._service.addCallManagerGroup(
                callManagerGroup={"name": name, "members": {"member": member_data}}
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_call_manager_group_members(
        self,
        name: str,
        members: Sequence[str],
    ) -> Dict[str, Any]:
        """Update the member list of an existing Call Manager Group.

        Args:
            name: Name of the group to update.
            members: New ordered list of Call Manager names.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the group does not exist.
            AXLError: On other AXL faults.
        """
        member_data = [
            {"priority": idx, "callManagerName": m}
            for idx, m in enumerate(members, start=1)
        ]
        try:
            return self._service.updateCallManagerGroup(
                name=name, members={"member": member_data}
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_call_manager_group(self, name: str) -> Dict[str, Any]:
        """Remove a Call Manager Group by name.

        Args:
            name: The name of the group to remove.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the group does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeCallManagerGroup(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Users
    # ═══════════════════════════════════════════════════════════════════

    def get_user(self, userid: str) -> Dict[str, Any]:
        """Retrieve an end user by user ID.

        Args:
            userid: The UCM user ID (login name).

        Returns:
            The full AXL response dict.  Access user fields via
            ``result['return']['user']``.

        Raises:
            AXLNotFoundError: If the user does not exist.
            AXLError: On other AXL faults.

        Example::

            result = client.get_user("jsmith")
            user = result['return']['user']
            print(f"{user['firstName']} {user['lastName']}")
        """
        try:
            return self._service.getUser(userid=userid)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_users(
        self,
        returned_tags: Optional[Dict[str, str]] = None,
        **search_criteria,
    ) -> Dict[str, Dict[str, Any]]:
        """List end users matching the given search criteria.

        Args:
            returned_tags: Dict of tag names to include in the response.
                Defaults to ``firstName``, ``lastName``, ``userid``.
            **search_criteria: One or more of ``firstName``, ``lastName``,
                ``userid``, ``department``.  Values may contain ``%`` wildcards.
                If no criteria are given, all users are returned.

        Returns:
            A dict keyed by userid, where each value is a dict with the
            requested tag values plus ``uuid``.

        Raises:
            AXLError: On AXL faults.

        Example::

            users = client.list_users(lastName="Smith%")
            for uid, data in users.items():
                print(uid, data['firstName'], data['lastName'])
        """
        allowed = {"firstName", "lastName", "userid", "department"}
        criteria = {k: v for k, v in search_criteria.items() if k in allowed}
        if not criteria:
            criteria = {"userid": "%"}

        if returned_tags is None:
            returned_tags = {"firstName": "", "lastName": "", "userid": ""}

        try:
            result = self._service.listUser(
                searchCriteria=criteria, returnedTags=returned_tags
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

        users: Dict[str, Dict[str, Any]] = {}
        if result["return"] is not None:
            for user in result["return"]["user"]:
                uid = user["userid"]
                users[uid] = {"uuid": user["uuid"]}
                for tag in returned_tags:
                    if tag in user:
                        users[uid][tag] = user[tag]

        return users

    def update_user(self, **user_data: Unpack[UpdateUser]) -> Dict[str, Any]:
        """Update an existing end user.

        Args:
            **user_data: Keyword arguments corresponding to the AXL
                ``updateUser`` operation fields.  Must include at least
                ``userid`` or ``uuid`` to identify the user.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the user does not exist.
            AXLError: On other AXL faults.

        Example::

            client.update_user(userid="jsmith", firstName="Jonathan")
        """
        try:
            return self._service.updateUser(**user_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Registration Dynamic
    # ═══════════════════════════════════════════════════════════════════

    def get_registration_dynamic(self, device: str) -> Dict[str, Any]:
        """Retrieve dynamic registration data for a specific device.

        Args:
            device: The device name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the device is not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getRegistrationDynamic(device=device)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_registration_dynamic(
        self,
        **search_criteria,
    ) -> Dict[str, Dict[str, Any]]:
        """List dynamic registration records matching search criteria.

        Args:
            **search_criteria: One or more of ``device``,
                ``lastKnownIpAddress``, ``lastKnownUcm``,
                ``lastKnownConfigVersion``, ``locationDetails``,
                ``endpointConnection``, ``portOrSsid``, ``lastSeen``.
                Values may contain ``%`` wildcards.
                If none given, returns all registrations.

        Returns:
            A dict keyed by device name, each value containing
            registration details.

        Raises:
            AXLError: On AXL faults.
        """
        allowed = {
            "device", "lastKnownIpAddress", "lastKnownUcm",
            "lastKnownConfigVersion", "locationDetails",
            "endpointConnection", "portOrSsid", "lastSeen",
        }
        criteria = {k: v for k, v in search_criteria.items() if k in allowed}
        if not criteria:
            criteria = {"device": "%"}

        returned_tags = {
            "device": "", "lastKnownIpAddress": "", "lastKnownUcm": "",
            "lastKnownConfigVersion": "", "locationDetails": "",
            "endpointConnection": "", "portOrSsid": "", "lastSeen": "",
        }

        try:
            result = self._service.listRegistrationDynamic(
                searchCriteria=criteria, returnedTags=returned_tags
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

        registrations: Dict[str, Dict[str, Any]] = {}
        if result["return"] is not None:
            for reg in result["return"]["registrationDynamic"]:
                device_name = reg["device"]["_value_1"]
                device_uuid = reg["device"]["uuid"]
                registrations[device_name] = {
                    "device": device_name,
                    "device_uuid": device_uuid,
                    "lastKnownIpAddress": reg["lastKnownIpAddress"],
                    "lastKnownUcm": reg["lastKnownUcm"],
                    "lastKnownConfigVersion": reg["lastKnownConfigVersion"],
                    "locationDetails": reg["locationDetails"],
                    "endpointConnection": reg["endpointConnection"],
                    "portOrSsid": reg["portOrSsid"],
                    "lastSeen": reg["lastSeen"],
                    "uuid": reg["uuid"],
                }

        return registrations

    # ═══════════════════════════════════════════════════════════════════
    #  Lines
    # ═══════════════════════════════════════════════════════════════════

    def get_line(self, pattern: str, route_partition_name: str) -> Dict[str, Any]:
        """Retrieve a directory number (line) by pattern and partition.

        Args:
            pattern: The directory number pattern (e.g. ``"1001"``).
            route_partition_name: The partition the DN belongs to.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If the line does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getLine(
                pattern=pattern, routePartitionName=route_partition_name
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_line(self, line_data: Line) -> Dict[str, Any]:
        """Add a new directory number (line).

        Args:
            line_data: A dict describing the line.  Required keys:
                ``pattern``, ``routePartitionName``, and ``usage``
                (``"Device"`` or ``"Template"``).

                Example::

                    {
                        "pattern": "1001",
                        "routePartitionName": "Internal-PT",
                        "usage": "Device",
                        "description": "John Smith - 1001",
                        "alertingName": "John Smith",
                        "shareLineAppearanceCssName": "",
                    }

        Returns:
            The AXL response dict (contains the UUID of the created line).

        Raises:
            AXLDuplicateError: If the line already exists.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.addLine(line=line_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_line(self, **line_data: Unpack[UpdateLine]) -> Dict[str, Any]:
        """Update an existing directory number (line).

        Args:
            **line_data: Keyword arguments for the ``updateLine`` operation.
                Must include ``pattern`` + ``routePartitionName`` **or**
                ``uuid`` to identify the line.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the line does not exist.
            AXLError: On other AXL faults.

        Example::

            client.update_line(
                pattern="1001",
                routePartitionName="Internal-PT",
                description="Updated Description",
            )
        """
        try:
            return self._service.updateLine(**line_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_line(self, pattern: str, route_partition_name: str) -> Dict[str, Any]:
        """Remove a directory number (line).

        Args:
            pattern: The directory number pattern.
            route_partition_name: The partition the DN belongs to.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the line does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeLine(
                pattern=pattern, routePartitionName=route_partition_name
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Phones
    # ═══════════════════════════════════════════════════════════════════

    def get_phone(self, name: str) -> Dict[str, Any]:
        """Retrieve a phone device by name.

        Args:
            name: The device name (e.g. ``"SEP001122334455"``).

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If the phone does not exist.
            AXLError: On other AXL faults.

        Example::

            result = client.get_phone("SEP001122334455")
            phone = result['return']['phone']
            print(phone['model'], phone['devicePoolName'])
        """
        try:
            return self._service.getPhone(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_phone(
        self,
        phone_data: Phone,
        line_data: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Add a new phone device.

        Args:
            phone_data: A dict describing the phone.  Required keys include
                ``name``, ``product``, ``class`` (``"Phone"``), ``protocol``,
                ``protocolSide`` (``"User"``), ``devicePoolName``,
                ``commonPhoneConfigName``, and ``phoneTemplateName``.

                Minimal example::

                    {
                        "name": "SEP001122334455",
                        "product": "Cisco 8845",
                        "class": "Phone",
                        "protocol": "SIP",
                        "protocolSide": "User",
                        "devicePoolName": "Default",
                        "commonPhoneConfigName": "Standard Common Phone Profile",
                        "phoneTemplateName": "Standard 8845 SIP",
                        "locationName": "Hub_None",
                        "securityProfileName": "Cisco 8845 - Standard SIP Non-Secure Profile",
                        "sipProfileName": "Standard SIP Profile",
                    }

            line_data: Optional list of line association dicts.  Each entry
                should specify at least ``dirn`` (with ``pattern`` and
                ``routePartitionName``) and ``index``::

                    [
                        {
                            "index": 1,
                            "dirn": {
                                "pattern": "1001",
                                "routePartitionName": "Internal-PT",
                            },
                            "display": "John Smith",
                            "displayAscii": "John Smith",
                        }
                    ]

        Returns:
            The AXL response dict (contains the UUID of the created phone).

        Raises:
            AXLDuplicateError: If a phone with this name already exists.
            AXLValidationError: If required fields are missing.
            AXLError: On other AXL faults.
        """
        if line_data is not None:
            phone_data["lines"] = {"line": line_data}

        try:
            return self._service.addPhone(phone=phone_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_phone(
        self,
        line_data: Optional[List[Dict[str, Any]]] = None,
        **phone_data: Unpack[UpdatePhone],
    ) -> Dict[str, Any]:
        """Update an existing phone device.

        Args:
            line_data: Optional new line associations (replaces existing).
            **phone_data: Keyword arguments for the ``updatePhone`` operation.
                Must include ``name`` or ``uuid`` to identify the phone.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the phone does not exist.
            AXLError: On other AXL faults.

        Example::

            client.update_phone(
                name="SEP001122334455",
                description="Updated Phone",
            )
        """
        if line_data is not None:
            phone_data["lines"] = {"line": line_data}

        try:
            return self._service.updatePhone(**phone_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_phone(self, name: str) -> Dict[str, Any]:
        """Remove a phone device by name.

        Args:
            name: The device name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the phone does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removePhone(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_phones(
        self,
        returned_tags: Optional[Dict[str, str]] = None,
        **search_criteria,
    ) -> Dict[str, Dict[str, Any]]:
        """List phones matching the given search criteria.

        Args:
            returned_tags: Dict of tags to include in the response.
                Defaults to ``name``, ``description``, ``devicePoolName``.
            **search_criteria: One or more of ``name``, ``description``,
                ``protocol``, ``callingSearchSpaceName``,
                ``devicePoolName``, ``securityProfileName``.
                Values may contain ``%`` wildcards.

        Returns:
            A dict keyed by device name.

        Raises:
            AXLError: On AXL faults.

        Example::

            phones = client.list_phones(name="SEP%")
            for name, info in phones.items():
                print(name, info['description'])
        """
        allowed = {
            "name", "description", "protocol", "callingSearchSpaceName",
            "devicePoolName", "securityProfileName",
        }
        criteria = {k: v for k, v in search_criteria.items() if k in allowed}
        if not criteria:
            criteria = {"name": "%"}

        if returned_tags is None:
            returned_tags = {"name": "", "description": "", "devicePoolName": ""}

        try:
            result = self._service.listPhone(
                searchCriteria=criteria, returnedTags=returned_tags
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

        phones: Dict[str, Dict[str, Any]] = {}
        if result["return"] is not None:
            for phone in result["return"]["phone"]:
                pname = phone["name"]
                phones[pname] = {"uuid": phone["uuid"]}
                for tag in returned_tags:
                    if tag in phone:
                        phones[pname][tag] = phone[tag]

        return phones

    # ═══════════════════════════════════════════════════════════════════
    #  Route Partitions
    # ═══════════════════════════════════════════════════════════════════

    def get_route_partition(
        self,
        name: str,
        returned_tags: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Retrieve a route partition by name.

        Args:
            name: The partition name.
            returned_tags: Optional dict of tags to return.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If the partition does not exist.
            AXLError: On other AXL faults.
        """
        try:
            if returned_tags is not None:
                return self._service.getRoutePartition(
                    name=name, returnedTags=returned_tags
                )
            return self._service.getRoutePartition(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_route_partition(
        self,
        name: str,
        description: str = "",
    ) -> Dict[str, Any]:
        """Add a new route partition.

        Args:
            name: Name for the partition.
            description: Optional description.

        Returns:
            The AXL response dict.

        Raises:
            AXLDuplicateError: If a partition with this name already exists.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.addRoutePartition(
                routePartition={"name": name, "description": description}
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_route_partitions(
        self,
        partitions: Sequence[Union[str, Dict[str, str]]],
    ) -> List[Dict[str, Any]]:
        """Add multiple route partitions in sequence.

        Args:
            partitions: A list where each element is either a partition name
                (str) or a dict with ``name`` and ``description`` keys.

        Returns:
            A list of AXL response dicts, one per partition.  Failed
            entries will have a ``fault`` key with the exception.

        Example::

            results = client.add_route_partitions([
                "Internal-PT",
                {"name": "PSTN-PT", "description": "PSTN Partition"},
            ])
        """
        results = []
        for partition in partitions:
            if isinstance(partition, str):
                partition = {"name": partition, "description": ""}
            try:
                results.append(
                    self._service.addRoutePartition(routePartition=partition)
                )
            except Fault as fault:
                results.append({"fault": _axl_error_from_fault(fault)})
        return results

    def remove_route_partition(self, name: str) -> Dict[str, Any]:
        """Remove a route partition by name.

        Args:
            name: The partition name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the partition does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeRoutePartition(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Calling Search Spaces
    # ═══════════════════════════════════════════════════════════════════

    def get_css(self, name: str) -> Dict[str, Any]:
        """Retrieve a Calling Search Space by name.

        Args:
            name: The CSS name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If the CSS does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getCss(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_css(
        self,
        name: str,
        description: str,
        partitions: Sequence[str],
    ) -> Dict[str, Any]:
        """Add a new Calling Search Space.

        Args:
            name: Name for the CSS.
            description: Description of the CSS.
            partitions: Ordered list of route partition names to include.

        Returns:
            The AXL response dict.

        Raises:
            AXLDuplicateError: If a CSS with this name already exists.
            AXLError: On other AXL faults.

        Example::

            client.add_css(
                "Internal-CSS",
                "Internal dialing",
                ["Internal-PT", "Emergency-PT"],
            )
        """
        members = [
            {"routePartitionName": pt, "index": idx}
            for idx, pt in enumerate(partitions, start=1)
        ]
        try:
            return self._service.addCss(
                css={
                    "name": name,
                    "description": description,
                    "members": {"member": members},
                }
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_css(
        self,
        name: str,
        description: Optional[str] = None,
        partitions: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        """Update an existing Calling Search Space.

        Args:
            name: The CSS name to update.
            description: New description (if provided).
            partitions: New ordered list of partition names (if provided).

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the CSS does not exist.
            AXLError: On other AXL faults.
        """
        kwargs: Dict[str, Any] = {"name": name}
        if description is not None:
            kwargs["description"] = description
        if partitions is not None:
            kwargs["members"] = {
                "member": [
                    {"routePartitionName": pt, "index": idx}
                    for idx, pt in enumerate(partitions, start=1)
                ]
            }
        try:
            return self._service.updateCss(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_css(self, name: str) -> Dict[str, Any]:
        """Remove a Calling Search Space by name.

        Args:
            name: The CSS name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the CSS does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeCss(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Route Groups
    # ═══════════════════════════════════════════════════════════════════

    def get_route_group(self, name: str) -> Dict[str, Any]:
        """Retrieve a Route Group by name.

        Args:
            name: The Route Group name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If the route group does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getRouteGroup(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_route_group(
        self,
        name: str,
        distribution_algorithm: str,
        devices: Sequence[str],
    ) -> Dict[str, Any]:
        """Add a new Route Group.

        Args:
            name: Name for the Route Group.
            distribution_algorithm: Distribution algorithm
                (``"Top Down"``, ``"Circular"``, or ``"Longest Idle Time"``).
            devices: Ordered list of gateway/trunk device names.

        Returns:
            The AXL response dict.

        Raises:
            AXLDuplicateError: If a route group with this name already exists.
            AXLError: On other AXL faults.

        Example::

            client.add_route_group(
                "PSTN-RG",
                "Top Down",
                ["PSTN-GW-1", "PSTN-GW-2"],
            )
        """
        members = [
            {"deviceSelectionOrder": idx, "deviceName": dev, "port": 0}
            for idx, dev in enumerate(devices, start=1)
        ]
        try:
            return self._service.addRouteGroup(
                routeGroup={
                    "name": name,
                    "distributionAlgorithm": distribution_algorithm,
                    "members": {"member": members},
                }
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_route_group(
        self,
        name: str,
        distribution_algorithm: Optional[str] = None,
        devices: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        """Update an existing Route Group.

        Args:
            name: Name of the Route Group to update.
            distribution_algorithm: New algorithm (if provided).
            devices: New ordered list of device names (if provided).

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the route group does not exist.
            AXLError: On other AXL faults.
        """
        kwargs: Dict[str, Any] = {"name": name}
        if distribution_algorithm is not None:
            kwargs["distributionAlgorithm"] = distribution_algorithm
        if devices is not None:
            kwargs["members"] = {
                "member": [
                    {"deviceSelectionOrder": idx, "deviceName": dev, "port": 0}
                    for idx, dev in enumerate(devices, start=1)
                ]
            }
        try:
            return self._service.updateRouteGroup(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_route_group(self, name: str) -> Dict[str, Any]:
        """Remove a Route Group by name.

        Args:
            name: The Route Group name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the route group does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeRouteGroup(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Route Lists
    # ═══════════════════════════════════════════════════════════════════

    def get_route_list(self, name: str) -> Dict[str, Any]:
        """Retrieve a Route List by name.

        Args:
            name: The Route List name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If the route list does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getRouteList(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_route_list(
        self,
        name: str,
        description: str,
        call_manager_group_name: str,
        route_list_enabled: bool,
        run_on_every_node: bool,
        route_groups: Sequence[str],
        digit_discard_instruction_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Add a new Route List.

        Args:
            name: Name for the Route List.
            description: Description.
            call_manager_group_name: The Call Manager Group to associate.
            route_list_enabled: Whether the route list is enabled.
            run_on_every_node: Whether to run on every node.
            route_groups: Ordered list of Route Group names.
            digit_discard_instruction_name: Optional DDI to apply to all
                members.

        Returns:
            The AXL response dict.

        Raises:
            AXLDuplicateError: If a route list with this name exists.
            AXLError: On other AXL faults.
        """
        members = [
            {
                "selectionOrder": idx,
                "routeGroupName": rg,
                "digitDiscardInstructionName": digit_discard_instruction_name,
            }
            for idx, rg in enumerate(route_groups, start=1)
        ]
        try:
            return self._service.addRouteList(
                routeList={
                    "name": name,
                    "description": description,
                    "callManagerGroupName": call_manager_group_name,
                    "routeListEnabled": route_list_enabled,
                    "runOnEveryNode": run_on_every_node,
                    "members": {"member": members},
                }
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_route_list(self, **route_list_data: Unpack[UpdateRouteList]) -> Dict[str, Any]:
        """Update an existing Route List.

        Args:
            **route_list_data: Keyword arguments for ``updateRouteList``.
                Must include ``name`` or ``uuid`` to identify the list.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the route list does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateRouteList(**route_list_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_route_list(self, name: str) -> Dict[str, Any]:
        """Remove a Route List by name.

        Args:
            name: The Route List name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the route list does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeRouteList(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Route Patterns
    # ═══════════════════════════════════════════════════════════════════

    def get_route_pattern(
        self,
        pattern: str,
        route_partition_name: str,
    ) -> Dict[str, Any]:
        """Retrieve a Route Pattern.

        Args:
            pattern: The route pattern string (e.g. ``"9.!"``).
            route_partition_name: The partition the pattern belongs to.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If the pattern does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getRoutePattern(
                pattern=pattern, routePartitionName=route_partition_name
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_route_pattern(
        self,
        pattern: str,
        route_partition_name: str,
        route_list_name: str,
        network_location: str = "OnNet",
        provide_outside_dialtone: bool = False,
        block_enable: bool = False,
        use_calling_party_phone_mask: str = "Off",
    ) -> Dict[str, Any]:
        """Add a new Route Pattern.

        Args:
            pattern: The route pattern string (e.g. ``"9.!"``).
            route_partition_name: The partition to assign the pattern to.
            route_list_name: The Route List to route calls through.
            network_location: ``"OnNet"`` or ``"OffNet"`` (default ``"OnNet"``).
            provide_outside_dialtone: Whether to provide outside dial tone.
            block_enable: Whether the pattern is blocked.

        Returns:
            The AXL response dict.

        Raises:
            AXLDuplicateError: If the route pattern already exists.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.addRoutePattern(
                routePattern={
                    "pattern": pattern,
                    "routePartitionName": route_partition_name,
                    "destination": {"routeListName": route_list_name},
                    "blockEnable": block_enable,
                    "useCallingPartyPhoneMask": use_calling_party_phone_mask,
                    "dialPlanName": None,
                    "digitDiscardInstructionName": None,
                    "networkLocation": network_location,
                    "prefixDigitsOut": None,
                    "routeFilterName": None,
                    "provideOutsideDialtone": provide_outside_dialtone,
                }
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_route_pattern(self, **route_pattern_data: Unpack[UpdateRoutePattern]) -> Dict[str, Any]:
        """Update an existing Route Pattern.

        Args:
            **route_pattern_data: Keyword arguments for ``updateRoutePattern``.
                Must include ``pattern`` + ``routePartitionName`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the pattern does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateRoutePattern(**route_pattern_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_route_pattern(
        self,
        pattern: str,
        route_partition_name: str,
    ) -> Dict[str, Any]:
        """Remove a Route Pattern.

        Args:
            pattern: The route pattern string.
            route_partition_name: The partition the pattern belongs to.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the pattern does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeRoutePattern(
                pattern=pattern, routePartitionName=route_partition_name
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Translation Patterns
    # ═══════════════════════════════════════════════════════════════════

    def get_translation_pattern(
        self,
        pattern: str,
        route_partition_name: str,
    ) -> Dict[str, Any]:
        """Retrieve a Translation Pattern.

        Args:
            pattern: The translation pattern string.
            route_partition_name: The partition the pattern belongs to.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If the pattern does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getTransPattern(
                pattern=pattern, routePartitionName=route_partition_name
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_translation_pattern(
        self,
        pattern: str,
        route_partition_name: str,
        provide_outside_dialtone: bool = False,
        block_enable: bool = False,
        usage: str = "Translation",
        **kwargs,
    ) -> Dict[str, Any]:
        """Add a new Translation Pattern.

        Args:
            pattern: The translation pattern string.
            route_partition_name: The partition to assign the pattern to.
            provide_outside_dialtone: Whether to provide outside dial tone.
            block_enable: Whether the pattern is blocked.
            usage: ``"Translation"`` or ``"Device"``.
            **kwargs: Additional fields for the ``transPattern`` element
                (e.g. ``callingSearchSpaceName``, ``calledPartyTransformationMask``).

        Returns:
            The AXL response dict.

        Raises:
            AXLDuplicateError: If the pattern already exists.
            AXLError: On other AXL faults.
        """
        trans_data = {
            "pattern": pattern,
            "routePartitionName": route_partition_name,
            "blockEnable": block_enable,
            "provideOutsideDialtone": provide_outside_dialtone,
            "usage": usage,
            **kwargs,
        }
        try:
            return self._service.addTransPattern(transPattern=trans_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_translation_pattern(self, **trans_data: Unpack[UpdateTransPattern]) -> Dict[str, Any]:
        """Update an existing Translation Pattern.

        Args:
            **trans_data: Keyword arguments for ``updateTransPattern``.
                Must include ``pattern`` + ``routePartitionName`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the pattern does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateTransPattern(**trans_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_translation_pattern(
        self,
        pattern: str,
        route_partition_name: str,
    ) -> Dict[str, Any]:
        """Remove a Translation Pattern.

        Args:
            pattern: The translation pattern string.
            route_partition_name: The partition the pattern belongs to.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the pattern does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeTransPattern(
                pattern=pattern, routePartitionName=route_partition_name
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  SIP Route Patterns
    # ═══════════════════════════════════════════════════════════════════

    def get_sip_route_pattern(
        self,
        pattern: str,
        route_partition_name: str,
    ) -> Dict[str, Any]:
        """Retrieve a SIP Route Pattern.

        Args:
            pattern: The SIP route pattern string.
            route_partition_name: The partition the pattern belongs to.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If the pattern does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getSipRoutePattern(
                pattern=pattern, routePartitionName=route_partition_name
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_sip_route_pattern(
        self,
        pattern: str,
        route_partition_name: str,
        sip_trunk_name: str,
        usage: str = "Domain Routing",
    ) -> Dict[str, Any]:
        """Add a new SIP Route Pattern.

        Args:
            pattern: The SIP route pattern string.
            route_partition_name: The partition.
            sip_trunk_name: The SIP Trunk to route to.
            usage: ``"Domain Routing"`` (default) or ``"IP Routing"``.

        Returns:
            The AXL response dict.

        Raises:
            AXLDuplicateError: If the pattern already exists.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.addSipRoutePattern(
                sipRoutePattern={
                    "pattern": pattern,
                    "routePartitionName": route_partition_name,
                    "sipTrunkName": sip_trunk_name,
                    "usage": usage,
                }
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_sip_route_pattern(self, **sip_rp_data: Unpack[UpdateSipRoutePattern]) -> Dict[str, Any]:
        """Update an existing SIP Route Pattern.

        Args:
            **sip_rp_data: Keyword arguments for ``updateSipRoutePattern``.
                Must include ``pattern`` + ``routePartitionName`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the pattern does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateSipRoutePattern(**sip_rp_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_sip_route_pattern(
        self,
        pattern: str,
        route_partition_name: str,
    ) -> Dict[str, Any]:
        """Remove a SIP Route Pattern.

        Args:
            pattern: The SIP route pattern string.
            route_partition_name: The partition.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the pattern does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeSipRoutePattern(
                pattern=pattern, routePartitionName=route_partition_name
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Conference Bridge
    # ═══════════════════════════════════════════════════════════════════

    def get_conference_bridge(self, name: str) -> Dict[str, Any]:
        """Retrieve a Conference Bridge by name.

        Args:
            name: The conference bridge name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If the bridge does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getConferenceBridge(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_conference_bridge(
        self,
        conference_bridge_data: ConferenceBridge,
    ) -> Dict[str, Any]:
        """Add a new Conference Bridge.

        Args:
            conference_bridge_data: A dict describing the bridge.  Required
                keys depend on the product type.

        Returns:
            The AXL response dict.

        Raises:
            AXLDuplicateError: If a bridge with this name already exists.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.addConferenceBridge(
                conferenceBridge=conference_bridge_data
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_conference_bridge_cms(
        self,
        name: str,
        description: str,
        conference_bridge_prefix: str,
        sip_trunk_name: str,
        security_icon_control: bool,
        override_sip_trunk_address: bool,
        addresses: List[str],
        username: str,
        password: str,
        http_port: int,
    ) -> Dict[str, Any]:
        """Add a Cisco Meeting Server (CMS) Conference Bridge.

        This is a convenience method that builds the correct data structure
        for a CMS-type conference bridge.

        Args:
            name: Conference bridge name.
            description: Description.
            conference_bridge_prefix: Numeric prefix for conference IDs.
            sip_trunk_name: Name of the SIP Trunk pointing to CMS.
            security_icon_control: Allow CFB to control call security icon.
            override_sip_trunk_address: Override SIP Trunk destination.
            addresses: List of address strings
                (e.g. ``["10.0.0.1"]``).
            username: CMS API username.
            password: CMS API password.
            http_port: CMS API HTTP port.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        cms_data = {
            "name": name,
            "description": description,
            "product": "Cisco Meeting Server",
            "conferenceBridgePrefix": conference_bridge_prefix,
            "sipTrunkName": sip_trunk_name,
            "allowCFBControlOfCallSecurityIcon": security_icon_control,
            "overrideSIPTrunkAddress": override_sip_trunk_address,
            "addresses": {"address": addresses},
            "userName": username,
            "password": password,
            "httpPort": http_port,
        }
        return self.add_conference_bridge(cms_data)

    def update_conference_bridge(self, **cfb_data: Unpack[UpdateConferenceBridge]) -> Dict[str, Any]:
        """Update an existing Conference Bridge.

        Args:
            **cfb_data: Keyword arguments for ``updateConferenceBridge``.
                Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the bridge does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateConferenceBridge(**cfb_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_conference_bridge(self, name: str) -> Dict[str, Any]:
        """Remove a Conference Bridge by name.

        Args:
            name: The conference bridge name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the bridge does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeConferenceBridge(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Media Resource Group / Media Resource Group List
    # ═══════════════════════════════════════════════════════════════════

    def get_media_resource_group(self, name: str) -> Dict[str, Any]:
        """Retrieve a Media Resource Group by name.

        Args:
            name: The MRG name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If the MRG does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getMediaResourceGroup(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_media_resource_group(
        self,
        name: str,
        description: str = "",
        devices: Optional[Sequence[str]] = None,
        multicast: bool = False,
    ) -> Dict[str, Any]:
        """Add a new Media Resource Group.

        Args:
            name: Name for the MRG.
            description: Optional description.
            devices: Optional list of media resource device names.
            multicast: Whether multicast is enabled for the MRG.

        Returns:
            The AXL response dict.

        Raises:
            AXLDuplicateError: If an MRG with this name already exists.
            AXLError: On other AXL faults.
        """
        mrg_data: MediaResourceGroup = {
            "name": name,
            "description": description,
            "multicast": multicast,
        }
        if devices:
            mrg_data["members"] = {
                "member": [{"deviceName": d} for d in devices]
            }
        else:
            mrg_data["members"] = xsd.SkipValue
        try:
            return self._service.addMediaResourceGroup(
                mediaResourceGroup=mrg_data
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_media_resource_group(self, name: str) -> Dict[str, Any]:
        """Remove a Media Resource Group by name.

        Args:
            name: The MRG name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the MRG does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeMediaResourceGroup(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def get_media_resource_list(self, name: str) -> Dict[str, Any]:
        """Retrieve a Media Resource Group List (MRGL) by name.

        Args:
            name: The MRGL name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If the MRGL does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getMediaResourceList(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_media_resource_list(
        self,
        name: str,
        members: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        """Add a new Media Resource Group List (MRGL).

        Args:
            name: Name for the MRGL.
            members: Optional ordered list of Media Resource Group names.

        Returns:
            The AXL response dict.

        Raises:
            AXLDuplicateError: If an MRGL with this name already exists.
            AXLError: On other AXL faults.
        """
        mrgl_data: MediaResourceList = {"name": name}
        if members:
            mrgl_data["members"] = {
                "member": [
                    {"order": idx, "mediaResourceGroupName": m}
                    for idx, m in enumerate(members, start=1)
                ]
            }
        try:
            return self._service.addMediaResourceList(
                mediaResourceList=mrgl_data
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_media_resource_list(self, name: str) -> Dict[str, Any]:
        """Remove a Media Resource Group List (MRGL) by name.

        Args:
            name: The MRGL name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the MRGL does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeMediaResourceList(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Device Pool
    # ═══════════════════════════════════════════════════════════════════

    def get_device_pool(self, name: str) -> Dict[str, Any]:
        """Retrieve a Device Pool by name.

        Args:
            name: The Device Pool name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If the device pool does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getDevicePool(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_device_pool(self, device_pool_data: DevicePool) -> Dict[str, Any]:
        """Add a new Device Pool.

        Args:
            device_pool_data: A dict describing the device pool.  Required
                keys: ``name``, ``callManagerGroupName``,
                ``dateTimeSettingName``, ``regionName``, ``srstName``.

                Example::

                    {
                        "name": "DP-Building-A",
                        "callManagerGroupName": "CMGroup-1",
                        "dateTimeSettingName": "CMLocal",
                        "regionName": "Default",
                        "locationName": "Hub_None",
                        "srstName": "Disable",
                    }

        Returns:
            The AXL response dict.

        Raises:
            AXLDuplicateError: If a device pool with this name exists.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.addDevicePool(devicePool=device_pool_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_device_pool(self, **device_pool_data: Unpack[UpdateDevicePool]) -> Dict[str, Any]:
        """Update an existing Device Pool.

        Args:
            **device_pool_data: Keyword arguments for ``updateDevicePool``.
                Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the device pool does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateDevicePool(**device_pool_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_device_pool(self, name: str) -> Dict[str, Any]:
        """Remove a Device Pool by name.

        Args:
            name: The Device Pool name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the device pool does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeDevicePool(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  LDAP Filter
    # ═══════════════════════════════════════════════════════════════════

    def get_ldap_filter(self, name: str) -> Dict[str, Any]:
        """Retrieve an LDAP Filter by name.

        Args:
            name: The LDAP filter name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If the filter does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getLdapFilter(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_ldap_filter(
        self,
        name: str,
        filter_string: str,
    ) -> Dict[str, Any]:
        """Add a new LDAP Filter.

        Args:
            name: Name for the LDAP filter.
            filter_string: The LDAP filter expression.

        Returns:
            The AXL response dict.

        Raises:
            AXLDuplicateError: If a filter with this name already exists.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.addLdapFilter(
                ldapFilter={"name": name, "filter": filter_string}
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_ldap_filter(self, name: str) -> Dict[str, Any]:
        """Remove an LDAP Filter by name.

        Args:
            name: The LDAP filter name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the filter does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeLdapFilter(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  LDAP Directory
    # ═══════════════════════════════════════════════════════════════════

    def get_ldap_directory(self, name: str) -> Dict[str, Any]:
        """Retrieve an LDAP Directory by name.

        Args:
            name: The LDAP directory name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If the directory does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getLdapDirectory(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_ldap_directory(
        self,
        ldap_directory_data: LdapDirectory,
    ) -> Dict[str, Any]:
        """Add a new LDAP Directory.

        Args:
            ldap_directory_data: A dict describing the LDAP directory
                configuration.

        Returns:
            The AXL response dict.

        Raises:
            AXLDuplicateError: If a directory with this name already exists.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.addLdapDirectory(
                ldapDirectory=ldap_directory_data
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_ldap_directory(self, name: str) -> Dict[str, Any]:
        """Remove an LDAP Directory by name.

        Args:
            name: The LDAP directory name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the directory does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeLdapDirectory(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def start_ldap_sync(self, ldap_name: Optional[str] = None) -> bool:
        """Trigger an LDAP synchronization via Thin AXL.

        Args:
            ldap_name: Optional name of a specific LDAP directory to sync.
                If ``None``, syncs all directories.

        Returns:
            ``True`` if at least one row was updated.

        Raises:
            AXLSQLError: If the SQL update fails.
        """
        query = "UPDATE directorypluginconfig SET syncnow = '1'"
        if ldap_name is not None:
            safe_name = _sanitize_sql_value(ldap_name)
            query += f" WHERE name = '{safe_name}'"

        result = self.sql_update(query)
        return result["rows_updated"] > 0

    # ═══════════════════════════════════════════════════════════════════
    #  LDAP System
    # ═══════════════════════════════════════════════════════════════════

    def get_ldap_system(self) -> Dict[str, Any]:
        """Retrieve the LDAP System configuration.

        Returns:
            The full AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.getLdapSystem()
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_ldap_system(
        self,
        sync_enabled: bool,
        ldap_server: str,
        user_id_attribute: str,
    ) -> Dict[str, Any]:
        """Update the LDAP System configuration.

        Args:
            sync_enabled: Whether LDAP sync is enabled.
            ldap_server: The LDAP server type (e.g. ``"Microsoft Active Directory"``).
            user_id_attribute: Attribute to use as user ID
                (e.g. ``"sAMAccountName"``).

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.updateLdapSystem(
                syncEnabled=sync_enabled,
                ldapServer=ldap_server,
                userIdAttribute=user_id_attribute,
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  LDAP Authentication
    # ═══════════════════════════════════════════════════════════════════

    def get_ldap_authentication(self) -> Dict[str, Any]:
        """Retrieve the LDAP Authentication configuration.

        Returns:
            The full AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.getLdapAuthentication()
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_ldap_authentication(
        self,
        enabled: bool,
        distinguished_name: str,
        ldap_password: str,
        search_base: str,
        servers: Sequence[str],
        port: int = 389,
        ssl_enabled: bool = False,
    ) -> Dict[str, Any]:
        """Update the LDAP Authentication configuration.

        Args:
            enabled: Whether to authenticate end users via LDAP.
            distinguished_name: Bind DN for LDAP.
            ldap_password: Bind password.
            search_base: LDAP search base for user lookup.
            servers: List of LDAP server hostnames or IPs.
            port: LDAP port number (default 389).
            ssl_enabled: Whether to use SSL/TLS (default ``False``).

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        server_data = [
            {"hostName": s, "ldapPortNumber": port, "sslEnabled": ssl_enabled}
            for s in servers
        ]
        try:
            return self._service.updateLdapAuthentication(
                authenticateEndUsers=enabled,
                distinguishedName=distinguished_name,
                ldapPassword=ldap_password,
                userSearchBase=search_base,
                servers={"server": server_data},
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Phone Security Profile
    # ═══════════════════════════════════════════════════════════════════

    def get_phone_security_profile(self, name: str) -> Dict[str, Any]:
        """Retrieve a Phone Security Profile by name.

        Args:
            name: The security profile name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If the profile does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getPhoneSecurityProfile(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_phone_security_profile(
        self,
        phone_type: str,
        protocol: str,
        name: str,
        description: str = "",
        device_security_mode: str = "Non Secure",
        authentication_mode: str = "By Null String",
        key_size: str = "1024",
        key_order: str = "RSA Only",
        ec_key_size: str = "384",
        tftp_encrypted_config: bool = False,
        nonce_validity_time: int = 600,
        transport_type: str = "TCP+UDP",
        sip_phone_port: int = 5060,
        enable_digest_authentication: bool = False,
    ) -> Dict[str, Any]:
        """Add a new Phone Security Profile.

        Args:
            phone_type: Phone model (e.g. ``"Cisco 8845"``).
            protocol: ``"SIP"`` or ``"SCCP"``.
            name: Profile name.
            description: Optional description.
            device_security_mode: ``"Non Secure"``, ``"Authenticated"``,
                or ``"Encrypted"``.
            authentication_mode: ``"By Null String"``,
                ``"By Existing Certificate"``, etc.
            key_size: RSA key size (``"1024"``, ``"2048"``, ``"4096"``).
            key_order: ``"RSA Only"`` or ``"ECDSA Preferred"``.
            ec_key_size: EC key size (``"256"``, ``"384"``, ``"521"``).
            tftp_encrypted_config: Whether TFTP config is encrypted.
            nonce_validity_time: Nonce validity in seconds.
            transport_type: ``"TCP+UDP"``, ``"TCP"``, or ``"TLS"``.
            sip_phone_port: SIP signaling port.
            enable_digest_authentication: Whether digest auth is enabled.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        profile = {
            "phoneType": phone_type,
            "protocol": protocol,
            "name": name,
            "description": description,
            "deviceSecurityMode": device_security_mode,
            "authenticationMode": authentication_mode,
            "keySize": key_size,
            "keyOrder": key_order,
            "ecKeySize": ec_key_size,
            "tftpEncryptedConfig": tftp_encrypted_config,
            "nonceValidityTime": nonce_validity_time,
            "transportType": transport_type,
            "sipPhonePort": sip_phone_port,
            "enableDigestAuthentication": enable_digest_authentication,
        }
        try:
            return self._service.addPhoneSecurityProfile(
                phoneSecurityProfile=profile
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  SIP Trunk Security Profile
    # ═══════════════════════════════════════════════════════════════════

    def get_sip_trunk_security_profile(self, name: str) -> Dict[str, Any]:
        """Retrieve a SIP Trunk Security Profile by name.

        Args:
            name: The profile name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If the profile does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getSipTrunkSecurityProfile(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_sip_trunk_security_profile(
        self,
        name: str,
        description: str = "",
        security_mode: str = "Non Secure",
        incoming_transport: str = "TCP+UDP",
        outgoing_transport: str = "TCP",
        digest_authentication: bool = False,
        nonce_policy_time: int = 600,
        x509_subject_name: str = "",
        incoming_port: int = 5060,
        app_level_authentication: bool = False,
        accept_presence_subscription: bool = False,
        accept_out_of_dialog_refer: bool = False,
        accept_unsolicited_notification: bool = False,
        allow_replace_header: bool = False,
        transmit_security_status: bool = False,
        sip_v150_outbound_sdp_offer_filtering: str = "Use Default Filter",
        allow_charging_header: bool = False,
    ) -> Dict[str, Any]:
        """Add a new SIP Trunk Security Profile.

        Args:
            name: Profile name.
            description: Optional description.
            security_mode: ``"Non Secure"``, ``"Authenticated"``,
                or ``"Encrypted"``.
            incoming_transport: ``"TCP+UDP"``, ``"TCP"``, or ``"TLS"``.
            outgoing_transport: ``"TCP"``, ``"UDP"``, or ``"TLS"``.
            digest_authentication: Enable digest auth.
            nonce_policy_time: Nonce validity in seconds.
            x509_subject_name: X.509 subject name for TLS.
            incoming_port: Incoming SIP port.
            app_level_authentication: Enable application-level auth.
            accept_presence_subscription: Accept presence subscriptions.
            accept_out_of_dialog_refer: Accept out-of-dialog REFER.
            accept_unsolicited_notification: Accept unsolicited NOTIFY.
            allow_replace_header: Allow Replaces header.
            transmit_security_status: Transmit security status.
            sip_v150_outbound_sdp_offer_filtering: V.150 SDP filter mode.
            allow_charging_header: Allow charging header.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        profile = {
            "name": name,
            "description": description,
            "securityMode": security_mode,
            "incomingTransport": incoming_transport,
            "outgoingTransport": outgoing_transport,
            "digestAuthentication": digest_authentication,
            "noncePolicyTime": nonce_policy_time,
            "x509SubjectName": x509_subject_name,
            "incomingPort": incoming_port,
            "applLevelAuthentication": app_level_authentication,
            "acceptPresenceSubscription": accept_presence_subscription,
            "acceptOutOfDialogRefer": accept_out_of_dialog_refer,
            "acceptUnsolicitedNotification": accept_unsolicited_notification,
            "allowReplaceHeader": allow_replace_header,
            "transmitSecurityStatus": transmit_security_status,
            "sipV150OutboundSdpOfferFiltering": sip_v150_outbound_sdp_offer_filtering,
            "allowChargingHeader": allow_charging_header,
        }
        try:
            return self._service.addSipTrunkSecurityProfile(
                sipTrunkSecurityProfile=profile
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_sip_trunk_security_profile(self, name: str) -> Dict[str, Any]:
        """Remove a SIP Trunk Security Profile by name.

        Args:
            name: The profile name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the profile does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeSipTrunkSecurityProfile(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  SIP Profile
    # ═══════════════════════════════════════════════════════════════════

    def get_sip_profile(self, name: str) -> Dict[str, Any]:
        """Retrieve a SIP Profile by name.

        Args:
            name: The SIP profile name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If the profile does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getSipProfile(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_sip_profile(
        self,
        sip_profile_data: SipProfile,
    ) -> Dict[str, Any]:
        """Add a new SIP Profile.

        Args:
            sip_profile_data: A dict describing the SIP profile.

        Returns:
            The AXL response dict.

        Raises:
            AXLDuplicateError: If a profile with this name already exists.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.addSipProfile(sipProfile=sip_profile_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_sip_profile(self, **profile_data: Unpack[UpdateSipProfile]) -> Dict[str, Any]:
        """Update an existing SIP Profile.

        Args:
            **profile_data: Keyword arguments for ``updateSipProfile``.
                Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the profile does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateSipProfile(**profile_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_sip_profile(self, name: str) -> Dict[str, Any]:
        """Remove a SIP Profile by name.

        Args:
            name: The SIP profile name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the profile does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeSipProfile(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  SIP Trunk
    # ═══════════════════════════════════════════════════════════════════

    def get_sip_trunk(self, name: str) -> Dict[str, Any]:
        """Retrieve a SIP Trunk by name.

        Args:
            name: The SIP trunk name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If the trunk does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getSipTrunk(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_sip_trunk(
        self,
        sip_trunk_data: SipTrunk,
    ) -> Dict[str, Any]:
        """Add a new SIP Trunk.

        Args:
            sip_trunk_data: A dict describing the SIP trunk.  Required
                keys: ``name``, ``product`` (``"SIP Trunk"``),
                ``class`` (``"Trunk"``), ``protocol`` (``"SIP"``),
                ``protocolSide`` (``"Network"``), ``devicePoolName``,
                ``securityProfileName``, ``sipProfileName``,
                ``locationName``, ``presenceGroupName``.

                Example::

                    {
                        "name": "SIP-Trunk-ITSP",
                        "product": "SIP Trunk",
                        "class": "Trunk",
                        "protocol": "SIP",
                        "protocolSide": "Network",
                        "devicePoolName": "Default",
                        "locationName": "Hub_None",
                        "presenceGroupName": "Standard Presence group",
                        "securityProfileName": "Non Secure SIP Trunk Profile",
                        "sipProfileName": "Standard SIP Profile",
                        "callingSearchSpaceName": "CSS-Trunk",
                        "destinations": {
                            "destination": [
                                {"addressIpv4": "10.0.0.100", "port": 5060, "sortOrder": 1}
                            ]
                        },
                    }

        Returns:
            The AXL response dict.

        Raises:
            AXLDuplicateError: If a trunk with this name already exists.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.addSipTrunk(sipTrunk=sip_trunk_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_sip_trunk(self, **trunk_data: Unpack[UpdateSipTrunk]) -> Dict[str, Any]:
        """Update an existing SIP Trunk.

        Args:
            **trunk_data: Keyword arguments for ``updateSipTrunk``.
                Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the trunk does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateSipTrunk(**trunk_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_sip_trunk(self, name: str) -> Dict[str, Any]:
        """Remove a SIP Trunk by name.

        Args:
            name: The SIP trunk name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the trunk does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeSipTrunk(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Device Reset / Restart
    # ═══════════════════════════════════════════════════════════════════

    def reset_device(self, device_name: str) -> Dict[str, Any]:
        """Perform a hard reset on a device (full reload).

        Args:
            device_name: The device name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the device does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.doDeviceReset(
                deviceName=device_name, isHardReset=True, isMGCP=False
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def restart_device(self, device_name: str) -> Dict[str, Any]:
        """Perform a soft restart on a device (config refresh).

        Args:
            device_name: The device name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the device does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.doDeviceReset(
                deviceName=device_name, isHardReset=False, isMGCP=False
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def reset_mgcp_device(self, device_name: str) -> Dict[str, Any]:
        """Perform a hard reset on an MGCP device.

        Args:
            device_name: The MGCP device name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.doDeviceReset(
                deviceName=device_name, isHardReset=True, isMGCP=True
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def restart_mgcp_device(self, device_name: str) -> Dict[str, Any]:
        """Perform a soft restart on an MGCP device.

        Args:
            device_name: The MGCP device name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.doDeviceReset(
                deviceName=device_name, isHardReset=False, isMGCP=True
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Remote Destinations
    # ═══════════════════════════════════════════════════════════════════

    def get_remote_destination(self, destination: str) -> Dict[str, Any]:
        """Retrieve a Remote Destination.

        Args:
            destination: The remote destination number.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If the destination does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getRemoteDestination(destination=destination)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_remote_destination(
        self,
        remote_destination_data: RemoteDestination,
    ) -> Dict[str, Any]:
        """Add a new Remote Destination.

        Args:
            remote_destination_data: A dict describing the remote destination.

        Returns:
            The AXL response dict.

        Raises:
            AXLDuplicateError: If a remote destination with this name already exists.
            AXLError: On other AXL faults.

        Note:
            Older UCM versions (pre-12.5) may reject the request with an
            internal error if ``<dualModeDeviceName>`` is sent as a nil
            element (Cisco bug CSCvq98025). Omit ``dualModeDeviceName``
            from ``remote_destination_data`` to avoid this on affected
            versions.
        """
        try:
            return self._service.addRemoteDestination(
                remoteDestination=remote_destination_data
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_remote_destination(self, destination: str) -> Dict[str, Any]:
        """Remove a Remote Destination.

        Args:
            destination: The remote destination number.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the destination does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeRemoteDestination(destination=destination)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  SQL Helper Methods (using Thin AXL with injection protection)
    # ═══════════════════════════════════════════════════════════════════

    def sql_get_device_pkid(self, device_name: str) -> Optional[str]:
        """Look up a device's PKID by name.

        Args:
            device_name: The device name.

        Returns:
            The PKID string, or ``None`` if not found.

        Raises:
            AXLSQLError: If the query fails.
        """
        safe = _sanitize_sql_value(device_name)
        result = self.sql_query(f"SELECT pkid FROM device WHERE name = '{safe}'")
        if result["num_rows"] > 0:
            return result["rows"][0]["pkid"]
        return None

    def sql_get_enduser_pkid(self, userid: str) -> Optional[str]:
        """Look up an end user's PKID by user ID.

        Args:
            userid: The user ID.

        Returns:
            The PKID string, or ``None`` if not found.

        Raises:
            AXLSQLError: If the query fails.
        """
        safe = _sanitize_sql_value(userid)
        result = self.sql_query(f"SELECT pkid FROM enduser WHERE userid = '{safe}'")
        if result["num_rows"] > 0:
            return result["rows"][0]["pkid"]
        return None

    def sql_get_user_group_pkid(self, group_name: str) -> Optional[str]:
        """Look up a user group's PKID by name.

        Args:
            group_name: The directory group name.

        Returns:
            The PKID string, or ``None`` if not found.

        Raises:
            AXLSQLError: If the query fails.
        """
        safe = _sanitize_sql_value(group_name)
        result = self.sql_query(f"SELECT pkid FROM dirgroup WHERE name = '{safe}'")
        if result["num_rows"] > 0:
            return result["rows"][0]["pkid"]
        return None

    def sql_associate_user_to_group(
        self,
        userid: str,
        group_name: str,
    ) -> bool:
        """Associate an end user with a user group via SQL.

        Args:
            userid: The user ID.
            group_name: The directory group name.

        Returns:
            ``True`` if the association was created successfully.

        Raises:
            AXLSQLError: If the update fails.
            ValueError: If the user or group is not found.
        """
        user_group_pkid = self.sql_get_user_group_pkid(group_name)
        enduser_pkid = self.sql_get_enduser_pkid(userid)

        if user_group_pkid is None:
            raise ValueError(f"User group not found: {group_name}")
        if enduser_pkid is None:
            raise ValueError(f"End user not found: {userid}")

        query = (
            f"INSERT INTO enduserdirgroupmap (fkenduser, fkdirgroup) "
            f"VALUES ('{enduser_pkid}', '{user_group_pkid}')"
        )
        result = self.sql_update(query)
        return result["rows_updated"] > 0

    def sql_remove_user_from_group(
        self,
        userid: str,
        group_name: str,
    ) -> bool:
        """Remove an end user from a user group via SQL.

        Args:
            userid: The user ID.
            group_name: The directory group name.

        Returns:
            ``True`` if the association was removed successfully.

        Raises:
            AXLSQLError: If the update fails.
            ValueError: If the user or group is not found.
        """
        user_group_pkid = self.sql_get_user_group_pkid(group_name)
        enduser_pkid = self.sql_get_enduser_pkid(userid)

        if user_group_pkid is None:
            raise ValueError(f"User group not found: {group_name}")
        if enduser_pkid is None:
            raise ValueError(f"End user not found: {userid}")

        query = (
            f"DELETE FROM enduserdirgroupmap "
            f"WHERE fkenduser = '{enduser_pkid}' AND fkdirgroup = '{user_group_pkid}'"
        )
        result = self.sql_update(query)
        return result["rows_updated"] > 0

    def sql_associate_device_to_user(
        self,
        device_name: str,
        userid: str,
        association_type: str = "1",
    ) -> bool:
        """Associate a device to a user via SQL.

        Args:
            device_name: The device name.
            userid: The user ID.
            association_type: The association type code (default ``"1"``).

        Returns:
            ``True`` if the association was created successfully.

        Raises:
            AXLSQLError: If the update fails.
            ValueError: If the device or user is not found.
        """
        device_pkid = self.sql_get_device_pkid(device_name)
        enduser_pkid = self.sql_get_enduser_pkid(userid)

        if device_pkid is None:
            raise ValueError(f"Device not found: {device_name}")
        if enduser_pkid is None:
            raise ValueError(f"End user not found: {userid}")

        safe_type = _sanitize_sql_value(association_type)
        query = (
            f"INSERT INTO enduserdevicemap (fkenduser, fkdevice, defaultprofile, tkuserassociation) "
            f"VALUES ('{enduser_pkid}', '{device_pkid}', 'f', '{safe_type}')"
        )
        result = self.sql_update(query)
        return result["rows_updated"] > 0

    def sql_update_service_parameter(
        self,
        param_name: str,
        param_value: str,
    ) -> bool:
        """Update a service parameter value via SQL.

        Args:
            param_name: The parameter name.
            param_value: The new parameter value.

        Returns:
            ``True`` if at least one row was updated.

        Raises:
            AXLSQLError: If the update fails.
        """
        safe_name = _sanitize_sql_value(param_name)
        safe_value = _sanitize_sql_value(param_value)
        query = (
            f"UPDATE processconfig SET paramvalue = '{safe_value}' "
            f"WHERE paramname = '{safe_name}'"
        )
        result = self.sql_update(query)
        return result["rows_updated"] > 0

    def sql_get_service_parameter(
        self,
        param_name: str,
    ) -> Optional[List[Dict[str, Optional[str]]]]:
        """Retrieve service parameter values via SQL.

        Args:
            param_name: The parameter name.

        Returns:
            A list of row dicts, or ``None`` if no matching parameter.

        Raises:
            AXLSQLError: If the query fails.
        """
        safe_name = _sanitize_sql_value(param_name)
        result = self.sql_query(
            f"SELECT * FROM processconfig WHERE paramname = '{safe_name}'"
        )
        if result["num_rows"] > 0:
            return result["rows"]
        return None

    # ═══════════════════════════════════════════════════════════════════
    #  Line Group
    # ═══════════════════════════════════════════════════════════════════

    def get_line_group(self, name: str) -> Dict[str, Any]:
        """Retrieve a Line Group by name.

        Args:
            name: The Line Group name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If the group does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getLineGroup(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_line_group(
        self,
        name: str,
        distribution_algorithm: str = "Top Down",
        rna_reversion_timeout: int = 10,
        hunt_algorithm_no_answer: str = "Try next member; then, try next group in Hunt List",
        hunt_algorithm_busy: str = "Try next member; then, try next group in Hunt List",
        hunt_algorithm_not_available: str = "Try next member; then, try next group in Hunt List",
        members: Optional[Sequence[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Add a new Line Group.

        Args:
            name: Name for the Line Group.
            distribution_algorithm: ``"Top Down"``, ``"Circular"``,
                ``"Longest Idle Time"``, or ``"Broadcast"``.
            rna_reversion_timeout: Ring-no-answer timeout in seconds.
            hunt_algorithm_no_answer: Action on no-answer.
            hunt_algorithm_busy: Action on busy.
            hunt_algorithm_not_available: Action when not available.
            members: Optional list of member dicts.  Each should include
                ``lineSelectionOrder`` and ``directoryNumber`` with
                ``pattern`` and ``routePartitionName``::

                    [
                        {
                            "lineSelectionOrder": 1,
                            "directoryNumber": {
                                "pattern": "1001",
                                "routePartitionName": "Internal-PT",
                            },
                        }
                    ]

        Returns:
            The AXL response dict.

        Raises:
            AXLDuplicateError: If a line group with this name already exists.
            AXLError: On other AXL faults.
        """
        lg_data: LineGroup = {
            "name": name,
            "distributionAlgorithm": distribution_algorithm,
            "rnaReversionTimeOut": rna_reversion_timeout,
            "huntAlgorithmNoAnswer": hunt_algorithm_no_answer,
            "huntAlgorithmBusy": hunt_algorithm_busy,
            "huntAlgorithmNotAvailable": hunt_algorithm_not_available,
        }
        if members:
            lg_data["members"] = {"member": list(members)}
        try:
            return self._service.addLineGroup(lineGroup=lg_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_line_group(self, **line_group_data: Unpack[UpdateLineGroup]) -> Dict[str, Any]:
        """Update an existing Line Group.

        Args:
            **line_group_data: Keyword arguments for ``updateLineGroup``.
                Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the group does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateLineGroup(**line_group_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_line_group(self, name: str) -> Dict[str, Any]:
        """Remove a Line Group by name.

        Args:
            name: The Line Group name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the group does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeLineGroup(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Hunt List
    # ═══════════════════════════════════════════════════════════════════

    def get_hunt_list(self, name: str) -> Dict[str, Any]:
        """Retrieve a Hunt List by name.

        Args:
            name: The Hunt List name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If the hunt list does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getHuntList(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_hunt_list(
        self,
        name: str,
        description: str,
        call_manager_group_name: str,
        route_list_enabled: bool = True,
        voice_mail_usage_flag: str = "true",
        line_groups: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        """Add a new Hunt List.

        Args:
            name: Name for the Hunt List.
            description: Description.
            call_manager_group_name: Associated Call Manager Group name.
            route_list_enabled: Whether the hunt list is enabled.
            voice_mail_usage_flag: ``"true"`` or ``"false"``.
            line_groups: Optional ordered list of Line Group names.

        Returns:
            The AXL response dict.

        Raises:
            AXLDuplicateError: If a hunt list with this name exists.
            AXLError: On other AXL faults.

        Example::

            client.add_hunt_list(
                "HL-Support",
                "Support Hunt List",
                "CMGroup-1",
                line_groups=["LG-Support-1", "LG-Support-2"],
            )
        """
        hl_data: HuntList = {
            "name": name,
            "description": description,
            "callManagerGroupName": call_manager_group_name,
            "routeListEnabled": route_list_enabled,
            "voiceMailUsage": voice_mail_usage_flag,
        }
        if line_groups:
            hl_data["members"] = {
                "member": [
                    {"selectionOrder": idx, "lineGroupName": lg}
                    for idx, lg in enumerate(line_groups, start=1)
                ]
            }
        try:
            return self._service.addHuntList(huntList=hl_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_hunt_list(self, **hunt_list_data: Unpack[UpdateHuntList]) -> Dict[str, Any]:
        """Update an existing Hunt List.

        Args:
            **hunt_list_data: Keyword arguments for ``updateHuntList``.
                Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the hunt list does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateHuntList(**hunt_list_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_hunt_list(self, name: str) -> Dict[str, Any]:
        """Remove a Hunt List by name.

        Args:
            name: The Hunt List name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the hunt list does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeHuntList(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Hunt Pilot
    # ═══════════════════════════════════════════════════════════════════

    def get_hunt_pilot(
        self,
        pattern: str,
        route_partition_name: str,
    ) -> Dict[str, Any]:
        """Retrieve a Hunt Pilot by pattern and partition.

        Args:
            pattern: The hunt pilot pattern (e.g. ``"2000"``).
            route_partition_name: The partition the pilot belongs to.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If the hunt pilot does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getHuntPilot(
                pattern=pattern, routePartitionName=route_partition_name
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_hunt_pilot(
        self,
        pattern: str,
        route_partition_name: str,
        hunt_list_name: str,
        description: str = "",
        provide_outside_dialtone: bool = False,
        block_enable: bool = False,
        use_calling_party_phone_mask: str = "Off",
    ) -> Dict[str, Any]:
        """Add a new Hunt Pilot.

        Args:
            pattern: The hunt pilot pattern.
            route_partition_name: The partition.
            hunt_list_name: The Hunt List to route calls to.
            description: Optional description.
            provide_outside_dialtone: Whether to provide outside dial tone.

        Returns:
            The AXL response dict.

        Raises:
            AXLDuplicateError: If the hunt pilot already exists.
            AXLError: On other AXL faults.

        Example::

            client.add_hunt_pilot(
                "2000", "Internal-PT", "HL-Support",
                description="Support Queue",
            )
        """
        try:
            return self._service.addHuntPilot(
                huntPilot={
                    "pattern": pattern,
                    "routePartitionName": route_partition_name,
                    "huntListName": hunt_list_name,
                    "description": description,
                    "blockEnable": block_enable,
                    "useCallingPartyPhoneMask": use_calling_party_phone_mask,
                    "provideOutsideDialtone": provide_outside_dialtone,
                }
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_hunt_pilot(self, **hunt_pilot_data: Unpack[UpdateHuntPilot]) -> Dict[str, Any]:
        """Update an existing Hunt Pilot.

        Args:
            **hunt_pilot_data: Keyword arguments for ``updateHuntPilot``.
                Must include ``pattern`` + ``routePartitionName`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the hunt pilot does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateHuntPilot(**hunt_pilot_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_hunt_pilot(
        self,
        pattern: str,
        route_partition_name: str,
    ) -> Dict[str, Any]:
        """Remove a Hunt Pilot.

        Args:
            pattern: The hunt pilot pattern.
            route_partition_name: The partition.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the hunt pilot does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeHuntPilot(
                pattern=pattern, routePartitionName=route_partition_name
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Call Park
    # ═══════════════════════════════════════════════════════════════════

    def get_call_park(
        self,
        pattern: str,
        route_partition_name: str,
    ) -> Dict[str, Any]:
        """Retrieve a Call Park number.

        Args:
            pattern: The call park number pattern.
            route_partition_name: The partition.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getCallPark(
                pattern=pattern, routePartitionName=route_partition_name
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_call_park(
        self,
        pattern: str,
        route_partition_name: str,
        description: str = "",
        call_manager_name: str = "",
        calling_search_space_for_single_number_retrieval: str = "",
    ) -> Dict[str, Any]:
        """Add a new Call Park number.

        Args:
            pattern: The call park pattern (e.g. ``"3000"``).
            route_partition_name: The partition.
            description: Optional description.
            call_manager_name: The CallManager to associate with.
            calling_search_space_for_single_number_retrieval: CSS for
                call park retrieval.

        Returns:
            The AXL response dict.

        Raises:
            AXLDuplicateError: If the pattern already exists.
            AXLError: On other AXL faults.
        """
        cp_data: CallPark = {
            "pattern": pattern,
            "routePartitionName": route_partition_name,
            "description": description,
        }
        if call_manager_name:
            cp_data["callManagerName"] = call_manager_name
        if calling_search_space_for_single_number_retrieval:
            cp_data["callingSearchSpaceForSingleNumberRetrival"] = (
                calling_search_space_for_single_number_retrieval
            )
        try:
            return self._service.addCallPark(callPark=cp_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_call_park(
        self,
        pattern: str,
        route_partition_name: str,
    ) -> Dict[str, Any]:
        """Remove a Call Park number.

        Args:
            pattern: The call park pattern.
            route_partition_name: The partition.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeCallPark(
                pattern=pattern, routePartitionName=route_partition_name
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Call Pickup Group
    # ═══════════════════════════════════════════════════════════════════

    def get_call_pickup_group(self, name: str) -> Dict[str, Any]:
        """Retrieve a Call Pickup Group by name.

        Args:
            name: The Call Pickup Group name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getCallPickupGroup(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_call_pickup_group(
        self,
        name: str,
        pattern: str,
        route_partition_name: str = "",
        description: str = "",
        members: Optional[Sequence[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Add a new Call Pickup Group.

        Args:
            name: Name for the group.
            pattern: The pickup group number pattern.
            route_partition_name: The partition (optional).
            description: Optional description.
            members: Optional list of member line dicts.

        Returns:
            The AXL response dict.

        Raises:
            AXLDuplicateError: If a group with this name already exists.
            AXLError: On other AXL faults.

        Example::

            client.add_call_pickup_group(
                "Pickup-Floor1", "4000", "Internal-PT"
            )
        """
        cpg_data: CallPickupGroup = {
            "name": name,
            "pattern": pattern,
            "routePartitionName": route_partition_name,
            "description": description,
        }
        if members:
            cpg_data["members"] = {"member": list(members)}
        try:
            return self._service.addCallPickupGroup(callPickupGroup=cpg_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_call_pickup_group(self, **cpg_data: Unpack[UpdateCallPickupGroup]) -> Dict[str, Any]:
        """Update an existing Call Pickup Group.

        Args:
            **cpg_data: Keyword arguments for ``updateCallPickupGroup``.
                Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateCallPickupGroup(**cpg_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_call_pickup_group(self, name: str) -> Dict[str, Any]:
        """Remove a Call Pickup Group by name.

        Args:
            name: The Call Pickup Group name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeCallPickupGroup(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Region
    # ═══════════════════════════════════════════════════════════════════

    def get_region(self, name: str) -> Dict[str, Any]:
        """Retrieve a Region by name.

        Args:
            name: The Region name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getRegion(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_region(self, name: str) -> Dict[str, Any]:
        """Add a new Region.

        Args:
            name: Name for the Region.

        Returns:
            The AXL response dict.

        Raises:
            AXLDuplicateError: If a region with this name already exists.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.addRegion(region={"name": name})
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_region(self, **region_data: Unpack[UpdateRegion]) -> Dict[str, Any]:
        """Update an existing Region.

        Args:
            **region_data: Keyword arguments for ``updateRegion``.
                Must include ``name`` or ``uuid``.  To configure
                region relationships, include ``relatedRegions``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the region does not exist.
            AXLError: On other AXL faults.

        Example::

            client.update_region(
                name="Region-A",
                relatedRegions={
                    "relatedRegion": [
                        {
                            "regionName": "Region-B",
                            "bandwidth": "G.711",
                            "videoBandwidth": "-1",
                        }
                    ]
                },
            )
        """
        try:
            return self._service.updateRegion(**region_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_region(self, name: str) -> Dict[str, Any]:
        """Remove a Region by name.

        Args:
            name: The Region name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the region does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeRegion(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Location
    # ═══════════════════════════════════════════════════════════════════

    def get_location(self, name: str) -> Dict[str, Any]:
        """Retrieve a Location by name.

        Args:
            name: The Location name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getLocation(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_location(
        self,
        name: str,
        related_locations: Optional[Sequence[Dict[str, Any]]] = None,
        between_locations: Optional[Sequence[Dict[str, Any]]] = None,
        within_audio_bandwidth: int = 0,
        within_video_bandwidth: int = 0,
        within_immersive_kbits: int = 0,
    ) -> Dict[str, Any]:
        """Add a new Location for CAC (Call Admission Control).

        Args:
            name: Name for the Location.
            related_locations: Optional list of related location dicts::

                [
                    {
                        "locationName": "Hub_None",
                        "weight": 50,
                        "audioBandwidth": 80,
                        "videoBandwidth": 384,
                    }
                ]

            between_locations: Optional list of between-location dicts.
                Defaults to a single entry for ``Hub_None`` with unlimited
                bandwidth (``-1``)::

                    [
                        {
                            "locationName": "Hub_None",
                            "weight": 50,
                            "audioBandwidth": -1,
                            "videoBandwidth": 384,
                            "immersiveBandwidth": 384,
                        }
                    ]

            within_audio_bandwidth: Audio bandwidth within the location
                (``0`` = unlimited, ``-1`` = no limit).
            within_video_bandwidth: Video bandwidth within the location.
            within_immersive_kbits: Immersive bandwidth within the location.

        Returns:
            The AXL response dict.

        Raises:
            AXLDuplicateError: If a location with this name already exists.
            AXLError: On other AXL faults.
        """
        if between_locations is None:
            between_locations = [
                {
                    "locationName": "Hub_None",
                    "weight": 50,
                    "audioBandwidth": 0,
                    "videoBandwidth": 384,
                    "immersiveBandwidth": 384,
                }
            ]
        loc_data: Location = {
            "name": name,
            "withinAudioBandwidth": within_audio_bandwidth,
            "withinVideoBandwidth": within_video_bandwidth,
            "withinImmersiveKbits": within_immersive_kbits,
            "betweenLocations": {
                "betweenLocation": list(between_locations)
            },
        }
        if related_locations:
            loc_data["relatedLocations"] = {
                "relatedLocation": list(related_locations)
            }
        try:
            return self._service.addLocation(location=loc_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_location(self, **location_data: Unpack[UpdateLocation]) -> Dict[str, Any]:
        """Update an existing Location.

        Args:
            **location_data: Keyword arguments for ``updateLocation``.
                Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the location does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateLocation(**location_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_location(self, name: str) -> Dict[str, Any]:
        """Remove a Location by name.

        Args:
            name: The Location name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the location does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeLocation(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Date/Time Group
    # ═══════════════════════════════════════════════════════════════════

    def get_date_time_group(self, name: str) -> Dict[str, Any]:
        """Retrieve a Date/Time Group by name.

        Args:
            name: The Date/Time Group name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getDateTimeGroup(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_date_time_group(
        self,
        name: str,
        time_zone: str,
        separator: str = "-",
        date_format: str = "M-D-Y",
        time_format: str = "12-hour",
    ) -> Dict[str, Any]:
        """Add a new Date/Time Group.

        Args:
            name: Name for the group.
            time_zone: Time zone identifier (e.g. ``"America/New_York"``).
            separator: Date separator character.
            date_format: Date format (e.g. ``"M-D-Y"``).
            time_format: ``"12-hour"`` or ``"24-hour"``.

        Returns:
            The AXL response dict.

        Raises:
            AXLDuplicateError: If a group with this name exists.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.addDateTimeGroup(
                dateTimeGroup={
                    "name": name,
                    "timeZone": time_zone,
                    "separator": separator,
                    "dateformat": date_format,
                    "timeFormat": time_format,
                }
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_date_time_group(self, **dtg_data: Unpack[UpdateDateTimeGroup]) -> Dict[str, Any]:
        """Update an existing Date/Time Group.

        Args:
            **dtg_data: Keyword arguments for ``updateDateTimeGroup``.
                Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the group does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateDateTimeGroup(**dtg_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_date_time_group(self, name: str) -> Dict[str, Any]:
        """Remove a Date/Time Group by name.

        Args:
            name: The Date/Time Group name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the group does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeDateTimeGroup(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  SRST (Survivable Remote Site Telephony)
    # ═══════════════════════════════════════════════════════════════════

    def get_srst(self, name: str) -> Dict[str, Any]:
        """Retrieve an SRST reference by name.

        Args:
            name: The SRST name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getSrst(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_srst(
        self,
        name: str,
        ip_address: str,
        port: int = 2000,
        sip_port: int = 5060,
        is_secure: bool = False,
    ) -> Dict[str, Any]:
        """Add a new SRST reference.

        Args:
            name: Name for the SRST reference.
            ip_address: IP address of the SRST router.
            port: SCCP port (default 2000).
            sip_port: SIP port (default 5060).
            is_secure: Whether the SRST is secure.

        Returns:
            The AXL response dict.

        Raises:
            AXLDuplicateError: If an SRST with this name exists.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.addSrst(
                srst={
                    "name": name,
                    "ipAddress": ip_address,
                    "port": port,
                    "SipPort": sip_port,
                    "isSecure": is_secure,
                }
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_srst(self, **srst_data: Unpack[UpdateSrst]) -> Dict[str, Any]:
        """Update an existing SRST reference.

        Args:
            **srst_data: Keyword arguments for ``updateSrst``.
                Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the SRST does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateSrst(**srst_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_srst(self, name: str) -> Dict[str, Any]:
        """Remove an SRST reference by name.

        Args:
            name: The SRST name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the SRST does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeSrst(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Phone NTP Reference
    # ═══════════════════════════════════════════════════════════════════

    def get_phone_ntp(self, name: str) -> Dict[str, Any]:
        """Retrieve a Phone NTP Reference by name.

        Args:
            name: The Phone NTP Reference name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getPhoneNtp(ipAddress=name, ipv6Address="")
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_phone_ntp(
        self,
        ip_address: str = "",
        description: str = "",
        mode: str = "Unicast",
        ipv6_address: str = "",
    ) -> Dict[str, Any]:
        """Add a new Phone NTP Reference.

        Args:
            ip_address: IPv4 address or hostname of the NTP server.
                Either *ip_address* or *ipv6_address* must be provided.
            description: Optional description.
            mode: ``"Unicast"``, ``"Multicast"``, or ``"Anycast"``.
            ipv6_address: IPv6 address of the NTP server.

        Returns:
            The AXL response dict.

        Raises:
            AXLDuplicateError: If this NTP reference already exists.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.addPhoneNtp(
                phoneNtp={
                    "ipAddress": ip_address,
                    "ipv6Address": ipv6_address,
                    "description": description,
                    "mode": mode,
                }
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_phone_ntp(self, ip_address: str) -> Dict[str, Any]:
        """Remove a Phone NTP Reference.

        Args:
            ip_address: IP address of the NTP reference to remove.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removePhoneNtp(ipAddress=ip_address, ipv6Address="")
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Common Device Config
    # ═══════════════════════════════════════════════════════════════════

    def get_common_device_config(self, name: str) -> Dict[str, Any]:
        """Retrieve a Common Device Configuration by name.

        Args:
            name: The Common Device Config name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getCommonDeviceConfig(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_common_device_config(
        self,
        common_device_config_data: CommonDeviceConfig,
    ) -> Dict[str, Any]:
        """Add a new Common Device Configuration.

        Args:
            common_device_config_data: A dict describing the config.
                Must include at minimum ``name``.

        Returns:
            The AXL response dict.

        Raises:
            AXLDuplicateError: If a config with this name exists.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.addCommonDeviceConfig(
                commonDeviceConfig=common_device_config_data
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_common_device_config(self, **cdc_data: Unpack[UpdateCommonDeviceConfig]) -> Dict[str, Any]:
        """Update an existing Common Device Configuration.

        Args:
            **cdc_data: Keyword arguments for ``updateCommonDeviceConfig``.
                Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateCommonDeviceConfig(**cdc_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_common_device_config(self, name: str) -> Dict[str, Any]:
        """Remove a Common Device Configuration by name.

        Args:
            name: The Common Device Config name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeCommonDeviceConfig(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Common Phone Config
    # ═══════════════════════════════════════════════════════════════════

    def get_common_phone_config(self, name: str) -> Dict[str, Any]:
        """Retrieve a Common Phone Configuration by name.

        Args:
            name: The Common Phone Config name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getCommonPhoneConfig(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_common_phone_config(
        self,
        common_phone_config_data: CommonPhoneConfig,
    ) -> Dict[str, Any]:
        """Add a new Common Phone Configuration.

        Args:
            common_phone_config_data: A dict describing the config.
                Must include at minimum ``name``.

        Returns:
            The AXL response dict.

        Raises:
            AXLDuplicateError: If a config with this name exists.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.addCommonPhoneConfig(
                commonPhoneConfig=common_phone_config_data
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_common_phone_config(self, **cpc_data: Unpack[UpdateCommonPhoneConfig]) -> Dict[str, Any]:
        """Update an existing Common Phone Configuration.

        Args:
            **cpc_data: Keyword arguments for ``updateCommonPhoneConfig``.
                Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateCommonPhoneConfig(**cpc_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_common_phone_config(self, name: str) -> Dict[str, Any]:
        """Remove a Common Phone Configuration by name.

        Args:
            name: The Common Phone Config name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeCommonPhoneConfig(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  CTI Route Point
    # ═══════════════════════════════════════════════════════════════════

    def get_cti_route_point(self, name: str) -> Dict[str, Any]:
        """Retrieve a CTI Route Point by name.

        Args:
            name: The CTI Route Point name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getCtiRoutePoint(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_cti_route_point(
        self,
        cti_route_point_data: CtiRoutePoint,
        line_data: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Add a new CTI Route Point.

        Args:
            cti_route_point_data: A dict describing the CTI Route Point.
                Required keys include ``name``, ``product``
                (``"CTI Route Point"``), ``class`` (``"CTI Route Point"``),
                ``protocol`` (``"SCCP"`` or ``"SIP"``),
                ``protocolSide`` (``"User"``), ``devicePoolName``.
            line_data: Optional list of line association dicts, same as
                :meth:`add_phone`.

        Returns:
            The AXL response dict.

        Raises:
            AXLDuplicateError: If the name already exists.
            AXLError: On other AXL faults.

        Example::

            client.add_cti_route_point({
                "name": "CTI-RP-IVR",
                "product": "CTI Route Point",
                "class": "CTI Route Point",
                "protocol": "SCCP",
                "protocolSide": "User",
                "devicePoolName": "Default",
            }, line_data=[
                {"index": 1, "dirn": {"pattern": "5000", "routePartitionName": "Internal-PT"}}
            ])
        """
        if line_data is not None:
            cti_route_point_data["lines"] = {"line": line_data}
        try:
            return self._service.addCtiRoutePoint(
                ctiRoutePoint=cti_route_point_data
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_cti_route_point(self, **cti_rp_data: Unpack[UpdateCtiRoutePoint]) -> Dict[str, Any]:
        """Update an existing CTI Route Point.

        Args:
            **cti_rp_data: Keyword arguments for ``updateCtiRoutePoint``.
                Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateCtiRoutePoint(**cti_rp_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_cti_route_point(self, name: str) -> Dict[str, Any]:
        """Remove a CTI Route Point by name.

        Args:
            name: The CTI Route Point name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeCtiRoutePoint(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  H.323 Gateway
    # ═══════════════════════════════════════════════════════════════════

    def get_h323_gateway(self, name: str) -> Dict[str, Any]:
        """Retrieve an H.323 Gateway by name.

        Args:
            name: The gateway name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getH323Gateway(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_h323_gateway(
        self,
        h323_gateway_data: H323Gateway,
    ) -> Dict[str, Any]:
        """Add a new H.323 Gateway.

        Args:
            h323_gateway_data: A dict describing the H.323 gateway.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addH323Gateway(h323Gateway=h323_gateway_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_h323_gateway(self, **gw_data: Unpack[UpdateH323Gateway]) -> Dict[str, Any]:
        """Update an existing H.323 Gateway.

        Args:
            **gw_data: Keyword arguments for ``updateH323Gateway``.
                Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateH323Gateway(**gw_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_h323_gateway(self, name: str) -> Dict[str, Any]:
        """Remove an H.323 Gateway by name.

        Args:
            name: The gateway name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeH323Gateway(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  H.323 Trunk
    # ═══════════════════════════════════════════════════════════════════

    def get_h323_trunk(self, name: str) -> Dict[str, Any]:
        """Retrieve an H.323 Trunk by name.

        Args:
            name: The trunk name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getH323Trunk(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_h323_trunk(
        self,
        h323_trunk_data: H323Trunk,
    ) -> Dict[str, Any]:
        """Add a new H.323 Trunk.

        Args:
            h323_trunk_data: A dict describing the H.323 trunk.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addH323Trunk(h323Trunk=h323_trunk_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_h323_trunk(self, **trunk_data: Unpack[UpdateH323Trunk]) -> Dict[str, Any]:
        """Update an existing H.323 Trunk.

        Args:
            **trunk_data: Keyword arguments for ``updateH323Trunk``.
                Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateH323Trunk(**trunk_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_h323_trunk(self, name: str) -> Dict[str, Any]:
        """Remove an H.323 Trunk by name.

        Args:
            name: The trunk name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeH323Trunk(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Transcoder
    # ═══════════════════════════════════════════════════════════════════

    def get_transcoder(self, name: str) -> Dict[str, Any]:
        """Retrieve a Transcoder by name.

        Args:
            name: The transcoder name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getTranscoder(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_transcoder(
        self,
        transcoder_data: Transcoder,
    ) -> Dict[str, Any]:
        """Add a new Transcoder.

        Args:
            transcoder_data: A dict describing the transcoder.  Required
                keys include ``name``, ``product``, ``devicePoolName``.

        Returns:
            The AXL response dict.

        Raises:
            AXLDuplicateError: If a transcoder with this name exists.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.addTranscoder(transcoder=transcoder_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_transcoder(self, **transcoder_data: Unpack[UpdateTranscoder]) -> Dict[str, Any]:
        """Update an existing Transcoder.

        Args:
            **transcoder_data: Keyword arguments for ``updateTranscoder``.
                Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateTranscoder(**transcoder_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_transcoder(self, name: str) -> Dict[str, Any]:
        """Remove a Transcoder by name.

        Args:
            name: The transcoder name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeTranscoder(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  MTP (Media Termination Point)
    # ═══════════════════════════════════════════════════════════════════

    def get_mtp(self, name: str) -> Dict[str, Any]:
        """Retrieve an MTP by name.

        Args:
            name: The MTP name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getMtp(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_mtp(
        self,
        mtp_data: Mtp,
    ) -> Dict[str, Any]:
        """Add a new Media Termination Point (MTP).

        Args:
            mtp_data: A dict describing the MTP.  Required keys include
                ``name``, ``product``, ``devicePoolName``.

        Returns:
            The AXL response dict.

        Raises:
            AXLDuplicateError: If an MTP with this name exists.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.addMtp(mtp=mtp_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_mtp(self, **mtp_data: Unpack[UpdateMtp]) -> Dict[str, Any]:
        """Update an existing MTP.

        Args:
            **mtp_data: Keyword arguments for ``updateMtp``.
                Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateMtp(**mtp_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_mtp(self, name: str) -> Dict[str, Any]:
        """Remove an MTP by name.

        Args:
            name: The MTP name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeMtp(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Voicemail Pilot / Profile / Port
    # ═══════════════════════════════════════════════════════════════════

    def get_voicemail_pilot(self, dir_n: str) -> Dict[str, Any]:
        """Retrieve a Voicemail Pilot by directory number.

        Args:
            dir_n: The voicemail pilot number.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getVoiceMailPilot(dirn=dir_n)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_voicemail_pilot(
        self,
        dir_n: str,
        description: str = "",
        calling_search_space_name: str = "",
        is_default: bool = False,
    ) -> Dict[str, Any]:
        """Add a new Voicemail Pilot.

        Args:
            dir_n: The voicemail pilot number.
            description: Optional description.
            calling_search_space_name: CSS for the pilot.
            is_default: Whether this is the default pilot.

        Returns:
            The AXL response dict.

        Raises:
            AXLDuplicateError: If the pilot already exists.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.addVoiceMailPilot(
                voiceMailPilot={
                    "dirn": dir_n,
                    "description": description,
                    "cssName": calling_search_space_name,
                    "isDefault": is_default,
                }
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_voicemail_pilot(self, dir_n: str) -> Dict[str, Any]:
        """Remove a Voicemail Pilot.

        Args:
            dir_n: The voicemail pilot number.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeVoiceMailPilot(dirn=dir_n)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def get_voicemail_profile(self, name: str) -> Dict[str, Any]:
        """Retrieve a Voicemail Profile by name.

        Args:
            name: The Voicemail Profile name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getVoiceMailProfile(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_voicemail_profile(
        self,
        name: str,
        description: str = "",
        voicemail_pilot_name: str = "",
        is_default: bool = False,
    ) -> Dict[str, Any]:
        """Add a new Voicemail Profile.

        Args:
            name: Name for the profile.
            description: Optional description.
            voicemail_pilot_name: Associated Voicemail Pilot number.
            is_default: Whether this is the default profile.

        Returns:
            The AXL response dict.

        Raises:
            AXLDuplicateError: If a profile with this name exists.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.addVoiceMailProfile(
                voiceMailProfile={
                    "name": name,
                    "description": description,
                    "voiceMailPilot": voicemail_pilot_name,
                    "isDefault": is_default,
                }
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_voicemail_profile(self, name: str) -> Dict[str, Any]:
        """Remove a Voicemail Profile by name.

        Args:
            name: The Voicemail Profile name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeVoiceMailProfile(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def get_voicemail_port(self, name: str) -> Dict[str, Any]:
        """Retrieve a Voicemail Port by name.

        Args:
            name: The voicemail port device name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getVoiceMailPort(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_voicemail_port(
        self,
        voicemail_port_data: VoiceMailPort,
    ) -> Dict[str, Any]:
        """Add a new Voicemail Port.

        Args:
            voicemail_port_data: A dict describing the voicemail port.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addVoiceMailPort(
                voiceMailPort=voicemail_port_data
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_voicemail_port(self, name: str) -> Dict[str, Any]:
        """Remove a Voicemail Port by name.

        Args:
            name: The voicemail port device name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeVoiceMailPort(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Application User
    # ═══════════════════════════════════════════════════════════════════

    def get_app_user(self, userid: str) -> Dict[str, Any]:
        """Retrieve an Application User by user ID.

        Args:
            userid: The application user ID.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If the user does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getAppUser(userid=userid)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_app_user(
        self,
        userid: str,
        password: str = "",
        associated_devices: Optional[Sequence[str]] = None,
        associated_groups: Optional[Sequence[str]] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """Add a new Application User.

        Args:
            userid: The application user ID.
            password: Password for the user.
            associated_devices: Optional list of device names to associate.
            associated_groups: Optional list of user group names to assign.
            **kwargs: Additional fields for ``addAppUser``.

        Returns:
            The AXL response dict.

        Raises:
            AXLDuplicateError: If the user already exists.
            AXLError: On other AXL faults.

        Example::

            client.add_app_user(
                "jtapi_user",
                password="secret",
                associated_devices=["CTI-RP-IVR"],
                associated_groups=["Standard CTI Enabled"],
            )
        """
        app_user_data: AppUser = {
            "userid": userid,
            "password": password,
            **kwargs,
        }
        if associated_devices:
            app_user_data["associatedDevices"] = {
                "device": list(associated_devices)
            }
        if associated_groups:
            app_user_data["associatedGroups"] = {
                "userGroup": [
                    {"name": g} for g in associated_groups
                ]
            }
        try:
            return self._service.addAppUser(appUser=app_user_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_app_user(self, **app_user_data: Unpack[UpdateAppUser]) -> Dict[str, Any]:
        """Update an existing Application User.

        Args:
            **app_user_data: Keyword arguments for ``updateAppUser``.
                Must include ``userid`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the user does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateAppUser(**app_user_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_app_user(self, userid: str) -> Dict[str, Any]:
        """Remove an Application User by user ID.

        Args:
            userid: The application user ID.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If the user does not exist.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeAppUser(userid=userid)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  User Group (Access Control Group)
    # ═══════════════════════════════════════════════════════════════════

    def get_user_group(self, name: str) -> Dict[str, Any]:
        """Retrieve a User Group (Access Control Group) by name.

        Args:
            name: The User Group name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getUserGroup(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_user_group(
        self,
        name: str,
        members: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        """Add a new User Group (Access Control Group).

        Args:
            name: Name for the User Group.
            members: Optional list of user IDs to include.

        Returns:
            The AXL response dict.

        Raises:
            AXLDuplicateError: If a group with this name exists.
            AXLError: On other AXL faults.
        """
        ug_data: UserGroup = {"name": name}
        if members:
            ug_data["members"] = {
                "member": [{"userId": uid} for uid in members]
            }
        try:
            return self._service.addUserGroup(userGroup=ug_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_user_group(self, **ug_data: Unpack[UpdateUserGroup]) -> Dict[str, Any]:
        """Update an existing User Group.

        Args:
            **ug_data: Keyword arguments for ``updateUserGroup``.
                Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateUserGroup(**ug_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_user_group(self, name: str) -> Dict[str, Any]:
        """Remove a User Group by name.

        Args:
            name: The User Group name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeUserGroup(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Device Profile (Extension Mobility)
    # ═══════════════════════════════════════════════════════════════════

    def get_device_profile(self, name: str) -> Dict[str, Any]:
        """Retrieve a Device Profile (Extension Mobility) by name.

        Args:
            name: The device profile name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getDeviceProfile(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_device_profile(
        self,
        device_profile_data: DeviceProfile,
        line_data: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Add a new Device Profile for Extension Mobility.

        Args:
            device_profile_data: A dict describing the profile.  Required
                keys include ``name``, ``product``, ``class`` (``"Device Profile"``),
                ``protocol``, ``protocolSide`` (``"User"``),
                ``phoneTemplateName``.
            line_data: Optional list of line association dicts.

        Returns:
            The AXL response dict.

        Raises:
            AXLDuplicateError: If the name already exists.
            AXLError: On other AXL faults.

        Example::

            client.add_device_profile({
                "name": "DP-jsmith-8845",
                "product": "Cisco 8845",
                "class": "Device Profile",
                "protocol": "SIP",
                "protocolSide": "User",
                "phoneTemplateName": "Standard 8845 SIP",
            }, line_data=[
                {"index": 1, "dirn": {"pattern": "1001", "routePartitionName": "Internal-PT"}}
            ])
        """
        if line_data is not None:
            device_profile_data["lines"] = {"line": line_data}
        try:
            return self._service.addDeviceProfile(
                deviceProfile=device_profile_data
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_device_profile(self, **dp_data: Unpack[UpdateDeviceProfile]) -> Dict[str, Any]:
        """Update an existing Device Profile.

        Args:
            **dp_data: Keyword arguments for ``updateDeviceProfile``.
                Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateDeviceProfile(**dp_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_device_profile(self, name: str) -> Dict[str, Any]:
        """Remove a Device Profile by name.

        Args:
            name: The device profile name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeDeviceProfile(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Route Filter
    # ═══════════════════════════════════════════════════════════════════

    def get_route_filter(self, name: str) -> Dict[str, Any]:
        """Retrieve a Route Filter by name.

        Args:
            name: The Route Filter name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getRouteFilter(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_route_filter(
        self,
        route_filter_data: RouteFilter,
    ) -> Dict[str, Any]:
        """Add a new Route Filter.

        Args:
            route_filter_data: A dict describing the route filter.
                Must include ``name`` and ``dialPlanName``.

        Returns:
            The AXL response dict.

        Raises:
            AXLDuplicateError: If a filter with this name exists.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.addRouteFilter(
                routeFilter=route_filter_data
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_route_filter(self, **rf_data: Unpack[UpdateRouteFilter]) -> Dict[str, Any]:
        """Update an existing Route Filter.

        Args:
            **rf_data: Keyword arguments for ``updateRouteFilter``.
                Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateRouteFilter(**rf_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_route_filter(self, name: str) -> Dict[str, Any]:
        """Remove a Route Filter by name.

        Args:
            name: The Route Filter name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeRouteFilter(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Calling Party Transformation Pattern
    # ═══════════════════════════════════════════════════════════════════

    def get_calling_party_transformation_pattern(
        self,
        pattern: str,
        route_partition_name: str,
    ) -> Dict[str, Any]:
        """Retrieve a Calling Party Transformation Pattern.

        Args:
            pattern: The pattern string.
            route_partition_name: The partition.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getCallingPartyTransformationPattern(
                pattern=pattern, routePartitionName=route_partition_name
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_calling_party_transformation_pattern(
        self,
        pattern: str,
        route_partition_name: str,
        calling_party_transformation_mask: str = "",
        calling_party_prefix_digits: str = "",
        **kwargs,
    ) -> Dict[str, Any]:
        """Add a new Calling Party Transformation Pattern.

        Args:
            pattern: The pattern string.
            route_partition_name: The partition.
            calling_party_transformation_mask: Transformation mask.
            calling_party_prefix_digits: Prefix digits.
            **kwargs: Additional fields.

        Returns:
            The AXL response dict.

        Raises:
            AXLDuplicateError: If the pattern already exists.
            AXLError: On other AXL faults.
        """
        tp_data = {
            "pattern": pattern,
            "routePartitionName": route_partition_name,
            "callingPartyTransformationMask": calling_party_transformation_mask,
            "callingPartyPrefixDigits": calling_party_prefix_digits,
            **kwargs,
        }
        try:
            return self._service.addCallingPartyTransformationPattern(
                callingPartyTransformationPattern=tp_data
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_calling_party_transformation_pattern(
        self,
        pattern: str,
        route_partition_name: str,
    ) -> Dict[str, Any]:
        """Remove a Calling Party Transformation Pattern.

        Args:
            pattern: The pattern string.
            route_partition_name: The partition.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeCallingPartyTransformationPattern(
                pattern=pattern, routePartitionName=route_partition_name
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Called Party Transformation Pattern
    # ═══════════════════════════════════════════════════════════════════

    def get_called_party_transformation_pattern(
        self,
        pattern: str,
        route_partition_name: str,
    ) -> Dict[str, Any]:
        """Retrieve a Called Party Transformation Pattern.

        Args:
            pattern: The pattern string.
            route_partition_name: The partition.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getCalledPartyTransformationPattern(
                pattern=pattern, routePartitionName=route_partition_name
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_called_party_transformation_pattern(
        self,
        pattern: str,
        route_partition_name: str,
        called_party_transformation_mask: str = "",
        called_party_prefix_digits: str = "",
        **kwargs,
    ) -> Dict[str, Any]:
        """Add a new Called Party Transformation Pattern.

        Args:
            pattern: The pattern string.
            route_partition_name: The partition.
            called_party_transformation_mask: Transformation mask.
            called_party_prefix_digits: Prefix digits.
            **kwargs: Additional fields.

        Returns:
            The AXL response dict.

        Raises:
            AXLDuplicateError: If the pattern already exists.
            AXLError: On other AXL faults.
        """
        tp_data = {
            "pattern": pattern,
            "routePartitionName": route_partition_name,
            "calledPartyTransformationMask": called_party_transformation_mask,
            "calledPartyPrefixDigits": called_party_prefix_digits,
            **kwargs,
        }
        try:
            return self._service.addCalledPartyTransformationPattern(
                calledPartyTransformationPattern=tp_data
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_called_party_transformation_pattern(
        self,
        pattern: str,
        route_partition_name: str,
    ) -> Dict[str, Any]:
        """Remove a Called Party Transformation Pattern.

        Args:
            pattern: The pattern string.
            route_partition_name: The partition.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeCalledPartyTransformationPattern(
                pattern=pattern, routePartitionName=route_partition_name
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Presence Group
    # ═══════════════════════════════════════════════════════════════════

    def get_presence_group(self, name: str) -> Dict[str, Any]:
        """Retrieve a Presence Group by name.

        Args:
            name: The Presence Group name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getPresenceGroup(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_presence_group(
        self,
        name: str,
        description: str = "",
    ) -> Dict[str, Any]:
        """Add a new Presence Group.

        Args:
            name: Name for the Presence Group.
            description: Optional description.

        Returns:
            The AXL response dict.

        Raises:
            AXLDuplicateError: If a group with this name exists.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.addPresenceGroup(
                presenceGroup={"name": name, "description": description}
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_presence_group(self, name: str) -> Dict[str, Any]:
        """Remove a Presence Group by name.

        Args:
            name: The Presence Group name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removePresenceGroup(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Credential Policy
    # ═══════════════════════════════════════════════════════════════════

    def get_credential_policy(self, name: str) -> Dict[str, Any]:
        """Retrieve a Credential Policy by name.

        Args:
            name: The Credential Policy name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getCredentialPolicy(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_credential_policy(self, **cp_data: Unpack[UpdateCredentialPolicy]) -> Dict[str, Any]:
        """Update an existing Credential Policy.

        Args:
            **cp_data: Keyword arguments for ``updateCredentialPolicy``.
                Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateCredentialPolicy(**cp_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Phone Button Template
    # ═══════════════════════════════════════════════════════════════════

    def get_phone_button_template(self, name: str) -> Dict[str, Any]:
        """Retrieve a Phone Button Template by name.

        Args:
            name: The Phone Button Template name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getPhoneButtonTemplate(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_phone_button_template(
        self,
        phone_button_template_data: PhoneButtonTemplate,
    ) -> Dict[str, Any]:
        """Add a new Phone Button Template.

        Args:
            phone_button_template_data: A dict describing the template.

        Returns:
            The AXL response dict.

        Raises:
            AXLDuplicateError: If the template already exists.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.addPhoneButtonTemplate(
                phoneButtonTemplate=phone_button_template_data
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_phone_button_template(self, **pbt_data: Unpack[UpdatePhoneButtonTemplate]) -> Dict[str, Any]:
        """Update an existing Phone Button Template.

        Args:
            **pbt_data: Keyword arguments for ``updatePhoneButtonTemplate``.
                Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updatePhoneButtonTemplate(**pbt_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_phone_button_template(self, name: str) -> Dict[str, Any]:
        """Remove a Phone Button Template by name.

        Args:
            name: The Phone Button Template name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removePhoneButtonTemplate(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Soft Key Template
    # ═══════════════════════════════════════════════════════════════════

    def get_soft_key_template(self, name: str) -> Dict[str, Any]:
        """Retrieve a Soft Key Template by name.

        Args:
            name: The Soft Key Template name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getSoftKeyTemplate(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_soft_key_template(
        self,
        soft_key_template_data: SoftKeyTemplate,
    ) -> Dict[str, Any]:
        """Add a new Soft Key Template.

        Args:
            soft_key_template_data: A dict describing the template.

        Returns:
            The AXL response dict.

        Raises:
            AXLDuplicateError: If the template already exists.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.addSoftKeyTemplate(
                softKeyTemplate=soft_key_template_data
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_soft_key_template(self, name: str) -> Dict[str, Any]:
        """Remove a Soft Key Template by name.

        Args:
            name: The Soft Key Template name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeSoftKeyTemplate(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Service Profile / UC Service
    # ═══════════════════════════════════════════════════════════════════

    def get_service_profile(self, name: str) -> Dict[str, Any]:
        """Retrieve a Service Profile by name.

        Args:
            name: The Service Profile name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getServiceProfile(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_service_profile(
        self,
        service_profile_data: ServiceProfile,
    ) -> Dict[str, Any]:
        """Add a new Service Profile.

        Args:
            service_profile_data: A dict describing the profile.

        Returns:
            The AXL response dict.

        Raises:
            AXLDuplicateError: If the profile already exists.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.addServiceProfile(
                serviceProfile=service_profile_data
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_service_profile(self, **sp_data: Unpack[UpdateServiceProfile]) -> Dict[str, Any]:
        """Update an existing Service Profile.

        Args:
            **sp_data: Keyword arguments for ``updateServiceProfile``.
                Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateServiceProfile(**sp_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_service_profile(self, name: str) -> Dict[str, Any]:
        """Remove a Service Profile by name.

        Args:
            name: The Service Profile name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeServiceProfile(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def get_uc_service(self, name: str) -> Dict[str, Any]:
        """Retrieve a UC Service by name.

        Args:
            name: The UC Service name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getUcService(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_uc_service(
        self,
        uc_service_data: UcService,
    ) -> Dict[str, Any]:
        """Add a new UC Service.

        Args:
            uc_service_data: A dict describing the UC service.

        Returns:
            The AXL response dict.

        Raises:
            AXLDuplicateError: If the service already exists.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.addUcService(ucService=uc_service_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_uc_service(self, **ucs_data: Unpack[UpdateUcService]) -> Dict[str, Any]:
        """Update an existing UC Service.

        Args:
            **ucs_data: Keyword arguments for ``updateUcService``.
                Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateUcService(**ucs_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_uc_service(self, name: str) -> Dict[str, Any]:
        """Remove a UC Service by name.

        Args:
            name: The UC Service name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeUcService(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Announcement
    # ═══════════════════════════════════════════════════════════════════

    def get_announcement(self, name: str) -> Dict[str, Any]:
        """Retrieve an Announcement by name.

        Args:
            name: The Announcement name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getAnnouncement(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_announcement(
        self,
        announcement_data: Announcement,
    ) -> Dict[str, Any]:
        """Add a new Announcement.

        Args:
            announcement_data: A dict describing the announcement.

        Returns:
            The AXL response dict.

        Raises:
            AXLDuplicateError: If the announcement already exists.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.addAnnouncement(
                announcement=announcement_data
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_announcement(self, name: str) -> Dict[str, Any]:
        """Remove an Announcement by name.

        Args:
            name: The Announcement name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeAnnouncement(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Remote Destination Profile
    # ═══════════════════════════════════════════════════════════════════

    def get_remote_destination_profile(self, name: str) -> Dict[str, Any]:
        """Retrieve a Remote Destination Profile by name.

        Args:
            name: The Remote Destination Profile name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getRemoteDestinationProfile(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_remote_destination_profile(
        self,
        rdp_data: RemoteDestinationProfile,
        line_data: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Add a new Remote Destination Profile.

        Args:
            rdp_data: A dict describing the profile.
            line_data: Optional list of line association dicts.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if line_data is not None:
            rdp_data["lines"] = {"line": line_data}
        try:
            return self._service.addRemoteDestinationProfile(
                remoteDestinationProfile=rdp_data
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_remote_destination_profile(self, **rdp_data: Unpack[UpdateRemoteDestinationProfile]) -> Dict[str, Any]:
        """Update an existing Remote Destination Profile.

        Args:
            **rdp_data: Keyword arguments for ``updateRemoteDestinationProfile``.
                Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateRemoteDestinationProfile(**rdp_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_remote_destination_profile(self, name: str) -> Dict[str, Any]:
        """Remove a Remote Destination Profile by name.

        Args:
            name: The Remote Destination Profile name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeRemoteDestinationProfile(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  AarGroup
    # ═══════════════════════════════════════════════════════════════════

    def get_aar_group(self, name: str) -> Dict[str, Any]:
        """Retrieve a AarGroup by name.

        Args:
            name: The AarGroup name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getAarGroup(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_aar_group(self, aar_group_data: AarGroup) -> Dict[str, Any]:
        """Add a new AarGroup.

        Args:
            aar_group_data: A dict describing the AarGroup.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addAarGroup(aarGroup=aar_group_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_aar_group(self, **kwargs: Unpack[UpdateAarGroup]) -> Dict[str, Any]:
        """Update an existing AarGroup.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateAarGroup(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_aar_group(self, name: str) -> Dict[str, Any]:
        """Remove a AarGroup by name.

        Args:
            name: The AarGroup name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeAarGroup(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_aar_group(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List AarGroup objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listAarGroup(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  AdvertisedPatterns
    # ═══════════════════════════════════════════════════════════════════

    def get_advertised_patterns(self, name: str) -> Dict[str, Any]:
        """Retrieve a AdvertisedPatterns by name.

        Args:
            name: The AdvertisedPatterns name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getAdvertisedPatterns(pattern=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_advertised_patterns(self, advertised_patterns_data: AdvertisedPatterns) -> Dict[str, Any]:
        """Add a new AdvertisedPatterns.

        Args:
            advertised_patterns_data: A dict describing the AdvertisedPatterns.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addAdvertisedPatterns(advertisedPatterns=advertised_patterns_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_advertised_patterns(self, **kwargs: Unpack[UpdateAdvertisedPatterns]) -> Dict[str, Any]:
        """Update an existing AdvertisedPatterns.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateAdvertisedPatterns(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_advertised_patterns(self, name: str) -> Dict[str, Any]:
        """Remove a AdvertisedPatterns by name.

        Args:
            name: The AdvertisedPatterns name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeAdvertisedPatterns(pattern=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_advertised_patterns(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List AdvertisedPatterns objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listAdvertisedPatterns(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Announcement
    # ═══════════════════════════════════════════════════════════════════

    def update_announcement(self, **kwargs: Unpack[UpdateAnnouncement]) -> Dict[str, Any]:
        """Update an existing Announcement.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateAnnouncement(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_announcement(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List Announcement objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listAnnouncement(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  AppServerInfo
    # ═══════════════════════════════════════════════════════════════════

    def get_app_server_info(self, **kwargs) -> Dict[str, Any]:
        """Retrieve an AppServerInfo.

        Args:
            **kwargs: Must include ``uuid``.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getAppServerInfo(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_app_server_info(self, app_server_info_data: AppServerInfo) -> Dict[str, Any]:
        """Add a new AppServerInfo.

        Args:
            app_server_info_data: A dict describing the AppServerInfo.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addAppServerInfo(appServerInfo=app_server_info_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_app_server_info(self, **kwargs: Unpack[UpdateAppServerInfo]) -> Dict[str, Any]:
        """Update an existing AppServerInfo.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateAppServerInfo(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_app_server_info(self, **kwargs) -> Dict[str, Any]:
        """Remove an AppServerInfo.

        Args:
            **kwargs: Must include ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeAppServerInfo(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  AppUser
    # ═══════════════════════════════════════════════════════════════════

    def list_app_user(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List AppUser objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listAppUser(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  ApplicationDialRules
    # ═══════════════════════════════════════════════════════════════════

    def get_application_dial_rules(self, name: str) -> Dict[str, Any]:
        """Retrieve a ApplicationDialRules by name.

        Args:
            name: The ApplicationDialRules name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getApplicationDialRules(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_application_dial_rules(self, application_dial_rules_data: ApplicationDialRules) -> Dict[str, Any]:
        """Add a new ApplicationDialRules.

        Args:
            application_dial_rules_data: A dict describing the ApplicationDialRules.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addApplicationDialRules(applicationDialRules=application_dial_rules_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_application_dial_rules(self, **kwargs: Unpack[UpdateApplicationDialRules]) -> Dict[str, Any]:
        """Update an existing ApplicationDialRules.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateApplicationDialRules(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_application_dial_rules(self, name: str) -> Dict[str, Any]:
        """Remove a ApplicationDialRules by name.

        Args:
            name: The ApplicationDialRules name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeApplicationDialRules(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_application_dial_rules(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List ApplicationDialRules objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listApplicationDialRules(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  ApplicationServer
    # ═══════════════════════════════════════════════════════════════════

    def get_application_server(self, uuid: str) -> Dict[str, Any]:
        """Retrieve an ApplicationServer by UUID.

        Args:
            uuid: The ApplicationServer UUID.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getApplicationServer(uuid=uuid)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_application_server(self, application_server_data: ApplicationServer) -> Dict[str, Any]:
        """Add a new ApplicationServer.

        Args:
            application_server_data: A dict describing the ApplicationServer.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addApplicationServer(applicationServer=application_server_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_application_server(self, **kwargs: Unpack[UpdateApplicationServer]) -> Dict[str, Any]:
        """Update an existing ApplicationServer.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateApplicationServer(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_application_server(self, uuid: str) -> Dict[str, Any]:
        """Remove an ApplicationServer by UUID.

        Args:
            uuid: The ApplicationServer UUID.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeApplicationServer(uuid=uuid)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_application_server(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List ApplicationServer objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listApplicationServer(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  ApplicationToSoftkeyTemplate
    # ═══════════════════════════════════════════════════════════════════

    def add_application_to_softkey_template(self, application_to_softkey_template_data: ApplicationToSoftKeyTemplate) -> Dict[str, Any]:
        """Add a new ApplicationToSoftkeyTemplate.

        Args:
            application_to_softkey_template_data: A dict describing the ApplicationToSoftkeyTemplate.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addApplicationToSoftkeyTemplate(applicationToSoftkeyTemplate=application_to_softkey_template_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_application_to_softkey_template(self, name: str) -> Dict[str, Any]:
        """Remove a ApplicationToSoftkeyTemplate by name.

        Args:
            name: The ApplicationToSoftkeyTemplate name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeApplicationToSoftkeyTemplate(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  ApplicationUserCapfProfile
    # ═══════════════════════════════════════════════════════════════════

    def get_application_user_capf_profile(self, instance_id: str) -> Dict[str, Any]:
        """Retrieve an ApplicationUserCapfProfile by instanceId.

        Args:
            instance_id: The ApplicationUserCapfProfile instanceId.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getApplicationUserCapfProfile(instanceId=instance_id)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_application_user_capf_profile(self, application_user_capf_profile_data: ApplicationUserCapfProfile) -> Dict[str, Any]:
        """Add a new ApplicationUserCapfProfile.

        Args:
            application_user_capf_profile_data: A dict describing the ApplicationUserCapfProfile.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addApplicationUserCapfProfile(applicationUserCapfProfile=application_user_capf_profile_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_application_user_capf_profile(self, **kwargs: Unpack[UpdateApplicationUserCapfProfile]) -> Dict[str, Any]:
        """Update an existing ApplicationUserCapfProfile.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateApplicationUserCapfProfile(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_application_user_capf_profile(self, instance_id: str) -> Dict[str, Any]:
        """Remove an ApplicationUserCapfProfile by instanceId.

        Args:
            instance_id: The ApplicationUserCapfProfile instanceId.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeApplicationUserCapfProfile(instanceId=instance_id)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_application_user_capf_profile(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List ApplicationUserCapfProfile objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listApplicationUserCapfProfile(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  AssignedPresenceServers
    # ═══════════════════════════════════════════════════════════════════

    def list_assigned_presence_servers(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List AssignedPresenceServers objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listAssignedPresenceServers(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  AssignedPresenceUsers
    # ═══════════════════════════════════════════════════════════════════

    def list_assigned_presence_users(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List AssignedPresenceUsers objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listAssignedPresenceUsers(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  AudioCodecPreferenceList
    # ═══════════════════════════════════════════════════════════════════

    def get_audio_codec_preference_list(self, name: str) -> Dict[str, Any]:
        """Retrieve a AudioCodecPreferenceList by name.

        Args:
            name: The AudioCodecPreferenceList name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getAudioCodecPreferenceList(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_audio_codec_preference_list(self, audio_codec_preference_list_data: AudioCodecPreferenceList) -> Dict[str, Any]:
        """Add a new AudioCodecPreferenceList.

        Args:
            audio_codec_preference_list_data: A dict describing the AudioCodecPreferenceList.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addAudioCodecPreferenceList(audioCodecPreferenceList=audio_codec_preference_list_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_audio_codec_preference_list(self, **kwargs: Unpack[UpdateAudioCodecPreferenceList]) -> Dict[str, Any]:
        """Update an existing AudioCodecPreferenceList.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateAudioCodecPreferenceList(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_audio_codec_preference_list(self, name: str) -> Dict[str, Any]:
        """Remove a AudioCodecPreferenceList by name.

        Args:
            name: The AudioCodecPreferenceList name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeAudioCodecPreferenceList(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_audio_codec_preference_list(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List AudioCodecPreferenceList objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listAudioCodecPreferenceList(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  AuthenticateUser
    # ═══════════════════════════════════════════════════════════════════

    # ═══════════════════════════════════════════════════════════════════
    #  BillingServer
    # ═══════════════════════════════════════════════════════════════════

    def get_billing_server(self, name: str) -> Dict[str, Any]:
        """Retrieve a BillingServer by name.

        Args:
            name: The BillingServer name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getBillingServer(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_billing_server(self, billing_server_data: BillingServer) -> Dict[str, Any]:
        """Add a new BillingServer.

        Args:
            billing_server_data: A dict describing the BillingServer.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addBillingServer(billingServer=billing_server_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_billing_server(self, **kwargs: Unpack[UpdateBillingServer]) -> Dict[str, Any]:
        """Update an existing BillingServer.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateBillingServer(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_billing_server(self, name: str) -> Dict[str, Any]:
        """Remove a BillingServer by name.

        Args:
            name: The BillingServer name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeBillingServer(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_billing_server(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List BillingServer objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listBillingServer(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  BlockedLearnedPatterns
    # ═══════════════════════════════════════════════════════════════════

    def get_blocked_learned_patterns(self, name: str) -> Dict[str, Any]:
        """Retrieve a BlockedLearnedPatterns by name.

        Args:
            name: The BlockedLearnedPatterns name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getBlockedLearnedPatterns(pattern=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_blocked_learned_patterns(self, blocked_learned_patterns_data: BlockedLearnedPatterns) -> Dict[str, Any]:
        """Add a new BlockedLearnedPatterns.

        Args:
            blocked_learned_patterns_data: A dict describing the BlockedLearnedPatterns.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addBlockedLearnedPatterns(blockedLearnedPatterns=blocked_learned_patterns_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_blocked_learned_patterns(self, **kwargs: Unpack[UpdateBlockedLearnedPatterns]) -> Dict[str, Any]:
        """Update an existing BlockedLearnedPatterns.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateBlockedLearnedPatterns(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_blocked_learned_patterns(self, name: str) -> Dict[str, Any]:
        """Remove a BlockedLearnedPatterns by name.

        Args:
            name: The BlockedLearnedPatterns name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeBlockedLearnedPatterns(pattern=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_blocked_learned_patterns(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List BlockedLearnedPatterns objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listBlockedLearnedPatterns(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  CCAProfiles
    # ═══════════════════════════════════════════════════════════════════

    def get_cca_profiles(self, cca_id: str = "", **kwargs) -> Dict[str, Any]:
        """Retrieve a CCAProfiles by ccaId.

        Args:
            cca_id: The CCA ID.
            **kwargs: Additional fields (e.g. uuid, returnedTags).

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            if cca_id:
                kwargs["ccaId"] = cca_id
            return self._service.getCCAProfiles(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_cca_profiles(self, cca_profiles_data: CCAProfiles) -> Dict[str, Any]:
        """Add a new CCAProfiles.

        Args:
            cca_profiles_data: A dict describing the CCAProfiles.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addCCAProfiles(cCAProfiles=cca_profiles_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_cca_profiles(self, **kwargs: Unpack[UpdateCCAProfiles]) -> Dict[str, Any]:
        """Update an existing CCAProfiles.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateCCAProfiles(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_cca_profiles(self, cca_id: str = "", **kwargs) -> Dict[str, Any]:
        """Remove a CCAProfiles by ccaId.

        Args:
            cca_id: The CCA ID.
            **kwargs: Additional fields (e.g. uuid).

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            if cca_id:
                kwargs["ccaId"] = cca_id
            return self._service.removeCCAProfiles(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_cca_profiles(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List CCAProfiles objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listCCAProfiles(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  CCMVersion
    # ═══════════════════════════════════════════════════════════════════

    def get_ccm_version(self, name: str = "") -> Dict[str, Any]:
        """Retrieve the CCM (Unified CM) version.

        Args:
            name: Optional process node name.  Pass ``""`` (the default)
                to retrieve the version from the publisher.

        Returns:
            The full AXL response dict.  The version string is at
            ``result["return"]["componentVersion"]["version"]``.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.getCCMVersion(processNodeName=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  CallManagerGroup
    # ═══════════════════════════════════════════════════════════════════

    def list_call_manager_group(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List CallManagerGroup objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listCallManagerGroup(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def apply_call_manager_group(self, name: str) -> Dict[str, Any]:
        """Apply configuration for a CallManagerGroup.

        Args:
            name: The CallManagerGroup name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.applyCallManagerGroup(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def reset_call_manager_group(self, name: str) -> Dict[str, Any]:
        """Reset a CallManagerGroup.

        Args:
            name: The CallManagerGroup name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.resetCallManagerGroup(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  CallPark
    # ═══════════════════════════════════════════════════════════════════

    def update_call_park(self, **kwargs: Unpack[UpdateCallPark]) -> Dict[str, Any]:
        """Update an existing CallPark.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateCallPark(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_call_park(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List CallPark objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listCallPark(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  CallPickupGroup
    # ═══════════════════════════════════════════════════════════════════

    def list_call_pickup_group(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List CallPickupGroup objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listCallPickupGroup(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  CalledPartyTracing
    # ═══════════════════════════════════════════════════════════════════

    def add_called_party_tracing(self, called_party_tracing_data: CalledPartyTracing) -> Dict[str, Any]:
        """Add a new CalledPartyTracing.

        Args:
            called_party_tracing_data: A dict describing the CalledPartyTracing.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addCalledPartyTracing(calledPartyTracing=called_party_tracing_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_called_party_tracing(self, directorynumber: str) -> Dict[str, Any]:
        """Remove a CalledPartyTracing by directory number.

        Args:
            directorynumber: The CalledPartyTracing directory number.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeCalledPartyTracing(directorynumber=directorynumber)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_called_party_tracing(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List CalledPartyTracing objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listCalledPartyTracing(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  CalledPartyTransformationPattern
    # ═══════════════════════════════════════════════════════════════════

    def update_called_party_transformation_pattern(self, **kwargs: Unpack[UpdateCalledPartyTransformationPattern]) -> Dict[str, Any]:
        """Update an existing CalledPartyTransformationPattern.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateCalledPartyTransformationPattern(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_called_party_transformation_pattern(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List CalledPartyTransformationPattern objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listCalledPartyTransformationPattern(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  CallerFilterList
    # ═══════════════════════════════════════════════════════════════════

    def get_caller_filter_list(self, name: str) -> Dict[str, Any]:
        """Retrieve a CallerFilterList by name.

        Args:
            name: The CallerFilterList name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getCallerFilterList(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_caller_filter_list(self, caller_filter_list_data: CallerFilterList) -> Dict[str, Any]:
        """Add a new CallerFilterList.

        Args:
            caller_filter_list_data: A dict describing the CallerFilterList.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addCallerFilterList(callerFilterList=caller_filter_list_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_caller_filter_list(self, **kwargs: Unpack[UpdateCallerFilterList]) -> Dict[str, Any]:
        """Update an existing CallerFilterList.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateCallerFilterList(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_caller_filter_list(self, name: str) -> Dict[str, Any]:
        """Remove a CallerFilterList by name.

        Args:
            name: The CallerFilterList name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeCallerFilterList(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_caller_filter_list(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List CallerFilterList objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listCallerFilterList(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  CallingPartyTransformationPattern
    # ═══════════════════════════════════════════════════════════════════

    def update_calling_party_transformation_pattern(self, **kwargs: Unpack[UpdateCallingPartyTransformationPattern]) -> Dict[str, Any]:
        """Update an existing CallingPartyTransformationPattern.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateCallingPartyTransformationPattern(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_calling_party_transformation_pattern(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List CallingPartyTransformationPattern objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listCallingPartyTransformationPattern(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  CcdAdvertisingService
    # ═══════════════════════════════════════════════════════════════════

    def get_ccd_advertising_service(self, name: str) -> Dict[str, Any]:
        """Retrieve a CcdAdvertisingService by name.

        Args:
            name: The CcdAdvertisingService name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getCcdAdvertisingService(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_ccd_advertising_service(self, ccd_advertising_service_data: CcdAdvertisingService) -> Dict[str, Any]:
        """Add a new CcdAdvertisingService.

        Args:
            ccd_advertising_service_data: A dict describing the CcdAdvertisingService.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addCcdAdvertisingService(ccdAdvertisingService=ccd_advertising_service_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_ccd_advertising_service(self, **kwargs: Unpack[UpdateCcdAdvertisingService]) -> Dict[str, Any]:
        """Update an existing CcdAdvertisingService.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateCcdAdvertisingService(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_ccd_advertising_service(self, name: str) -> Dict[str, Any]:
        """Remove a CcdAdvertisingService by name.

        Args:
            name: The CcdAdvertisingService name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeCcdAdvertisingService(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_ccd_advertising_service(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List CcdAdvertisingService objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listCcdAdvertisingService(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  CcdHostedDN
    # ═══════════════════════════════════════════════════════════════════

    def get_ccd_hosted_dn(self, hosted_pattern: str) -> Dict[str, Any]:
        """Retrieve a CcdHostedDN by hostedPattern.

        Args:
            hosted_pattern: The CcdHostedDN hostedPattern.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getCcdHostedDN(hostedPattern=hosted_pattern)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_ccd_hosted_dn(self, ccd_hosted_dn_data: CcdHostedDN) -> Dict[str, Any]:
        """Add a new CcdHostedDN.

        Args:
            ccd_hosted_dn_data: A dict describing the CcdHostedDN.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addCcdHostedDN(ccdHostedDN=ccd_hosted_dn_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_ccd_hosted_dn(self, **kwargs: Unpack[UpdateCcdHostedDN]) -> Dict[str, Any]:
        """Update an existing CcdHostedDN.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateCcdHostedDN(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_ccd_hosted_dn(self, hosted_pattern: str) -> Dict[str, Any]:
        """Remove a CcdHostedDN by hostedPattern.

        Args:
            hosted_pattern: The CcdHostedDN hostedPattern.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeCcdHostedDN(hostedPattern=hosted_pattern)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_ccd_hosted_dn(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List CcdHostedDN objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listCcdHostedDN(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  CcdHostedDNGroup
    # ═══════════════════════════════════════════════════════════════════

    def get_ccd_hosted_dn_group(self, name: str) -> Dict[str, Any]:
        """Retrieve a CcdHostedDNGroup by name.

        Args:
            name: The CcdHostedDNGroup name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getCcdHostedDNGroup(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_ccd_hosted_dn_group(self, ccd_hosted_dn_group_data: CcdHostedDNGroup) -> Dict[str, Any]:
        """Add a new CcdHostedDNGroup.

        Args:
            ccd_hosted_dn_group_data: A dict describing the CcdHostedDNGroup.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addCcdHostedDNGroup(ccdHostedDNGroup=ccd_hosted_dn_group_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_ccd_hosted_dn_group(self, **kwargs: Unpack[UpdateCcdHostedDNGroup]) -> Dict[str, Any]:
        """Update an existing CcdHostedDNGroup.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateCcdHostedDNGroup(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_ccd_hosted_dn_group(self, name: str) -> Dict[str, Any]:
        """Remove a CcdHostedDNGroup by name.

        Args:
            name: The CcdHostedDNGroup name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeCcdHostedDNGroup(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_ccd_hosted_dn_group(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List CcdHostedDNGroup objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listCcdHostedDNGroup(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  CcdRequestingService
    # ═══════════════════════════════════════════════════════════════════

    def get_ccd_requesting_service(self, name: str) -> Dict[str, Any]:
        """Retrieve a CcdRequestingService by name.

        Args:
            name: The CcdRequestingService name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getCcdRequestingService(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_ccd_requesting_service(self, ccd_requesting_service_data: CcdRequestingService) -> Dict[str, Any]:
        """Add a new CcdRequestingService.

        Args:
            ccd_requesting_service_data: A dict describing the CcdRequestingService.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addCcdRequestingService(ccdRequestingService=ccd_requesting_service_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_ccd_requesting_service(self, **kwargs: Unpack[UpdateCcdRequestingService]) -> Dict[str, Any]:
        """Update an existing CcdRequestingService.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateCcdRequestingService(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_ccd_requesting_service(self, name: str) -> Dict[str, Any]:
        """Remove a CcdRequestingService by name.

        Args:
            name: The CcdRequestingService name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeCcdRequestingService(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Change
    # ═══════════════════════════════════════════════════════════════════

    def list_change(self, **kwargs) -> Dict[str, Any]:
        """List changes since a given change ID.

        Args:
            **kwargs: Keyword arguments passed to the WSDL operation.
                Typically ``startChangeId`` and optionally ``objectList``.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.listChange(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  ChangeDNDStatus
    # ═══════════════════════════════════════════════════════════════════

    # ═══════════════════════════════════════════════════════════════════
    #  CiscoCatalyst600024PortFXSGateway
    # ═══════════════════════════════════════════════════════════════════

    def get_cisco_catalyst600024_port_fxs_gateway(self, name: str) -> Dict[str, Any]:
        """Retrieve a CiscoCatalyst600024PortFXSGateway by name.

        Args:
            name: The CiscoCatalyst600024PortFXSGateway name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getCiscoCatalyst600024PortFXSGateway(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_cisco_catalyst600024_port_fxs_gateway(self, cisco_catalyst600024_port_fxs_gateway_data: CiscoCatalyst600024PortFXSGateway) -> Dict[str, Any]:
        """Add a new CiscoCatalyst600024PortFXSGateway.

        Args:
            cisco_catalyst600024_port_fxs_gateway_data: A dict describing the CiscoCatalyst600024PortFXSGateway.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addCiscoCatalyst600024PortFXSGateway(ciscoCatalyst600024PortFXSGateway=cisco_catalyst600024_port_fxs_gateway_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_cisco_catalyst600024_port_fxs_gateway(self, **kwargs: Unpack[UpdateCiscoCatalyst600024PortFXSGateway]) -> Dict[str, Any]:
        """Update an existing CiscoCatalyst600024PortFXSGateway.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateCiscoCatalyst600024PortFXSGateway(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_cisco_catalyst600024_port_fxs_gateway(self, name: str) -> Dict[str, Any]:
        """Remove a CiscoCatalyst600024PortFXSGateway by name.

        Args:
            name: The CiscoCatalyst600024PortFXSGateway name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeCiscoCatalyst600024PortFXSGateway(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_cisco_catalyst600024_port_fxs_gateway(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List CiscoCatalyst600024PortFXSGateway objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listCiscoCatalyst600024PortFXSGateway(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def apply_cisco_catalyst600024_port_fxs_gateway(self, name: str) -> Dict[str, Any]:
        """Apply configuration for a CiscoCatalyst600024PortFXSGateway.

        Args:
            name: The CiscoCatalyst600024PortFXSGateway name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.applyCiscoCatalyst600024PortFXSGateway(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def reset_cisco_catalyst600024_port_fxs_gateway(self, name: str) -> Dict[str, Any]:
        """Reset a CiscoCatalyst600024PortFXSGateway.

        Args:
            name: The CiscoCatalyst600024PortFXSGateway name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.resetCiscoCatalyst600024PortFXSGateway(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def restart_cisco_catalyst600024_port_fxs_gateway(self, name: str) -> Dict[str, Any]:
        """Restart a CiscoCatalyst600024PortFXSGateway.

        Args:
            name: The CiscoCatalyst600024PortFXSGateway name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.restartCiscoCatalyst600024PortFXSGateway(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  CiscoCatalyst6000E1VoIPGateway
    # ═══════════════════════════════════════════════════════════════════

    def get_cisco_catalyst6000_e1_vo_ip_gateway(self, name: str) -> Dict[str, Any]:
        """Retrieve a CiscoCatalyst6000E1VoIPGateway by name.

        Args:
            name: The CiscoCatalyst6000E1VoIPGateway name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getCiscoCatalyst6000E1VoIPGateway(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_cisco_catalyst6000_e1_vo_ip_gateway(self, cisco_catalyst6000_e1_vo_ip_gateway_data: CiscoCatalyst6000E1VoIPGateway) -> Dict[str, Any]:
        """Add a new CiscoCatalyst6000E1VoIPGateway.

        Args:
            cisco_catalyst6000_e1_vo_ip_gateway_data: A dict describing the CiscoCatalyst6000E1VoIPGateway.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addCiscoCatalyst6000E1VoIPGateway(ciscoCatalyst6000E1VoIPGateway=cisco_catalyst6000_e1_vo_ip_gateway_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_cisco_catalyst6000_e1_vo_ip_gateway(self, **kwargs: Unpack[UpdateCiscoCatalyst6000E1VoIPGateway]) -> Dict[str, Any]:
        """Update an existing CiscoCatalyst6000E1VoIPGateway.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateCiscoCatalyst6000E1VoIPGateway(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_cisco_catalyst6000_e1_vo_ip_gateway(self, name: str) -> Dict[str, Any]:
        """Remove a CiscoCatalyst6000E1VoIPGateway by name.

        Args:
            name: The CiscoCatalyst6000E1VoIPGateway name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeCiscoCatalyst6000E1VoIPGateway(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_cisco_catalyst6000_e1_vo_ip_gateway(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List CiscoCatalyst6000E1VoIPGateway objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listCiscoCatalyst6000E1VoIPGateway(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def apply_cisco_catalyst6000_e1_vo_ip_gateway(self, name: str) -> Dict[str, Any]:
        """Apply configuration for a CiscoCatalyst6000E1VoIPGateway.

        Args:
            name: The CiscoCatalyst6000E1VoIPGateway name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.applyCiscoCatalyst6000E1VoIPGateway(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def reset_cisco_catalyst6000_e1_vo_ip_gateway(self, name: str) -> Dict[str, Any]:
        """Reset a CiscoCatalyst6000E1VoIPGateway.

        Args:
            name: The CiscoCatalyst6000E1VoIPGateway name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.resetCiscoCatalyst6000E1VoIPGateway(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def restart_cisco_catalyst6000_e1_vo_ip_gateway(self, name: str) -> Dict[str, Any]:
        """Restart a CiscoCatalyst6000E1VoIPGateway.

        Args:
            name: The CiscoCatalyst6000E1VoIPGateway name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.restartCiscoCatalyst6000E1VoIPGateway(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  CiscoCatalyst6000T1VoIPGatewayPri
    # ═══════════════════════════════════════════════════════════════════

    def get_cisco_catalyst6000_t1_vo_ip_gateway_pri(self, name: str) -> Dict[str, Any]:
        """Retrieve a CiscoCatalyst6000T1VoIPGatewayPri by name.

        Args:
            name: The CiscoCatalyst6000T1VoIPGatewayPri name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getCiscoCatalyst6000T1VoIPGatewayPri(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_cisco_catalyst6000_t1_vo_ip_gateway_pri(self, cisco_catalyst6000_t1_vo_ip_gateway_pri_data: CiscoCatalyst6000T1VoIPGatewayPri) -> Dict[str, Any]:
        """Add a new CiscoCatalyst6000T1VoIPGatewayPri.

        Args:
            cisco_catalyst6000_t1_vo_ip_gateway_pri_data: A dict describing the CiscoCatalyst6000T1VoIPGatewayPri.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addCiscoCatalyst6000T1VoIPGatewayPri(ciscoCatalyst6000T1VoIPGatewayPri=cisco_catalyst6000_t1_vo_ip_gateway_pri_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_cisco_catalyst6000_t1_vo_ip_gateway_pri(self, **kwargs: Unpack[UpdateCiscoCatalyst6000T1VoIPGatewayPri]) -> Dict[str, Any]:
        """Update an existing CiscoCatalyst6000T1VoIPGatewayPri.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateCiscoCatalyst6000T1VoIPGatewayPri(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_cisco_catalyst6000_t1_vo_ip_gateway_pri(self, name: str) -> Dict[str, Any]:
        """Remove a CiscoCatalyst6000T1VoIPGatewayPri by name.

        Args:
            name: The CiscoCatalyst6000T1VoIPGatewayPri name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeCiscoCatalyst6000T1VoIPGatewayPri(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_cisco_catalyst6000_t1_vo_ip_gateway_pri(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List CiscoCatalyst6000T1VoIPGatewayPri objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listCiscoCatalyst6000T1VoIPGatewayPri(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def apply_cisco_catalyst6000_t1_vo_ip_gateway_pri(self, name: str) -> Dict[str, Any]:
        """Apply configuration for a CiscoCatalyst6000T1VoIPGatewayPri.

        Args:
            name: The CiscoCatalyst6000T1VoIPGatewayPri name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.applyCiscoCatalyst6000T1VoIPGatewayPri(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def reset_cisco_catalyst6000_t1_vo_ip_gateway_pri(self, name: str) -> Dict[str, Any]:
        """Reset a CiscoCatalyst6000T1VoIPGatewayPri.

        Args:
            name: The CiscoCatalyst6000T1VoIPGatewayPri name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.resetCiscoCatalyst6000T1VoIPGatewayPri(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def restart_cisco_catalyst6000_t1_vo_ip_gateway_pri(self, name: str) -> Dict[str, Any]:
        """Restart a CiscoCatalyst6000T1VoIPGatewayPri.

        Args:
            name: The CiscoCatalyst6000T1VoIPGatewayPri name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.restartCiscoCatalyst6000T1VoIPGatewayPri(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  CiscoCatalyst6000T1VoIPGatewayT1
    # ═══════════════════════════════════════════════════════════════════

    def get_cisco_catalyst6000_t1_vo_ip_gateway_t1(self, name: str) -> Dict[str, Any]:
        """Retrieve a CiscoCatalyst6000T1VoIPGatewayT1 by name.

        Args:
            name: The CiscoCatalyst6000T1VoIPGatewayT1 name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getCiscoCatalyst6000T1VoIPGatewayT1(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_cisco_catalyst6000_t1_vo_ip_gateway_t1(self, cisco_catalyst6000_t1_vo_ip_gateway_t1_data: CiscoCatalyst6000T1VoIPGatewayT1) -> Dict[str, Any]:
        """Add a new CiscoCatalyst6000T1VoIPGatewayT1.

        Args:
            cisco_catalyst6000_t1_vo_ip_gateway_t1_data: A dict describing the CiscoCatalyst6000T1VoIPGatewayT1.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addCiscoCatalyst6000T1VoIPGatewayT1(ciscoCatalyst6000T1VoIPGatewayT1=cisco_catalyst6000_t1_vo_ip_gateway_t1_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_cisco_catalyst6000_t1_vo_ip_gateway_t1(self, **kwargs: Unpack[UpdateCiscoCatalyst6000T1VoIPGatewayT1]) -> Dict[str, Any]:
        """Update an existing CiscoCatalyst6000T1VoIPGatewayT1.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateCiscoCatalyst6000T1VoIPGatewayT1(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_cisco_catalyst6000_t1_vo_ip_gateway_t1(self, name: str) -> Dict[str, Any]:
        """Remove a CiscoCatalyst6000T1VoIPGatewayT1 by name.

        Args:
            name: The CiscoCatalyst6000T1VoIPGatewayT1 name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeCiscoCatalyst6000T1VoIPGatewayT1(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_cisco_catalyst6000_t1_vo_ip_gateway_t1(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List CiscoCatalyst6000T1VoIPGatewayT1 objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listCiscoCatalyst6000T1VoIPGatewayT1(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def apply_cisco_catalyst6000_t1_vo_ip_gateway_t1(self, name: str) -> Dict[str, Any]:
        """Apply configuration for a CiscoCatalyst6000T1VoIPGatewayT1.

        Args:
            name: The CiscoCatalyst6000T1VoIPGatewayT1 name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.applyCiscoCatalyst6000T1VoIPGatewayT1(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def reset_cisco_catalyst6000_t1_vo_ip_gateway_t1(self, name: str) -> Dict[str, Any]:
        """Reset a CiscoCatalyst6000T1VoIPGatewayT1.

        Args:
            name: The CiscoCatalyst6000T1VoIPGatewayT1 name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.resetCiscoCatalyst6000T1VoIPGatewayT1(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def restart_cisco_catalyst6000_t1_vo_ip_gateway_t1(self, name: str) -> Dict[str, Any]:
        """Restart a CiscoCatalyst6000T1VoIPGatewayT1.

        Args:
            name: The CiscoCatalyst6000T1VoIPGatewayT1 name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.restartCiscoCatalyst6000T1VoIPGatewayT1(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  CmcInfo
    # ═══════════════════════════════════════════════════════════════════

    def get_cmc_info(self, name: str) -> Dict[str, Any]:
        """Retrieve a CmcInfo by name.

        Args:
            name: The CmcInfo name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getCmcInfo(code=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_cmc_info(self, cmc_info_data: CmcInfo) -> Dict[str, Any]:
        """Add a new CmcInfo.

        Args:
            cmc_info_data: A dict describing the CmcInfo.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addCmcInfo(cmcInfo=cmc_info_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_cmc_info(self, **kwargs: Unpack[UpdateCmcInfo]) -> Dict[str, Any]:
        """Update an existing CmcInfo.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateCmcInfo(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_cmc_info(self, name: str) -> Dict[str, Any]:
        """Remove a CmcInfo by name.

        Args:
            name: The CmcInfo name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeCmcInfo(code=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_cmc_info(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List CmcInfo objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listCmcInfo(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  CommonDeviceConfig
    # ═══════════════════════════════════════════════════════════════════

    def list_common_device_config(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List CommonDeviceConfig objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listCommonDeviceConfig(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def apply_common_device_config(self, name: str) -> Dict[str, Any]:
        """Apply configuration for a CommonDeviceConfig.

        Args:
            name: The CommonDeviceConfig name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.applyCommonDeviceConfig(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def reset_common_device_config(self, name: str) -> Dict[str, Any]:
        """Reset a CommonDeviceConfig.

        Args:
            name: The CommonDeviceConfig name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.resetCommonDeviceConfig(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  CommonPhoneConfig
    # ═══════════════════════════════════════════════════════════════════

    def list_common_phone_config(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List CommonPhoneConfig objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listCommonPhoneConfig(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def apply_common_phone_config(self, name: str) -> Dict[str, Any]:
        """Apply configuration for a CommonPhoneConfig.

        Args:
            name: The CommonPhoneConfig name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.applyCommonPhoneConfig(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def reset_common_phone_config(self, name: str) -> Dict[str, Any]:
        """Reset a CommonPhoneConfig.

        Args:
            name: The CommonPhoneConfig name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.resetCommonPhoneConfig(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  ConferenceBridge
    # ═══════════════════════════════════════════════════════════════════

    def list_conference_bridge(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List ConferenceBridge objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listConferenceBridge(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def apply_conference_bridge(self, name: str) -> Dict[str, Any]:
        """Apply configuration for a ConferenceBridge.

        Args:
            name: The ConferenceBridge name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.applyConferenceBridge(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def reset_conference_bridge(self, name: str) -> Dict[str, Any]:
        """Reset a ConferenceBridge.

        Args:
            name: The ConferenceBridge name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.resetConferenceBridge(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def restart_conference_bridge(self, name: str) -> Dict[str, Any]:
        """Restart a ConferenceBridge.

        Args:
            name: The ConferenceBridge name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.restartConferenceBridge(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  ConferenceNow
    # ═══════════════════════════════════════════════════════════════════

    def get_conference_now(self, conferenceNowNumber: str) -> Dict[str, Any]:
        """Retrieve a ConferenceNow by conference number.

        Args:
            conferenceNowNumber: The ConferenceNow number.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getConferenceNow(conferenceNowNumber=conferenceNowNumber)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_conference_now(self, conference_now_data: ConferenceNow) -> Dict[str, Any]:
        """Add a new ConferenceNow.

        Args:
            conference_now_data: A dict describing the ConferenceNow.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addConferenceNow(conferenceNow=conference_now_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_conference_now(self, **kwargs: Unpack[UpdateConferenceNow]) -> Dict[str, Any]:
        """Update an existing ConferenceNow.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateConferenceNow(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_conference_now(self, conferenceNowNumber: str) -> Dict[str, Any]:
        """Remove a ConferenceNow by conference number.

        Args:
            conferenceNowNumber: The ConferenceNow number.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeConferenceNow(conferenceNowNumber=conferenceNowNumber)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_conference_now(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List ConferenceNow objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listConferenceNow(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  ConfigEnterpriseParameters
    # ═══════════════════════════════════════════════════════════════════

    def apply_config_enterprise_parameters(self) -> Dict[str, Any]:
        """Apply configuration for enterprise parameters.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.applyConfigEnterpriseParameters()
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  CredentialPolicy
    # ═══════════════════════════════════════════════════════════════════

    def add_credential_policy(self, credential_policy_data: CredentialPolicy) -> Dict[str, Any]:
        """Add a new CredentialPolicy.

        Args:
            credential_policy_data: A dict describing the CredentialPolicy.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addCredentialPolicy(credentialPolicy=credential_policy_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_credential_policy(self, name: str) -> Dict[str, Any]:
        """Remove a CredentialPolicy by name.

        Args:
            name: The CredentialPolicy name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeCredentialPolicy(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_credential_policy(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List CredentialPolicy objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listCredentialPolicy(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Css
    # ═══════════════════════════════════════════════════════════════════

    def list_css(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List Css objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listCss(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  CtiRoutePoint
    # ═══════════════════════════════════════════════════════════════════

    def list_cti_route_point(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List CtiRoutePoint objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listCtiRoutePoint(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def apply_cti_route_point(self, name: str) -> Dict[str, Any]:
        """Apply configuration for a CtiRoutePoint.

        Args:
            name: The CtiRoutePoint name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.applyCtiRoutePoint(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def reset_cti_route_point(self, name: str) -> Dict[str, Any]:
        """Reset a CtiRoutePoint.

        Args:
            name: The CtiRoutePoint name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.resetCtiRoutePoint(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def restart_cti_route_point(self, name: str) -> Dict[str, Any]:
        """Restart a CtiRoutePoint.

        Args:
            name: The CtiRoutePoint name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.restartCtiRoutePoint(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  CumaServerSecurityProfile
    # ═══════════════════════════════════════════════════════════════════

    def get_cuma_server_security_profile(self, name: str) -> Dict[str, Any]:
        """Retrieve a CumaServerSecurityProfile by name.

        Args:
            name: The CumaServerSecurityProfile name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getCumaServerSecurityProfile(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_cuma_server_security_profile(self, cuma_server_security_profile_data: CumaServerSecurityProfile) -> Dict[str, Any]:
        """Add a new CumaServerSecurityProfile.

        Args:
            cuma_server_security_profile_data: A dict describing the CumaServerSecurityProfile.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addCumaServerSecurityProfile(cumaServerSecurityProfile=cuma_server_security_profile_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_cuma_server_security_profile(self, **kwargs: Unpack[UpdateCumaServerSecurityProfile]) -> Dict[str, Any]:
        """Update an existing CumaServerSecurityProfile.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateCumaServerSecurityProfile(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_cuma_server_security_profile(self, name: str) -> Dict[str, Any]:
        """Remove a CumaServerSecurityProfile by name.

        Args:
            name: The CumaServerSecurityProfile name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeCumaServerSecurityProfile(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_cuma_server_security_profile(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List CumaServerSecurityProfile objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listCumaServerSecurityProfile(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  CustomUserField
    # ═══════════════════════════════════════════════════════════════════

    def get_custom_user_field(self, field: str) -> Dict[str, Any]:
        """Retrieve a CustomUserField by field name.

        Args:
            field: The CustomUserField field name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getCustomUserField(field=field)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_custom_user_field(self, custom_user_field_data: CustomUserField) -> Dict[str, Any]:
        """Add a new CustomUserField.

        Args:
            custom_user_field_data: A dict describing the CustomUserField.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addCustomUserField(customUserField=custom_user_field_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_custom_user_field(self, **kwargs: Unpack[UpdateCustomUserField]) -> Dict[str, Any]:
        """Update an existing CustomUserField.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateCustomUserField(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_custom_user_field(self, field: str) -> Dict[str, Any]:
        """Remove a CustomUserField by field name.

        Args:
            field: The CustomUserField field name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeCustomUserField(field=field)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_custom_user_field(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List CustomUserField objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listCustomUserField(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Customer
    # ═══════════════════════════════════════════════════════════════════

    def get_customer(self, name: str) -> Dict[str, Any]:
        """Retrieve a Customer by name.

        Args:
            name: The Customer name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getCustomer(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_customer(self, customer_data: Customer) -> Dict[str, Any]:
        """Add a new Customer.

        Args:
            customer_data: A dict describing the Customer.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addCustomer(customer=customer_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_customer(self, **kwargs: Unpack[UpdateCustomer]) -> Dict[str, Any]:
        """Update an existing Customer.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateCustomer(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_customer(self, name: str) -> Dict[str, Any]:
        """Remove a Customer by name.

        Args:
            name: The Customer name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeCustomer(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_customer(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List Customer objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listCustomer(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  DateTimeGroup
    # ═══════════════════════════════════════════════════════════════════

    def list_date_time_group(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List DateTimeGroup objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listDateTimeGroup(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def apply_date_time_group(self, name: str) -> Dict[str, Any]:
        """Apply configuration for a DateTimeGroup.

        Args:
            name: The DateTimeGroup name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.applyDateTimeGroup(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def reset_date_time_group(self, name: str) -> Dict[str, Any]:
        """Reset a DateTimeGroup.

        Args:
            name: The DateTimeGroup name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.resetDateTimeGroup(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Ddi
    # ═══════════════════════════════════════════════════════════════════

    def get_ddi(self, **kwargs) -> Dict[str, Any]:
        """Retrieve a Ddi.

        Args:
            **kwargs: Must include ``name`` + ``dialPlanName``, or ``uuid``.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getDdi(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_ddi(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List Ddi objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listDdi(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  DefaultDeviceProfile
    # ═══════════════════════════════════════════════════════════════════

    def get_default_device_profile(self, name: str) -> Dict[str, Any]:
        """Retrieve a DefaultDeviceProfile by name.

        Args:
            name: The DefaultDeviceProfile name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getDefaultDeviceProfile(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_default_device_profile(self, default_device_profile_data: DefaultDeviceProfile) -> Dict[str, Any]:
        """Add a new DefaultDeviceProfile.

        Args:
            default_device_profile_data: A dict describing the DefaultDeviceProfile.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addDefaultDeviceProfile(defaultDeviceProfile=default_device_profile_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_default_device_profile(self, **kwargs: Unpack[UpdateDefaultDeviceProfile]) -> Dict[str, Any]:
        """Update an existing DefaultDeviceProfile.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateDefaultDeviceProfile(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_default_device_profile(self, name: str) -> Dict[str, Any]:
        """Remove a DefaultDeviceProfile by name.

        Args:
            name: The DefaultDeviceProfile name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeDefaultDeviceProfile(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_default_device_profile(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List DefaultDeviceProfile objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listDefaultDeviceProfile(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  DeviceLogin
    # ═══════════════════════════════════════════════════════════════════

    # ═══════════════════════════════════════════════════════════════════
    #  DeviceLogout
    # ═══════════════════════════════════════════════════════════════════

    # ═══════════════════════════════════════════════════════════════════
    #  DeviceMobility
    # ═══════════════════════════════════════════════════════════════════

    def get_device_mobility(self, name: str) -> Dict[str, Any]:
        """Retrieve a DeviceMobility by name.

        Args:
            name: The DeviceMobility name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getDeviceMobility(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_device_mobility(self, device_mobility_data: DeviceMobility) -> Dict[str, Any]:
        """Add a new DeviceMobility.

        Args:
            device_mobility_data: A dict describing the DeviceMobility.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addDeviceMobility(deviceMobility=device_mobility_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_device_mobility(self, **kwargs: Unpack[UpdateDeviceMobility]) -> Dict[str, Any]:
        """Update an existing DeviceMobility.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateDeviceMobility(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_device_mobility(self, name: str) -> Dict[str, Any]:
        """Remove a DeviceMobility by name.

        Args:
            name: The DeviceMobility name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeDeviceMobility(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_device_mobility(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List DeviceMobility objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listDeviceMobility(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  DeviceMobilityGroup
    # ═══════════════════════════════════════════════════════════════════

    def get_device_mobility_group(self, name: str) -> Dict[str, Any]:
        """Retrieve a DeviceMobilityGroup by name.

        Args:
            name: The DeviceMobilityGroup name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getDeviceMobilityGroup(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_device_mobility_group(self, device_mobility_group_data: DeviceMobilityGroup) -> Dict[str, Any]:
        """Add a new DeviceMobilityGroup.

        Args:
            device_mobility_group_data: A dict describing the DeviceMobilityGroup.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addDeviceMobilityGroup(deviceMobilityGroup=device_mobility_group_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_device_mobility_group(self, **kwargs: Unpack[UpdateDeviceMobilityGroup]) -> Dict[str, Any]:
        """Update an existing DeviceMobilityGroup.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateDeviceMobilityGroup(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_device_mobility_group(self, name: str) -> Dict[str, Any]:
        """Remove a DeviceMobilityGroup by name.

        Args:
            name: The DeviceMobilityGroup name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeDeviceMobilityGroup(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_device_mobility_group(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List DeviceMobilityGroup objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listDeviceMobilityGroup(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  DevicePool
    # ═══════════════════════════════════════════════════════════════════

    def list_device_pool(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List DevicePool objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listDevicePool(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def apply_device_pool(self, name: str) -> Dict[str, Any]:
        """Apply configuration for a DevicePool.

        Args:
            name: The DevicePool name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.applyDevicePool(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def reset_device_pool(self, name: str) -> Dict[str, Any]:
        """Reset a DevicePool.

        Args:
            name: The DevicePool name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.resetDevicePool(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def restart_device_pool(self, name: str) -> Dict[str, Any]:
        """Restart a DevicePool.

        Args:
            name: The DevicePool name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.restartDevicePool(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  DeviceProfile
    # ═══════════════════════════════════════════════════════════════════

    def list_device_profile(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List DeviceProfile objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listDeviceProfile(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  DeviceProfileOptions
    # ═══════════════════════════════════════════════════════════════════

    def get_device_profile_options(self, uuid: str) -> Dict[str, Any]:
        """Retrieve DeviceProfileOptions.

        Args:
            uuid: The UUID of the device profile.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getDeviceProfileOptions(uuid=uuid)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  DhcpServer
    # ═══════════════════════════════════════════════════════════════════

    def get_dhcp_server(self, process_node_name: str) -> Dict[str, Any]:
        """Retrieve a DhcpServer by process node name.

        Args:
            process_node_name: The process node name hosting the DHCP server.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getDhcpServer(processNodeName=process_node_name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_dhcp_server(self, dhcp_server_data: DhcpServer) -> Dict[str, Any]:
        """Add a new DhcpServer.

        Args:
            dhcp_server_data: A dict describing the DhcpServer.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addDhcpServer(dhcpServer=dhcp_server_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_dhcp_server(self, **kwargs: Unpack[UpdateDhcpServer]) -> Dict[str, Any]:
        """Update an existing DhcpServer.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateDhcpServer(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_dhcp_server(self, process_node_name: str) -> Dict[str, Any]:
        """Remove a DhcpServer by process node name.

        Args:
            process_node_name: The process node name hosting the DHCP server.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeDhcpServer(processNodeName=process_node_name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_dhcp_server(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List DhcpServer objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listDhcpServer(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  DhcpSubnet
    # ═══════════════════════════════════════════════════════════════════

    def get_dhcp_subnet(self, dhcp_server_name: str, subnet_ip_address: str) -> Dict[str, Any]:
        """Retrieve a DhcpSubnet by server name and subnet IP.

        Args:
            dhcp_server_name: The DHCP server (process node) name.
            subnet_ip_address: The subnet IP address.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getDhcpSubnet(
                dhcpServerName=dhcp_server_name,
                subnetIpAddress=subnet_ip_address,
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_dhcp_subnet(self, dhcp_subnet_data: DhcpSubnet) -> Dict[str, Any]:
        """Add a new DhcpSubnet.

        Args:
            dhcp_subnet_data: A dict describing the DhcpSubnet.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addDhcpSubnet(dhcpSubnet=dhcp_subnet_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_dhcp_subnet(self, **kwargs: Unpack[UpdateDhcpSubnet]) -> Dict[str, Any]:
        """Update an existing DhcpSubnet.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateDhcpSubnet(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_dhcp_subnet(self, dhcp_server_name: str, subnet_ip_address: str) -> Dict[str, Any]:
        """Remove a DhcpSubnet by server name and subnet IP.

        Args:
            dhcp_server_name: The DHCP server (process node) name.
            subnet_ip_address: The subnet IP address.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeDhcpSubnet(
                dhcpServerName=dhcp_server_name,
                subnetIpAddress=subnet_ip_address,
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_dhcp_subnet(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List DhcpSubnet objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listDhcpSubnet(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  DialPlan
    # ═══════════════════════════════════════════════════════════════════

    def get_dial_plan(self, name: str) -> Dict[str, Any]:
        """Retrieve a DialPlan by name.

        Args:
            name: The DialPlan name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getDialPlan(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_dial_plan(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List DialPlan objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listDialPlan(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  DialPlanTag
    # ═══════════════════════════════════════════════════════════════════

    def get_dial_plan_tag(self, **kwargs) -> Dict[str, Any]:
        """Retrieve a DialPlanTag.

        Args:
            **kwargs: Must include ``name`` + ``dialPlanName``, or ``uuid``.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getDialPlanTag(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_dial_plan_tag(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List DialPlanTag objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listDialPlanTag(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  DirNumberAliasLookupandSync
    # ═══════════════════════════════════════════════════════════════════

    def get_dir_number_alias_lookupand_sync(self, name: str) -> Dict[str, Any]:
        """Retrieve a DirNumberAliasLookupandSync by name.

        Args:
            name: The DirNumberAliasLookupandSync name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getDirNumberAliasLookupandSync(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_dir_number_alias_lookupand_sync(self, dir_number_alias_lookupand_sync_data: DirNumberAliasLookupandSync) -> Dict[str, Any]:
        """Add a new DirNumberAliasLookupandSync.

        Args:
            dir_number_alias_lookupand_sync_data: A dict describing the DirNumberAliasLookupandSync.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addDirNumberAliasLookupandSync(dirNumberAliasLookupandSync=dir_number_alias_lookupand_sync_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_dir_number_alias_lookupand_sync(self, **kwargs: Unpack[UpdateDirNumberAliasLookupandSync]) -> Dict[str, Any]:
        """Update an existing DirNumberAliasLookupandSync.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateDirNumberAliasLookupandSync(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_dir_number_alias_lookupand_sync(self, name: str) -> Dict[str, Any]:
        """Remove a DirNumberAliasLookupandSync by name.

        Args:
            name: The DirNumberAliasLookupandSync name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeDirNumberAliasLookupandSync(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_dir_number_alias_lookupand_sync(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List DirNumberAliasLookupandSync objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listDirNumberAliasLookupandSync(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  DirectedCallPark
    # ═══════════════════════════════════════════════════════════════════

    def get_directed_call_park(
        self, pattern: str, route_partition_name: str = "",
    ) -> Dict[str, Any]:
        """Retrieve a Directed Call Park by pattern.

        Args:
            pattern: The directed call park pattern.
            route_partition_name: The route partition (default ``""`` for
                no partition).

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getDirectedCallPark(
                pattern=pattern, routePartitionName=route_partition_name,
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_directed_call_park(self, directed_call_park_data: DirectedCallPark) -> Dict[str, Any]:
        """Add a new DirectedCallPark.

        Args:
            directed_call_park_data: A dict describing the DirectedCallPark.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addDirectedCallPark(directedCallPark=directed_call_park_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_directed_call_park(self, **kwargs: Unpack[UpdateDirectedCallPark]) -> Dict[str, Any]:
        """Update an existing DirectedCallPark.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateDirectedCallPark(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_directed_call_park(
        self, pattern: str, route_partition_name: str = "",
    ) -> Dict[str, Any]:
        """Remove a Directed Call Park by pattern.

        Args:
            pattern: The directed call park pattern.
            route_partition_name: The route partition (default ``""`` for
                no partition).

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeDirectedCallPark(
                pattern=pattern, routePartitionName=route_partition_name,
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_directed_call_park(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List DirectedCallPark objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listDirectedCallPark(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def apply_directed_call_park(self, name: str) -> Dict[str, Any]:
        """Apply configuration for a DirectedCallPark.

        Args:
            name: The DirectedCallPark name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.applyDirectedCallPark(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def reset_directed_call_park(self, name: str) -> Dict[str, Any]:
        """Reset a DirectedCallPark.

        Args:
            name: The DirectedCallPark name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.resetDirectedCallPark(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  DirectoryLookupDialRules
    # ═══════════════════════════════════════════════════════════════════

    def get_directory_lookup_dial_rules(self, name: str) -> Dict[str, Any]:
        """Retrieve a DirectoryLookupDialRules by name.

        Args:
            name: The DirectoryLookupDialRules name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getDirectoryLookupDialRules(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_directory_lookup_dial_rules(self, directory_lookup_dial_rules_data: DirectoryLookupDialRules) -> Dict[str, Any]:
        """Add a new DirectoryLookupDialRules.

        Args:
            directory_lookup_dial_rules_data: A dict describing the DirectoryLookupDialRules.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addDirectoryLookupDialRules(directoryLookupDialRules=directory_lookup_dial_rules_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_directory_lookup_dial_rules(self, **kwargs: Unpack[UpdateDirectoryLookupDialRules]) -> Dict[str, Any]:
        """Update an existing DirectoryLookupDialRules.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateDirectoryLookupDialRules(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_directory_lookup_dial_rules(self, name: str) -> Dict[str, Any]:
        """Remove a DirectoryLookupDialRules by name.

        Args:
            name: The DirectoryLookupDialRules name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeDirectoryLookupDialRules(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_directory_lookup_dial_rules(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List DirectoryLookupDialRules objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listDirectoryLookupDialRules(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  ElinGroup
    # ═══════════════════════════════════════════════════════════════════

    def get_elin_group(self, name: str) -> Dict[str, Any]:
        """Retrieve a ElinGroup by name.

        Args:
            name: The ElinGroup name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getElinGroup(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_elin_group(self, elin_group_data: ElinGroup) -> Dict[str, Any]:
        """Add a new ElinGroup.

        Args:
            elin_group_data: A dict describing the ElinGroup.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addElinGroup(elinGroup=elin_group_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_elin_group(self, **kwargs: Unpack[UpdateElinGroup]) -> Dict[str, Any]:
        """Update an existing ElinGroup.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateElinGroup(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_elin_group(self, name: str) -> Dict[str, Any]:
        """Remove a ElinGroup by name.

        Args:
            name: The ElinGroup name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeElinGroup(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_elin_group(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List ElinGroup objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listElinGroup(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  EndUserCapfProfile
    # ═══════════════════════════════════════════════════════════════════

    def get_end_user_capf_profile(self, instance_id: str) -> Dict[str, Any]:
        """Retrieve a EndUserCapfProfile by instance ID.

        Args:
            instance_id: The EndUserCapfProfile instance ID.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getEndUserCapfProfile(instanceId=instance_id)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_end_user_capf_profile(self, end_user_capf_profile_data: EndUserCapfProfile) -> Dict[str, Any]:
        """Add a new EndUserCapfProfile.

        Args:
            end_user_capf_profile_data: A dict describing the EndUserCapfProfile.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addEndUserCapfProfile(endUserCapfProfile=end_user_capf_profile_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_end_user_capf_profile(self, **kwargs: Unpack[UpdateEndUserCapfProfile]) -> Dict[str, Any]:
        """Update an existing EndUserCapfProfile.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateEndUserCapfProfile(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_end_user_capf_profile(self, instance_id: str) -> Dict[str, Any]:
        """Remove a EndUserCapfProfile by instance ID.

        Args:
            instance_id: The EndUserCapfProfile instance ID.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeEndUserCapfProfile(instanceId=instance_id)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_end_user_capf_profile(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List EndUserCapfProfile objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listEndUserCapfProfile(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  EnterpriseFeatureAccessConfiguration
    # ═══════════════════════════════════════════════════════════════════

    def get_enterprise_feature_access_configuration(self, name: str, **kwargs) -> Dict[str, Any]:
        """Retrieve an EnterpriseFeatureAccessConfiguration by pattern.

        Args:
            name: The pattern.
            **kwargs: Additional keyword args (e.g. ``routePartitionName``).

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getEnterpriseFeatureAccessConfiguration(pattern=name, **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_enterprise_feature_access_configuration(self, enterprise_feature_access_configuration_data: EnterpriseFeatureAccessConfiguration) -> Dict[str, Any]:
        """Add a new EnterpriseFeatureAccessConfiguration.

        Args:
            enterprise_feature_access_configuration_data: A dict describing the EnterpriseFeatureAccessConfiguration.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addEnterpriseFeatureAccessConfiguration(enterpriseFeatureAccessConfiguration=enterprise_feature_access_configuration_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_enterprise_feature_access_configuration(self, **kwargs: Unpack[UpdateEnterpriseFeatureAccessConfiguration]) -> Dict[str, Any]:
        """Update an existing EnterpriseFeatureAccessConfiguration.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateEnterpriseFeatureAccessConfiguration(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_enterprise_feature_access_configuration(self, name: str, **kwargs) -> Dict[str, Any]:
        """Remove an EnterpriseFeatureAccessConfiguration by pattern.

        Args:
            name: The pattern.
            **kwargs: Additional keyword args (e.g. ``routePartitionName``).

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeEnterpriseFeatureAccessConfiguration(pattern=name, **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_enterprise_feature_access_configuration(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List EnterpriseFeatureAccessConfiguration objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listEnterpriseFeatureAccessConfiguration(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  EnterpriseParametersReset
    # ═══════════════════════════════════════════════════════════════════

    # ═══════════════════════════════════════════════════════════════════
    #  ExpresswayCConfiguration
    # ═══════════════════════════════════════════════════════════════════

    def get_expressway_c_configuration(self, name: str) -> Dict[str, Any]:
        """Retrieve a ExpresswayCConfiguration by name.

        Args:
            name: The ExpresswayCConfiguration name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getExpresswayCConfiguration(HostNameOrIP=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_expressway_c_configuration(self, expressway_c_configuration_data: ExpresswayCConfiguration) -> Dict[str, Any]:
        """Add a new ExpresswayCConfiguration.

        Args:
            expressway_c_configuration_data: A dict describing the ExpresswayCConfiguration.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addExpresswayCConfiguration(expresswayCConfiguration=expressway_c_configuration_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_expressway_c_configuration(self, **kwargs: Unpack[UpdateExpresswayCConfiguration]) -> Dict[str, Any]:
        """Update an existing ExpresswayCConfiguration.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateExpresswayCConfiguration(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_expressway_c_configuration(self, name: str) -> Dict[str, Any]:
        """Remove a ExpresswayCConfiguration by name.

        Args:
            name: The ExpresswayCConfiguration name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeExpresswayCConfiguration(HostNameOrIP=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_expressway_c_configuration(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List ExpresswayCConfiguration objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listExpresswayCConfiguration(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  ExternalCallControlProfile
    # ═══════════════════════════════════════════════════════════════════

    def get_external_call_control_profile(self, name: str) -> Dict[str, Any]:
        """Retrieve a ExternalCallControlProfile by name.

        Args:
            name: The ExternalCallControlProfile name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getExternalCallControlProfile(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_external_call_control_profile(self, external_call_control_profile_data: ExternalCallControlProfile) -> Dict[str, Any]:
        """Add a new ExternalCallControlProfile.

        Args:
            external_call_control_profile_data: A dict describing the ExternalCallControlProfile.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addExternalCallControlProfile(externalCallControlProfile=external_call_control_profile_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_external_call_control_profile(self, **kwargs: Unpack[UpdateExternalCallControlProfile]) -> Dict[str, Any]:
        """Update an existing ExternalCallControlProfile.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateExternalCallControlProfile(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_external_call_control_profile(self, name: str) -> Dict[str, Any]:
        """Remove a ExternalCallControlProfile by name.

        Args:
            name: The ExternalCallControlProfile name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeExternalCallControlProfile(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_external_call_control_profile(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List ExternalCallControlProfile objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listExternalCallControlProfile(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  FacInfo
    # ═══════════════════════════════════════════════════════════════════

    def get_fac_info(self, name: str) -> Dict[str, Any]:
        """Retrieve a FacInfo by name.

        Args:
            name: The FacInfo name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getFacInfo(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_fac_info(self, fac_info_data: FacInfo) -> Dict[str, Any]:
        """Add a new FacInfo.

        Args:
            fac_info_data: A dict describing the FacInfo.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addFacInfo(facInfo=fac_info_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_fac_info(self, **kwargs: Unpack[UpdateFacInfo]) -> Dict[str, Any]:
        """Update an existing FacInfo.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateFacInfo(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_fac_info(self, name: str) -> Dict[str, Any]:
        """Remove a FacInfo by name.

        Args:
            name: The FacInfo name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeFacInfo(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_fac_info(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List FacInfo objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listFacInfo(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  FallbackProfile
    # ═══════════════════════════════════════════════════════════════════

    def get_fallback_profile(self, name: str) -> Dict[str, Any]:
        """Retrieve a FallbackProfile by name.

        Args:
            name: The FallbackProfile name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getFallbackProfile(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_fallback_profile(self, fallback_profile_data: FallbackProfile) -> Dict[str, Any]:
        """Add a new FallbackProfile.

        Args:
            fallback_profile_data: A dict describing the FallbackProfile.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addFallbackProfile(fallbackProfile=fallback_profile_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_fallback_profile(self, **kwargs: Unpack[UpdateFallbackProfile]) -> Dict[str, Any]:
        """Update an existing FallbackProfile.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateFallbackProfile(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_fallback_profile(self, name: str) -> Dict[str, Any]:
        """Remove a FallbackProfile by name.

        Args:
            name: The FallbackProfile name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeFallbackProfile(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_fallback_profile(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List FallbackProfile objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listFallbackProfile(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  FeatureControlPolicy
    # ═══════════════════════════════════════════════════════════════════

    def get_feature_control_policy(self, name: str) -> Dict[str, Any]:
        """Retrieve a FeatureControlPolicy by name.

        Args:
            name: The FeatureControlPolicy name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getFeatureControlPolicy(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_feature_control_policy(self, feature_control_policy_data: FeatureControlPolicy) -> Dict[str, Any]:
        """Add a new FeatureControlPolicy.

        Args:
            feature_control_policy_data: A dict describing the FeatureControlPolicy.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addFeatureControlPolicy(featureControlPolicy=feature_control_policy_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_feature_control_policy(self, **kwargs: Unpack[UpdateFeatureControlPolicy]) -> Dict[str, Any]:
        """Update an existing FeatureControlPolicy.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateFeatureControlPolicy(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_feature_control_policy(self, name: str) -> Dict[str, Any]:
        """Remove a FeatureControlPolicy by name.

        Args:
            name: The FeatureControlPolicy name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeFeatureControlPolicy(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_feature_control_policy(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List FeatureControlPolicy objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listFeatureControlPolicy(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  FeatureGroupTemplate
    # ═══════════════════════════════════════════════════════════════════

    def get_feature_group_template(self, name: str) -> Dict[str, Any]:
        """Retrieve a FeatureGroupTemplate by name.

        Args:
            name: The FeatureGroupTemplate name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getFeatureGroupTemplate(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_feature_group_template(self, feature_group_template_data: FeatureGroupTemplate) -> Dict[str, Any]:
        """Add a new FeatureGroupTemplate.

        Args:
            feature_group_template_data: A dict describing the FeatureGroupTemplate.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addFeatureGroupTemplate(featureGroupTemplate=feature_group_template_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_feature_group_template(self, **kwargs: Unpack[UpdateFeatureGroupTemplate]) -> Dict[str, Any]:
        """Update an existing FeatureGroupTemplate.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateFeatureGroupTemplate(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_feature_group_template(self, name: str) -> Dict[str, Any]:
        """Remove a FeatureGroupTemplate by name.

        Args:
            name: The FeatureGroupTemplate name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeFeatureGroupTemplate(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_feature_group_template(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List FeatureGroupTemplate objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listFeatureGroupTemplate(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Gatekeeper
    # ═══════════════════════════════════════════════════════════════════

    def get_gatekeeper(self, name: str) -> Dict[str, Any]:
        """Retrieve a Gatekeeper by name.

        Args:
            name: The Gatekeeper name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getGatekeeper(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_gatekeeper(self, gatekeeper_data: Gatekeeper) -> Dict[str, Any]:
        """Add a new Gatekeeper.

        Args:
            gatekeeper_data: A dict describing the Gatekeeper.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addGatekeeper(gatekeeper=gatekeeper_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_gatekeeper(self, **kwargs: Unpack[UpdateGatekeeper]) -> Dict[str, Any]:
        """Update an existing Gatekeeper.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateGatekeeper(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_gatekeeper(self, name: str) -> Dict[str, Any]:
        """Remove a Gatekeeper by name.

        Args:
            name: The Gatekeeper name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeGatekeeper(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_gatekeeper(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List Gatekeeper objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listGatekeeper(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def apply_gatekeeper(self, name: str) -> Dict[str, Any]:
        """Apply configuration for a Gatekeeper.

        Args:
            name: The Gatekeeper name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.applyGatekeeper(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def reset_gatekeeper(self, name: str) -> Dict[str, Any]:
        """Reset a Gatekeeper.

        Args:
            name: The Gatekeeper name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.resetGatekeeper(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def restart_gatekeeper(self, name: str) -> Dict[str, Any]:
        """Restart a Gatekeeper.

        Args:
            name: The Gatekeeper name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.restartGatekeeper(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Gateway
    # ═══════════════════════════════════════════════════════════════════

    def get_gateway(self, domain_name: str = "", **kwargs) -> Dict[str, Any]:
        """Retrieve a Gateway by domainName.

        Args:
            domain_name: The Gateway domain name.
            **kwargs: Additional keyword arguments (e.g., ``uuid``).

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            if domain_name:
                kwargs["domainName"] = domain_name
            return self._service.getGateway(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_gateway(self, gateway_data: Gateway) -> Dict[str, Any]:
        """Add a new Gateway.

        Args:
            gateway_data: A dict describing the Gateway.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addGateway(gateway=gateway_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_gateway(self, **kwargs: Unpack[UpdateGateway]) -> Dict[str, Any]:
        """Update an existing Gateway.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateGateway(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_gateway(self, domain_name: str = "", **kwargs) -> Dict[str, Any]:
        """Remove a Gateway by domainName.

        Args:
            domain_name: The Gateway domain name.
            **kwargs: Additional keyword arguments (e.g., ``uuid``).

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            if domain_name:
                kwargs["domainName"] = domain_name
            return self._service.removeGateway(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_gateway(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List Gateway objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listGateway(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def apply_gateway(self, name: str) -> Dict[str, Any]:
        """Apply configuration for a Gateway.

        Args:
            name: The Gateway name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.applyGateway(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def reset_gateway(self, name: str) -> Dict[str, Any]:
        """Reset a Gateway.

        Args:
            name: The Gateway name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.resetGateway(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def restart_gateway(self, name: str) -> Dict[str, Any]:
        """Restart a Gateway.

        Args:
            name: The Gateway name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.restartGateway(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  GatewayEndpointAnalogAccess
    # ═══════════════════════════════════════════════════════════════════

    def get_gateway_endpoint_analog_access(self, name: str) -> Dict[str, Any]:
        """Retrieve a GatewayEndpointAnalogAccess by name.

        Args:
            name: The GatewayEndpointAnalogAccess name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getGatewayEndpointAnalogAccess(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_gateway_endpoint_analog_access(self, gateway_endpoint_analog_access_data: GatewayEndpointAnalogAccess) -> Dict[str, Any]:
        """Add a new GatewayEndpointAnalogAccess.

        Args:
            gateway_endpoint_analog_access_data: A dict describing the GatewayEndpointAnalogAccess.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addGatewayEndpointAnalogAccess(gatewayEndpointAnalogAccess=gateway_endpoint_analog_access_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_gateway_endpoint_analog_access(self, **kwargs: Unpack[UpdateGatewayEndpointAnalogAccess]) -> Dict[str, Any]:
        """Update an existing GatewayEndpointAnalogAccess.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateGatewayEndpointAnalogAccess(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_gateway_endpoint_analog_access(self, name: str) -> Dict[str, Any]:
        """Remove a GatewayEndpointAnalogAccess by name.

        Args:
            name: The GatewayEndpointAnalogAccess name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeGatewayEndpointAnalogAccess(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  GatewayEndpointDigitalAccessBri
    # ═══════════════════════════════════════════════════════════════════

    def get_gateway_endpoint_digital_access_bri(self, name: str) -> Dict[str, Any]:
        """Retrieve a GatewayEndpointDigitalAccessBri by name.

        Args:
            name: The GatewayEndpointDigitalAccessBri name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getGatewayEndpointDigitalAccessBri(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_gateway_endpoint_digital_access_bri(self, gateway_endpoint_digital_access_bri_data: GatewayEndpointDigitalAccessBri) -> Dict[str, Any]:
        """Add a new GatewayEndpointDigitalAccessBri.

        Args:
            gateway_endpoint_digital_access_bri_data: A dict describing the GatewayEndpointDigitalAccessBri.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addGatewayEndpointDigitalAccessBri(gatewayEndpointDigitalAccessBri=gateway_endpoint_digital_access_bri_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_gateway_endpoint_digital_access_bri(self, **kwargs: Unpack[UpdateGatewayEndpointDigitalAccessBri]) -> Dict[str, Any]:
        """Update an existing GatewayEndpointDigitalAccessBri.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateGatewayEndpointDigitalAccessBri(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_gateway_endpoint_digital_access_bri(self, name: str) -> Dict[str, Any]:
        """Remove a GatewayEndpointDigitalAccessBri by name.

        Args:
            name: The GatewayEndpointDigitalAccessBri name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeGatewayEndpointDigitalAccessBri(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  GatewayEndpointDigitalAccessPri
    # ═══════════════════════════════════════════════════════════════════

    def get_gateway_endpoint_digital_access_pri(self, name: str) -> Dict[str, Any]:
        """Retrieve a GatewayEndpointDigitalAccessPri by name.

        Args:
            name: The GatewayEndpointDigitalAccessPri name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getGatewayEndpointDigitalAccessPri(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_gateway_endpoint_digital_access_pri(self, gateway_endpoint_digital_access_pri_data: GatewayEndpointDigitalAccessPri) -> Dict[str, Any]:
        """Add a new GatewayEndpointDigitalAccessPri.

        Args:
            gateway_endpoint_digital_access_pri_data: A dict describing the GatewayEndpointDigitalAccessPri.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addGatewayEndpointDigitalAccessPri(gatewayEndpointDigitalAccessPri=gateway_endpoint_digital_access_pri_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_gateway_endpoint_digital_access_pri(self, **kwargs: Unpack[UpdateGatewayEndpointDigitalAccessPri]) -> Dict[str, Any]:
        """Update an existing GatewayEndpointDigitalAccessPri.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateGatewayEndpointDigitalAccessPri(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_gateway_endpoint_digital_access_pri(self, name: str) -> Dict[str, Any]:
        """Remove a GatewayEndpointDigitalAccessPri by name.

        Args:
            name: The GatewayEndpointDigitalAccessPri name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeGatewayEndpointDigitalAccessPri(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  GatewayEndpointDigitalAccessT1
    # ═══════════════════════════════════════════════════════════════════

    def get_gateway_endpoint_digital_access_t1(self, name: str) -> Dict[str, Any]:
        """Retrieve a GatewayEndpointDigitalAccessT1 by name.

        Args:
            name: The GatewayEndpointDigitalAccessT1 name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getGatewayEndpointDigitalAccessT1(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_gateway_endpoint_digital_access_t1(self, gateway_endpoint_digital_access_t1_data: GatewayEndpointDigitalAccessT1) -> Dict[str, Any]:
        """Add a new GatewayEndpointDigitalAccessT1.

        Args:
            gateway_endpoint_digital_access_t1_data: A dict describing the GatewayEndpointDigitalAccessT1.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addGatewayEndpointDigitalAccessT1(gatewayEndpointDigitalAccessT1=gateway_endpoint_digital_access_t1_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_gateway_endpoint_digital_access_t1(self, **kwargs: Unpack[UpdateGatewayEndpointDigitalAccessT1]) -> Dict[str, Any]:
        """Update an existing GatewayEndpointDigitalAccessT1.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateGatewayEndpointDigitalAccessT1(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_gateway_endpoint_digital_access_t1(self, name: str) -> Dict[str, Any]:
        """Remove a GatewayEndpointDigitalAccessT1 by name.

        Args:
            name: The GatewayEndpointDigitalAccessT1 name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeGatewayEndpointDigitalAccessT1(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  GatewaySccpEndpoints
    # ═══════════════════════════════════════════════════════════════════

    def get_gateway_sccp_endpoints(self, name: str) -> Dict[str, Any]:
        """Retrieve a GatewaySccpEndpoints by name.

        Args:
            name: The GatewaySccpEndpoints name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getGatewaySccpEndpoints(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_gateway_sccp_endpoints(self, gateway_sccp_endpoints_data: GatewaySccpEndpoints) -> Dict[str, Any]:
        """Add a new GatewaySccpEndpoints.

        Args:
            gateway_sccp_endpoints_data: A dict describing the GatewaySccpEndpoints.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addGatewaySccpEndpoints(gatewaySccpEndpoints=gateway_sccp_endpoints_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_gateway_sccp_endpoints(self, **kwargs: Unpack[UpdateGatewaySccpEndpoints]) -> Dict[str, Any]:
        """Update an existing GatewaySccpEndpoints.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateGatewaySccpEndpoints(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_gateway_sccp_endpoints(self, name: str) -> Dict[str, Any]:
        """Remove a GatewaySccpEndpoints by name.

        Args:
            name: The GatewaySccpEndpoints name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeGatewaySccpEndpoints(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  GatewaySubunits
    # ═══════════════════════════════════════════════════════════════════

    def add_gateway_subunits(self, gateway_subunits_data: GatewaySubunits) -> Dict[str, Any]:
        """Add a new GatewaySubunits.

        Args:
            gateway_subunits_data: A dict describing the GatewaySubunits.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addGatewaySubunits(gatewaySubunits=gateway_subunits_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_gateway_subunits(self, name: str) -> Dict[str, Any]:
        """Remove a GatewaySubunits by name.

        Args:
            name: The GatewaySubunits name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeGatewaySubunits(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  GeoLocation
    # ═══════════════════════════════════════════════════════════════════

    def get_geo_location(self, name: str) -> Dict[str, Any]:
        """Retrieve a GeoLocation by name.

        Args:
            name: The GeoLocation name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getGeoLocation(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_geo_location(self, geo_location_data: GeoLocation) -> Dict[str, Any]:
        """Add a new GeoLocation.

        Args:
            geo_location_data: A dict describing the GeoLocation.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addGeoLocation(geoLocation=geo_location_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_geo_location(self, **kwargs: Unpack[UpdateGeoLocation]) -> Dict[str, Any]:
        """Update an existing GeoLocation.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateGeoLocation(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_geo_location(self, name: str) -> Dict[str, Any]:
        """Remove a GeoLocation by name.

        Args:
            name: The GeoLocation name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeGeoLocation(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_geo_location(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List GeoLocation objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listGeoLocation(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  GeoLocationFilter
    # ═══════════════════════════════════════════════════════════════════

    def get_geo_location_filter(self, name: str) -> Dict[str, Any]:
        """Retrieve a GeoLocationFilter by name.

        Args:
            name: The GeoLocationFilter name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getGeoLocationFilter(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_geo_location_filter(self, geo_location_filter_data: GeoLocationFilter) -> Dict[str, Any]:
        """Add a new GeoLocationFilter.

        Args:
            geo_location_filter_data: A dict describing the GeoLocationFilter.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addGeoLocationFilter(geoLocationFilter=geo_location_filter_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_geo_location_filter(self, **kwargs: Unpack[UpdateGeoLocationFilter]) -> Dict[str, Any]:
        """Update an existing GeoLocationFilter.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateGeoLocationFilter(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_geo_location_filter(self, name: str) -> Dict[str, Any]:
        """Remove a GeoLocationFilter by name.

        Args:
            name: The GeoLocationFilter name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeGeoLocationFilter(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_geo_location_filter(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List GeoLocationFilter objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listGeoLocationFilter(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  GeoLocationPolicy
    # ═══════════════════════════════════════════════════════════════════

    def get_geo_location_policy(self, name: str) -> Dict[str, Any]:
        """Retrieve a GeoLocationPolicy by name.

        Args:
            name: The GeoLocationPolicy name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getGeoLocationPolicy(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_geo_location_policy(self, geo_location_policy_data: GeoLocationPolicy) -> Dict[str, Any]:
        """Add a new GeoLocationPolicy.

        Args:
            geo_location_policy_data: A dict describing the GeoLocationPolicy.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addGeoLocationPolicy(geoLocationPolicy=geo_location_policy_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_geo_location_policy(self, **kwargs: Unpack[UpdateGeoLocationPolicy]) -> Dict[str, Any]:
        """Update an existing GeoLocationPolicy.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateGeoLocationPolicy(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_geo_location_policy(self, name: str) -> Dict[str, Any]:
        """Remove a GeoLocationPolicy by name.

        Args:
            name: The GeoLocationPolicy name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeGeoLocationPolicy(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_geo_location_policy(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List GeoLocationPolicy objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listGeoLocationPolicy(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  H323Gateway
    # ═══════════════════════════════════════════════════════════════════

    def list_h323_gateway(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List H323Gateway objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listH323Gateway(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def apply_h323_gateway(self, name: str) -> Dict[str, Any]:
        """Apply configuration for a H323Gateway.

        Args:
            name: The H323Gateway name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.applyH323Gateway(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def reset_h323_gateway(self, name: str) -> Dict[str, Any]:
        """Reset a H323Gateway.

        Args:
            name: The H323Gateway name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.resetH323Gateway(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def restart_h323_gateway(self, name: str) -> Dict[str, Any]:
        """Restart a H323Gateway.

        Args:
            name: The H323Gateway name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.restartH323Gateway(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  H323Phone
    # ═══════════════════════════════════════════════════════════════════

    def get_h323_phone(self, name: str) -> Dict[str, Any]:
        """Retrieve a H323Phone by name.

        Args:
            name: The H323Phone name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getH323Phone(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_h323_phone(self, h323_phone_data: H323Phone) -> Dict[str, Any]:
        """Add a new H323Phone.

        Args:
            h323_phone_data: A dict describing the H323Phone.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addH323Phone(h323Phone=h323_phone_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_h323_phone(self, **kwargs: Unpack[UpdateH323Phone]) -> Dict[str, Any]:
        """Update an existing H323Phone.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateH323Phone(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_h323_phone(self, name: str) -> Dict[str, Any]:
        """Remove a H323Phone by name.

        Args:
            name: The H323Phone name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeH323Phone(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_h323_phone(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List H323Phone objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listH323Phone(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def apply_h323_phone(self, name: str) -> Dict[str, Any]:
        """Apply configuration for a H323Phone.

        Args:
            name: The H323Phone name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.applyH323Phone(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def reset_h323_phone(self, name: str) -> Dict[str, Any]:
        """Reset a H323Phone.

        Args:
            name: The H323Phone name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.resetH323Phone(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def restart_h323_phone(self, name: str) -> Dict[str, Any]:
        """Restart a H323Phone.

        Args:
            name: The H323Phone name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.restartH323Phone(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  H323Trunk
    # ═══════════════════════════════════════════════════════════════════

    def list_h323_trunk(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List H323Trunk objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listH323Trunk(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def reset_h323_trunk(self, name: str) -> Dict[str, Any]:
        """Reset a H323Trunk.

        Args:
            name: The H323Trunk name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.resetH323Trunk(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def restart_h323_trunk(self, name: str) -> Dict[str, Any]:
        """Restart a H323Trunk.

        Args:
            name: The H323Trunk name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.restartH323Trunk(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  HandoffConfiguration
    # ═══════════════════════════════════════════════════════════════════

    def get_handoff_configuration(self, **kwargs) -> Dict[str, Any]:
        """Retrieve a HandoffConfiguration.

        Args:
            **kwargs: Must include ``pattern`` (and optionally
                ``routePartitionName``); or ``uuid``.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getHandoffConfiguration(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_handoff_configuration(self, handoff_configuration_data: HandoffConfiguration) -> Dict[str, Any]:
        """Add a new HandoffConfiguration.

        Args:
            handoff_configuration_data: A dict describing the HandoffConfiguration.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addHandoffConfiguration(handoffConfiguration=handoff_configuration_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_handoff_configuration(self, **kwargs: Unpack[UpdateHandoffConfiguration]) -> Dict[str, Any]:
        """Update an existing HandoffConfiguration.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateHandoffConfiguration(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_handoff_configuration(self, **kwargs) -> Dict[str, Any]:
        """Remove a HandoffConfiguration.

        Args:
            **kwargs: Must include ``pattern`` (and optionally
                ``routePartitionName``); or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeHandoffConfiguration(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  HttpProfile
    # ═══════════════════════════════════════════════════════════════════

    def get_http_profile(self, name: str) -> Dict[str, Any]:
        """Retrieve a HttpProfile by name.

        Args:
            name: The HttpProfile name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getHttpProfile(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_http_profile(self, http_profile_data: HttpProfile) -> Dict[str, Any]:
        """Add a new HttpProfile.

        Args:
            http_profile_data: A dict describing the HttpProfile.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addHttpProfile(httpProfile=http_profile_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_http_profile(self, **kwargs: Unpack[UpdateHttpProfile]) -> Dict[str, Any]:
        """Update an existing HttpProfile.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateHttpProfile(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_http_profile(self, name: str) -> Dict[str, Any]:
        """Remove a HttpProfile by name.

        Args:
            name: The HttpProfile name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeHttpProfile(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  HuntList
    # ═══════════════════════════════════════════════════════════════════

    def list_hunt_list(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List HuntList objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listHuntList(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def apply_hunt_list(self, name: str) -> Dict[str, Any]:
        """Apply configuration for a HuntList.

        Args:
            name: The HuntList name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.applyHuntList(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def reset_hunt_list(self, name: str) -> Dict[str, Any]:
        """Reset a HuntList.

        Args:
            name: The HuntList name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.resetHuntList(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  HuntPilot
    # ═══════════════════════════════════════════════════════════════════

    def list_hunt_pilot(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List HuntPilot objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listHuntPilot(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  ImeClient
    # ═══════════════════════════════════════════════════════════════════

    def get_ime_client(self, name: str) -> Dict[str, Any]:
        """Retrieve a ImeClient by name.

        Args:
            name: The ImeClient name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getImeClient(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_ime_client(self, ime_client_data: ImeClient) -> Dict[str, Any]:
        """Add a new ImeClient.

        Args:
            ime_client_data: A dict describing the ImeClient.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addImeClient(imeClient=ime_client_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_ime_client(self, **kwargs: Unpack[UpdateImeClient]) -> Dict[str, Any]:
        """Update an existing ImeClient.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateImeClient(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_ime_client(self, name: str) -> Dict[str, Any]:
        """Remove a ImeClient by name.

        Args:
            name: The ImeClient name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeImeClient(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_ime_client(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List ImeClient objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listImeClient(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  ImeE164Transformation
    # ═══════════════════════════════════════════════════════════════════

    def get_ime_e164_transformation(self, name: str) -> Dict[str, Any]:
        """Retrieve a ImeE164Transformation by name.

        Args:
            name: The ImeE164Transformation name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getImeE164Transformation(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_ime_e164_transformation(self, ime_e164_transformation_data: ImeE164Transformation) -> Dict[str, Any]:
        """Add a new ImeE164Transformation.

        Args:
            ime_e164_transformation_data: A dict describing the ImeE164Transformation.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addImeE164Transformation(imeE164Transformation=ime_e164_transformation_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_ime_e164_transformation(self, **kwargs: Unpack[UpdateImeE164Transformation]) -> Dict[str, Any]:
        """Update an existing ImeE164Transformation.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateImeE164Transformation(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_ime_e164_transformation(self, name: str) -> Dict[str, Any]:
        """Remove a ImeE164Transformation by name.

        Args:
            name: The ImeE164Transformation name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeImeE164Transformation(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_ime_e164_transformation(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List ImeE164Transformation objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listImeE164Transformation(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  ImeEnrolledPattern
    # ═══════════════════════════════════════════════════════════════════

    def get_ime_enrolled_pattern(self, pattern: str) -> Dict[str, Any]:
        """Retrieve a ImeEnrolledPattern by pattern.

        Args:
            pattern: The ImeEnrolledPattern pattern.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getImeEnrolledPattern(pattern=pattern)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_ime_enrolled_pattern(self, ime_enrolled_pattern_data: ImeEnrolledPattern) -> Dict[str, Any]:
        """Add a new ImeEnrolledPattern.

        Args:
            ime_enrolled_pattern_data: A dict describing the ImeEnrolledPattern.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addImeEnrolledPattern(imeEnrolledPattern=ime_enrolled_pattern_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_ime_enrolled_pattern(self, **kwargs: Unpack[UpdateImeEnrolledPattern]) -> Dict[str, Any]:
        """Update an existing ImeEnrolledPattern.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateImeEnrolledPattern(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_ime_enrolled_pattern(self, pattern: str) -> Dict[str, Any]:
        """Remove a ImeEnrolledPattern by pattern.

        Args:
            pattern: The ImeEnrolledPattern pattern.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeImeEnrolledPattern(pattern=pattern)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_ime_enrolled_pattern(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List ImeEnrolledPattern objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listImeEnrolledPattern(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  ImeEnrolledPatternGroup
    # ═══════════════════════════════════════════════════════════════════

    def get_ime_enrolled_pattern_group(self, name: str) -> Dict[str, Any]:
        """Retrieve a ImeEnrolledPatternGroup by name.

        Args:
            name: The ImeEnrolledPatternGroup name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getImeEnrolledPatternGroup(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_ime_enrolled_pattern_group(self, ime_enrolled_pattern_group_data: ImeEnrolledPatternGroup) -> Dict[str, Any]:
        """Add a new ImeEnrolledPatternGroup.

        Args:
            ime_enrolled_pattern_group_data: A dict describing the ImeEnrolledPatternGroup.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addImeEnrolledPatternGroup(imeEnrolledPatternGroup=ime_enrolled_pattern_group_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_ime_enrolled_pattern_group(self, **kwargs: Unpack[UpdateImeEnrolledPatternGroup]) -> Dict[str, Any]:
        """Update an existing ImeEnrolledPatternGroup.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateImeEnrolledPatternGroup(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_ime_enrolled_pattern_group(self, name: str) -> Dict[str, Any]:
        """Remove a ImeEnrolledPatternGroup by name.

        Args:
            name: The ImeEnrolledPatternGroup name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeImeEnrolledPatternGroup(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_ime_enrolled_pattern_group(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List ImeEnrolledPatternGroup objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listImeEnrolledPatternGroup(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  ImeExclusionNumber
    # ═══════════════════════════════════════════════════════════════════

    def get_ime_exclusion_number(self, pattern: str) -> Dict[str, Any]:
        """Retrieve a ImeExclusionNumber by pattern.

        Args:
            pattern: The ImeExclusionNumber pattern.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getImeExclusionNumber(pattern=pattern)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_ime_exclusion_number(self, ime_exclusion_number_data: ImeExclusionNumber) -> Dict[str, Any]:
        """Add a new ImeExclusionNumber.

        Args:
            ime_exclusion_number_data: A dict describing the ImeExclusionNumber.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addImeExclusionNumber(imeExclusionNumber=ime_exclusion_number_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_ime_exclusion_number(self, **kwargs: Unpack[UpdateImeExclusionNumber]) -> Dict[str, Any]:
        """Update an existing ImeExclusionNumber.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateImeExclusionNumber(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_ime_exclusion_number(self, pattern: str) -> Dict[str, Any]:
        """Remove a ImeExclusionNumber by pattern.

        Args:
            pattern: The ImeExclusionNumber pattern.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeImeExclusionNumber(pattern=pattern)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_ime_exclusion_number(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List ImeExclusionNumber objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listImeExclusionNumber(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  ImeExclusionNumberGroup
    # ═══════════════════════════════════════════════════════════════════

    def get_ime_exclusion_number_group(self, name: str) -> Dict[str, Any]:
        """Retrieve a ImeExclusionNumberGroup by name.

        Args:
            name: The ImeExclusionNumberGroup name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getImeExclusionNumberGroup(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_ime_exclusion_number_group(self, ime_exclusion_number_group_data: ImeExclusionNumberGroup) -> Dict[str, Any]:
        """Add a new ImeExclusionNumberGroup.

        Args:
            ime_exclusion_number_group_data: A dict describing the ImeExclusionNumberGroup.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addImeExclusionNumberGroup(imeExclusionNumberGroup=ime_exclusion_number_group_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_ime_exclusion_number_group(self, **kwargs: Unpack[UpdateImeExclusionNumberGroup]) -> Dict[str, Any]:
        """Update an existing ImeExclusionNumberGroup.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateImeExclusionNumberGroup(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_ime_exclusion_number_group(self, name: str) -> Dict[str, Any]:
        """Remove a ImeExclusionNumberGroup by name.

        Args:
            name: The ImeExclusionNumberGroup name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeImeExclusionNumberGroup(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_ime_exclusion_number_group(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List ImeExclusionNumberGroup objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listImeExclusionNumberGroup(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  ImeFirewall
    # ═══════════════════════════════════════════════════════════════════

    def get_ime_firewall(self, name: str) -> Dict[str, Any]:
        """Retrieve a ImeFirewall by name.

        Args:
            name: The ImeFirewall name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getImeFirewall(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_ime_firewall(self, ime_firewall_data: ImeFirewall) -> Dict[str, Any]:
        """Add a new ImeFirewall.

        Args:
            ime_firewall_data: A dict describing the ImeFirewall.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addImeFirewall(imeFirewall=ime_firewall_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_ime_firewall(self, **kwargs: Unpack[UpdateImeFirewall]) -> Dict[str, Any]:
        """Update an existing ImeFirewall.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateImeFirewall(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_ime_firewall(self, name: str) -> Dict[str, Any]:
        """Remove a ImeFirewall by name.

        Args:
            name: The ImeFirewall name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeImeFirewall(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_ime_firewall(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List ImeFirewall objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listImeFirewall(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  ImeRouteFilterElement
    # ═══════════════════════════════════════════════════════════════════

    def get_ime_route_filter_element(self, name: str) -> Dict[str, Any]:
        """Retrieve a ImeRouteFilterElement by name.

        Args:
            name: The ImeRouteFilterElement name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getImeRouteFilterElement(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_ime_route_filter_element(self, ime_route_filter_element_data: ImeRouteFilterElement) -> Dict[str, Any]:
        """Add a new ImeRouteFilterElement.

        Args:
            ime_route_filter_element_data: A dict describing the ImeRouteFilterElement.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addImeRouteFilterElement(imeRouteFilterElement=ime_route_filter_element_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_ime_route_filter_element(self, **kwargs: Unpack[UpdateImeRouteFilterElement]) -> Dict[str, Any]:
        """Update an existing ImeRouteFilterElement.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateImeRouteFilterElement(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_ime_route_filter_element(self, name: str) -> Dict[str, Any]:
        """Remove a ImeRouteFilterElement by name.

        Args:
            name: The ImeRouteFilterElement name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeImeRouteFilterElement(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_ime_route_filter_element(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List ImeRouteFilterElement objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listImeRouteFilterElement(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  ImeRouteFilterGroup
    # ═══════════════════════════════════════════════════════════════════

    def get_ime_route_filter_group(self, name: str) -> Dict[str, Any]:
        """Retrieve a ImeRouteFilterGroup by name.

        Args:
            name: The ImeRouteFilterGroup name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getImeRouteFilterGroup(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_ime_route_filter_group(self, ime_route_filter_group_data: ImeRouteFilterGroup) -> Dict[str, Any]:
        """Add a new ImeRouteFilterGroup.

        Args:
            ime_route_filter_group_data: A dict describing the ImeRouteFilterGroup.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addImeRouteFilterGroup(imeRouteFilterGroup=ime_route_filter_group_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_ime_route_filter_group(self, **kwargs: Unpack[UpdateImeRouteFilterGroup]) -> Dict[str, Any]:
        """Update an existing ImeRouteFilterGroup.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateImeRouteFilterGroup(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_ime_route_filter_group(self, name: str) -> Dict[str, Any]:
        """Remove a ImeRouteFilterGroup by name.

        Args:
            name: The ImeRouteFilterGroup name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeImeRouteFilterGroup(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_ime_route_filter_group(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List ImeRouteFilterGroup objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listImeRouteFilterGroup(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  ImeServer
    # ═══════════════════════════════════════════════════════════════════

    def get_ime_server(self, name: str) -> Dict[str, Any]:
        """Retrieve a ImeServer by name.

        Args:
            name: The ImeServer name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getImeServer(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_ime_server(self, ime_server_data: ImeServer) -> Dict[str, Any]:
        """Add a new ImeServer.

        Args:
            ime_server_data: A dict describing the ImeServer.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addImeServer(imeServer=ime_server_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_ime_server(self, **kwargs: Unpack[UpdateImeServer]) -> Dict[str, Any]:
        """Update an existing ImeServer.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateImeServer(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_ime_server(self, name: str) -> Dict[str, Any]:
        """Remove a ImeServer by name.

        Args:
            name: The ImeServer name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeImeServer(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_ime_server(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List ImeServer objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listImeServer(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  ImportedDirectoryUriCatalogs
    # ═══════════════════════════════════════════════════════════════════

    def get_imported_directory_uri_catalogs(self, name: str) -> Dict[str, Any]:
        """Retrieve a ImportedDirectoryUriCatalogs by name.

        Args:
            name: The ImportedDirectoryUriCatalogs name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getImportedDirectoryUriCatalogs(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_imported_directory_uri_catalogs(self, imported_directory_uri_catalogs_data: ImportedDirectoryUriCatalogs) -> Dict[str, Any]:
        """Add a new ImportedDirectoryUriCatalogs.

        Args:
            imported_directory_uri_catalogs_data: A dict describing the ImportedDirectoryUriCatalogs.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addImportedDirectoryUriCatalogs(importedDirectoryUriCatalogs=imported_directory_uri_catalogs_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_imported_directory_uri_catalogs(self, **kwargs: Unpack[UpdateImportedDirectoryUriCatalogs]) -> Dict[str, Any]:
        """Update an existing ImportedDirectoryUriCatalogs.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateImportedDirectoryUriCatalogs(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_imported_directory_uri_catalogs(self, name: str) -> Dict[str, Any]:
        """Remove a ImportedDirectoryUriCatalogs by name.

        Args:
            name: The ImportedDirectoryUriCatalogs name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeImportedDirectoryUriCatalogs(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_imported_directory_uri_catalogs(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List ImportedDirectoryUriCatalogs objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listImportedDirectoryUriCatalogs(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  InfrastructureDevice
    # ═══════════════════════════════════════════════════════════════════

    def get_infrastructure_device(self, uuid: str) -> Dict[str, Any]:
        """Retrieve an InfrastructureDevice by UUID.

        Args:
            uuid: The InfrastructureDevice UUID.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getInfrastructureDevice(uuid=uuid)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_infrastructure_device(self, infrastructure_device_data: InfrastructureDevice) -> Dict[str, Any]:
        """Add a new InfrastructureDevice.

        Args:
            infrastructure_device_data: A dict describing the InfrastructureDevice.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addInfrastructureDevice(infrastructureDevice=infrastructure_device_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_infrastructure_device(self, **kwargs: Unpack[UpdateInfrastructureDevice]) -> Dict[str, Any]:
        """Update an existing InfrastructureDevice.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateInfrastructureDevice(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_infrastructure_device(self, uuid: str) -> Dict[str, Any]:
        """Remove an InfrastructureDevice by UUID.

        Args:
            uuid: The InfrastructureDevice UUID.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeInfrastructureDevice(uuid=uuid)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_infrastructure_device(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List InfrastructureDevice objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listInfrastructureDevice(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  InteractiveVoiceResponse
    # ═══════════════════════════════════════════════════════════════════

    def get_interactive_voice_response(self, name: str) -> Dict[str, Any]:
        """Retrieve a InteractiveVoiceResponse by name.

        Args:
            name: The InteractiveVoiceResponse name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getInteractiveVoiceResponse(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_interactive_voice_response(self, **kwargs: Unpack[UpdateInteractiveVoiceResponse]) -> Dict[str, Any]:
        """Update an existing InteractiveVoiceResponse.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateInteractiveVoiceResponse(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_interactive_voice_response(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List InteractiveVoiceResponse objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listInteractiveVoiceResponse(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  IpPhoneServices
    # ═══════════════════════════════════════════════════════════════════

    def get_ip_phone_services(self, name: str) -> Dict[str, Any]:
        """Retrieve an IP Phone Service by service name.

        Args:
            name: The IP Phone Service name (``serviceName``).

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getIpPhoneServices(serviceName=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_ip_phone_services(self, ip_phone_services_data: IpPhoneServices) -> Dict[str, Any]:
        """Add a new IpPhoneServices.

        Args:
            ip_phone_services_data: A dict describing the IpPhoneServices.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addIpPhoneServices(ipPhoneServices=ip_phone_services_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_ip_phone_services(self, **kwargs: Unpack[UpdateIpPhoneServices]) -> Dict[str, Any]:
        """Update an existing IpPhoneServices.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateIpPhoneServices(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_ip_phone_services(self, name: str) -> Dict[str, Any]:
        """Remove an IP Phone Service by service name.

        Args:
            name: The IP Phone Service name (``serviceName``).

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeIpPhoneServices(serviceName=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_ip_phone_services(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List IpPhoneServices objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listIpPhoneServices(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  IvrUserLocale
    # ═══════════════════════════════════════════════════════════════════

    def get_ivr_user_locale(self, user_locale: str) -> Dict[str, Any]:
        """Retrieve a IvrUserLocale by userLocale.

        Args:
            user_locale: The IvrUserLocale userLocale.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getIvrUserLocale(userLocale=user_locale)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_ivr_user_locale(self, ivr_user_locale_data: IvrUserLocale) -> Dict[str, Any]:
        """Add a new IvrUserLocale.

        Args:
            ivr_user_locale_data: A dict describing the IvrUserLocale.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addIvrUserLocale(ivrUserLocale=ivr_user_locale_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_ivr_user_locale(self, **kwargs: Unpack[UpdateIvrUserLocale]) -> Dict[str, Any]:
        """Update an existing IvrUserLocale.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateIvrUserLocale(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_ivr_user_locale(self, user_locale: str) -> Dict[str, Any]:
        """Remove a IvrUserLocale by userLocale.

        Args:
            user_locale: The IvrUserLocale userLocale.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeIvrUserLocale(userLocale=user_locale)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_ivr_user_locale(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List IvrUserLocale objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listIvrUserLocale(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  LbmGroup
    # ═══════════════════════════════════════════════════════════════════

    def get_lbm_group(self, name: str) -> Dict[str, Any]:
        """Retrieve a LbmGroup by name.

        Args:
            name: The LbmGroup name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getLbmGroup(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_lbm_group(self, lbm_group_data: LbmGroup) -> Dict[str, Any]:
        """Add a new LbmGroup.

        Args:
            lbm_group_data: A dict describing the LbmGroup.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addLbmGroup(lbmGroup=lbm_group_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_lbm_group(self, **kwargs: Unpack[UpdateLbmGroup]) -> Dict[str, Any]:
        """Update an existing LbmGroup.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateLbmGroup(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_lbm_group(self, name: str) -> Dict[str, Any]:
        """Remove a LbmGroup by name.

        Args:
            name: The LbmGroup name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeLbmGroup(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_lbm_group(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List LbmGroup objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listLbmGroup(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  LbmHubGroup
    # ═══════════════════════════════════════════════════════════════════

    def get_lbm_hub_group(self, name: str) -> Dict[str, Any]:
        """Retrieve a LbmHubGroup by name.

        Args:
            name: The LbmHubGroup name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getLbmHubGroup(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_lbm_hub_group(self, lbm_hub_group_data: LbmHubGroup) -> Dict[str, Any]:
        """Add a new LbmHubGroup.

        Args:
            lbm_hub_group_data: A dict describing the LbmHubGroup.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addLbmHubGroup(lbmHubGroup=lbm_hub_group_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_lbm_hub_group(self, **kwargs: Unpack[UpdateLbmHubGroup]) -> Dict[str, Any]:
        """Update an existing LbmHubGroup.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateLbmHubGroup(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_lbm_hub_group(self, name: str) -> Dict[str, Any]:
        """Remove a LbmHubGroup by name.

        Args:
            name: The LbmHubGroup name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeLbmHubGroup(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_lbm_hub_group(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List LbmHubGroup objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listLbmHubGroup(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  LdapDirectory
    # ═══════════════════════════════════════════════════════════════════

    def update_ldap_directory(self, **kwargs: Unpack[UpdateLdapDirectory]) -> Dict[str, Any]:
        """Update an existing LdapDirectory.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateLdapDirectory(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_ldap_directory(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List LdapDirectory objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listLdapDirectory(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  LdapFilter
    # ═══════════════════════════════════════════════════════════════════

    def update_ldap_filter(self, **kwargs: Unpack[UpdateLdapFilter]) -> Dict[str, Any]:
        """Update an existing LdapFilter.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateLdapFilter(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_ldap_filter(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List LdapFilter objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listLdapFilter(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  LdapSearch
    # ═══════════════════════════════════════════════════════════════════

    def get_ldap_search(self, name: str) -> Dict[str, Any]:
        """Retrieve a LdapSearch by name.

        Args:
            name: The LdapSearch name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getLdapSearch(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_ldap_search(self, **kwargs: Unpack[UpdateLdapSearch]) -> Dict[str, Any]:
        """Update an existing LdapSearch.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateLdapSearch(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_ldap_search(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List LdapSearch objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listLdapSearch(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  LdapSyncCustomField
    # ═══════════════════════════════════════════════════════════════════

    def get_ldap_sync_custom_field(self, name: str) -> Dict[str, Any]:
        """Retrieve a LdapSyncCustomField by name.

        Args:
            name: The LdapSyncCustomField name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getLdapSyncCustomField(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_ldap_sync_custom_field(self, ldap_sync_custom_field_data: LdapSyncCustomField) -> Dict[str, Any]:
        """Add a new LdapSyncCustomField.

        Args:
            ldap_sync_custom_field_data: A dict describing the LdapSyncCustomField.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addLdapSyncCustomField(ldapSyncCustomField=ldap_sync_custom_field_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_ldap_sync_custom_field(self, **kwargs: Unpack[UpdateLdapSyncCustomField]) -> Dict[str, Any]:
        """Update an existing LdapSyncCustomField.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateLdapSyncCustomField(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_ldap_sync_custom_field(self, name: str) -> Dict[str, Any]:
        """Remove a LdapSyncCustomField by name.

        Args:
            name: The LdapSyncCustomField name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeLdapSyncCustomField(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_ldap_sync_custom_field(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List LdapSyncCustomField objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listLdapSyncCustomField(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Line
    # ═══════════════════════════════════════════════════════════════════

    def list_line(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List Line objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listLine(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def apply_line(self, **kwargs) -> Dict[str, Any]:
        """Apply configuration for a Line.

        Args:
            **kwargs: Keyword arguments passed to the WSDL operation.
                Typically ``pattern`` and ``routePartitionName``.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.applyLine(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def reset_line(self, **kwargs) -> Dict[str, Any]:
        """Reset a Line.

        Args:
            **kwargs: Keyword arguments passed to the WSDL operation.
                Typically ``pattern`` and ``routePartitionName``.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.resetLine(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def restart_line(self, **kwargs) -> Dict[str, Any]:
        """Restart a Line.

        Args:
            **kwargs: Keyword arguments passed to the WSDL operation.
                Typically ``pattern`` and ``routePartitionName``.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.restartLine(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  LineGroup
    # ═══════════════════════════════════════════════════════════════════

    def list_line_group(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List LineGroup objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listLineGroup(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  LocalRouteGroup
    # ═══════════════════════════════════════════════════════════════════

    def get_local_route_group(self, name: str) -> Dict[str, Any]:
        """Retrieve a LocalRouteGroup by name.

        Args:
            name: The LocalRouteGroup name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getLocalRouteGroup(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_local_route_group(self, local_route_group_data: LocalRouteGroup) -> Dict[str, Any]:
        """Add a new LocalRouteGroup.

        Args:
            local_route_group_data: A dict describing the LocalRouteGroup.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addLocalRouteGroup(localRouteGroup=local_route_group_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_local_route_group(self, **kwargs: Unpack[UpdateLocalRouteGroup]) -> Dict[str, Any]:
        """Update an existing LocalRouteGroup.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateLocalRouteGroup(localRouteGroup=kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_local_route_group(self, name: str) -> Dict[str, Any]:
        """Remove a LocalRouteGroup by name.

        Args:
            name: The LocalRouteGroup name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeLocalRouteGroup(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_local_route_group(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List LocalRouteGroup objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listLocalRouteGroup(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Location
    # ═══════════════════════════════════════════════════════════════════

    def list_location(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List Location objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listLocation(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  MediaResourceGroup
    # ═══════════════════════════════════════════════════════════════════

    def update_media_resource_group(self, **kwargs: Unpack[UpdateMediaResourceGroup]) -> Dict[str, Any]:
        """Update an existing MediaResourceGroup.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateMediaResourceGroup(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_media_resource_group(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List MediaResourceGroup objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listMediaResourceGroup(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  MediaResourceList
    # ═══════════════════════════════════════════════════════════════════

    def update_media_resource_list(self, **kwargs: Unpack[UpdateMediaResourceList]) -> Dict[str, Any]:
        """Update an existing MediaResourceList.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateMediaResourceList(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_media_resource_list(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List MediaResourceList objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listMediaResourceList(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  MeetMe
    # ═══════════════════════════════════════════════════════════════════

    def get_meet_me(self, name: str, **kwargs) -> Dict[str, Any]:
        """Retrieve a MeetMe by pattern.

        Args:
            name: The pattern.
            **kwargs: Additional keyword args (e.g. ``routePartitionName``).

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getMeetMe(pattern=name, **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_meet_me(self, meet_me_data: MeetMe) -> Dict[str, Any]:
        """Add a new MeetMe.

        Args:
            meet_me_data: A dict describing the MeetMe.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addMeetMe(meetMe=meet_me_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_meet_me(self, **kwargs: Unpack[UpdateMeetMe]) -> Dict[str, Any]:
        """Update an existing MeetMe.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateMeetMe(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_meet_me(self, name: str, **kwargs) -> Dict[str, Any]:
        """Remove a MeetMe by pattern.

        Args:
            name: The pattern.
            **kwargs: Additional keyword args (e.g. ``routePartitionName``).

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeMeetMe(pattern=name, **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_meet_me(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List MeetMe objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listMeetMe(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  MessageWaiting
    # ═══════════════════════════════════════════════════════════════════

    def get_message_waiting(self, name: str, **kwargs) -> Dict[str, Any]:
        """Retrieve a MessageWaiting by pattern.

        Args:
            name: The pattern.
            **kwargs: Additional keyword args (e.g. ``routePartitionName``).

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getMessageWaiting(pattern=name, **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_message_waiting(self, message_waiting_data: MessageWaiting) -> Dict[str, Any]:
        """Add a new MessageWaiting.

        Args:
            message_waiting_data: A dict describing the MessageWaiting.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addMessageWaiting(messageWaiting=message_waiting_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_message_waiting(self, **kwargs: Unpack[UpdateMessageWaiting]) -> Dict[str, Any]:
        """Update an existing MessageWaiting.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateMessageWaiting(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_message_waiting(self, name: str, **kwargs) -> Dict[str, Any]:
        """Remove a MessageWaiting by pattern.

        Args:
            name: The pattern.
            **kwargs: Additional keyword args (e.g. ``routePartitionName``).

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeMessageWaiting(pattern=name, **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_message_waiting(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List MessageWaiting objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listMessageWaiting(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  MlppDomain
    # ═══════════════════════════════════════════════════════════════════

    def get_mlpp_domain(self, name: str) -> Dict[str, Any]:
        """Retrieve a MlppDomain by name.

        Args:
            name: The MlppDomain name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getMlppDomain(domainName=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_mlpp_domain(self, mlpp_domain_data: MlppDomain) -> Dict[str, Any]:
        """Add a new MlppDomain.

        Args:
            mlpp_domain_data: A dict describing the MlppDomain.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addMlppDomain(mlppDomain=mlpp_domain_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_mlpp_domain(self, **kwargs: Unpack[UpdateMlppDomain]) -> Dict[str, Any]:
        """Update an existing MlppDomain.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateMlppDomain(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_mlpp_domain(self, name: str) -> Dict[str, Any]:
        """Remove a MlppDomain by name.

        Args:
            name: The MlppDomain name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeMlppDomain(domainName=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_mlpp_domain(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List MlppDomain objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listMlppDomain(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  MobileVoiceAccess
    # ═══════════════════════════════════════════════════════════════════

    def get_mobile_voice_access(self, name: str) -> Dict[str, Any]:
        """Retrieve a MobileVoiceAccess by name.

        Args:
            name: The MobileVoiceAccess name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getMobileVoiceAccess(pattern=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_mobile_voice_access(self, mobile_voice_access_data: MobileVoiceAccess) -> Dict[str, Any]:
        """Add a new MobileVoiceAccess.

        Args:
            mobile_voice_access_data: A dict describing the MobileVoiceAccess.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addMobileVoiceAccess(mobileVoiceAccess=mobile_voice_access_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_mobile_voice_access(self, **kwargs: Unpack[UpdateMobileVoiceAccess]) -> Dict[str, Any]:
        """Update an existing MobileVoiceAccess.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateMobileVoiceAccess(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_mobile_voice_access(self, name: str) -> Dict[str, Any]:
        """Remove a MobileVoiceAccess by name.

        Args:
            name: The MobileVoiceAccess name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeMobileVoiceAccess(pattern=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Mobility
    # ═══════════════════════════════════════════════════════════════════

    def get_mobility(self, name: str) -> Dict[str, Any]:
        """Retrieve a Mobility by name.

        Args:
            name: The Mobility name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getMobility(handoffNumber=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_mobility(self, mobility_data: Mobility) -> Dict[str, Any]:
        """Add a new Mobility.

        Args:
            mobility_data: A dict describing the Mobility.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addMobility(mobility=mobility_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_mobility(self, **kwargs: Unpack[UpdateMobility]) -> Dict[str, Any]:
        """Update an existing Mobility.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateMobility(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  MobilityProfile
    # ═══════════════════════════════════════════════════════════════════

    def get_mobility_profile(self, name: str) -> Dict[str, Any]:
        """Retrieve a MobilityProfile by name.

        Args:
            name: The MobilityProfile name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getMobilityProfile(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_mobility_profile(self, mobility_profile_data: MobilityProfile) -> Dict[str, Any]:
        """Add a new MobilityProfile.

        Args:
            mobility_profile_data: A dict describing the MobilityProfile.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addMobilityProfile(mobilityProfile=mobility_profile_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_mobility_profile(self, **kwargs: Unpack[UpdateMobilityProfile]) -> Dict[str, Any]:
        """Update an existing MobilityProfile.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateMobilityProfile(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_mobility_profile(self, name: str) -> Dict[str, Any]:
        """Remove a MobilityProfile by name.

        Args:
            name: The MobilityProfile name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeMobilityProfile(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_mobility_profile(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List MobilityProfile objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listMobilityProfile(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  MohAudioSource
    # ═══════════════════════════════════════════════════════════════════

    def get_moh_audio_source(self, name: str) -> Dict[str, Any]:
        """Retrieve a MohAudioSource by name.

        Args:
            name: The MohAudioSource name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getMohAudioSource(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_moh_audio_source(self, **kwargs: Unpack[UpdateMohAudioSource]) -> Dict[str, Any]:
        """Update an existing MohAudioSource.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateMohAudioSource(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_moh_audio_source(self, name: str) -> Dict[str, Any]:
        """Remove a MohAudioSource by name.

        Args:
            name: The MohAudioSource name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeMohAudioSource(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_moh_audio_source(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List MohAudioSource objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listMohAudioSource(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  MohServer
    # ═══════════════════════════════════════════════════════════════════

    def get_moh_server(self, name: str) -> Dict[str, Any]:
        """Retrieve a MohServer by name.

        Args:
            name: The MohServer name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getMohServer(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_moh_server(self, **kwargs: Unpack[UpdateMohServer]) -> Dict[str, Any]:
        """Update an existing MohServer.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateMohServer(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_moh_server(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List MohServer objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listMohServer(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  MraServiceDomain
    # ═══════════════════════════════════════════════════════════════════

    def get_mra_service_domain(self, name: str) -> Dict[str, Any]:
        """Retrieve a MraServiceDomain by name.

        Args:
            name: The MraServiceDomain name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getMraServiceDomain(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_mra_service_domain(self, mra_service_domain_data: MraServiceDomain) -> Dict[str, Any]:
        """Add a new MraServiceDomain.

        Args:
            mra_service_domain_data: A dict describing the MraServiceDomain.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addMraServiceDomain(mraServiceDomain=mra_service_domain_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_mra_service_domain(self, **kwargs: Unpack[UpdateMraServiceDomain]) -> Dict[str, Any]:
        """Update an existing MraServiceDomain.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateMraServiceDomain(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_mra_service_domain(self, name: str) -> Dict[str, Any]:
        """Remove a MraServiceDomain by name.

        Args:
            name: The MraServiceDomain name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeMraServiceDomain(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_mra_service_domain(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List MraServiceDomain objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listMraServiceDomain(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Mtp
    # ═══════════════════════════════════════════════════════════════════

    def list_mtp(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List Mtp objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listMtp(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def apply_mtp(self, name: str) -> Dict[str, Any]:
        """Apply configuration for a Mtp.

        Args:
            name: The Mtp name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.applyMtp(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def reset_mtp(self, name: str) -> Dict[str, Any]:
        """Reset a Mtp.

        Args:
            name: The Mtp name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.resetMtp(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def restart_mtp(self, name: str) -> Dict[str, Any]:
        """Restart a Mtp.

        Args:
            name: The Mtp name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.restartMtp(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  NetworkAccessProfile
    # ═══════════════════════════════════════════════════════════════════

    def get_network_access_profile(self, name: str) -> Dict[str, Any]:
        """Retrieve a NetworkAccessProfile by name.

        Args:
            name: The NetworkAccessProfile name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getNetworkAccessProfile(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_network_access_profile(self, network_access_profile_data: NetworkAccessProfile) -> Dict[str, Any]:
        """Add a new NetworkAccessProfile.

        Args:
            network_access_profile_data: A dict describing the NetworkAccessProfile.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addNetworkAccessProfile(networkAccessProfile=network_access_profile_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_network_access_profile(self, **kwargs: Unpack[UpdateNetworkAccessProfile]) -> Dict[str, Any]:
        """Update an existing NetworkAccessProfile.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateNetworkAccessProfile(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_network_access_profile(self, name: str) -> Dict[str, Any]:
        """Remove a NetworkAccessProfile by name.

        Args:
            name: The NetworkAccessProfile name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeNetworkAccessProfile(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_network_access_profile(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List NetworkAccessProfile objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listNetworkAccessProfile(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Phone
    # ═══════════════════════════════════════════════════════════════════

    def apply_phone(self, name: str) -> Dict[str, Any]:
        """Apply configuration for a Phone.

        Args:
            name: The Phone name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.applyPhone(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def reset_phone(self, name: str) -> Dict[str, Any]:
        """Reset a Phone.

        Args:
            name: The Phone name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.resetPhone(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def restart_phone(self, name: str) -> Dict[str, Any]:
        """Restart a Phone.

        Args:
            name: The Phone name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.restartPhone(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  PhoneButtonTemplate
    # ═══════════════════════════════════════════════════════════════════

    def list_phone_button_template(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List PhoneButtonTemplate objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listPhoneButtonTemplate(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def apply_phone_button_template(self, name: str) -> Dict[str, Any]:
        """Apply configuration for a PhoneButtonTemplate.

        Args:
            name: The PhoneButtonTemplate name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.applyPhoneButtonTemplate(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def restart_phone_button_template(self, name: str) -> Dict[str, Any]:
        """Restart a PhoneButtonTemplate.

        Args:
            name: The PhoneButtonTemplate name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.restartPhoneButtonTemplate(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  PhoneNtp
    # ═══════════════════════════════════════════════════════════════════

    def update_phone_ntp(self, **kwargs: Unpack[UpdatePhoneNtp]) -> Dict[str, Any]:
        """Update an existing PhoneNtp.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updatePhoneNtp(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_phone_ntp(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List PhoneNtp objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listPhoneNtp(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  PhoneSecurityProfile
    # ═══════════════════════════════════════════════════════════════════

    def update_phone_security_profile(self, **kwargs: Unpack[UpdatePhoneSecurityProfile]) -> Dict[str, Any]:
        """Update an existing PhoneSecurityProfile.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updatePhoneSecurityProfile(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_phone_security_profile(self, name: str) -> Dict[str, Any]:
        """Remove a PhoneSecurityProfile by name.

        Args:
            name: The PhoneSecurityProfile name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removePhoneSecurityProfile(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_phone_security_profile(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List PhoneSecurityProfile objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listPhoneSecurityProfile(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def apply_phone_security_profile(self, name: str) -> Dict[str, Any]:
        """Apply configuration for a PhoneSecurityProfile.

        Args:
            name: The PhoneSecurityProfile name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.applyPhoneSecurityProfile(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def reset_phone_security_profile(self, name: str) -> Dict[str, Any]:
        """Reset a PhoneSecurityProfile.

        Args:
            name: The PhoneSecurityProfile name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.resetPhoneSecurityProfile(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  PhysicalLocation
    # ═══════════════════════════════════════════════════════════════════

    def get_physical_location(self, name: str) -> Dict[str, Any]:
        """Retrieve a PhysicalLocation by name.

        Args:
            name: The PhysicalLocation name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getPhysicalLocation(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_physical_location(self, physical_location_data: PhysicalLocation) -> Dict[str, Any]:
        """Add a new PhysicalLocation.

        Args:
            physical_location_data: A dict describing the PhysicalLocation.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addPhysicalLocation(physicalLocation=physical_location_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_physical_location(self, **kwargs: Unpack[UpdatePhysicalLocation]) -> Dict[str, Any]:
        """Update an existing PhysicalLocation.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updatePhysicalLocation(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_physical_location(self, name: str) -> Dict[str, Any]:
        """Remove a PhysicalLocation by name.

        Args:
            name: The PhysicalLocation name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removePhysicalLocation(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_physical_location(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List PhysicalLocation objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listPhysicalLocation(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  PresenceGroup
    # ═══════════════════════════════════════════════════════════════════

    def update_presence_group(self, **kwargs: Unpack[UpdatePresenceGroup]) -> Dict[str, Any]:
        """Update an existing PresenceGroup.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updatePresenceGroup(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_presence_group(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List PresenceGroup objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listPresenceGroup(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  PresenceRedundancyGroup
    # ═══════════════════════════════════════════════════════════════════

    def get_presence_redundancy_group(self, name: str) -> Dict[str, Any]:
        """Retrieve a PresenceRedundancyGroup by name.

        Args:
            name: The PresenceRedundancyGroup name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getPresenceRedundancyGroup(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_presence_redundancy_group(self, presence_redundancy_group_data: PresenceRedundancyGroup) -> Dict[str, Any]:
        """Add a new PresenceRedundancyGroup.

        Args:
            presence_redundancy_group_data: A dict describing the PresenceRedundancyGroup.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addPresenceRedundancyGroup(presenceRedundancyGroup=presence_redundancy_group_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_presence_redundancy_group(self, **kwargs: Unpack[UpdatePresenceRedundancyGroup]) -> Dict[str, Any]:
        """Update an existing PresenceRedundancyGroup.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updatePresenceRedundancyGroup(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_presence_redundancy_group(self, name: str) -> Dict[str, Any]:
        """Remove a PresenceRedundancyGroup by name.

        Args:
            name: The PresenceRedundancyGroup name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removePresenceRedundancyGroup(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_presence_redundancy_group(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List PresenceRedundancyGroup objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listPresenceRedundancyGroup(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  ProcessNode
    # ═══════════════════════════════════════════════════════════════════

    def get_process_node(self, name: str) -> Dict[str, Any]:
        """Retrieve a ProcessNode by name.

        Args:
            name: The ProcessNode name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getProcessNode(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_process_node(self, process_node_data: ProcessNode) -> Dict[str, Any]:
        """Add a new ProcessNode.

        Args:
            process_node_data: A dict describing the ProcessNode.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addProcessNode(processNode=process_node_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_process_node(self, **kwargs: Unpack[UpdateProcessNode]) -> Dict[str, Any]:
        """Update an existing ProcessNode.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateProcessNode(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_process_node(self, name: str) -> Dict[str, Any]:
        """Remove a ProcessNode by name.

        Args:
            name: The ProcessNode name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeProcessNode(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_process_node(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List ProcessNode objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listProcessNode(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  ProcessNodeService
    # ═══════════════════════════════════════════════════════════════════

    def get_process_node_service(self, **kwargs) -> Dict[str, Any]:
        """Retrieve a ProcessNodeService.

        Args:
            **kwargs: Must include ``processNodeName`` + ``service``, or ``uuid``.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getProcessNodeService(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_process_node_service(self, **kwargs: Unpack[UpdateProcessNodeService]) -> Dict[str, Any]:
        """Update an existing ProcessNodeService.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateProcessNodeService(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_process_node_service(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List ProcessNodeService objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listProcessNodeService(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  RecordingProfile
    # ═══════════════════════════════════════════════════════════════════

    def get_recording_profile(self, name: str) -> Dict[str, Any]:
        """Retrieve a RecordingProfile by name.

        Args:
            name: The RecordingProfile name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getRecordingProfile(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_recording_profile(self, recording_profile_data: RecordingProfile) -> Dict[str, Any]:
        """Add a new RecordingProfile.

        Args:
            recording_profile_data: A dict describing the RecordingProfile.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addRecordingProfile(recordingProfile=recording_profile_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_recording_profile(self, **kwargs: Unpack[UpdateRecordingProfile]) -> Dict[str, Any]:
        """Update an existing RecordingProfile.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateRecordingProfile(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_recording_profile(self, name: str) -> Dict[str, Any]:
        """Remove a RecordingProfile by name.

        Args:
            name: The RecordingProfile name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeRecordingProfile(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_recording_profile(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List RecordingProfile objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listRecordingProfile(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Region
    # ═══════════════════════════════════════════════════════════════════

    def list_region(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List Region objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listRegion(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def apply_region(self, name: str) -> Dict[str, Any]:
        """Apply configuration for a Region.

        Args:
            name: The Region name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.applyRegion(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def restart_region(self, name: str) -> Dict[str, Any]:
        """Restart a Region.

        Args:
            name: The Region name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.restartRegion(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  RemoteCluster
    # ═══════════════════════════════════════════════════════════════════

    def get_remote_cluster(self, cluster_id: str) -> Dict[str, Any]:
        """Retrieve a RemoteCluster by clusterId.

        Args:
            cluster_id: The RemoteCluster clusterId.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getRemoteCluster(clusterId=cluster_id)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_remote_cluster(self, remote_cluster_data: RemoteCluster) -> Dict[str, Any]:
        """Add a new RemoteCluster.

        Args:
            remote_cluster_data: A dict describing the RemoteCluster.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addRemoteCluster(remoteCluster=remote_cluster_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_remote_cluster(self, **kwargs: Unpack[UpdateRemoteCluster]) -> Dict[str, Any]:
        """Update an existing RemoteCluster.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateRemoteCluster(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_remote_cluster(self, cluster_id: str) -> Dict[str, Any]:
        """Remove a RemoteCluster by clusterId.

        Args:
            cluster_id: The RemoteCluster clusterId.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeRemoteCluster(clusterId=cluster_id)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_remote_cluster(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List RemoteCluster objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listRemoteCluster(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  RemoteDestination
    # ═══════════════════════════════════════════════════════════════════

    def update_remote_destination(self, **kwargs: Unpack[UpdateRemoteDestination]) -> Dict[str, Any]:
        """Update an existing RemoteDestination.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateRemoteDestination(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_remote_destination(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List RemoteDestination objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listRemoteDestination(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  RemoteDestinationProfile
    # ═══════════════════════════════════════════════════════════════════

    def list_remote_destination_profile(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List RemoteDestinationProfile objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listRemoteDestinationProfile(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  ResourcePriorityNamespace
    # ═══════════════════════════════════════════════════════════════════

    def get_resource_priority_namespace(self, name: str) -> Dict[str, Any]:
        """Retrieve a ResourcePriorityNamespace by name.

        Args:
            name: The ResourcePriorityNamespace name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getResourcePriorityNamespace(namespace=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_resource_priority_namespace(self, resource_priority_namespace_data: ResourcePriorityNamespace) -> Dict[str, Any]:
        """Add a new ResourcePriorityNamespace.

        Args:
            resource_priority_namespace_data: A dict describing the ResourcePriorityNamespace.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addResourcePriorityNamespace(resourcePriorityNamespace=resource_priority_namespace_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_resource_priority_namespace(self, **kwargs: Unpack[UpdateResourcePriorityNamespace]) -> Dict[str, Any]:
        """Update an existing ResourcePriorityNamespace.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateResourcePriorityNamespace(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_resource_priority_namespace(self, name: str) -> Dict[str, Any]:
        """Remove a ResourcePriorityNamespace by name.

        Args:
            name: The ResourcePriorityNamespace name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeResourcePriorityNamespace(namespace=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_resource_priority_namespace(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List ResourcePriorityNamespace objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listResourcePriorityNamespace(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def apply_resource_priority_namespace(self, name: str) -> Dict[str, Any]:
        """Apply configuration for a ResourcePriorityNamespace.

        Args:
            name: The ResourcePriorityNamespace name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.applyResourcePriorityNamespace(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def reset_resource_priority_namespace(self, name: str) -> Dict[str, Any]:
        """Reset a ResourcePriorityNamespace.

        Args:
            name: The ResourcePriorityNamespace name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.resetResourcePriorityNamespace(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def restart_resource_priority_namespace(self, name: str) -> Dict[str, Any]:
        """Restart a ResourcePriorityNamespace.

        Args:
            name: The ResourcePriorityNamespace name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.restartResourcePriorityNamespace(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  ResourcePriorityNamespaceList
    # ═══════════════════════════════════════════════════════════════════

    def get_resource_priority_namespace_list(self, name: str) -> Dict[str, Any]:
        """Retrieve a ResourcePriorityNamespaceList by name.

        Args:
            name: The ResourcePriorityNamespaceList name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getResourcePriorityNamespaceList(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_resource_priority_namespace_list(self, resource_priority_namespace_list_data: ResourcePriorityNamespaceList) -> Dict[str, Any]:
        """Add a new ResourcePriorityNamespaceList.

        Args:
            resource_priority_namespace_list_data: A dict describing the ResourcePriorityNamespaceList.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addResourcePriorityNamespaceList(resourcePriorityNamespaceList=resource_priority_namespace_list_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_resource_priority_namespace_list(self, **kwargs: Unpack[UpdateResourcePriorityNamespaceList]) -> Dict[str, Any]:
        """Update an existing ResourcePriorityNamespaceList.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateResourcePriorityNamespaceList(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_resource_priority_namespace_list(self, name: str) -> Dict[str, Any]:
        """Remove a ResourcePriorityNamespaceList by name.

        Args:
            name: The ResourcePriorityNamespaceList name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeResourcePriorityNamespaceList(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_resource_priority_namespace_list(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List ResourcePriorityNamespaceList objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listResourcePriorityNamespaceList(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def apply_resource_priority_namespace_list(self, name: str) -> Dict[str, Any]:
        """Apply configuration for a ResourcePriorityNamespaceList.

        Args:
            name: The ResourcePriorityNamespaceList name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.applyResourcePriorityNamespaceList(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def reset_resource_priority_namespace_list(self, name: str) -> Dict[str, Any]:
        """Reset a ResourcePriorityNamespaceList.

        Args:
            name: The ResourcePriorityNamespaceList name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.resetResourcePriorityNamespaceList(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def restart_resource_priority_namespace_list(self, name: str) -> Dict[str, Any]:
        """Restart a ResourcePriorityNamespaceList.

        Args:
            name: The ResourcePriorityNamespaceList name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.restartResourcePriorityNamespaceList(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  RouteFilter
    # ═══════════════════════════════════════════════════════════════════

    def list_route_filter(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List RouteFilter objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listRouteFilter(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  RouteGroup
    # ═══════════════════════════════════════════════════════════════════

    def list_route_group(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List RouteGroup objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listRouteGroup(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  RouteList
    # ═══════════════════════════════════════════════════════════════════

    def list_route_list(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List RouteList objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listRouteList(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def apply_route_list(self, name: str) -> Dict[str, Any]:
        """Apply configuration for a RouteList.

        Args:
            name: The RouteList name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.applyRouteList(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def reset_route_list(self, name: str) -> Dict[str, Any]:
        """Reset a RouteList.

        Args:
            name: The RouteList name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.resetRouteList(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  RoutePartition
    # ═══════════════════════════════════════════════════════════════════

    def update_route_partition(self, **kwargs: Unpack[UpdateRoutePartition]) -> Dict[str, Any]:
        """Update an existing RoutePartition.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateRoutePartition(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_route_partition(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List RoutePartition objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listRoutePartition(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def apply_route_partition(self, name: str) -> Dict[str, Any]:
        """Apply configuration for a RoutePartition.

        Args:
            name: The RoutePartition name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.applyRoutePartition(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def restart_route_partition(self, name: str) -> Dict[str, Any]:
        """Restart a RoutePartition.

        Args:
            name: The RoutePartition name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.restartRoutePartition(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  RoutePattern
    # ═══════════════════════════════════════════════════════════════════

    def list_route_pattern(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List RoutePattern objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listRoutePattern(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  SIPNormalizationScript
    # ═══════════════════════════════════════════════════════════════════

    def get_sip_normalization_script(self, name: str) -> Dict[str, Any]:
        """Retrieve a SIPNormalizationScript by name.

        Args:
            name: The SIPNormalizationScript name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getSIPNormalizationScript(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_sip_normalization_script(self, sip_normalization_script_data: SIPNormalizationScript) -> Dict[str, Any]:
        """Add a new SIPNormalizationScript.

        Args:
            sip_normalization_script_data: A dict describing the SIPNormalizationScript.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addSIPNormalizationScript(sIPNormalizationScript=sip_normalization_script_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_sip_normalization_script(self, **kwargs: Unpack[UpdateSIPNormalizationScript]) -> Dict[str, Any]:
        """Update an existing SIPNormalizationScript.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateSIPNormalizationScript(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_sip_normalization_script(self, name: str) -> Dict[str, Any]:
        """Remove a SIPNormalizationScript by name.

        Args:
            name: The SIPNormalizationScript name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeSIPNormalizationScript(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_sip_normalization_script(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List SIPNormalizationScript objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listSIPNormalizationScript(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  SNMPCommunityString
    # ═══════════════════════════════════════════════════════════════════

    def get_snmp_community_string(self, name: str) -> Dict[str, Any]:
        """Retrieve a SNMPCommunityString by name.

        Args:
            name: The SNMPCommunityString name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getSNMPCommunityString(communityName=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_snmp_community_string(self, snmp_community_string_data: RCommunityString) -> Dict[str, Any]:
        """Add a new SNMPCommunityString.

        Args:
            snmp_community_string_data: A dict describing the SNMPCommunityString.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addSNMPCommunityString(CommunityString=snmp_community_string_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_snmp_community_string(self, **kwargs: Unpack[UpdateSNMPCommunityString]) -> Dict[str, Any]:
        """Update an existing SNMPCommunityString.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateSNMPCommunityString(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_snmp_community_string(self, name: str) -> Dict[str, Any]:
        """Remove a SNMPCommunityString by name.

        Args:
            name: The SNMPCommunityString name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeSNMPCommunityString(CommunityString=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  SNMPUser
    # ═══════════════════════════════════════════════════════════════════

    def get_snmp_user(self, name: str) -> Dict[str, Any]:
        """Retrieve a SNMPUser by name.

        Args:
            name: The SNMPUser name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getSNMPUser(userName=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_snmp_user(self, snmp_user_data: RSNMPUser) -> Dict[str, Any]:
        """Add a new SNMPUser.

        Args:
            snmp_user_data: A dict describing the SNMPUser.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addSNMPUser(user=snmp_user_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_snmp_user(self, **kwargs: Unpack[UpdateSNMPUser]) -> Dict[str, Any]:
        """Update an existing SNMPUser.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateSNMPUser(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_snmp_user(self, name: str) -> Dict[str, Any]:
        """Remove a SNMPUser by name.

        Args:
            name: The SNMPUser name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeSNMPUser(User=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  SafCcdPurgeBlockLearnedRoutes
    # ═══════════════════════════════════════════════════════════════════

    def get_saf_ccd_purge_block_learned_routes(self, **kwargs) -> Dict[str, Any]:
        """Retrieve a SafCcdPurgeBlockLearnedRoutes.

        Args:
            **kwargs: Must include ``learnedPattern`` (or ``learnedPatternPrefix``),
                ``callControlIdentity``, and ``ipAddress``; or ``uuid``.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getSafCcdPurgeBlockLearnedRoutes(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_saf_ccd_purge_block_learned_routes(self, saf_ccd_purge_block_learned_routes_data: SafCcdPurgeBlockLearnedRoutes) -> Dict[str, Any]:
        """Add a new SafCcdPurgeBlockLearnedRoutes.

        Args:
            saf_ccd_purge_block_learned_routes_data: A dict describing the SafCcdPurgeBlockLearnedRoutes.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addSafCcdPurgeBlockLearnedRoutes(safCcdPurgeBlockLearnedRoutes=saf_ccd_purge_block_learned_routes_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_saf_ccd_purge_block_learned_routes(self, **kwargs: Unpack[UpdateSafCcdPurgeBlockLearnedRoutes]) -> Dict[str, Any]:
        """Update an existing SafCcdPurgeBlockLearnedRoutes.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateSafCcdPurgeBlockLearnedRoutes(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_saf_ccd_purge_block_learned_routes(self, **kwargs) -> Dict[str, Any]:
        """Remove a SafCcdPurgeBlockLearnedRoutes.

        Args:
            **kwargs: Must include ``learnedPattern`` (or ``learnedPatternPrefix``),
                ``callControlIdentity``, and ``ipAddress``; or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeSafCcdPurgeBlockLearnedRoutes(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_saf_ccd_purge_block_learned_routes(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List SafCcdPurgeBlockLearnedRoutes objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listSafCcdPurgeBlockLearnedRoutes(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  SafForwarder
    # ═══════════════════════════════════════════════════════════════════

    def get_saf_forwarder(self, name: str) -> Dict[str, Any]:
        """Retrieve a SafForwarder by name.

        Args:
            name: The SafForwarder name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getSafForwarder(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_saf_forwarder(self, saf_forwarder_data: SafForwarder) -> Dict[str, Any]:
        """Add a new SafForwarder.

        Args:
            saf_forwarder_data: A dict describing the SafForwarder.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addSafForwarder(safForwarder=saf_forwarder_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_saf_forwarder(self, **kwargs: Unpack[UpdateSafForwarder]) -> Dict[str, Any]:
        """Update an existing SafForwarder.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateSafForwarder(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_saf_forwarder(self, name: str) -> Dict[str, Any]:
        """Remove a SafForwarder by name.

        Args:
            name: The SafForwarder name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeSafForwarder(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_saf_forwarder(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List SafForwarder objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listSafForwarder(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  SafSecurityProfile
    # ═══════════════════════════════════════════════════════════════════

    def get_saf_security_profile(self, name: str) -> Dict[str, Any]:
        """Retrieve a SafSecurityProfile by name.

        Args:
            name: The SafSecurityProfile name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getSafSecurityProfile(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_saf_security_profile(self, saf_security_profile_data: SafSecurityProfile) -> Dict[str, Any]:
        """Add a new SafSecurityProfile.

        Args:
            saf_security_profile_data: A dict describing the SafSecurityProfile.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addSafSecurityProfile(safSecurityProfile=saf_security_profile_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_saf_security_profile(self, **kwargs: Unpack[UpdateSafSecurityProfile]) -> Dict[str, Any]:
        """Update an existing SafSecurityProfile.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateSafSecurityProfile(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_saf_security_profile(self, name: str) -> Dict[str, Any]:
        """Remove a SafSecurityProfile by name.

        Args:
            name: The SafSecurityProfile name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeSafSecurityProfile(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_saf_security_profile(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List SafSecurityProfile objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listSafSecurityProfile(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  SdpTransparencyProfile
    # ═══════════════════════════════════════════════════════════════════

    def get_sdp_transparency_profile(self, name: str) -> Dict[str, Any]:
        """Retrieve a SdpTransparencyProfile by name.

        Args:
            name: The SdpTransparencyProfile name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getSdpTransparencyProfile(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_sdp_transparency_profile(self, sdp_transparency_profile_data: SdpTransparencyProfile) -> Dict[str, Any]:
        """Add a new SdpTransparencyProfile.

        Args:
            sdp_transparency_profile_data: A dict describing the SdpTransparencyProfile.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addSdpTransparencyProfile(sdpTransparencyProfile=sdp_transparency_profile_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_sdp_transparency_profile(self, **kwargs: Unpack[UpdateSdpTransparencyProfile]) -> Dict[str, Any]:
        """Update an existing SdpTransparencyProfile.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateSdpTransparencyProfile(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_sdp_transparency_profile(self, name: str) -> Dict[str, Any]:
        """Remove a SdpTransparencyProfile by name.

        Args:
            name: The SdpTransparencyProfile name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeSdpTransparencyProfile(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_sdp_transparency_profile(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List SdpTransparencyProfile objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listSdpTransparencyProfile(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  ServiceProfile
    # ═══════════════════════════════════════════════════════════════════

    def list_service_profile(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List ServiceProfile objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listServiceProfile(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  SipDialRules
    # ═══════════════════════════════════════════════════════════════════

    def get_sip_dial_rules(self, name: str) -> Dict[str, Any]:
        """Retrieve a SipDialRules by name.

        Args:
            name: The SipDialRules name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getSipDialRules(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_sip_dial_rules(self, sip_dial_rules_data: SipDialRules) -> Dict[str, Any]:
        """Add a new SipDialRules.

        Args:
            sip_dial_rules_data: A dict describing the SipDialRules.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addSipDialRules(sipDialRules=sip_dial_rules_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_sip_dial_rules(self, **kwargs: Unpack[UpdateSipDialRules]) -> Dict[str, Any]:
        """Update an existing SipDialRules.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateSipDialRules(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_sip_dial_rules(self, name: str) -> Dict[str, Any]:
        """Remove a SipDialRules by name.

        Args:
            name: The SipDialRules name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeSipDialRules(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_sip_dial_rules(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List SipDialRules objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listSipDialRules(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  SipProfile
    # ═══════════════════════════════════════════════════════════════════

    def list_sip_profile(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List SipProfile objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listSipProfile(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def apply_sip_profile(self, name: str) -> Dict[str, Any]:
        """Apply configuration for a SipProfile.

        Args:
            name: The SipProfile name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.applySipProfile(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def restart_sip_profile(self, name: str) -> Dict[str, Any]:
        """Restart a SipProfile.

        Args:
            name: The SipProfile name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.restartSipProfile(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  SipRealm
    # ═══════════════════════════════════════════════════════════════════

    def get_sip_realm(self, realm: str) -> Dict[str, Any]:
        """Retrieve a SipRealm by realm.

        Args:
            realm: The SipRealm realm.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getSipRealm(realm=realm)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_sip_realm(self, sip_realm_data: SipRealm) -> Dict[str, Any]:
        """Add a new SipRealm.

        Args:
            sip_realm_data: A dict describing the SipRealm.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addSipRealm(sipRealm=sip_realm_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_sip_realm(self, **kwargs: Unpack[UpdateSipRealm]) -> Dict[str, Any]:
        """Update an existing SipRealm.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateSipRealm(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_sip_realm(self, realm: str) -> Dict[str, Any]:
        """Remove a SipRealm by realm.

        Args:
            realm: The SipRealm realm.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeSipRealm(realm=realm)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_sip_realm(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List SipRealm objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listSipRealm(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  SipRoutePattern
    # ═══════════════════════════════════════════════════════════════════

    def list_sip_route_pattern(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List SipRoutePattern objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listSipRoutePattern(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  SipTrunk
    # ═══════════════════════════════════════════════════════════════════

    def list_sip_trunk(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List SipTrunk objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listSipTrunk(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def reset_sip_trunk(self, name: str) -> Dict[str, Any]:
        """Reset a SipTrunk.

        Args:
            name: The SipTrunk name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.resetSipTrunk(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def restart_sip_trunk(self, name: str) -> Dict[str, Any]:
        """Restart a SipTrunk.

        Args:
            name: The SipTrunk name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.restartSipTrunk(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  SipTrunkSecurityProfile
    # ═══════════════════════════════════════════════════════════════════

    def update_sip_trunk_security_profile(self, **kwargs: Unpack[UpdateSipTrunkSecurityProfile]) -> Dict[str, Any]:
        """Update an existing SipTrunkSecurityProfile.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateSipTrunkSecurityProfile(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_sip_trunk_security_profile(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List SipTrunkSecurityProfile objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listSipTrunkSecurityProfile(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def apply_sip_trunk_security_profile(self, name: str) -> Dict[str, Any]:
        """Apply configuration for a SipTrunkSecurityProfile.

        Args:
            name: The SipTrunkSecurityProfile name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.applySipTrunkSecurityProfile(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def reset_sip_trunk_security_profile(self, name: str) -> Dict[str, Any]:
        """Reset a SipTrunkSecurityProfile.

        Args:
            name: The SipTrunkSecurityProfile name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.resetSipTrunkSecurityProfile(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  SoftKeyTemplate
    # ═══════════════════════════════════════════════════════════════════

    def update_soft_key_template(self, **kwargs: Unpack[UpdateSoftKeyTemplate]) -> Dict[str, Any]:
        """Update an existing SoftKeyTemplate.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateSoftKeyTemplate(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_soft_key_template(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List SoftKeyTemplate objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listSoftKeyTemplate(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def apply_soft_key_template(self, name: str) -> Dict[str, Any]:
        """Apply configuration for a SoftKeyTemplate.

        Args:
            name: The SoftKeyTemplate name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.applySoftKeyTemplate(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def restart_soft_key_template(self, name: str) -> Dict[str, Any]:
        """Restart a SoftKeyTemplate.

        Args:
            name: The SoftKeyTemplate name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.restartSoftKeyTemplate(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Srst
    # ═══════════════════════════════════════════════════════════════════

    def list_srst(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List Srst objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listSrst(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def apply_srst(self, name: str) -> Dict[str, Any]:
        """Apply configuration for a Srst.

        Args:
            name: The Srst name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.applySrst(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def reset_srst(self, name: str) -> Dict[str, Any]:
        """Reset a Srst.

        Args:
            name: The Srst name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.resetSrst(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def restart_srst(self, name: str) -> Dict[str, Any]:
        """Restart a Srst.

        Args:
            name: The Srst name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.restartSrst(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  TimePeriod
    # ═══════════════════════════════════════════════════════════════════

    def get_time_period(self, name: str) -> Dict[str, Any]:
        """Retrieve a TimePeriod by name.

        Args:
            name: The TimePeriod name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getTimePeriod(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_time_period(self, time_period_data: TimePeriod) -> Dict[str, Any]:
        """Add a new TimePeriod.

        Args:
            time_period_data: A dict describing the TimePeriod.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addTimePeriod(timePeriod=time_period_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_time_period(self, **kwargs: Unpack[UpdateTimePeriod]) -> Dict[str, Any]:
        """Update an existing TimePeriod.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateTimePeriod(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_time_period(self, name: str) -> Dict[str, Any]:
        """Remove a TimePeriod by name.

        Args:
            name: The TimePeriod name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeTimePeriod(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_time_period(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List TimePeriod objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listTimePeriod(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  TimeSchedule
    # ═══════════════════════════════════════════════════════════════════

    def get_time_schedule(self, name: str) -> Dict[str, Any]:
        """Retrieve a TimeSchedule by name.

        Args:
            name: The TimeSchedule name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getTimeSchedule(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_time_schedule(self, time_schedule_data: TimeSchedule) -> Dict[str, Any]:
        """Add a new TimeSchedule.

        Args:
            time_schedule_data: A dict describing the TimeSchedule.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addTimeSchedule(timeSchedule=time_schedule_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_time_schedule(self, **kwargs: Unpack[UpdateTimeSchedule]) -> Dict[str, Any]:
        """Update an existing TimeSchedule.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateTimeSchedule(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_time_schedule(self, name: str) -> Dict[str, Any]:
        """Remove a TimeSchedule by name.

        Args:
            name: The TimeSchedule name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeTimeSchedule(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_time_schedule(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List TimeSchedule objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listTimeSchedule(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  TodAccess
    # ═══════════════════════════════════════════════════════════════════

    def get_tod_access(self, name: str) -> Dict[str, Any]:
        """Retrieve a TodAccess by name.

        Args:
            name: The TodAccess name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getTodAccess(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_tod_access(self, tod_access_data: TodAccess) -> Dict[str, Any]:
        """Add a new TodAccess.

        Args:
            tod_access_data: A dict describing the TodAccess.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addTodAccess(todAccess=tod_access_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_tod_access(self, **kwargs: Unpack[UpdateTodAccess]) -> Dict[str, Any]:
        """Update an existing TodAccess.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateTodAccess(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_tod_access(self, name: str) -> Dict[str, Any]:
        """Remove a TodAccess by name.

        Args:
            name: The TodAccess name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeTodAccess(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_tod_access(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List TodAccess objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listTodAccess(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  TransPattern
    # ═══════════════════════════════════════════════════════════════════

    def list_trans_pattern(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List TransPattern objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listTransPattern(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Transcoder
    # ═══════════════════════════════════════════════════════════════════

    def list_transcoder(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List Transcoder objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listTranscoder(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def apply_transcoder(self, name: str) -> Dict[str, Any]:
        """Apply configuration for a Transcoder.

        Args:
            name: The Transcoder name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.applyTranscoder(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def reset_transcoder(self, name: str) -> Dict[str, Any]:
        """Reset a Transcoder.

        Args:
            name: The Transcoder name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.resetTranscoder(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  TransformationProfile
    # ═══════════════════════════════════════════════════════════════════

    def get_transformation_profile(self, name: str) -> Dict[str, Any]:
        """Retrieve a TransformationProfile by name.

        Args:
            name: The TransformationProfile name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getTransformationProfile(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_transformation_profile(self, transformation_profile_data: TransformationProfile) -> Dict[str, Any]:
        """Add a new TransformationProfile.

        Args:
            transformation_profile_data: A dict describing the TransformationProfile.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addTransformationProfile(transformationProfile=transformation_profile_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_transformation_profile(self, **kwargs: Unpack[UpdateTransformationProfile]) -> Dict[str, Any]:
        """Update an existing TransformationProfile.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateTransformationProfile(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_transformation_profile(self, name: str) -> Dict[str, Any]:
        """Remove a TransformationProfile by name.

        Args:
            name: The TransformationProfile name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeTransformationProfile(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_transformation_profile(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List TransformationProfile objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listTransformationProfile(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  UcService
    # ═══════════════════════════════════════════════════════════════════

    def list_uc_service(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List UcService objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listUcService(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def apply_uc_service(self, name: str) -> Dict[str, Any]:
        """Apply configuration for a UcService.

        Args:
            name: The UcService name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.applyUcService(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def reset_uc_service(self, name: str) -> Dict[str, Any]:
        """Reset a UcService.

        Args:
            name: The UcService name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.resetUcService(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def restart_uc_service(self, name: str) -> Dict[str, Any]:
        """Restart a UcService.

        Args:
            name: The UcService name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.restartUcService(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  UnitsToGateway
    # ═══════════════════════════════════════════════════════════════════

    def add_units_to_gateway(self, units_to_gateway_data: UnitsToGateway) -> Dict[str, Any]:
        """Add a new UnitsToGateway.

        Args:
            units_to_gateway_data: A dict describing the UnitsToGateway.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addUnitsToGateway(unitsToGateway=units_to_gateway_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_units_to_gateway(self, name: str) -> Dict[str, Any]:
        """Remove a UnitsToGateway by name.

        Args:
            name: The UnitsToGateway name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeUnitsToGateway(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  UniversalDeviceTemplate
    # ═══════════════════════════════════════════════════════════════════

    def get_universal_device_template(self, name: str) -> Dict[str, Any]:
        """Retrieve a UniversalDeviceTemplate by name.

        Args:
            name: The UniversalDeviceTemplate name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getUniversalDeviceTemplate(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_universal_device_template(self, universal_device_template_data: UniversalDeviceTemplate) -> Dict[str, Any]:
        """Add a new UniversalDeviceTemplate.

        Args:
            universal_device_template_data: A dict describing the UniversalDeviceTemplate.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addUniversalDeviceTemplate(universalDeviceTemplate=universal_device_template_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_universal_device_template(self, **kwargs: Unpack[UpdateUniversalDeviceTemplate]) -> Dict[str, Any]:
        """Update an existing UniversalDeviceTemplate.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateUniversalDeviceTemplate(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_universal_device_template(self, name: str) -> Dict[str, Any]:
        """Remove a UniversalDeviceTemplate by name.

        Args:
            name: The UniversalDeviceTemplate name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeUniversalDeviceTemplate(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_universal_device_template(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List UniversalDeviceTemplate objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listUniversalDeviceTemplate(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  UniversalLineTemplate
    # ═══════════════════════════════════════════════════════════════════

    def get_universal_line_template(self, name: str) -> Dict[str, Any]:
        """Retrieve a UniversalLineTemplate by name.

        Args:
            name: The UniversalLineTemplate name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getUniversalLineTemplate(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_universal_line_template(self, universal_line_template_data: UniversalLineTemplate) -> Dict[str, Any]:
        """Add a new UniversalLineTemplate.

        Args:
            universal_line_template_data: A dict describing the UniversalLineTemplate.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addUniversalLineTemplate(universalLineTemplate=universal_line_template_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_universal_line_template(self, **kwargs: Unpack[UpdateUniversalLineTemplate]) -> Dict[str, Any]:
        """Update an existing UniversalLineTemplate.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateUniversalLineTemplate(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_universal_line_template(self, name: str) -> Dict[str, Any]:
        """Remove a UniversalLineTemplate by name.

        Args:
            name: The UniversalLineTemplate name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeUniversalLineTemplate(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_universal_line_template(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List UniversalLineTemplate objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listUniversalLineTemplate(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  User
    # ═══════════════════════════════════════════════════════════════════

    def add_user(self, user_data: User) -> Dict[str, Any]:
        """Add a new end user.

        Args:
            user_data: A dict describing the user.  Required keys:
                ``userid``, ``lastName``, ``presenceGroupName``.

                Example::

                    {
                        "userid": "jsmith",
                        "firstName": "John",
                        "lastName": "Smith",
                        "password": "changeme",
                        "pin": "12345",
                        "presenceGroupName": "Standard Presence group",
                    }

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addUser(user=user_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_user(self, userid: str) -> Dict[str, Any]:
        """Remove an end user by userid.

        Args:
            userid: The user ID to remove.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeUser(userid=userid)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  UserGroup
    # ═══════════════════════════════════════════════════════════════════

    def list_user_group(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List UserGroup objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listUserGroup(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  UserProfileProvision
    # ═══════════════════════════════════════════════════════════════════

    def get_user_profile_provision(self, name: str) -> Dict[str, Any]:
        """Retrieve a UserProfileProvision by name.

        Args:
            name: The UserProfileProvision name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getUserProfileProvision(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_user_profile_provision(self, user_profile_provision_data: UserProfileProvision) -> Dict[str, Any]:
        """Add a new UserProfileProvision.

        Args:
            user_profile_provision_data: A dict describing the UserProfileProvision.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addUserProfileProvision(userProfileProvision=user_profile_provision_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_user_profile_provision(self, **kwargs: Unpack[UpdateUserProfileProvision]) -> Dict[str, Any]:
        """Update an existing UserProfileProvision.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateUserProfileProvision(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_user_profile_provision(self, name: str) -> Dict[str, Any]:
        """Remove a UserProfileProvision by name.

        Args:
            name: The UserProfileProvision name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeUserProfileProvision(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_user_profile_provision(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List UserProfileProvision objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listUserProfileProvision(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Vg224
    # ═══════════════════════════════════════════════════════════════════

    def get_vg224(self, domain_name: str = "", **kwargs) -> Dict[str, Any]:
        """Retrieve a Vg224 by domainName.

        Args:
            domain_name: The Vg224 domain name.
            **kwargs: Additional keyword arguments (e.g., ``uuid``).

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            if domain_name:
                kwargs["domainName"] = domain_name
            return self._service.getVg224(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_vg224(self, vg224_data: Vg224) -> Dict[str, Any]:
        """Add a new Vg224.

        Args:
            vg224_data: A dict describing the Vg224.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addVg224(vg224=vg224_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_vg224(self, **kwargs: Unpack[UpdateVg224]) -> Dict[str, Any]:
        """Update an existing Vg224.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateVg224(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_vg224(self, domain_name: str = "", **kwargs) -> Dict[str, Any]:
        """Remove a Vg224 by domainName.

        Args:
            domain_name: The Vg224 domain name.
            **kwargs: Additional keyword arguments (e.g., ``uuid``).

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            if domain_name:
                kwargs["domainName"] = domain_name
            return self._service.removeVg224(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def reset_vg224(self, name: str) -> Dict[str, Any]:
        """Reset a Vg224.

        Args:
            name: The Vg224 name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.resetVg224(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def restart_vg224(self, name: str) -> Dict[str, Any]:
        """Restart a Vg224.

        Args:
            name: The Vg224 name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.restartVg224(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  VohServer
    # ═══════════════════════════════════════════════════════════════════

    def get_voh_server(self, name: str) -> Dict[str, Any]:
        """Retrieve a VohServer by name.

        Args:
            name: The VohServer name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getVohServer(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_voh_server(self, voh_server_data: VohServer) -> Dict[str, Any]:
        """Add a new VohServer.

        Args:
            voh_server_data: A dict describing the VohServer.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addVohServer(vohServer=voh_server_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_voh_server(self, **kwargs: Unpack[UpdateVohServer]) -> Dict[str, Any]:
        """Update an existing VohServer.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateVohServer(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_voh_server(self, name: str) -> Dict[str, Any]:
        """Remove a VohServer by name.

        Args:
            name: The VohServer name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeVohServer(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_voh_server(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List VohServer objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listVohServer(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  VoiceMailPilot
    # ═══════════════════════════════════════════════════════════════════

    def update_voice_mail_pilot(self, **kwargs: Unpack[UpdateVoiceMailPilot]) -> Dict[str, Any]:
        """Update an existing VoiceMailPilot.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateVoiceMailPilot(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_voice_mail_pilot(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List VoiceMailPilot objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listVoiceMailPilot(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  VoiceMailPort
    # ═══════════════════════════════════════════════════════════════════

    def update_voice_mail_port(self, **kwargs: Unpack[UpdateVoiceMailPort]) -> Dict[str, Any]:
        """Update an existing VoiceMailPort.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateVoiceMailPort(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_voice_mail_port(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List VoiceMailPort objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listVoiceMailPort(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def apply_voice_mail_port(self, name: str) -> Dict[str, Any]:
        """Apply configuration for a VoiceMailPort.

        Args:
            name: The VoiceMailPort name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.applyVoiceMailPort(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def reset_voice_mail_port(self, name: str) -> Dict[str, Any]:
        """Reset a VoiceMailPort.

        Args:
            name: The VoiceMailPort name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.resetVoiceMailPort(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def restart_voice_mail_port(self, name: str) -> Dict[str, Any]:
        """Restart a VoiceMailPort.

        Args:
            name: The VoiceMailPort name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.restartVoiceMailPort(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  VoiceMailProfile
    # ═══════════════════════════════════════════════════════════════════

    def update_voice_mail_profile(self, **kwargs: Unpack[UpdateVoiceMailProfile]) -> Dict[str, Any]:
        """Update an existing VoiceMailProfile.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateVoiceMailProfile(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_voice_mail_profile(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List VoiceMailProfile objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listVoiceMailProfile(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def apply_voice_mail_profile(self, name: str) -> Dict[str, Any]:
        """Apply configuration for a VoiceMailProfile.

        Args:
            name: The VoiceMailProfile name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.applyVoiceMailProfile(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def reset_voice_mail_profile(self, name: str) -> Dict[str, Any]:
        """Reset a VoiceMailProfile.

        Args:
            name: The VoiceMailProfile name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.resetVoiceMailProfile(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def restart_voice_mail_profile(self, name: str) -> Dict[str, Any]:
        """Restart a VoiceMailProfile.

        Args:
            name: The VoiceMailProfile name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.restartVoiceMailProfile(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  VpnGateway
    # ═══════════════════════════════════════════════════════════════════

    def get_vpn_gateway(self, name: str) -> Dict[str, Any]:
        """Retrieve a VpnGateway by name.

        Args:
            name: The VpnGateway name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getVpnGateway(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_vpn_gateway(self, vpn_gateway_data: VpnGateway) -> Dict[str, Any]:
        """Add a new VpnGateway.

        Args:
            vpn_gateway_data: A dict describing the VpnGateway.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addVpnGateway(vpnGateway=vpn_gateway_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_vpn_gateway(self, **kwargs: Unpack[UpdateVpnGateway]) -> Dict[str, Any]:
        """Update an existing VpnGateway.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateVpnGateway(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_vpn_gateway(self, name: str) -> Dict[str, Any]:
        """Remove a VpnGateway by name.

        Args:
            name: The VpnGateway name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeVpnGateway(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_vpn_gateway(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List VpnGateway objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listVpnGateway(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  VpnGroup
    # ═══════════════════════════════════════════════════════════════════

    def get_vpn_group(self, name: str) -> Dict[str, Any]:
        """Retrieve a VpnGroup by name.

        Args:
            name: The VpnGroup name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getVpnGroup(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_vpn_group(self, vpn_group_data: VpnGroup) -> Dict[str, Any]:
        """Add a new VpnGroup.

        Args:
            vpn_group_data: A dict describing the VpnGroup.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addVpnGroup(vpnGroup=vpn_group_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_vpn_group(self, **kwargs: Unpack[UpdateVpnGroup]) -> Dict[str, Any]:
        """Update an existing VpnGroup.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateVpnGroup(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_vpn_group(self, name: str) -> Dict[str, Any]:
        """Remove a VpnGroup by name.

        Args:
            name: The VpnGroup name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeVpnGroup(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_vpn_group(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List VpnGroup objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listVpnGroup(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  VpnProfile
    # ═══════════════════════════════════════════════════════════════════

    def get_vpn_profile(self, name: str) -> Dict[str, Any]:
        """Retrieve a VpnProfile by name.

        Args:
            name: The VpnProfile name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getVpnProfile(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_vpn_profile(self, vpn_profile_data: VpnProfile) -> Dict[str, Any]:
        """Add a new VpnProfile.

        Args:
            vpn_profile_data: A dict describing the VpnProfile.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addVpnProfile(vpnProfile=vpn_profile_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_vpn_profile(self, **kwargs: Unpack[UpdateVpnProfile]) -> Dict[str, Any]:
        """Update an existing VpnProfile.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateVpnProfile(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_vpn_profile(self, name: str) -> Dict[str, Any]:
        """Remove a VpnProfile by name.

        Args:
            name: The VpnProfile name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeVpnProfile(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_vpn_profile(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List VpnProfile objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listVpnProfile(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  WLANProfile
    # ═══════════════════════════════════════════════════════════════════

    def get_wlan_profile(self, name: str) -> Dict[str, Any]:
        """Retrieve a WLANProfile by name.

        Args:
            name: The WLANProfile name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getWLANProfile(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_wlan_profile(self, wlan_profile_data: WLANProfile) -> Dict[str, Any]:
        """Add a new WLANProfile.

        Args:
            wlan_profile_data: A dict describing the WLANProfile.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addWLANProfile(wLANProfile=wlan_profile_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_wlan_profile(self, **kwargs: Unpack[UpdateWLANProfile]) -> Dict[str, Any]:
        """Update an existing WLANProfile.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateWLANProfile(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_wlan_profile(self, name: str) -> Dict[str, Any]:
        """Remove a WLANProfile by name.

        Args:
            name: The WLANProfile name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeWLANProfile(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_wlan_profile(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List WLANProfile objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listWLANProfile(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  WifiHotspot
    # ═══════════════════════════════════════════════════════════════════

    def get_wifi_hotspot(self, name: str) -> Dict[str, Any]:
        """Retrieve a WifiHotspot by name.

        Args:
            name: The WifiHotspot name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getWifiHotspot(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_wifi_hotspot(self, wifi_hotspot_data: WifiHotspot) -> Dict[str, Any]:
        """Add a new WifiHotspot.

        Args:
            wifi_hotspot_data: A dict describing the WifiHotspot.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addWifiHotspot(wifiHotspot=wifi_hotspot_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_wifi_hotspot(self, **kwargs: Unpack[UpdateWifiHotspot]) -> Dict[str, Any]:
        """Update an existing WifiHotspot.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateWifiHotspot(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_wifi_hotspot(self, name: str) -> Dict[str, Any]:
        """Remove a WifiHotspot by name.

        Args:
            name: The WifiHotspot name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeWifiHotspot(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_wifi_hotspot(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List WifiHotspot objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listWifiHotspot(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  WirelessAccessPointControllers
    # ═══════════════════════════════════════════════════════════════════

    def get_wireless_access_point_controllers(self, name: str) -> Dict[str, Any]:
        """Retrieve a WirelessAccessPointControllers by name.

        Args:
            name: The WirelessAccessPointControllers name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getWirelessAccessPointControllers(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_wireless_access_point_controllers(self, wireless_access_point_controllers_data: WirelessAccessPointControllers) -> Dict[str, Any]:
        """Add a new WirelessAccessPointControllers.

        Args:
            wireless_access_point_controllers_data: A dict describing the WirelessAccessPointControllers.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addWirelessAccessPointControllers(wirelessAccessPointControllers=wireless_access_point_controllers_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_wireless_access_point_controllers(self, **kwargs: Unpack[UpdateWirelessAccessPointControllers]) -> Dict[str, Any]:
        """Update an existing WirelessAccessPointControllers.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateWirelessAccessPointControllers(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_wireless_access_point_controllers(self, name: str) -> Dict[str, Any]:
        """Remove a WirelessAccessPointControllers by name.

        Args:
            name: The WirelessAccessPointControllers name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeWirelessAccessPointControllers(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_wireless_access_point_controllers(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List WirelessAccessPointControllers objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listWirelessAccessPointControllers(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  WlanProfileGroup
    # ═══════════════════════════════════════════════════════════════════

    def get_wlan_profile_group(self, name: str) -> Dict[str, Any]:
        """Retrieve a WlanProfileGroup by name.

        Args:
            name: The WlanProfileGroup name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.getWlanProfileGroup(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_wlan_profile_group(self, wlan_profile_group_data: WlanProfileGroup) -> Dict[str, Any]:
        """Add a new WlanProfileGroup.

        Args:
            wlan_profile_group_data: A dict describing the WlanProfileGroup.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addWlanProfileGroup(wlanProfileGroup=wlan_profile_group_data)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_wlan_profile_group(self, **kwargs: Unpack[UpdateWlanProfileGroup]) -> Dict[str, Any]:
        """Update an existing WlanProfileGroup.

        Args:
            **kwargs: Fields to update. Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.updateWlanProfileGroup(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_wlan_profile_group(self, name: str) -> Dict[str, Any]:
        """Remove a WlanProfileGroup by name.

        Args:
            name: The WlanProfileGroup name.

        Returns:
            The AXL response dict.

        Raises:
            AXLNotFoundError: If not found.
            AXLError: On other AXL faults.
        """
        try:
            return self._service.removeWlanProfileGroup(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_wlan_profile_group(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List WlanProfileGroup objects matching search criteria.

        Args:
            search_criteria: Dict of field names to search patterns.
                Uses SQL LIKE syntax (``%`` as wildcard).
            returned_tags: Dict of field names to return.
            **kwargs: Additional arguments passed to the AXL call.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listWlanProfileGroup(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  AarGroupMatrix (Configuration)
    # ═══════════════════════════════════════════════════════════════════

    def update_aar_group_matrix(self, **kwargs: Unpack[UpdateAarGroupMatrix]) -> Dict[str, Any]:
        """Update AarGroupMatrix configuration.

        Args:
            **kwargs: Fields to update.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.updateAarGroupMatrix(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Annunciator (Configuration)
    # ═══════════════════════════════════════════════════════════════════

    def get_annunciator(self, name: str = "", **kwargs) -> Dict[str, Any]:
        """Retrieve Annunciator configuration.

        Args:
            name: The annunciator name.
            **kwargs: Additional fields (e.g. uuid, returnedTags).

        Returns:
            The full AXL response dict.

        Raises:
            AXLNotFoundError: If the annunciator is not found.
            AXLError: On AXL faults.
        """
        try:
            if name:
                kwargs["name"] = name
            return self._service.getAnnunciator(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_annunciator(self, **kwargs: Unpack[UpdateAnnunciator]) -> Dict[str, Any]:
        """Update Annunciator configuration.

        Args:
            **kwargs: Fields to update.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.updateAnnunciator(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  CallManager (Configuration)
    # ═══════════════════════════════════════════════════════════════════

    def get_call_manager(self, name: str) -> Dict[str, Any]:
        """Retrieve CallManager by name.

        Args:
            name: The CallManager name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.getCallManager(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_call_manager(self, **kwargs: Unpack[UpdateCallManager]) -> Dict[str, Any]:
        """Update CallManager configuration.

        Args:
            **kwargs: Fields to update.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.updateCallManager(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_call_manager(self, search_criteria: Optional[Dict[str, str]] = None,
                     returned_tags: Optional[Dict[str, str]] = None,
                     **kwargs) -> Dict[str, Any]:
        """List CallManager objects.

        Args:
            search_criteria: Search filter dict.
            returned_tags: Fields to return.
            **kwargs: Additional arguments.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listCallManager(searchCriteria=search_criteria,
                                           returnedTags=returned_tags or {},
                                           **kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def apply_call_manager(self, name: str) -> Dict[str, Any]:
        """Apply configuration for CallManager.

        Args:
            name: The CallManager name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.applyCallManager(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def reset_call_manager(self, name: str) -> Dict[str, Any]:
        """Reset CallManager.

        Args:
            name: The CallManager name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.resetCallManager(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def restart_call_manager(self, name: str) -> Dict[str, Any]:
        """Restart CallManager.

        Args:
            name: The CallManager name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.restartCallManager(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  CcdFeatureConfig (Configuration)
    # ═══════════════════════════════════════════════════════════════════

    def get_ccd_feature_config(self, **kwargs) -> Dict[str, Any]:
        """Retrieve CcdFeatureConfig configuration.

        Args:
            **kwargs: Keyword arguments passed to the WSDL operation.
                Requires ``paramName`` and ``returnedTags``.

        Returns:
            The full AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.getCcdFeatureConfig(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_ccd_feature_config(self, **kwargs: Unpack[UpdateCcdFeatureConfig]) -> Dict[str, Any]:
        """Update CcdFeatureConfig configuration.

        Args:
            **kwargs: Fields to update.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.updateCcdFeatureConfig(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  CiscoCloudOnboarding (Configuration)
    # ═══════════════════════════════════════════════════════════════════

    def update_cisco_cloud_onboarding(self, **kwargs: Unpack[UpdateCiscoCloudOnboarding]) -> Dict[str, Any]:
        """Update CiscoCloudOnboarding configuration.

        Args:
            **kwargs: Fields to update.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.updateCiscoCloudOnboarding(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  CredentialPolicyDefault (Configuration)
    # ═══════════════════════════════════════════════════════════════════

    def get_device_defaults(self, **kwargs) -> Dict[str, Any]:
        """Retrieve DeviceDefaults configuration.

        Args:
            **kwargs: Must include ``Model`` + ``Protocol``, or ``uuid``.

        Returns:
            The full AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.getDeviceDefaults(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_device_defaults(self, **kwargs: Unpack[UpdateDeviceDefaults]) -> Dict[str, Any]:
        """Update DeviceDefaults configuration.

        Args:
            **kwargs: Fields to update.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.updateDeviceDefaults(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  EmccFeatureConfig (Configuration)
    # ═══════════════════════════════════════════════════════════════════

    def get_emcc_feature_config(self, **kwargs) -> Dict[str, Any]:
        """Retrieve EmccFeatureConfig configuration.

        Args:
            **kwargs: Must include ``parameterName``; or ``uuid``.

        Returns:
            The full AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.getEmccFeatureConfig(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_emcc_feature_config(self, **kwargs: Unpack[UpdateEmccFeatureConfig]) -> Dict[str, Any]:
        """Update EmccFeatureConfig configuration.

        Args:
            **kwargs: Fields to update.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.updateEmccFeatureConfig(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  EnterpriseParameters (Configuration)
    # ═══════════════════════════════════════════════════════════════════

    def reset_enterprise_parameters(self) -> Dict[str, Any]:
        """Reset EnterpriseParameters.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.resetEnterpriseParameters()
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def restart_enterprise_parameters(self) -> Dict[str, Any]:
        """Restart EnterpriseParameters.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.restartEnterpriseParameters()
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  EnterprisePhoneConfig (Configuration)
    # ═══════════════════════════════════════════════════════════════════

    def get_enterprise_phone_config(self) -> Dict[str, Any]:
        """Retrieve EnterprisePhoneConfig configuration.

        Returns:
            The full AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.getEnterprisePhoneConfig()
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_enterprise_phone_config(self, **kwargs: Unpack[UpdateEnterprisePhoneConfig]) -> Dict[str, Any]:
        """Update EnterprisePhoneConfig configuration.

        Args:
            **kwargs: Fields to update.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.updateEnterprisePhoneConfig(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  FallbackFeatureConfig (Configuration)
    # ═══════════════════════════════════════════════════════════════════

    def get_fallback_feature_config(self) -> Dict[str, Any]:
        """Retrieve FallbackFeatureConfig configuration.

        Returns:
            The full AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.getFallbackFeatureConfig()
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_fallback_feature_config(self, **kwargs: Unpack[UpdateFallbackFeatureConfig]) -> Dict[str, Any]:
        """Update FallbackFeatureConfig configuration.

        Args:
            **kwargs: Fields to update.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.updateFallbackFeatureConfig(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  FixedMohAudioSource (Configuration)
    # ═══════════════════════════════════════════════════════════════════

    def get_fixed_moh_audio_source(self, name: str) -> Dict[str, Any]:
        """Retrieve FixedMohAudioSource by name.

        Args:
            name: The FixedMohAudioSource name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.getFixedMohAudioSource(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_fixed_moh_audio_source(self, **kwargs: Unpack[UpdateFixedMohAudioSource]) -> Dict[str, Any]:
        """Update FixedMohAudioSource configuration.

        Args:
            **kwargs: Fields to update.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.updateFixedMohAudioSource(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  IlsConfig (Configuration)
    # ═══════════════════════════════════════════════════════════════════

    def get_ils_config(self, **kwargs) -> Dict[str, Any]:
        """Retrieve IlsConfig configuration.

        Args:
            **kwargs: Keyword arguments passed to the WSDL operation.
                Requires ``returnedTags``.

        Returns:
            The full AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.getIlsConfig(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_ils_config(self, **kwargs: Unpack[UpdateIlsConfig]) -> Dict[str, Any]:
        """Update IlsConfig configuration.

        Args:
            **kwargs: Fields to update.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.updateIlsConfig(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  ImeFeatureConfig (Configuration)
    # ═══════════════════════════════════════════════════════════════════

    def get_ime_feature_config(self) -> Dict[str, Any]:
        """Retrieve ImeFeatureConfig configuration.

        Returns:
            The full AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.getImeFeatureConfig()
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_ime_feature_config(self, **kwargs: Unpack[UpdateImeFeatureConfig]) -> Dict[str, Any]:
        """Update ImeFeatureConfig configuration.

        Args:
            **kwargs: Fields to update.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.updateImeFeatureConfig(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  InterClusterDirectoryUri (Configuration)
    # ═══════════════════════════════════════════════════════════════════

    def update_inter_cluster_directory_uri(self, **kwargs: Unpack[UpdateInterClusterDirectoryUri]) -> Dict[str, Any]:
        """Update InterClusterDirectoryUri configuration.

        Args:
            **kwargs: Fields to update.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.updateInterClusterDirectoryUri(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  InterClusterServiceProfile (Configuration)
    # ═══════════════════════════════════════════════════════════════════

    def get_inter_cluster_service_profile(self, **kwargs) -> Dict[str, Any]:
        """Retrieve InterClusterServiceProfile configuration.

        Args:
            **kwargs: Must include ``interClusterService`` or ``uuid``.

        Returns:
            The full AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.getInterClusterServiceProfile(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_inter_cluster_service_profile(self, **kwargs: Unpack[UpdateInterClusterServiceProfile]) -> Dict[str, Any]:
        """Update InterClusterServiceProfile configuration.

        Args:
            **kwargs: Fields to update.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.updateInterClusterServiceProfile(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  PageLayoutPreferences (Configuration)
    # ═══════════════════════════════════════════════════════════════════

    def get_page_layout_preferences(self, **kwargs) -> Dict[str, Any]:
        """Retrieve PageLayoutPreferences configuration.

        Args:
            **kwargs: Keyword arguments passed to the WSDL operation.
                Requires ``pageName``.

        Returns:
            The full AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.getPageLayoutPreferences(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_page_layout_preferences(self, **kwargs: Unpack[UpdatePageLayoutPreferences]) -> Dict[str, Any]:
        """Update PageLayoutPreferences configuration.

        Args:
            **kwargs: Fields to update.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.updatePageLayoutPreferences(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  RegionMatrix (Configuration)
    # ═══════════════════════════════════════════════════════════════════

    def update_region_matrix(self, **kwargs: Unpack[UpdateRegionMatrix]) -> Dict[str, Any]:
        """Update RegionMatrix configuration.

        Args:
            **kwargs: Fields to update.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.updateRegionMatrix(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  RoutePartitionsForLearnedPatterns (Configuration)
    # ═══════════════════════════════════════════════════════════════════

    def update_route_partitions_for_learned_patterns(self, **kwargs: Unpack[UpdateRoutePartitionsForLearnedPatterns]) -> Dict[str, Any]:
        """Update RoutePartitionsForLearnedPatterns configuration.

        Args:
            **kwargs: Fields to update.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.updateRoutePartitionsForLearnedPatterns(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  SNMPMIB2List (Configuration)
    # ═══════════════════════════════════════════════════════════════════

    def get_snmpmib2_list(self, **kwargs) -> Dict[str, Any]:
        """Retrieve SNMPMIB2List configuration.

        Args:
            **kwargs: Keyword arguments passed to the WSDL operation.
                Requires ``sysContact``.

        Returns:
            The full AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.getSNMPMIB2List(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_snmpmib2_list(self, **kwargs: Unpack[UpdateSNMPMIB2List]) -> Dict[str, Any]:
        """Update SNMPMIB2List configuration.

        Args:
            **kwargs: Fields to update.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.updateSNMPMIB2List(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  SecureConfig (Configuration)
    # ═══════════════════════════════════════════════════════════════════

    def get_secure_config(self, **kwargs) -> Dict[str, Any]:
        """Retrieve SecureConfig configuration.

        Args:
            **kwargs: Must include ``name`` or ``uuid``.

        Returns:
            The full AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.getSecureConfig(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_secure_config(self, **kwargs: Unpack[UpdateSecureConfig]) -> Dict[str, Any]:
        """Update SecureConfig configuration.

        Args:
            **kwargs: Fields to update.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.updateSecureConfig(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  SelfProvisioning (Configuration)
    # ═══════════════════════════════════════════════════════════════════

    def get_soft_key_set(self, name: str) -> Dict[str, Any]:
        """Retrieve SoftKeySet by name.

        Args:
            name: The SoftKeySet name.

        Returns:
            The full AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.getSoftKeySet(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_soft_key_set(self, **kwargs: Unpack[UpdateSoftKeySet]) -> Dict[str, Any]:
        """Update SoftKeySet configuration.

        Args:
            **kwargs: Fields to update.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.updateSoftKeySet(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  SyslogConfiguration (Configuration)
    # ═══════════════════════════════════════════════════════════════════

    def get_syslog_configuration(self, **kwargs) -> Dict[str, Any]:
        """Retrieve SyslogConfiguration configuration.

        Args:
            **kwargs: Keyword arguments passed to the WSDL operation.

        Returns:
            The full AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.getSyslogConfiguration(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_syslog_configuration(self, **kwargs: Unpack[UpdateSyslogConfiguration]) -> Dict[str, Any]:
        """Update SyslogConfiguration configuration.

        Args:
            **kwargs: Fields to update.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.updateSyslogConfiguration(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    # ═══════════════════════════════════════════════════════════════════
    #  Special / Miscellaneous Operations
    # ═══════════════════════════════════════════════════════════════════

    def execute_sql_query_inactive(self, sql: str) -> Dict[str, Any]:
        """Execute a SQL query against the inactive database partition.

        Args:
            sql: The SQL query string.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.executeSQLQueryInactive(sql=sql)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def do_ldap_sync(self, name: Optional[str] = None, sync: bool = True) -> Dict[str, Any]:
        """Trigger an LDAP directory sync.

        Args:
            name: Optional LDAP directory name. If ``None``, syncs all.
            sync: Whether to sync (default ``True``).

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            kwargs = {"sync": sync}
            if name:
                kwargs["name"] = name
            return self._service.doLdapSync(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def get_ldap_sync_status(self, name: Optional[str] = None) -> Dict[str, Any]:
        """Get the status of an LDAP sync operation.

        Args:
            name: Optional LDAP directory name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            kwargs = {}
            if name:
                kwargs["name"] = name
            return self._service.getLdapSyncStatus(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def wipe_phone(self, name: str) -> Dict[str, Any]:
        """Wipe a phone device.

        Args:
            name: The phone device name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.wipePhone(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def get_service_parameter(self, process_node_name: str,
                               service: str, name: str) -> Dict[str, Any]:
        """Retrieve a service parameter.

        Args:
            process_node_name: The UCM node hostname.
            service: The service name.
            name: The parameter name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.getServiceParameter(
                processNodeName=process_node_name,
                service=service,
                name=name,
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_service_parameter(self, search_criteria: Optional[Dict[str, str]] = None,
                                returned_tags: Optional[Dict[str, str]] = None,
                                **kwargs) -> Dict[str, Any]:
        """List service parameters.

        Args:
            search_criteria: Search filter dict.
            returned_tags: Fields to return.
            **kwargs: Additional arguments.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listServiceParameter(
                searchCriteria=search_criteria,
                returnedTags=returned_tags or {},
                **kwargs,
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_service_parameter(self, process_node_name: str,
                                  service: str, name: str,
                                  value: str) -> Dict[str, Any]:
        """Update a service parameter.

        Args:
            process_node_name: The UCM node hostname.
            service: The service name.
            name: The parameter name.
            value: The new value.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.updateServiceParameter(
                processNodeName=process_node_name,
                service=service,
                name=name,
                value=value,
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def do_service_parameters_reset(self) -> Dict[str, Any]:
        """Reset all service parameters to defaults.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.doServiceParametersReset()
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def get_num_devices(self, **kwargs) -> Dict[str, Any]:
        """Get the number of registered devices.

        Args:
            **kwargs: Keyword arguments passed to the WSDL operation.
                Requires ``class`` (device class, e.g. 'Phone').

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.getNumDevices(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def get_os_version(self) -> Dict[str, Any]:
        """Get the UCM OS version.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.getOSVersion()
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def get_phone_options(self, uuid: str) -> Dict[str, Any]:
        """Get available phone product options.

        Args:
            uuid: The UUID of the phone.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.getPhoneOptions(uuid=uuid)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def get_line_options(self, uuid: str) -> Dict[str, Any]:
        """Get available line options.

        Args:
            uuid: The UUID of the line.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.getLineOptions(uuid=uuid)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def get_sip_profile_options(self, uuid: str) -> Dict[str, Any]:
        """Get available SIP profile options.

        Args:
            uuid: The UUID of the SIP profile.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.getSipProfileOptions(uuid=uuid)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def get_trans_pattern_options(self, uuid: str) -> Dict[str, Any]:
        """Get available translation pattern options.

        Args:
            uuid: The UUID of the translation pattern.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.getTransPatternOptions(uuid=uuid)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def get_phone_type_display_instance(self, **kwargs) -> Dict[str, Any]:
        """Get phone type display instance info.

        Args:
            **kwargs: Keyword arguments passed to the WSDL operation.
                Requires ``productName`` and ``protocol``.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.getPhoneTypeDisplayInstance(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def get_transport_settings(self) -> Dict[str, Any]:
        """Get transport settings.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.getTransportSettings()
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def do_update_transport_settings(self, **kwargs) -> Dict[str, Any]:
        """Update transport settings.

        Args:
            **kwargs: Transport settings to update.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.doUpdateTransportSettings(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def get_licensed_user(self, **kwargs) -> Dict[str, Any]:
        """Retrieve licensed user info.

        Args:
            **kwargs: Must include ``name`` or ``uuid``.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.getLicensedUser(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_licensed_user(self, search_criteria: Optional[Dict[str, str]] = None,
                           returned_tags: Optional[Dict[str, str]] = None,
                           **kwargs) -> Dict[str, Any]:
        """List licensed users.

        Args:
            search_criteria: Search filter dict.
            returned_tags: Fields to return.
            **kwargs: Additional arguments.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"userid": "%"}
        try:
            return self._service.listLicensedUser(
                searchCriteria=search_criteria,
                returnedTags=returned_tags or {},
                **kwargs,
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def get_mobile_smart_client_profile(self, name: str) -> Dict[str, Any]:
        """Retrieve a Mobile Smart Client Profile by name.

        Args:
            name: The profile name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.getMobileSmartClientProfile(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_mobile_smart_client_profile(self, search_criteria: Optional[Dict[str, str]] = None,
                                          returned_tags: Optional[Dict[str, str]] = None,
                                          **kwargs) -> Dict[str, Any]:
        """List Mobile Smart Client Profiles.

        Args:
            search_criteria: Search filter dict.
            returned_tags: Fields to return.
            **kwargs: Additional arguments.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listMobileSmartClientProfile(
                searchCriteria=search_criteria,
                returnedTags=returned_tags or {},
                **kwargs,
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_unassigned_device(self, search_criteria: Optional[Dict[str, str]] = None,
                                returned_tags: Optional[Dict[str, str]] = None,
                                **kwargs) -> Dict[str, Any]:
        """List unassigned devices.

        Args:
            search_criteria: Search filter dict.
            returned_tags: Fields to return.
            **kwargs: Additional arguments.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listUnassignedDevice(
                searchCriteria=search_criteria,
                returnedTags=returned_tags or {},
                **kwargs,
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_unassigned_presence_servers(self, **kwargs) -> Dict[str, Any]:
        """List unassigned presence servers.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.listUnassignedPresenceServers(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_unassigned_presence_users(self, search_criteria: Optional[Dict[str, str]] = None,
                                        returned_tags: Optional[Dict[str, str]] = None,
                                        **kwargs) -> Dict[str, Any]:
        """List unassigned presence users.

        Args:
            search_criteria: Search filter dict.
            returned_tags: Fields to return.
            **kwargs: Additional arguments.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"userid": "%"}
        try:
            return self._service.listUnassignedPresenceUsers(
                searchCriteria=search_criteria,
                returnedTags=returned_tags or {},
                **kwargs,
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_route_plan(self, search_criteria: Optional[Dict[str, str]] = None,
                        returned_tags: Optional[Dict[str, str]] = None,
                        **kwargs) -> Dict[str, Any]:
        """List route plan entries.

        Args:
            search_criteria: Search filter dict.
            returned_tags: Fields to return.
            **kwargs: Additional arguments.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"dnOrPattern": "%"}
        try:
            return self._service.listRoutePlan(
                searchCriteria=search_criteria,
                returnedTags=returned_tags or {},
                **kwargs,
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def associate_user_devices(self, userid: str, devices: list) -> Dict[str, Any]:
        """Associate phones to an end user.

        This is a convenience method that updates the user record to include
        the given devices in its ``associatedDevices`` list.

        Args:
            userid: The end user ID.
            devices: List of device name strings.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.updateUser(
                userid=userid,
                associatedDevices={"device": devices},
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_user_phone_association(
        self,
        user_phone_association_data: UserPhoneAssociation,
    ) -> Dict[str, Any]:
        """Provision a user, phone, line, and DN in a single operation.

        This wraps the AXL ``addUserPhoneAssociation`` operation which
        creates or updates a user and associates a phone/line/DN in one
        call.

        Args:
            user_phone_association_data: A dict describing the user, phone,
                line, and DN association.  See :class:`UserPhoneAssociation`.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addUserPhoneAssociation(
                userPhoneAssociation=user_phone_association_data
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def add_phone_activation_code(
        self,
        phone_activation_code_data: PhoneActivationCode,
    ) -> Dict[str, Any]:
        """Add a phone activation code.

        Args:
            phone_activation_code_data: Activation code data dict.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.addPhoneActivationCode(
                phoneActivationCode=phone_activation_code_data
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_phone_activation_code(self, search_criteria: Optional[Dict[str, str]] = None,
                                    returned_tags: Optional[Dict[str, str]] = None,
                                    **kwargs) -> Dict[str, Any]:
        """List phone activation codes.

        Args:
            search_criteria: Search filter dict.
            returned_tags: Fields to return.
            **kwargs: Additional arguments.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"phoneName": "%"}
        try:
            return self._service.listPhoneActivationCode(
                searchCriteria=search_criteria,
                returnedTags=returned_tags or {},
                **kwargs,
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_phone_activation_code(self, **kwargs) -> Dict[str, Any]:
        """Remove a phone activation code.

        Args:
            **kwargs: Identification of the activation code.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.removePhoneActivationCode(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def get_ime_learned_routes(self, **kwargs) -> Dict[str, Any]:
        """Get IME learned routes.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.getImeLearnedRoutes(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def remove_ime_learned_routes(self, **kwargs) -> Dict[str, Any]:
        """Remove IME learned routes.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.removeImeLearnedRoutes(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_ime_learned_routes(self, **kwargs: Unpack[UpdateImeLearnedRoutes]) -> Dict[str, Any]:
        """Update IME learned routes.

        Args:
            **kwargs: Fields to update.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.updateImeLearnedRoutes(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def get_smart_license_status(self) -> Dict[str, Any]:
        """Get smart license status.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.getSmartLicenseStatus()
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def do_smart_license_register(self, **kwargs) -> Dict[str, Any]:
        """Register smart license.

        Args:
            **kwargs: Registration parameters.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.doSmartLicenseRegister(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def do_smart_license_de_register(self) -> Dict[str, Any]:
        """Deregister smart license.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.doSmartLicenseDeRegister()
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def do_smart_license_re_register(self, **kwargs) -> Dict[str, Any]:
        """Re-register smart license.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.doSmartLicenseReRegister(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def do_smart_license_renew_authorization(self) -> Dict[str, Any]:
        """Renew smart license authorization.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.doSmartLicenseRenewAuthorization()
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def do_smart_license_renew_registration(self) -> Dict[str, Any]:
        """Renew smart license registration.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.doSmartLicenseRenewRegistration()
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def do_smart_entitlement_request(self, **kwargs) -> Dict[str, Any]:
        """Submit a smart entitlement request.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.doSmartEntitlementRequest(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def do_update_license_usage(self, **kwargs) -> Dict[str, Any]:
        """Update license usage.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.doUpdateLicenseUsage(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def do_update_remote_cluster(self, **kwargs) -> Dict[str, Any]:
        """Update a remote cluster.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.doUpdateRemoteCluster(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def unassign_presence_user(self, **kwargs) -> Dict[str, Any]:
        """Unassign a presence user.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.unassignPresenceUser(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_credential_policy_default(self, **kwargs: Unpack[UpdateCredentialPolicyDefault]) -> Dict[str, Any]:
        """Update the default credential policy.

        Args:
            **kwargs: Fields to update.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.updateCredentialPolicyDefault(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_self_provisioning(self, **kwargs: Unpack[UpdateSelfProvisioning]) -> Dict[str, Any]:
        """Update self-provisioning settings.

        Args:
            **kwargs: Fields to update.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.updateSelfProvisioning(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def get_tvs_certificate(self, name: str) -> Dict[str, Any]:
        """Retrieve a TVS certificate.

        Args:
            name: The certificate name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.getTvsCertificate(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_tvs_certificate(self, search_criteria: Optional[Dict[str, str]] = None,
                              returned_tags: Optional[Dict[str, str]] = None,
                              **kwargs) -> Dict[str, Any]:
        """List TVS certificates.

        Args:
            search_criteria: Search filter dict.
            returned_tags: Fields to return.
            **kwargs: Additional arguments.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"subjectName": "%"}
        try:
            return self._service.listTvsCertificate(
                searchCriteria=search_criteria,
                returnedTags=returned_tags or {},
                **kwargs,
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def update_tvs_certificate(self, **kwargs: Unpack[UpdateTvsCertificate]) -> Dict[str, Any]:
        """Update a TVS certificate.

        Args:
            **kwargs: Fields to update.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.updateTvsCertificate(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def assign_presence_user(self, **kwargs) -> Dict[str, Any]:
        """Assign a presence user.

        Args:
            **kwargs: Presence user assignment parameters.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.assignPresenceUser(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def do_authenticate_user(self, userid: str, pin: str) -> Dict[str, Any]:
        """Authenticate an end user.

        Args:
            userid: The user ID.
            pin: The user PIN.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.doAuthenticateUser(userid=userid, pin=pin)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def do_change_dnd_status(self, **kwargs) -> Dict[str, Any]:
        """Change the Do Not Disturb status for a line/device.

        Args:
            **kwargs: DND parameters (e.g. ``lineOrDevice``, ``dndStatus``).

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.doChangeDNDStatus(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def do_device_login(self, **kwargs) -> Dict[str, Any]:
        """Log in a device (Extension Mobility).

        Args:
            **kwargs: Login parameters (``deviceName``, ``loginDuration``,
                ``userId``, ``profileName``).

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.doDeviceLogin(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def do_device_logout(self, **kwargs) -> Dict[str, Any]:
        """Log out a device (Extension Mobility).

        Args:
            **kwargs: Logout parameters (``deviceName``).

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.doDeviceLogout(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def do_enterprise_parameters_reset(self) -> Dict[str, Any]:
        """Reset all enterprise parameters to defaults.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.doEnterpriseParametersReset()
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def get_credential_policy_default(self, **kwargs) -> Dict[str, Any]:
        """Retrieve the default credential policy.

        Args:
            **kwargs: Must include ``credentialUser`` and
                ``credentialType``; or ``uuid``.

        Returns:
            The full AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.getCredentialPolicyDefault(**kwargs)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_annunciator(self, search_criteria: Optional[Dict[str, str]] = None,
                         returned_tags: Optional[Dict[str, str]] = None,
                         **kwargs) -> Dict[str, Any]:
        """List Annunciator resources.

        Args:
            search_criteria: Search filter dict.
            returned_tags: Fields to return.
            **kwargs: Additional arguments.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listAnnunciator(
                searchCriteria=search_criteria,
                returnedTags=returned_tags or {},
                **kwargs,
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_cisco_cloud_onboarding(self, search_criteria: Optional[Dict[str, str]] = None,
                                     returned_tags: Optional[Dict[str, str]] = None,
                                     **kwargs) -> Dict[str, Any]:
        """List Cisco Cloud Onboarding configurations.

        Args:
            search_criteria: Search filter dict.
            returned_tags: Fields to return.
            **kwargs: Additional arguments.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {}
        try:
            return self._service.listCiscoCloudOnboarding(
                searchCriteria=search_criteria,
                returnedTags=returned_tags or {},
                **kwargs,
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def list_device_defaults(self, search_criteria: Optional[Dict[str, str]] = None,
                              returned_tags: Optional[Dict[str, str]] = None,
                              **kwargs) -> Dict[str, Any]:
        """List device defaults.

        Args:
            search_criteria: Search filter dict.
            returned_tags: Fields to return.
            **kwargs: Additional arguments.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        if search_criteria is None:
            search_criteria = {"name": "%"}
        try:
            return self._service.listDeviceDefaults(
                searchCriteria=search_criteria,
                returnedTags=returned_tags or {},
                **kwargs,
            )
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault

    def lock_phone(self, name: str) -> Dict[str, Any]:
        """Lock a phone device.

        Args:
            name: The phone device name.

        Returns:
            The AXL response dict.

        Raises:
            AXLError: On AXL faults.
        """
        try:
            return self._service.lockPhone(name=name)
        except Fault as fault:
            raise _axl_error_from_fault(fault) from fault
