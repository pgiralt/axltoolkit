"""
Auto-generated AXL TypedDict models for ``add_*`` and ``update_*`` method payloads.

DO NOT EDIT — regenerate with ``python scripts/generate_models.py``.

These TypedDict classes document the fields accepted by each
``add_*`` and ``update_*`` method. Required fields are annotated
explicitly. Enum-typed fields accept both the enum member and a
plain string.
"""

import sys
from typing import Any, Dict, List, Optional, Sequence, Union

if sys.version_info >= (3, 11):
    from typing import NotRequired, Required, TypedDict
else:
    from typing_extensions import NotRequired, Required, TypedDict


class RArrayOfHosts(TypedDict, total=False):
    """AXL model — ``RArrayOfHosts``.
    """

    item: NotRequired[List[str]]


class RCcdParam(TypedDict, total=False):
    """AXL model — ``RCcdParam``.
    """

    ccdParamName: NotRequired[str]
    ccdParamValue: NotRequired[str]


class RCommunityString(TypedDict, total=False):
    """AXL model — ``RCommunityString``.

     Used by ``AXLClient.add_snmpcommunity_string()``.
    """

    communityName: Required[str]
    accessPrivilege: Required[str]
    ArrayOfHosts: Required["RArrayOfHosts"]


class RSNMPCommunityString1(TypedDict, total=False):
    """AXL model — ``RSNMPCommunityString1``.
    """

    accessPrivilege: NotRequired[str]
    ArrayOfHosts: NotRequired["RArrayOfHosts"]


class RSNMPUser(TypedDict, total=False):
    """AXL model — ``RSNMPUser``.

     Used by ``AXLClient.add_snmpuser()``.
    """

    userName: Required[str]
    authRequired: Required[bool]
    authPassword: Required[str]
    authProtocol: Required[str]
    privacyRequired: Required[bool]
    privacyPassword: Required[str]
    privacyProtocol: Required[str]
    accessPrivilege: Required[str]
    ArrayOfHosts: Required["RArrayOfHosts"]


class FkType(TypedDict, total=False):
    """AXL model — ``XFkType``.
    """

    pass


class LoadInformation(TypedDict, total=False):
    """AXL model — ``XLoadInformation``.
    """

    pass


class VendorConfig(TypedDict, total=False):
    """AXL model — ``XVendorConfig``.
    """

    pass


class UGatewayEndpointDigitalT1(TypedDict, total=False):
    """AXL model — ``UGatewayEndpointDigitalT1``.
    """

    index: NotRequired[Any]
    description: NotRequired[str]
    callingSearchSpaceName: NotRequired[str]
    devicePoolName: NotRequired[str]
    commonDeviceConfigName: NotRequired[str]
    networkLocation: NotRequired["NetworkLocation"]
    locationName: NotRequired[str]
    mediaResourceListName: NotRequired[str]
    automatedAlternateRoutingCssName: NotRequired[str]
    aarNeighborhoodName: NotRequired[str]
    loadInformation: NotRequired["LoadInformation"]
    vendorConfig: NotRequired["VendorConfig"]
    traceFlag: NotRequired[bool]
    mlppDomainId: NotRequired[str]
    mlppIndicationStatus: NotRequired["Status"]
    preemption: NotRequired["Preemption"]
    useTrustedRelayPoint: NotRequired["Status"]
    retryVideoCallAsAudio: NotRequired[bool]
    cgpnTransformationCssName: NotRequired[str]
    useDevicePoolCgpnTransformCss: NotRequired[bool]
    geoLocationName: NotRequired[str]
    sendGeoLocation: NotRequired[bool]
    cdpnTransformationCssName: NotRequired[str]
    useDevicePoolCdpnTransformCss: NotRequired[bool]
    v150: NotRequired[bool]
    geoLocationFilterName: NotRequired[str]
    ports: NotRequired[Any]
    trunkSelectionOrder: NotRequired["TrunkSelectionOrder"]
    clockReference: NotRequired["ClockReference"]
    csuParam: NotRequired["CSUParam"]
    digitSending: NotRequired["DigitSending"]
    pcmType: NotRequired["Encode"]
    fdlChannel: NotRequired["FDLChannel"]
    yellowAlarm: NotRequired["YellowAlarm"]
    zeroSupression: NotRequired["ZeroSuppression"]
    smdiBasePort: NotRequired[Any]
    handleDtmfPrecedenceSignals: NotRequired[bool]
    encodeOutboundVoiceRouteClass: NotRequired[bool]
    routeClassSignalling: NotRequired["Status"]
    pstnAccess: NotRequired[bool]
    imeE164TransformationName: NotRequired[str]
    confidentialAccess: NotRequired[Any]
    connectCallBeforePlayingAnnouncement: NotRequired[bool]
    calledPartyUnknownPrefix: NotRequired[str]
    calledPartyUnknownStripDigits: NotRequired[Any]
    calledPartyUnknownTransformationCssName: NotRequired[str]
    useDevicePoolCalledCssUnkn: NotRequired[bool]


class AarGroup(TypedDict, total=False):
    """AXL model — ``XAarGroup``.

     Used by ``AXLClient.add_aar_group()``.
    """

    name: NotRequired[Any]


class AdvertisedPatterns(TypedDict, total=False):
    """AXL model — ``XAdvertisedPatterns``.

     Used by ``AXLClient.add_advertised_patterns()``.
    """

    description: NotRequired[str]
    pattern: NotRequired[str]
    patternType: NotRequired["GlobalNumber"]
    hostedRoutePSTNRule: NotRequired["HostedRoutePatternPSTNRule"]
    pstnFailStrip: NotRequired[Any]
    pstnFailPrepend: NotRequired[str]


class AnalogPort(TypedDict, total=False):
    """AXL model — ``XAnalogPort``.
    """

    portNumber: NotRequired[Any]
    attendantDn: NotRequired[str]
    unattendedPort: NotRequired[bool]
    callerIdDn: NotRequired[str]
    callerIdEnable: NotRequired[bool]
    callingPartySelection: NotRequired["CallingPartySelection"]
    digitSending: NotRequired["DigitSending"]
    expectedDigits: NotRequired[Any]
    sigDigits: NotRequired[Any]
    lines: NotRequired[Any]
    prefixDn: NotRequired[str]
    presentationBit: NotRequired["PresentationBit"]
    silenceSuppressionThreshold: NotRequired["SilenceSuppressionThreshold"]
    smdiPortNumber: NotRequired[Any]
    startDialProtocol: NotRequired["StartDialProtocol"]
    trunk: NotRequired["Trunk"]
    trunkDirection: NotRequired["TrunkDirection"]
    trunkLevel: NotRequired["TrunkLevel"]
    trunkPadRx: NotRequired["TrunkPad"]
    trunkPadTx: NotRequired["TrunkPad"]
    vendorConfig: NotRequired["VendorConfig"]
    timer1: NotRequired[Any]
    timer2: NotRequired[Any]
    timer3: NotRequired[Any]
    timer4: NotRequired[Any]
    timer5: NotRequired[Any]
    timer6: NotRequired[Any]


class Announcement(TypedDict, total=False):
    """AXL model — ``XAnnouncement``.

     Used by ``AXLClient.add_announcement()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    announcementFile: NotRequired["AnnouncementFile"]


class Content(TypedDict, total=False):
    """AXL model — ``XContent``.
    """

    pass


class AppServerInfo(TypedDict, total=False):
    """AXL model — ``XAppServerInfo``.

     Used by ``AXLClient.add_app_server_info()``.
    """

    appServerName: NotRequired[str]
    appServerContent: NotRequired["AppServerContent"]
    content: NotRequired["Content"]


class AppUser(TypedDict, total=False):
    """AXL model — ``XAppUser``.

     Used by ``AXLClient.add_app_user()``.
    """

    userid: NotRequired[str]
    password: NotRequired[str]
    passwordCredentials: NotRequired[Any]
    digestCredentials: NotRequired[str]
    presenceGroupName: NotRequired[str]
    acceptPresenceSubscription: NotRequired[bool]
    acceptOutOfDialogRefer: NotRequired[bool]
    acceptUnsolicitedNotification: NotRequired[bool]
    allowReplaceHeader: NotRequired[bool]
    associatedDevices: NotRequired[Any]
    associatedGroups: NotRequired[Any]
    ctiControlledDeviceProfiles: NotRequired[Any]


class ApplicationDialRules(TypedDict, total=False):
    """AXL model — ``XApplicationDialRules``.

     Used by ``AXLClient.add_application_dial_rules()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    numberBeginWith: NotRequired[str]
    numberOfDigits: NotRequired[Any]
    digitsToBeRemoved: NotRequired[Any]
    prefixPattern: NotRequired[str]
    priority: NotRequired[Any]


class ApplicationServer(TypedDict, total=False):
    """AXL model — ``XApplicationServer``.

     Used by ``AXLClient.add_application_server()``.
    """

    appServerType: NotRequired["AppServer"]
    name: NotRequired[str]
    ipAddress: NotRequired[str]
    appUsers: NotRequired[Any]
    url: NotRequired[str]
    endUserUrl: NotRequired[str]
    processNodeName: NotRequired[str]
    endUsers: NotRequired[Any]


class ApplicationToSoftKeyTemplate(TypedDict, total=False):
    """AXL model — ``XApplicationToSoftKeyTemplate``.

     Used by ``AXLClient.add_application_to_softkey_template()``.
    """

    softKeyTemplateName: Required[str]
    standardSoftKeyTemplateName: Required[str]


class ApplicationUserCapfProfile(TypedDict, total=False):
    """AXL model — ``XApplicationUserCapfProfile``.

     Used by ``AXLClient.add_application_user_capf_profile()``.
    """

    applicationUser: NotRequired[str]
    instanceId: NotRequired[str]
    certificateOperation: NotRequired["CertificateOperation"]
    authenticationMode: NotRequired["AuthenticationMode"]
    authenticationString: NotRequired[str]
    keySize: NotRequired["KeySize"]
    keyOrder: NotRequired["KeyOrder"]
    ecKeySize: NotRequired["ECKeySize"]
    operationCompletion: NotRequired[str]


class AudioCodecPreferenceList(TypedDict, total=False):
    """AXL model — ``XAudioCodecPreferenceList``.

     Used by ``AXLClient.add_audio_codec_preference_list()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    codecsInList: NotRequired[Any]


class BillingServer(TypedDict, total=False):
    """AXL model — ``XBillingServer``.

     Used by ``AXLClient.add_billing_server()``.
    """

    hostName: NotRequired[str]
    userId: NotRequired[str]
    password: NotRequired[str]
    directory: NotRequired[str]
    resendOnFailure: NotRequired[bool]
    billingServerProtocol: NotRequired["Billingserverprotocol"]


class BlockedLearnedPatterns(TypedDict, total=False):
    """AXL model — ``XBlockedLearnedPatterns``.

     Used by ``AXLClient.add_blocked_learned_patterns()``.
    """

    description: NotRequired[str]
    pattern: NotRequired[str]
    prefix: NotRequired[str]
    clusterId: NotRequired[str]
    patternType: NotRequired["GlobalNumber"]


class CCAProfiles(TypedDict, total=False):
    """AXL model — ``XCCAProfiles``.

     Used by ``AXLClient.add_ccaprofiles()``.
    """

    ccaId: NotRequired[str]
    primarySoftSwitchId: NotRequired[str]
    secondarySoftSwitchId: NotRequired[str]
    objectClass: NotRequired[str]
    subscriberType: NotRequired[str]
    sipAliasSuffix: NotRequired[str]
    sipUserNameSuffix: NotRequired[str]


class CallForwardAll(TypedDict, total=False):
    """AXL model — ``XCallForwardAll``.
    """

    forwardToVoiceMail: NotRequired[bool]
    callingSearchSpaceName: NotRequired[str]
    secondaryCallingSearchSpaceName: NotRequired[str]
    destination: NotRequired[str]


class CallForwardAlternateParty(TypedDict, total=False):
    """AXL model — ``XCallForwardAlternateParty``.
    """

    callingSearchSpaceName: NotRequired[str]
    destination: NotRequired[str]
    duration: NotRequired[Any]


class CallForwardBusy(TypedDict, total=False):
    """AXL model — ``XCallForwardBusy``.
    """

    forwardToVoiceMail: NotRequired[bool]
    callingSearchSpaceName: NotRequired[str]
    destination: NotRequired[str]


class CallForwardBusyInt(TypedDict, total=False):
    """AXL model — ``XCallForwardBusyInt``.
    """

    forwardToVoiceMail: NotRequired[bool]
    callingSearchSpaceName: NotRequired[str]
    destination: NotRequired[str]


class CallForwardNoAnswer(TypedDict, total=False):
    """AXL model — ``XCallForwardNoAnswer``.
    """

    forwardToVoiceMail: NotRequired[bool]
    callingSearchSpaceName: NotRequired[str]
    destination: NotRequired[str]
    duration: NotRequired[Any]


class CallForwardNoAnswerInt(TypedDict, total=False):
    """AXL model — ``XCallForwardNoAnswerInt``.
    """

    forwardToVoiceMail: NotRequired[bool]
    callingSearchSpaceName: NotRequired[str]
    destination: NotRequired[str]
    duration: NotRequired[Any]


class CallForwardNoCoverage(TypedDict, total=False):
    """AXL model — ``XCallForwardNoCoverage``.
    """

    forwardToVoiceMail: NotRequired[bool]
    callingSearchSpaceName: NotRequired[str]
    destination: NotRequired[str]


class CallForwardNoCoverageInt(TypedDict, total=False):
    """AXL model — ``XCallForwardNoCoverageInt``.
    """

    forwardToVoiceMail: NotRequired[bool]
    callingSearchSpaceName: NotRequired[str]
    destination: NotRequired[str]


class CallForwardNotRegistered(TypedDict, total=False):
    """AXL model — ``XCallForwardNotRegistered``.
    """

    forwardToVoiceMail: NotRequired[bool]
    callingSearchSpaceName: NotRequired[str]
    destination: NotRequired[str]


class CallForwardNotRegisteredInt(TypedDict, total=False):
    """AXL model — ``XCallForwardNotRegisteredInt``.
    """

    forwardToVoiceMail: NotRequired[bool]
    callingSearchSpaceName: NotRequired[str]
    destination: NotRequired[str]


class CallForwardOnFailure(TypedDict, total=False):
    """AXL model — ``XCallForwardOnFailure``.
    """

    forwardToVoiceMail: NotRequired[bool]
    callingSearchSpaceName: NotRequired[str]
    destination: NotRequired[str]


class CallManagerGroup(TypedDict, total=False):
    """AXL model — ``XCallManagerGroup``.

     Used by ``AXLClient.add_call_manager_group()``.
    """

    name: NotRequired[str]
    tftpDefault: NotRequired[bool]
    members: NotRequired[Any]


class CallPark(TypedDict, total=False):
    """AXL model — ``XCallPark``.

     Used by ``AXLClient.add_call_park()``.
    """

    pattern: NotRequired[str]
    description: NotRequired[str]
    routePartitionName: NotRequired[str]
    callManagerName: NotRequired[str]


class CallPickupGroup(TypedDict, total=False):
    """AXL model — ``XCallPickupGroup``.

     Used by ``AXLClient.add_call_pickup_group()``.
    """

    pattern: NotRequired[str]
    description: NotRequired[str]
    routePartitionName: NotRequired[str]
    members: NotRequired[Any]
    pickupNotification: NotRequired["PickupNotification"]
    pickupNotificationTimer: NotRequired[Any]
    callInfoForPickupNotification: NotRequired[Any]
    name: NotRequired[str]


class CalledPartyTracing(TypedDict, total=False):
    """AXL model — ``XCalledPartyTracing``.

     Used by ``AXLClient.add_called_party_tracing()``.
    """

    directorynumber: NotRequired[str]
    description: NotRequired[str]


class CalledPartyTransformationPattern(TypedDict, total=False):
    """AXL model — ``XCalledPartyTransformationPattern``.

     Used by ``AXLClient.add_called_party_transformation_pattern()``.
    """

    pattern: NotRequired[str]
    description: NotRequired[str]
    routePartitionName: NotRequired[str]
    calledPartyTransformationMask: NotRequired[str]
    dialPlanName: NotRequired[str]
    digitDiscardInstructionName: NotRequired[str]
    routeFilterName: NotRequired[str]
    calledPartyPrefixDigits: NotRequired[str]
    calledPartyNumberingPlan: NotRequired["NumberingPlan"]
    calledPartyNumberType: NotRequired["PriOfNumber"]
    mlppPreemptionDisabled: NotRequired[bool]


class CallerFilterList(TypedDict, total=False):
    """AXL model — ``XCallerFilterList``.

     Used by ``AXLClient.add_caller_filter_list()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    isAllowedType: NotRequired[bool]
    endUserIdName: NotRequired[str]
    members: NotRequired[Any]


class CallingPartyTransformationPattern(TypedDict, total=False):
    """AXL model — ``XCallingPartyTransformationPattern``.

     Used by ``AXLClient.add_calling_party_transformation_pattern()``.
    """

    pattern: NotRequired[str]
    description: NotRequired[str]
    routePartitionName: NotRequired[str]
    callingPartyTransformationMask: NotRequired[str]
    useCallingPartyPhoneMask: NotRequired["Status"]
    dialPlanName: NotRequired[str]
    digitDiscardInstructionName: NotRequired[str]
    callingPartyPrefixDigits: NotRequired[str]
    routeFilterName: NotRequired[str]
    callingLinePresentationBit: NotRequired["PresentationBit"]
    callingPartyNumberingPlan: NotRequired["NumberingPlan"]
    callingPartyNumberType: NotRequired["PriOfNumber"]
    mlppPreemptionDisabled: NotRequired[bool]


class CallsQueue(TypedDict, total=False):
    """AXL model — ``XCallsQueue``.
    """

    maxCallersInQueue: NotRequired[Any]
    queueFullDestination: NotRequired[str]
    callingSearchSpacePilotQueueFull: NotRequired[str]
    maxWaitTimeInQueue: NotRequired[Any]
    maxWaitTimeDestination: NotRequired[str]
    callingSearchSpaceMaxWaitTime: NotRequired[str]
    noAgentDestination: NotRequired[str]
    callingSearchSpaceNoAgent: NotRequired[str]
    networkHoldMohAudioSourceID: NotRequired[Any]


class CcdAdvertisingService(TypedDict, total=False):
    """AXL model — ``XCcdAdvertisingService``.

     Used by ``AXLClient.add_ccd_advertising_service()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    isActivated: NotRequired[bool]
    hostDnGroup: NotRequired[str]
    safSipTrunk: NotRequired[str]
    safH323Trunk: NotRequired[str]


class CcdHostedDN(TypedDict, total=False):
    """AXL model — ``XCcdHostedDN``.

     Used by ``AXLClient.add_ccd_hosted_dn()``.
    """

    hostedPattern: NotRequired[str]
    description: NotRequired[str]
    CcdHostedDnGroup: NotRequired[str]
    pstnFailoverStripDigits: NotRequired[Any]
    pstnFailoverPrependDigits: NotRequired[str]
    usePstnFailover: NotRequired[bool]


class CcdHostedDNGroup(TypedDict, total=False):
    """AXL model — ``XCcdHostedDNGroup``.

     Used by ``AXLClient.add_ccd_hosted_dngroup()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    pstnFailoverStripDigits: NotRequired[Any]
    pstnFailoverPrependDigits: NotRequired[str]
    usePstnFailover: NotRequired[bool]


class CcdRequestingService(TypedDict, total=False):
    """AXL model — ``XCcdRequestingService``.

     Used by ``AXLClient.add_ccd_requesting_service()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    isActivated: NotRequired[bool]
    routePartitionName: NotRequired[str]
    learnedPatternPrefix: NotRequired[str]
    pstnPrefix: NotRequired[str]
    associatedTrunks: NotRequired[Any]


CiscoCatalyst600024PortFXSGateway = TypedDict("CiscoCatalyst600024PortFXSGateway", {
    "name": NotRequired[str],
    "description": NotRequired[str],
    "product": NotRequired["Product"],
    "class": NotRequired["Class"],
    "protocol": NotRequired["DeviceProtocol"],
    "protocolSide": NotRequired["ProtocolSide"],
    "callingSearchSpaceName": NotRequired[str],
    "devicePoolName": NotRequired[str],
    "commonDeviceConfigName": NotRequired[str],
    "networkLocale": NotRequired["Country"],
    "locationName": NotRequired[str],
    "mediaResourceListName": NotRequired[str],
    "automatedAlternateRoutingCssName": NotRequired[str],
    "aarNeighborhoodName": NotRequired[str],
    "loadInformation": NotRequired["LoadInformation"],
    "vendorConfig": NotRequired["VendorConfig"],
    "traceFlag": NotRequired[bool],
    "mlppDomainId": NotRequired[str],
    "useTrustedRelayPoint": NotRequired["Status"],
    "cgpnTransformationCssName": NotRequired[str],
    "useDevicePoolCgpnTransformCss": NotRequired[bool],
    "geoLocationName": NotRequired[str],
    "ports": NotRequired[Any],
    "portSelectionOrder": NotRequired["TrunkSelectionOrder"],
    "transmitUtf8": NotRequired[bool],
    "geoLocationFilterName": NotRequired[str],
}, total=False)
CiscoCatalyst600024PortFXSGateway.__doc__ = '"""AXL model — ``XCiscoCatalyst600024PortFXSGateway``.\n\n     Used by ``AXLClient.add_cisco_catalyst600024port_fxsgateway()``."""'


CiscoCatalyst6000E1VoIPGateway = TypedDict("CiscoCatalyst6000E1VoIPGateway", {
    "name": NotRequired[str],
    "description": NotRequired[str],
    "product": NotRequired["Product"],
    "class": NotRequired["Class"],
    "protocol": NotRequired["DeviceProtocol"],
    "protocolSide": NotRequired["ProtocolSide"],
    "callingSearchSpaceName": NotRequired[str],
    "devicePoolName": NotRequired[str],
    "commonDeviceConfigName": NotRequired[str],
    "networkLocation": NotRequired["NetworkLocation"],
    "locationName": NotRequired[str],
    "networkLocale": NotRequired["Country"],
    "mediaResourceListName": NotRequired[str],
    "automatedAlternateRoutingCssName": NotRequired[str],
    "aarNeighborhoodName": NotRequired[str],
    "loadInformation": NotRequired["LoadInformation"],
    "vendorConfig": NotRequired["VendorConfig"],
    "mlppDomainId": NotRequired[str],
    "useTrustedRelayPoint": NotRequired["Status"],
    "cgpnTransformationCssName": NotRequired[str],
    "useDevicePoolCgpnTransformCss": NotRequired[bool],
    "geoLocationName": NotRequired[str],
    "redirectInboundNumberIe": NotRequired[bool],
    "calledPlan": NotRequired["NumberingPlan"],
    "calledPri": NotRequired["PriOfNumber"],
    "callerIdDn": NotRequired[str],
    "callingPartySelection": NotRequired["CallingPartySelection"],
    "callingPlan": NotRequired["NumberingPlan"],
    "callingPri": NotRequired["PriOfNumber"],
    "chanIe": NotRequired["PRIChanIE"],
    "clockReference": NotRequired["ClockReference"],
    "dChannelEnable": NotRequired[bool],
    "channelSelectionOrder": NotRequired["TrunkSelectionOrder"],
    "displayIE": NotRequired[bool],
    "pcmType": NotRequired["Encode"],
    "csuParam": NotRequired["CSUParam"],
    "firstDelay": NotRequired[Any],
    "interfaceIdPresent": NotRequired[bool],
    "interfaceId": NotRequired[Any],
    "intraDelay": NotRequired[Any],
    "mcdnEnable": NotRequired[bool],
    "redirectOutboundNumberIe": NotRequired[bool],
    "numDigitsToStrip": NotRequired[Any],
    "passingPrecedenceLevelThrough": NotRequired[bool],
    "prefix": NotRequired[str],
    "callingLinePresentationBit": NotRequired["PresentationBit"],
    "connectedLineIdPresentation": NotRequired["PresentationBit"],
    "priProtocol": NotRequired["PriProtocol"],
    "securityAccessLevel": NotRequired[Any],
    "sendCallingNameInFacilityIe": NotRequired[bool],
    "sendExLeadingCharInDispIe": NotRequired[bool],
    "sendRestart": NotRequired[bool],
    "setupNonIsdnPi": NotRequired[bool],
    "sigDigits": NotRequired[Any],
    "span": NotRequired[Any],
    "statusPoll": NotRequired[bool],
    "smdiBasePort": NotRequired[Any],
    "packetCaptureMode": NotRequired["PacketCaptureMode"],
    "packetCaptureDuration": NotRequired[Any],
    "transmitUtf8": NotRequired[bool],
    "v150": NotRequired[bool],
    "asn1RoseOidEncoding": NotRequired["ASN1RoseOidEncoding"],
    "QSIGVariant": NotRequired["QSIGVariant"],
    "unattendedPort": NotRequired[bool],
    "cdpnTransformationCssName": NotRequired[str],
    "useDevicePoolCdpnTransformCss": NotRequired[bool],
    "nationalPrefix": NotRequired[str],
    "internationalPrefix": NotRequired[str],
    "unknownPrefix": NotRequired[str],
    "subscriberPrefix": NotRequired[str],
    "geoLocationFilterName": NotRequired[str],
    "nationalStripDigits": NotRequired[Any],
    "internationalStripDigits": NotRequired[Any],
    "unknownStripDigits": NotRequired[Any],
    "subscriberStripDigits": NotRequired[Any],
    "nationalTransformationCssName": NotRequired[str],
    "internationalTransformationCssName": NotRequired[str],
    "unknownTransformationCssName": NotRequired[str],
    "subscriberTransformationCssName": NotRequired[str],
    "useDevicePoolCgpnTransformCssNatl": NotRequired[bool],
    "useDevicePoolCgpnTransformCssIntl": NotRequired[bool],
    "useDevicePoolCgpnTransformCssUnkn": NotRequired[bool],
    "useDevicePoolCgpnTransformCssSubs": NotRequired[bool],
    "pstnAccess": NotRequired[bool],
    "imeE164TransformationName": NotRequired[str],
}, total=False)
CiscoCatalyst6000E1VoIPGateway.__doc__ = '"""AXL model — ``XCiscoCatalyst6000E1VoIPGateway``.\n\n     Used by ``AXLClient.add_cisco_catalyst6000e1vo_ipgateway()``."""'


CiscoCatalyst6000T1VoIPGatewayPri = TypedDict("CiscoCatalyst6000T1VoIPGatewayPri", {
    "name": NotRequired[str],
    "description": NotRequired[str],
    "product": NotRequired["Product"],
    "class": NotRequired["Class"],
    "protocol": NotRequired["DeviceProtocol"],
    "protocolSide": NotRequired["ProtocolSide"],
    "callingSearchSpaceName": NotRequired[str],
    "devicePoolName": NotRequired[str],
    "commonDeviceConfigName": NotRequired[str],
    "networkLocation": NotRequired["NetworkLocation"],
    "locationName": NotRequired[str],
    "networkLocale": NotRequired["Country"],
    "mediaResourceListName": NotRequired[str],
    "automatedAlternateRoutingCssName": NotRequired[str],
    "aarNeighborhoodName": NotRequired[str],
    "loadInformation": NotRequired["LoadInformation"],
    "vendorConfig": NotRequired["VendorConfig"],
    "mlppDomainId": NotRequired[str],
    "mlppIndicationStatus": NotRequired["Status"],
    "mlppPreemption": NotRequired["Preemption"],
    "useTrustedRelayPoint": NotRequired["Status"],
    "cgpnTransformationCssName": NotRequired[str],
    "useDevicePoolCgpnTransformCss": NotRequired[bool],
    "geoLocationName": NotRequired[str],
    "redirectInboundNumberIe": NotRequired[bool],
    "calledPlan": NotRequired["NumberingPlan"],
    "calledPri": NotRequired["PriOfNumber"],
    "callerIdDn": NotRequired[str],
    "callingPartySelection": NotRequired["CallingPartySelection"],
    "callingPlan": NotRequired["NumberingPlan"],
    "callingPri": NotRequired["PriOfNumber"],
    "chanIe": NotRequired["PRIChanIE"],
    "clockReference": NotRequired["ClockReference"],
    "dChannelEnable": NotRequired[bool],
    "channelSelectionOrder": NotRequired["TrunkSelectionOrder"],
    "displayIE": NotRequired[bool],
    "pcmType": NotRequired["Encode"],
    "csuParam": NotRequired["CSUParam"],
    "firstDelay": NotRequired[Any],
    "interfaceIdPresent": NotRequired[bool],
    "interfaceId": NotRequired[Any],
    "intraDelay": NotRequired[Any],
    "mcdnEnable": NotRequired[bool],
    "redirectOutboundNumberIe": NotRequired[bool],
    "numDigitsToStrip": NotRequired[Any],
    "passingPrecedenceLevelThrough": NotRequired[bool],
    "prefix": NotRequired[str],
    "callingLinePresentationBit": NotRequired["PresentationBit"],
    "connectedLineIdPresentation": NotRequired["PresentationBit"],
    "priProtocol": NotRequired["PriProtocol"],
    "securityAccessLevel": NotRequired[Any],
    "sendCallingNameInFacilityIe": NotRequired[bool],
    "sendExLeadingCharInDispIe": NotRequired[bool],
    "sendRestart": NotRequired[bool],
    "setupNonIsdnPi": NotRequired[bool],
    "sigDigits": NotRequired[Any],
    "span": NotRequired[Any],
    "statusPoll": NotRequired[bool],
    "smdiBasePort": NotRequired[Any],
    "packetCaptureMode": NotRequired["PacketCaptureMode"],
    "packetCaptureDuration": NotRequired[Any],
    "transmitUtf8": NotRequired[bool],
    "v150": NotRequired[bool],
    "asn1RoseOidEncoding": NotRequired["ASN1RoseOidEncoding"],
    "QSIGVariant": NotRequired["QSIGVariant"],
    "unattendedPort": NotRequired[bool],
    "cdpnTransformationCssName": NotRequired[str],
    "useDevicePoolCdpnTransformCss": NotRequired[bool],
    "nationalPrefix": NotRequired[str],
    "internationalPrefix": NotRequired[str],
    "unknownPrefix": NotRequired[str],
    "subscriberPrefix": NotRequired[str],
    "geoLocationFilterName": NotRequired[str],
    "nationalStripDigits": NotRequired[Any],
    "internationalStripDigits": NotRequired[Any],
    "unknownStripDigits": NotRequired[Any],
    "subscriberStripDigits": NotRequired[Any],
    "nationalTransformationCssName": NotRequired[str],
    "internationalTransformationCssName": NotRequired[str],
    "unknownTransformationCssName": NotRequired[str],
    "subscriberTransformationCssName": NotRequired[str],
    "useDevicePoolCgpnTransformCssNatl": NotRequired[bool],
    "useDevicePoolCgpnTransformCssIntl": NotRequired[bool],
    "useDevicePoolCgpnTransformCssUnkn": NotRequired[bool],
    "useDevicePoolCgpnTransformCssSubs": NotRequired[bool],
    "pstnAccess": NotRequired[bool],
    "imeE164TransformationName": NotRequired[str],
}, total=False)
CiscoCatalyst6000T1VoIPGatewayPri.__doc__ = '"""AXL model — ``XCiscoCatalyst6000T1VoIPGatewayPri``.\n\n     Used by ``AXLClient.add_cisco_catalyst6000t1vo_ipgateway_pri()``."""'


CiscoCatalyst6000T1VoIPGatewayT1 = TypedDict("CiscoCatalyst6000T1VoIPGatewayT1", {
    "name": NotRequired[str],
    "description": NotRequired[str],
    "product": NotRequired["Product"],
    "class": NotRequired["Class"],
    "protocol": NotRequired["DeviceProtocol"],
    "protocolSide": NotRequired["ProtocolSide"],
    "callingSearchSpaceName": NotRequired[str],
    "devicePoolName": NotRequired[str],
    "commonDeviceConfigName": NotRequired[str],
    "networkLocation": NotRequired["NetworkLocation"],
    "locationName": NotRequired[str],
    "mediaResourceListName": NotRequired[str],
    "automatedAlternateRoutingCssName": NotRequired[str],
    "aarNeighborhoodName": NotRequired[str],
    "loadInformation": NotRequired["LoadInformation"],
    "vendorConfig": NotRequired["VendorConfig"],
    "traceFlag": NotRequired[bool],
    "mlppDomainId": NotRequired[str],
    "mlppIndicationStatus": NotRequired["Status"],
    "preemption": NotRequired["Preemption"],
    "useTrustedRelayPoint": NotRequired["Status"],
    "retryVideoCallAsAudio": NotRequired[bool],
    "cgpnTransformationCssName": NotRequired[str],
    "useDevicePoolCgpnTransformCss": NotRequired[bool],
    "geoLocationName": NotRequired[str],
    "sendGeoLocation": NotRequired[bool],
    "ports": NotRequired[Any],
    "trunkSelectionOrder": NotRequired["TrunkSelectionOrder"],
    "clockReference": NotRequired["ClockReference"],
    "csuParam": NotRequired["CSUParam"],
    "digitSending": NotRequired["DigitSending"],
    "pcmType": NotRequired["Encode"],
    "fdlChannel": NotRequired["FDLChannel"],
    "yellowAlarm": NotRequired["YellowAlarm"],
    "zeroSupression": NotRequired["ZeroSuppression"],
    "smdiBasePort": NotRequired[Any],
    "handleDtmfPrecedenceSignals": NotRequired[bool],
    "cdpnTransformationCssName": NotRequired[str],
    "useDevicePoolCdpnTransformCss": NotRequired[bool],
    "geoLocationFilterName": NotRequired[str],
    "pstnAccess": NotRequired[bool],
    "imeE164TransformationName": NotRequired[str],
}, total=False)
CiscoCatalyst6000T1VoIPGatewayT1.__doc__ = '"""AXL model — ``XCiscoCatalyst6000T1VoIPGatewayT1``.\n\n     Used by ``AXLClient.add_cisco_catalyst6000t1vo_ipgateway_t1()``."""'


class CmcInfo(TypedDict, total=False):
    """AXL model — ``XCmcInfo``.

     Used by ``AXLClient.add_cmc_info()``.
    """

    code: NotRequired[str]
    description: NotRequired[str]


class CommonDeviceConfig(TypedDict, total=False):
    """AXL model — ``XCommonDeviceConfig``.

     Used by ``AXLClient.add_common_device_config()``.
    """

    name: NotRequired[str]
    softkeyTemplateName: NotRequired[str]
    userLocale: NotRequired["UserLocale"]
    networkHoldMohAudioSourceId: NotRequired[Any]
    userHoldMohAudioSourceId: NotRequired[Any]
    mlppDomainId: NotRequired[str]
    mlppIndicationStatus: NotRequired["Status"]
    useTrustedRelayPoint: NotRequired[bool]
    preemption: NotRequired["Preemption"]
    ipAddressingMode: NotRequired["IPAddressingMode"]
    ipAddressingModePreferenceControl: NotRequired["IPAddressingModePrefControl"]
    allowAutoConfigurationForPhones: NotRequired["Status"]
    useImeForOutboundCalls: NotRequired["Status"]
    confidentialAccess: NotRequired[Any]
    allowDuplicateAddressDetection: NotRequired["Status"]
    acceptRedirectMessages: NotRequired["Status"]
    replyMulticastEchoRequest: NotRequired["Status"]


class CommonPhoneConfig(TypedDict, total=False):
    """AXL model — ``XCommonPhoneConfig``.

     Used by ``AXLClient.add_common_phone_config()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    unlockPwd: NotRequired[str]
    dndOption: NotRequired["DNDOption"]
    dndAlertingType: NotRequired["RingSetting"]
    backgroundImage: NotRequired[bool]
    phonePersonalization: NotRequired["PhonePersonalization"]
    phoneServiceDisplay: NotRequired["PhoneServiceDisplay"]
    sshUserId: NotRequired[str]
    sshPwd: NotRequired[str]
    vendorConfig: NotRequired["VendorConfig"]
    alwaysUsePrimeLine: NotRequired["Status"]
    alwaysUsePrimeLineForVoiceMessage: NotRequired["Status"]
    vpnGroupName: NotRequired[str]
    vpnProfileName: NotRequired[str]
    featureControlPolicy: NotRequired[str]
    wifiHotspotProfile: NotRequired[str]


class ConferenceBridge(TypedDict, total=False):
    """AXL model — ``XConferenceBridge``.

     Used by ``AXLClient.add_conference_bridge()``.
    """

    name: NotRequired[Any]
    description: NotRequired[str]
    product: NotRequired["Product"]
    devicePoolName: NotRequired[str]
    commonDeviceConfigName: NotRequired[str]
    locationName: NotRequired[str]
    subUnit: NotRequired[Any]
    loadInformation: NotRequired["LoadInformation"]
    vendorConfig: NotRequired["VendorConfig"]
    maximumCapacity: NotRequired[Any]
    useTrustedRelayPoint: NotRequired["Status"]
    securityProfileName: NotRequired[str]
    destinationAddress: NotRequired[str]
    mcuConferenceBridgeSipPort: NotRequired[Any]
    sipProfile: NotRequired[str]
    srtpAllowed: NotRequired[bool]
    normalizationScript: NotRequired[str]
    enableTrace: NotRequired[bool]
    normalizationScriptInfos: NotRequired[Any]
    userName: NotRequired[str]
    password: NotRequired[str]
    httpPort: NotRequired[Any]
    useHttps: NotRequired[bool]
    addresses: NotRequired[Any]
    conferenceBridgePrefix: NotRequired[str]
    allowCFBControlOfCallSecurityIcon: NotRequired[bool]
    overrideSIPTrunkAddress: NotRequired[bool]
    sipTrunkName: NotRequired[str]


class ConferenceNow(TypedDict, total=False):
    """AXL model — ``XConferenceNow``.

     Used by ``AXLClient.add_conference_now()``.
    """

    conferenceNowNumber: NotRequired[str]
    routePartitionName: NotRequired[str]
    description: NotRequired[str]
    maxWaitTimeForHost: NotRequired[Any]
    MohAudioSourceId: NotRequired[Any]


class CredentialPolicy(TypedDict, total=False):
    """AXL model — ``XCredentialPolicy``.

     Used by ``AXLClient.add_credential_policy()``.
    """

    name: NotRequired[str]
    failedLogon: NotRequired[Any]
    resetFailedLogonAttempts: NotRequired[Any]
    lockoutDuration: NotRequired[Any]
    credChangeDuration: NotRequired[Any]
    credExpiresAfter: NotRequired[Any]
    minCredLength: NotRequired[Any]
    prevCredStoredNum: NotRequired[Any]
    inactiveDaysAllowed: NotRequired[Any]
    expiryWarningDays: NotRequired[Any]
    trivialCredCheck: NotRequired[bool]
    minCharsToChange: NotRequired[Any]


class Css(TypedDict, total=False):
    """AXL model — ``XCss``.

     Used by ``AXLClient.add_css()``.
    """

    description: NotRequired[str]
    members: NotRequired[Any]
    partitionUsage: NotRequired["PartitionUsage"]
    name: NotRequired[str]


CtiRoutePoint = TypedDict("CtiRoutePoint", {
    "name": NotRequired[str],
    "description": NotRequired[str],
    "product": NotRequired["Product"],
    "class": NotRequired["Class"],
    "protocol": NotRequired["DeviceProtocol"],
    "protocolSide": NotRequired["ProtocolSide"],
    "callingSearchSpaceName": NotRequired[str],
    "devicePoolName": NotRequired[str],
    "commonDeviceConfigName": NotRequired[str],
    "locationName": NotRequired[str],
    "mediaResourceListName": NotRequired[str],
    "networkHoldMohAudioSourceId": NotRequired[Any],
    "userHoldMohAudioSourceId": NotRequired[Any],
    "useTrustedRelayPoint": NotRequired["Status"],
    "cgpnTransformationCssName": NotRequired[str],
    "useDevicePoolCgpnTransformCss": NotRequired[bool],
    "geoLocationName": NotRequired[str],
    "userLocale": NotRequired["UserLocale"],
    "lines": NotRequired[Any],
}, total=False)
CtiRoutePoint.__doc__ = '"""AXL model — ``XCtiRoutePoint``.\n\n     Used by ``AXLClient.add_cti_route_point()``."""'


class CumaServerSecurityProfile(TypedDict, total=False):
    """AXL model — ``XCumaServerSecurityProfile``.

     Used by ``AXLClient.add_cuma_server_security_profile()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    securityMode: NotRequired["DeviceSecurityMode"]
    transportType: NotRequired["Transport"]
    x509SubjectName: NotRequired[str]
    serverIpHostName: NotRequired[str]


class CustomUserField(TypedDict, total=False):
    """AXL model — ``XCustomUserField``.

     Used by ``AXLClient.add_custom_user_field()``.
    """

    field: NotRequired[str]


class Customer(TypedDict, total=False):
    """AXL model — ``XCustomer``.

     Used by ``AXLClient.add_customer()``.
    """

    name: NotRequired[str]


class DateTimeGroup(TypedDict, total=False):
    """AXL model — ``XDateTimeGroup``.

     Used by ``AXLClient.add_date_time_group()``.
    """

    name: NotRequired[str]
    timeZone: NotRequired["TimeZone"]
    separator: NotRequired[str]
    dateformat: NotRequired[str]
    timeFormat: NotRequired[str]
    phoneNtpReferences: NotRequired[Any]


DefaultDeviceProfile = TypedDict("DefaultDeviceProfile", {
    "name": NotRequired[str],
    "description": NotRequired[str],
    "product": NotRequired["Product"],
    "class": NotRequired["Class"],
    "protocol": NotRequired["DeviceProtocol"],
    "protocolSide": NotRequired["ProtocolSide"],
    "userHoldMohAudioSourceId": NotRequired[Any],
    "userLocale": NotRequired["UserLocale"],
    "phoneButtonTemplate": NotRequired[str],
    "softkeyTemplate": NotRequired[str],
    "privacy": NotRequired["Status"],
    "singleButtonBarge": NotRequired["Barge"],
    "joinAcrossLines": NotRequired["Status"],
    "ignorePi": NotRequired[bool],
    "dndStatus": NotRequired[bool],
    "dndRingSetting": NotRequired["RingSetting"],
    "dndOption": NotRequired["DNDOption"],
    "mlppDomainId": NotRequired[str],
    "mlppIndication": NotRequired["Status"],
    "preemption": NotRequired["Preemption"],
    "alwaysUsePrimeLine": NotRequired["Status"],
    "alwaysUsePrimeLineForVoiceMessage": NotRequired["Status"],
    "emccCallingSearchSpace": NotRequired[str],
}, total=False)
DefaultDeviceProfile.__doc__ = '"""AXL model — ``XDefaultDeviceProfile``.\n\n     Used by ``AXLClient.add_default_device_profile()``."""'


class DeviceMobility(TypedDict, total=False):
    """AXL model — ``XDeviceMobility``.

     Used by ``AXLClient.add_device_mobility()``.
    """

    name: NotRequired[str]
    subNetDetails: NotRequired[Any]
    members: NotRequired[Any]


class DeviceMobilityGroup(TypedDict, total=False):
    """AXL model — ``XDeviceMobilityGroup``.

     Used by ``AXLClient.add_device_mobility_group()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]


class DevicePool(TypedDict, total=False):
    """AXL model — ``XDevicePool``.

     Used by ``AXLClient.add_device_pool()``.
    """

    name: NotRequired[str]
    autoSearchSpaceName: NotRequired[str]
    dateTimeSettingName: NotRequired[str]
    callManagerGroupName: NotRequired[str]
    mediaResourceListName: NotRequired[str]
    regionName: NotRequired[str]
    networkLocale: NotRequired["Country"]
    srstName: NotRequired[str]
    connectionMonitorDuration: NotRequired[Any]
    automatedAlternateRoutingCssName: NotRequired[str]
    aarNeighborhoodName: NotRequired[str]
    locationName: NotRequired[str]
    mobilityCssName: NotRequired[str]
    physicalLocationName: NotRequired[str]
    deviceMobilityGroupName: NotRequired[str]
    revertPriority: NotRequired["RevertPriority"]
    singleButtonBarge: NotRequired["Barge"]
    joinAcrossLines: NotRequired["Status"]
    cgpnTransformationCssName: NotRequired[str]
    cdpnTransformationCssName: NotRequired[str]
    localRouteGroupName: NotRequired[str]
    geoLocationName: NotRequired[str]
    geoLocationFilterName: NotRequired[str]
    callingPartyNationalPrefix: NotRequired[str]
    callingPartyInternationalPrefix: NotRequired[str]
    callingPartyUnknownPrefix: NotRequired[str]
    callingPartySubscriberPrefix: NotRequired[str]
    adjunctCallingSearchSpace: NotRequired[str]
    callingPartyNationalStripDigits: NotRequired[Any]
    callingPartyInternationalStripDigits: NotRequired[Any]
    callingPartyUnknownStripDigits: NotRequired[Any]
    callingPartySubscriberStripDigits: NotRequired[Any]
    callingPartyNationalTransformationCssName: NotRequired[str]
    callingPartyInternationalTransformationCssName: NotRequired[str]
    callingPartyUnknownTransformationCssName: NotRequired[str]
    callingPartySubscriberTransformationCssName: NotRequired[str]
    calledPartyNationalPrefix: NotRequired[str]
    calledPartyInternationalPrefix: NotRequired[str]
    calledPartyUnknownPrefix: NotRequired[str]
    calledPartySubscriberPrefix: NotRequired[str]
    calledPartyNationalStripDigits: NotRequired[Any]
    calledPartyInternationalStripDigits: NotRequired[Any]
    calledPartyUnknownStripDigits: NotRequired[Any]
    calledPartySubscriberStripDigits: NotRequired[Any]
    calledPartyNationalTransformationCssName: NotRequired[str]
    calledPartyInternationalTransformationCssName: NotRequired[str]
    calledPartyUnknownTransformationCssName: NotRequired[str]
    calledPartySubscriberTransformationCssName: NotRequired[str]
    imeEnrolledPatternGroupName: NotRequired[str]
    cntdPnTransformationCssName: NotRequired[str]
    localRouteGroup: NotRequired[List[Any]]
    redirectingPartyTransformationCSS: NotRequired[str]
    callingPartyTransformationCSS: NotRequired[str]
    wirelessLanProfileGroup: NotRequired[str]
    elinGroup: NotRequired[str]
    mraServiceDomain: NotRequired[str]


DeviceProfile = TypedDict("DeviceProfile", {
    "name": NotRequired[str],
    "description": NotRequired[str],
    "product": NotRequired["Product"],
    "class": NotRequired["Class"],
    "protocol": NotRequired["DeviceProtocol"],
    "protocolSide": NotRequired["ProtocolSide"],
    "userHoldMohAudioSourceId": NotRequired[Any],
    "vendorConfig": NotRequired["VendorConfig"],
    "traceFlag": NotRequired[bool],
    "mlppDomainId": NotRequired[str],
    "mlppIndicationStatus": NotRequired["Status"],
    "preemption": NotRequired["Preemption"],
    "lines": NotRequired[Any],
    "phoneTemplateName": NotRequired[str],
    "speeddials": NotRequired[Any],
    "busyLampFields": NotRequired[Any],
    "blfDirectedCallParks": NotRequired[Any],
    "addOnModules": NotRequired[Any],
    "userLocale": NotRequired["UserLocale"],
    "singleButtonBarge": NotRequired["Barge"],
    "joinAcrossLines": NotRequired["Status"],
    "loginUserId": NotRequired[str],
    "ignorePresentationIndicators": NotRequired[bool],
    "dndOption": NotRequired["DNDOption"],
    "dndRingSetting": NotRequired["RingSetting"],
    "dndStatus": NotRequired[bool],
    "emccCallingSearchSpace": NotRequired[str],
    "alwaysUsePrimeLine": NotRequired["Status"],
    "alwaysUsePrimeLineForVoiceMessage": NotRequired["Status"],
    "softkeyTemplateName": NotRequired[str],
    "callInfoPrivacyStatus": NotRequired["Status"],
    "services": NotRequired[Any],
    "featureControlPolicy": NotRequired[str],
}, total=False)
DeviceProfile.__doc__ = '"""AXL model — ``XDeviceProfile``.\n\n     Used by ``AXLClient.add_device_profile()``."""'


class DhcpServer(TypedDict, total=False):
    """AXL model — ``XDhcpServer``.

     Used by ``AXLClient.add_dhcp_server()``.
    """

    processNodeName: NotRequired[str]
    primaryDnsIpAddress: NotRequired[str]
    secondaryDnsIpAddress: NotRequired[str]
    primaryTftpServerIpAddress: NotRequired[str]
    secondaryTftpServerIpAddress: NotRequired[str]
    bootstrapServerIpAddress: NotRequired[str]
    domainName: NotRequired[str]
    tftpServerName: NotRequired[str]
    arpCacheTimeout: NotRequired[Any]
    ipAddressLeaseTime: NotRequired[Any]
    renewalTime: NotRequired[Any]
    rebindingTime: NotRequired[Any]


class DhcpSubnet(TypedDict, total=False):
    """AXL model — ``XDhcpSubnet``.

     Used by ``AXLClient.add_dhcp_subnet()``.
    """

    dhcpServerName: NotRequired[str]
    subnetIpAddress: NotRequired[str]
    primaryStartIpAddress: NotRequired[str]
    primaryEndIpAddress: NotRequired[str]
    secondaryStartIpAddress: NotRequired[str]
    secondaryEndIpAddress: NotRequired[str]
    primaryRouterIpAddress: NotRequired[str]
    secondaryRouterIpAddress: NotRequired[str]
    subnetMask: NotRequired[str]
    domainName: NotRequired[str]
    primaryDnsIpAddress: NotRequired[str]
    secondaryDnsIpAddress: NotRequired[str]
    tftpServerName: NotRequired[str]
    primaryTftpServerIpAddress: NotRequired[str]
    secondaryTftpServerIpAddress: NotRequired[str]
    bootstrapServerIpAddress: NotRequired[str]
    arpCacheTimeout: NotRequired[Any]
    ipAddressLeaseTime: NotRequired[Any]
    renewalTime: NotRequired[Any]
    rebindingTime: NotRequired[Any]


class DirNumberAliasLookupandSync(TypedDict, total=False):
    """AXL model — ``XDirNumberAliasLookupandSync``.

     Used by ``AXLClient.add_dir_number_alias_lookupand_sync()``.
    """

    ldapConfigName: NotRequired[str]
    ldapManagerDisgName: NotRequired[str]
    ldapPassword: NotRequired[str]
    ldapUserSearch: NotRequired[str]
    ldapDirectoryServerUsage: NotRequired["LDAPDirectoryFunction"]
    keepAliveSearch: NotRequired[str]
    keepAliveTime: NotRequired["KeepAliveTimeInterval"]
    sipAliasSuffix: NotRequired[str]
    enableCachingofRecords: NotRequired[bool]
    servers: NotRequired[Any]
    cacheSizeforAliasLookup: NotRequired[Any]
    cacheAgeforAliasLookup: NotRequired[Any]


class DirectedCallPark(TypedDict, total=False):
    """AXL model — ``XDirectedCallPark``.

     Used by ``AXLClient.add_directed_call_park()``.
    """

    pattern: NotRequired[str]
    description: NotRequired[str]
    routePartitionName: NotRequired[str]
    retrievalPrefix: NotRequired[str]
    reversionPattern: NotRequired[str]
    revertCssName: NotRequired[str]


class DirectoryLookupDialRules(TypedDict, total=False):
    """AXL model — ``XDirectoryLookupDialRules``.

     Used by ``AXLClient.add_directory_lookup_dial_rules()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    numberBeginWith: NotRequired[str]
    numberOfDigits: NotRequired[Any]
    digitsToBeRemoved: NotRequired[Any]
    prefixPattern: NotRequired[str]
    priority: NotRequired[Any]


class Dirn(TypedDict, total=False):
    """AXL model — ``XDirn``.
    """

    pattern: NotRequired[str]
    routePartitionName: NotRequired[str]


class ElinGroup(TypedDict, total=False):
    """AXL model — ``XElinGroup``.

     Used by ``AXLClient.add_elin_group()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    elinNumbers: NotRequired[Any]


class EndUserCapfProfile(TypedDict, total=False):
    """AXL model — ``XEndUserCapfProfile``.

     Used by ``AXLClient.add_end_user_capf_profile()``.
    """

    endUserId: NotRequired[str]
    instanceId: NotRequired[str]
    certificationOperation: NotRequired["CertificateOperation"]
    authenticationMode: NotRequired["AuthenticationMode"]
    authenticationString: NotRequired[str]
    keySize: NotRequired["KeySize"]
    keyOrder: NotRequired["KeyOrder"]
    ecKeySize: NotRequired["ECKeySize"]
    operationCompletion: NotRequired[str]


class EnterpriseFeatureAccessConfiguration(TypedDict, total=False):
    """AXL model — ``XEnterpriseFeatureAccessConfiguration``.

     Used by ``AXLClient.add_enterprise_feature_access_configuration()``.
    """

    pattern: NotRequired[str]
    routePartitionName: NotRequired[str]
    description: NotRequired[str]
    isDefaultEafNumber: NotRequired[bool]


class ExpresswayCConfiguration(TypedDict, total=False):
    """AXL model — ``XExpresswayCConfiguration``.

     Used by ``AXLClient.add_expressway_cconfiguration()``.
    """

    HostNameOrIP: NotRequired[str]
    description: NotRequired[str]
    X509SubjectNameorSubjectAlternateName: NotRequired[str]


class ExternalCallControlProfile(TypedDict, total=False):
    """AXL model — ``XExternalCallControlProfile``.

     Used by ``AXLClient.add_external_call_control_profile()``.
    """

    name: NotRequired[str]
    primaryUri: NotRequired[str]
    secondaryUri: NotRequired[str]
    enableLoadBalancing: NotRequired[bool]
    routingRequestTimer: NotRequired[Any]
    diversionReroutingCssName: NotRequired[str]
    callTreatmentOnFailure: NotRequired["CallTreatmentOnFailure"]


class FacInfo(TypedDict, total=False):
    """AXL model — ``XFacInfo``.

     Used by ``AXLClient.add_fac_info()``.
    """

    name: NotRequired[str]
    code: NotRequired[str]
    authorizationLevel: NotRequired[Any]


class FallbackProfile(TypedDict, total=False):
    """AXL model — ``XFallbackProfile``.

     Used by ``AXLClient.add_fallback_profile()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    advertisedFallbackDirectoryE164Number: NotRequired[str]
    qosSensistivityLevel: NotRequired[Any]
    callCss: NotRequired["FallBackCSSSelection"]
    callAnswerTimer: NotRequired[Any]
    directoryNumberPartition: NotRequired[str]
    directoryNumber: NotRequired[str]
    numberOfDigitsForCallerIDPartialMatch: NotRequired[Any]


class FeatureControlPolicy(TypedDict, total=False):
    """AXL model — ``XFeatureControlPolicy``.

     Used by ``AXLClient.add_feature_control_policy()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    features: NotRequired[Any]


class FeatureGroupTemplate(TypedDict, total=False):
    """AXL model — ``XFeatureGroupTemplate``.

     Used by ``AXLClient.add_feature_group_template()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    homeCluster: NotRequired[bool]
    imAndUcPresenceEnable: NotRequired[bool]
    serviceProfile: NotRequired[str]
    enableUserToHostConferenceNow: NotRequired[bool]
    allowCTIControl: NotRequired[bool]
    enableEMCC: NotRequired[bool]
    enableMobility: NotRequired[bool]
    enableMobileVoiceAccess: NotRequired[bool]
    maxDeskPickupWait: NotRequired[Any]
    remoteDestinationLimit: NotRequired[Any]
    BLFPresenceGp: NotRequired[str]
    subscribeCallingSearch: NotRequired[str]
    userLocale: NotRequired["UserLocale"]
    userProfile: NotRequired[str]
    meetingInformation: NotRequired[bool]


class Gatekeeper(TypedDict, total=False):
    """AXL model — ``XGatekeeper``.

     Used by ``AXLClient.add_gatekeeper()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    rrqTimeToLive: NotRequired[Any]
    retryTimeout: NotRequired[Any]
    enableDevice: NotRequired[bool]


class Gateway(TypedDict, total=False):
    """AXL model — ``XGateway``.

     Used by ``AXLClient.add_gateway()``.
    """

    domainName: NotRequired[str]
    description: NotRequired[str]
    product: NotRequired["Product"]
    protocol: NotRequired["DeviceProtocol"]
    callManagerGroupName: NotRequired[str]
    units: NotRequired[Any]
    vendorConfig: NotRequired["VendorConfig"]


GatewayEndpointAnalog = TypedDict("GatewayEndpointAnalog", {
    "index": NotRequired[Any],
    "name": NotRequired[str],
    "description": NotRequired[str],
    "product": NotRequired["Product"],
    "model": NotRequired["Model"],
    "class": NotRequired["Class"],
    "protocol": NotRequired["DeviceProtocol"],
    "protocolSide": NotRequired["ProtocolSide"],
    "callingSearchSpaceName": NotRequired[str],
    "devicePoolName": NotRequired[str],
    "commonDeviceConfigName": NotRequired[str],
    "networkLocale": NotRequired["Country"],
    "locationName": NotRequired[str],
    "mediaResourceListName": NotRequired[str],
    "automatedAlternateRoutingCssName": NotRequired[str],
    "aarNeighborhoodName": NotRequired[str],
    "vendorConfig": NotRequired["VendorConfig"],
    "mlppDomainId": NotRequired[str],
    "useTrustedRelayPoint": NotRequired["Status"],
    "retryVideoCallAsAudio": NotRequired[bool],
    "cgpnTransformationCssName": NotRequired[str],
    "useDevicePoolCgpnTransformCss": NotRequired[bool],
    "geoLocationName": NotRequired[str],
    "geoLocationFilterName": NotRequired[str],
    "port": NotRequired["AnalogPort"],
    "trunkSelectionOrder": NotRequired["TrunkSelectionOrder"],
    "transmitUtf8": NotRequired[bool],
    "cdpnTransformationCssName": NotRequired[str],
    "useDevicePoolCdpnTransformCss": NotRequired[bool],
    "callingPartyNumberPrefix": NotRequired[str],
    "callingPartyStripDigits": NotRequired[Any],
    "callingPartyUnknownTransformationCssName": NotRequired[str],
    "useDevicePoolCgpnTransformCssUnknown": NotRequired[bool],
    "hotlineDevice": NotRequired[bool],
    "packetCaptureMode": NotRequired["PacketCaptureMode"],
    "packetCaptureDuration": NotRequired[Any],
    "pstnAccess": NotRequired[bool],
    "imeE164TransformationName": NotRequired[str],
    "imeE164DirectoryNumber": NotRequired[str],
    "confidentialAccess": NotRequired[Any],
    "elinGroup": NotRequired[str],
}, total=False)
GatewayEndpointAnalog.__doc__ = '"""AXL model — ``XGatewayEndpointAnalog``."""'


class GatewayEndpointAnalogAccess(TypedDict, total=False):
    """AXL model — ``XGatewayEndpointAnalogAccess``.

     Used by ``AXLClient.add_gateway_endpoint_analog_access()``.
    """

    domainName: NotRequired[str]
    gatewayUuid: NotRequired[str]
    unit: NotRequired[Any]
    subunit: NotRequired[Any]
    endpoint: NotRequired["GatewayEndpointAnalog"]


GatewayEndpointDigitalBri = TypedDict("GatewayEndpointDigitalBri", {
    "index": NotRequired[Any],
    "name": NotRequired[str],
    "description": NotRequired[str],
    "product": NotRequired["Product"],
    "class": NotRequired["Class"],
    "protocol": NotRequired["DeviceProtocol"],
    "protocolSide": NotRequired["ProtocolSide"],
    "callingSearchSpaceName": NotRequired[str],
    "devicePoolName": NotRequired[str],
    "commonDeviceConfigName": NotRequired[str],
    "networkLocation": NotRequired["NetworkLocation"],
    "locationName": NotRequired[str],
    "mediaResourceListName": NotRequired[str],
    "networkLocale": NotRequired["Country"],
    "automatedAlternateRoutingCssName": NotRequired[str],
    "aarNeighborhoodName": NotRequired[str],
    "vendorConfig": NotRequired["VendorConfig"],
    "cgpnTransformationCssName": NotRequired[str],
    "useDevicePoolCgpnTransformCss": NotRequired[bool],
    "geoLocationName": NotRequired[str],
    "redirectInboundNumberIe": NotRequired[bool],
    "briProtocol": NotRequired["BriProtocol"],
    "calledPlan": NotRequired["NumberingPlan"],
    "calledPri": NotRequired["PriOfNumber"],
    "callerIdDn": NotRequired[str],
    "callingPartySelection": NotRequired["CallingPartySelection"],
    "callingPlan": NotRequired["NumberingPlan"],
    "callingPri": NotRequired["PriOfNumber"],
    "clockReference": NotRequired["ClockReference"],
    "csuParam": NotRequired["CSUParam"],
    "dChannelEnable": NotRequired[bool],
    "channelSelectionOrder": NotRequired["TrunkSelectionOrder"],
    "pcmType": NotRequired["Encode"],
    "firstDelay": NotRequired[Any],
    "intraDelay": NotRequired[Any],
    "redirectOutboundNumberIe": NotRequired[bool],
    "numDigitsToStrip": NotRequired[Any],
    "prefix": NotRequired[str],
    "presentationBit": NotRequired["PresentationBit"],
    "sendRestart": NotRequired[bool],
    "setupNonIsdnPi": NotRequired[bool],
    "sigDigits": NotRequired[Any],
    "statusPoll": NotRequired[bool],
    "packetCaptureMode": NotRequired["PacketCaptureMode"],
    "packetCaptureDuration": NotRequired[Any],
    "cdpnTransformationCssName": NotRequired[str],
    "useDevicePoolCdpnTransformCss": NotRequired[bool],
    "geoLocationFilterName": NotRequired[str],
    "nationalPrefix": NotRequired[str],
    "internationalPrefix": NotRequired[str],
    "unknownPrefix": NotRequired[str],
    "subscriberPrefix": NotRequired[str],
    "nationalStripDigits": NotRequired[Any],
    "internationalStripDigits": NotRequired[Any],
    "unknownStripDigits": NotRequired[Any],
    "subscriberStripDigits": NotRequired[Any],
    "nationalTransformationCssName": NotRequired[str],
    "internationalTransformationCssName": NotRequired[str],
    "unknownTransformationCssName": NotRequired[str],
    "subscriberTransformationCssName": NotRequired[str],
    "pstnAccess": NotRequired[bool],
    "imeE164TransformationName": NotRequired[str],
    "useDevicePoolCgpnTransformCssNatl": NotRequired[bool],
    "useDevicePoolCgpnTransformCssIntl": NotRequired[bool],
    "useDevicePoolCgpnTransformCssUnkn": NotRequired[bool],
    "useDevicePoolCgpnTransformCssSubs": NotRequired[bool],
    "unattendedPort": NotRequired[bool],
    "GClearEnable": NotRequired[bool],
    "enableDatalinkOnFirstCall": NotRequired[bool],
    "calledPartyNationalPrefix": NotRequired[str],
    "calledPartyInternationalPrefix": NotRequired[str],
    "calledPartyUnknownPrefix": NotRequired[str],
    "calledPartySubscriberPrefix": NotRequired[str],
    "calledPartyNationalStripDigits": NotRequired[Any],
    "calledPartyInternationalStripDigits": NotRequired[Any],
    "calledPartyUnknownStripDigits": NotRequired[Any],
    "calledPartySubscriberStripDigits": NotRequired[Any],
    "calledPartyNationalTransformationCssName": NotRequired[str],
    "calledPartyInternationalTransformationCssName": NotRequired[str],
    "calledPartyUnknownTransformationCssName": NotRequired[str],
    "calledPartySubscriberTransformationCssName": NotRequired[str],
    "useDevicePoolCalledCssNatl": NotRequired[bool],
    "useDevicePoolCalledCssIntl": NotRequired[bool],
    "useDevicePoolCalledCssUnkn": NotRequired[bool],
    "useDevicePoolCalledCssSubs": NotRequired[bool],
    "connectCallBeforePlayingAnnouncement": NotRequired[bool],
}, total=False)
GatewayEndpointDigitalBri.__doc__ = '"""AXL model — ``XGatewayEndpointDigitalBri``."""'


class GatewayEndpointDigitalAccessBri(TypedDict, total=False):
    """AXL model — ``XGatewayEndpointDigitalAccessBri``.

     Used by ``AXLClient.add_gateway_endpoint_digital_access_bri()``.
    """

    domainName: NotRequired[str]
    gatewayUuid: NotRequired[str]
    unit: NotRequired[Any]
    subunit: NotRequired[Any]
    endpoint: NotRequired["GatewayEndpointDigitalBri"]


GatewayEndpointDigitalPri = TypedDict("GatewayEndpointDigitalPri", {
    "index": NotRequired[Any],
    "name": NotRequired[str],
    "description": NotRequired[str],
    "product": NotRequired["Product"],
    "class": NotRequired["Class"],
    "protocol": NotRequired["DeviceProtocol"],
    "protocolSide": NotRequired["ProtocolSide"],
    "callingSearchSpaceName": NotRequired[str],
    "devicePoolName": NotRequired[str],
    "commonDeviceConfigName": NotRequired[str],
    "networkLocation": NotRequired["NetworkLocation"],
    "locationName": NotRequired[str],
    "networkLocale": NotRequired["Country"],
    "mediaResourceListName": NotRequired[str],
    "automatedAlternateRoutingCssName": NotRequired[str],
    "aarNeighborhoodName": NotRequired[str],
    "loadInformation": NotRequired["LoadInformation"],
    "vendorConfig": NotRequired["VendorConfig"],
    "mlppDomainId": NotRequired[str],
    "mlppIndicationStatus": NotRequired["Status"],
    "mlppPreemption": NotRequired["Preemption"],
    "useTrustedRelayPoint": NotRequired["Status"],
    "cgpnTransformationCssName": NotRequired[str],
    "useDevicePoolCgpnTransformCss": NotRequired[bool],
    "geoLocationName": NotRequired[str],
    "redirectInboundNumberIe": NotRequired[bool],
    "calledPlan": NotRequired["NumberingPlan"],
    "calledPri": NotRequired["PriOfNumber"],
    "callerIdDn": NotRequired[str],
    "callingPartySelection": NotRequired["CallingPartySelection"],
    "callingPlan": NotRequired["NumberingPlan"],
    "callingPri": NotRequired["PriOfNumber"],
    "chanIE": NotRequired["PRIChanIE"],
    "clockReference": NotRequired["ClockReference"],
    "dChannelEnable": NotRequired[bool],
    "channelSelectionOrder": NotRequired["TrunkSelectionOrder"],
    "displayIe": NotRequired[bool],
    "pcmType": NotRequired["Encode"],
    "csuParam": NotRequired["CSUParam"],
    "firstDelay": NotRequired[Any],
    "interfaceIdPresent": NotRequired[bool],
    "interfaceId": NotRequired[Any],
    "intraDelay": NotRequired[Any],
    "mcdnEnable": NotRequired[bool],
    "redirectOutboundNumberIe": NotRequired[bool],
    "numDigitsToStrip": NotRequired[Any],
    "passingPrecedenceLevelThrough": NotRequired[bool],
    "prefix": NotRequired[str],
    "callingLinePresentationBit": NotRequired["PresentationBit"],
    "connectedLineIdPresentation": NotRequired["PresentationBit"],
    "priProtocol": NotRequired["PriProtocol"],
    "securityAccessLevel": NotRequired[Any],
    "sendCallingNameInFacilityIe": NotRequired[bool],
    "sendExLeadingCharInDispIe": NotRequired[bool],
    "sendRestart": NotRequired[bool],
    "setupNonIsdnPi": NotRequired[bool],
    "sigDigits": NotRequired[Any],
    "span": NotRequired[Any],
    "statusPoll": NotRequired[bool],
    "smdiBasePort": NotRequired[Any],
    "GClearEnable": NotRequired[bool],
    "packetCaptureMode": NotRequired["PacketCaptureMode"],
    "packetCaptureDuration": NotRequired[Any],
    "transmitUtf8": NotRequired[bool],
    "v150": NotRequired[bool],
    "asn1RoseOidEncoding": NotRequired["ASN1RoseOidEncoding"],
    "qsigVariant": NotRequired["QSIGVariant"],
    "unattendedPort": NotRequired[bool],
    "cdpnTransformationCssName": NotRequired[str],
    "useDevicePoolCdpnTransformCss": NotRequired[bool],
    "nationalPrefix": NotRequired[str],
    "internationalPrefix": NotRequired[str],
    "unknownPrefix": NotRequired[str],
    "subscriberPrefix": NotRequired[str],
    "geoLocationFilterName": NotRequired[str],
    "routeClassSignalling": NotRequired["Status"],
    "nationalStripDigits": NotRequired[Any],
    "internationalStripDigits": NotRequired[Any],
    "unknownStripDigits": NotRequired[Any],
    "subscriberStripDigits": NotRequired[Any],
    "nationalTransformationCssName": NotRequired[str],
    "internationalTransformationCssName": NotRequired[str],
    "unknownTransformationCssName": NotRequired[str],
    "subscriberTransformationCssName": NotRequired[str],
    "pstnAccess": NotRequired[bool],
    "imeE164TransformationName": NotRequired[str],
    "useDevicePoolCgpnTransformCssNatl": NotRequired[bool],
    "useDevicePoolCgpnTransformCssIntl": NotRequired[bool],
    "useDevicePoolCgpnTransformCssUnkn": NotRequired[bool],
    "useDevicePoolCgpnTransformCssSubs": NotRequired[bool],
    "calledPartyNationalPrefix": NotRequired[str],
    "calledPartyInternationalPrefix": NotRequired[str],
    "calledPartyUnknownPrefix": NotRequired[str],
    "calledPartySubscriberPrefix": NotRequired[str],
    "calledPartyNationalStripDigits": NotRequired[Any],
    "calledPartyInternationalStripDigits": NotRequired[Any],
    "calledPartyUnknownStripDigits": NotRequired[Any],
    "calledPartySubscriberStripDigits": NotRequired[Any],
    "calledPartyNationalTransformationCssName": NotRequired[str],
    "calledPartyInternationalTransformationCssName": NotRequired[str],
    "calledPartyUnknownTransformationCssName": NotRequired[str],
    "calledPartySubscriberTransformationCssName": NotRequired[str],
    "useDevicePoolCalledCssNatl": NotRequired[bool],
    "useDevicePoolCalledCssIntl": NotRequired[bool],
    "useDevicePoolCalledCssUnkn": NotRequired[bool],
    "useDevicePoolCalledCssSubs": NotRequired[bool],
    "useDevicePoolCntdPartyTransformationCss": NotRequired[bool],
    "cntdPartyTransformationCssName": NotRequired[str],
    "confidentialAccess": NotRequired[Any],
    "connectCallBeforePlayingAnnouncement": NotRequired[bool],
}, total=False)
GatewayEndpointDigitalPri.__doc__ = '"""AXL model — ``XGatewayEndpointDigitalPri``."""'


class GatewayEndpointDigitalAccessPri(TypedDict, total=False):
    """AXL model — ``XGatewayEndpointDigitalAccessPri``.

     Used by ``AXLClient.add_gateway_endpoint_digital_access_pri()``.
    """

    domainName: NotRequired[str]
    gatewayUuid: NotRequired[str]
    unit: NotRequired[Any]
    subunit: NotRequired[Any]
    endpoint: NotRequired["GatewayEndpointDigitalPri"]


GatewayEndpointDigitalT1 = TypedDict("GatewayEndpointDigitalT1", {
    "index": NotRequired[Any],
    "name": NotRequired[str],
    "description": NotRequired[str],
    "product": NotRequired["Product"],
    "class": NotRequired["Class"],
    "protocol": NotRequired["DeviceProtocol"],
    "protocolSide": NotRequired["ProtocolSide"],
    "callingSearchSpaceName": NotRequired[str],
    "devicePoolName": NotRequired[str],
    "commonDeviceConfigName": NotRequired[str],
    "networkLocation": NotRequired["NetworkLocation"],
    "locationName": NotRequired[str],
    "mediaResourceListName": NotRequired[str],
    "automatedAlternateRoutingCssName": NotRequired[str],
    "aarNeighborhoodName": NotRequired[str],
    "loadInformation": NotRequired["LoadInformation"],
    "vendorConfig": NotRequired["VendorConfig"],
    "traceFlag": NotRequired[bool],
    "mlppDomainId": NotRequired[str],
    "mlppIndicationStatus": NotRequired["Status"],
    "preemption": NotRequired["Preemption"],
    "useTrustedRelayPoint": NotRequired["Status"],
    "retryVideoCallAsAudio": NotRequired[bool],
    "cgpnTransformationCssName": NotRequired[str],
    "useDevicePoolCgpnTransformCss": NotRequired[bool],
    "geoLocationName": NotRequired[str],
    "sendGeoLocation": NotRequired[bool],
    "cdpnTransformationCssName": NotRequired[str],
    "useDevicePoolCdpnTransformCss": NotRequired[bool],
    "v150": NotRequired[bool],
    "geoLocationFilterName": NotRequired[str],
    "ports": NotRequired[Any],
    "trunkSelectionOrder": NotRequired["TrunkSelectionOrder"],
    "clockReference": NotRequired["ClockReference"],
    "csuParam": NotRequired["CSUParam"],
    "digitSending": NotRequired["DigitSending"],
    "pcmType": NotRequired["Encode"],
    "fdlChannel": NotRequired["FDLChannel"],
    "yellowAlarm": NotRequired["YellowAlarm"],
    "zeroSupression": NotRequired["ZeroSuppression"],
    "smdiBasePort": NotRequired[Any],
    "handleDtmfPrecedenceSignals": NotRequired[bool],
    "encodeOutboundVoiceRouteClass": NotRequired[bool],
    "routeClassSignalling": NotRequired["Status"],
    "pstnAccess": NotRequired[bool],
    "imeE164TransformationName": NotRequired[str],
    "confidentialAccess": NotRequired[Any],
    "connectCallBeforePlayingAnnouncement": NotRequired[bool],
    "calledPartyUnknownPrefix": NotRequired[str],
    "calledPartyUnknownStripDigits": NotRequired[Any],
    "calledPartyUnknownTransformationCssName": NotRequired[str],
    "useDevicePoolCalledCssUnkn": NotRequired[bool],
}, total=False)
GatewayEndpointDigitalT1.__doc__ = '"""AXL model — ``XGatewayEndpointDigitalT1``."""'


class GatewayEndpointDigitalAccessT1(TypedDict, total=False):
    """AXL model — ``XGatewayEndpointDigitalAccessT1``.

     Used by ``AXLClient.add_gateway_endpoint_digital_access_t1()``.
    """

    domainName: NotRequired[str]
    gatewayUuid: NotRequired[str]
    unit: NotRequired[Any]
    subunit: NotRequired[Any]
    endpoint: NotRequired["GatewayEndpointDigitalT1"]


GatewaySccp = TypedDict("GatewaySccp", {
    "index": NotRequired[Any],
    "name": NotRequired[str],
    "description": NotRequired[str],
    "product": NotRequired["Product"],
    "model": NotRequired["Model"],
    "class": NotRequired["Class"],
    "protocol": NotRequired["DeviceProtocol"],
    "protocolSide": NotRequired["ProtocolSide"],
    "callingSearchSpaceName": NotRequired[str],
    "devicePoolName": NotRequired[str],
    "commonDeviceConfigName": NotRequired[str],
    "networkLocale": NotRequired["Country"],
    "locationName": NotRequired[str],
    "mediaResourceListName": NotRequired[str],
    "automatedAlternateRoutingCssName": NotRequired[str],
    "aarNeighborhoodName": NotRequired[str],
    "vendorConfig": NotRequired["VendorConfig"],
    "mlppDomainId": NotRequired[str],
    "useTrustedRelayPoint": NotRequired["Status"],
    "retryVideoCallAsAudio": NotRequired[bool],
    "cgpnTransformationCssName": NotRequired[str],
    "useDevicePoolCgpnTransformCss": NotRequired[bool],
    "geoLocationName": NotRequired[str],
    "geoLocationFilterName": NotRequired[str],
    "transmitUtf8": NotRequired[bool],
    "cdpnTransformationCssName": NotRequired[str],
    "useDevicePoolCdpnTransformCss": NotRequired[bool],
    "callingPartyNumberPrefix": NotRequired[str],
    "callingPartyStripDigits": NotRequired[Any],
    "callingPartyUnknownTransformationCssName": NotRequired[str],
    "useDevicePoolCgpnTransformCssUnknown": NotRequired[bool],
    "hotlineDevice": NotRequired[bool],
    "packetCaptureMode": NotRequired["PacketCaptureMode"],
    "packetCaptureDuration": NotRequired[Any],
    "pstnAccess": NotRequired[bool],
    "imeE164TransformationName": NotRequired[str],
    "phoneTemplateName": NotRequired[str],
    "securityProfileName": NotRequired[str],
    "userLocale": NotRequired["UserLocale"],
    "deviceMobilityMode": NotRequired["Status"],
    "ownerUserId": NotRequired[str],
    "commonPhoneConfigName": NotRequired[str],
    "alwaysUsePrimeLine": NotRequired["Status"],
    "alwaysUsePrimeLineForVM": NotRequired["Status"],
    "allowCtiControlFlag": NotRequired[bool],
    "remoteDevice": NotRequired[bool],
    "subscribeCallingSearchSpaceName": NotRequired[str],
    "unattendedPort": NotRequired[bool],
    "presenceGroupName": NotRequired[str],
    "mlppIndicationStatus": NotRequired["Status"],
    "preemption": NotRequired["Preemption"],
    "hlogStatus": NotRequired[bool],
    "ignorePresentationIndicators": NotRequired["PresentationBit"],
    "lines": NotRequired[Any],
    "confidentialAccess": NotRequired[Any],
}, total=False)
GatewaySccp.__doc__ = '"""AXL model — ``XGatewaySccp``."""'


class GatewaySccpEndpoints(TypedDict, total=False):
    """AXL model — ``XGatewaySccpEndpoints``.

     Used by ``AXLClient.add_gateway_sccp_endpoints()``.
    """

    domainName: NotRequired[str]
    gatewayUuid: NotRequired[str]
    unit: NotRequired[Any]
    subunit: NotRequired[Any]
    endpoint: NotRequired["GatewaySccp"]


class GatewaySubunits(TypedDict, total=False):
    """AXL model — ``XGatewaySubunits``.

     Used by ``AXLClient.add_gateway_subunits()``.
    """

    domainName: NotRequired[str]
    gatewayUuid: NotRequired[str]
    unit: NotRequired[Any]
    subunits: NotRequired[Any]


class GeoLocation(TypedDict, total=False):
    """AXL model — ``XGeoLocation``.

     Used by ``AXLClient.add_geo_location()``.
    """

    name: NotRequired[str]
    country: NotRequired[str]
    description: NotRequired[str]
    nationalSubDivision: NotRequired[str]
    district: NotRequired[str]
    communityName: NotRequired[str]
    cityDivision: NotRequired[str]
    neighbourhood: NotRequired[str]
    street: NotRequired[str]
    leadingStreetDirection: NotRequired[str]
    trailingStreetSuffix: NotRequired[str]
    streetSuffix: NotRequired[str]
    houseNumber: NotRequired[str]
    houseNumberSuffix: NotRequired[str]
    landmark: NotRequired[str]
    location: NotRequired[str]
    floor: NotRequired[str]
    occupantName: NotRequired[str]
    postalCode: NotRequired[str]


class GeoLocationFilter(TypedDict, total=False):
    """AXL model — ``XGeoLocationFilter``.

     Used by ``AXLClient.add_geo_location_filter()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    useCountry: NotRequired[bool]
    useNationalSubDivision: NotRequired[bool]
    useDistrict: NotRequired[bool]
    useCommunityName: NotRequired[bool]
    useCityDivision: NotRequired[bool]
    useNeighbourhood: NotRequired[bool]
    useStreet: NotRequired[bool]
    useLeadingStreetDirection: NotRequired[bool]
    useTrailingStreetSuffix: NotRequired[bool]
    useStreetSuffix: NotRequired[bool]
    useHouseNumber: NotRequired[bool]
    useHouseNumberSuffix: NotRequired[bool]
    useLandmark: NotRequired[bool]
    useLocation: NotRequired[bool]
    useFloor: NotRequired[bool]
    useOccupantName: NotRequired[bool]
    usePostalCode: NotRequired[bool]


class GeoLocationPolicy(TypedDict, total=False):
    """AXL model — ``XGeoLocationPolicy``.

     Used by ``AXLClient.add_geo_location_policy()``.
    """

    name: NotRequired[str]
    country: NotRequired[str]
    description: NotRequired[str]
    nationalSubDivision: NotRequired[str]
    district: NotRequired[str]
    communityName: NotRequired[str]
    cityDivision: NotRequired[str]
    neighbourhood: NotRequired[str]
    street: NotRequired[str]
    leadingStreetDirection: NotRequired[str]
    trailingStreetSuffix: NotRequired[str]
    streetSuffix: NotRequired[str]
    houseNumber: NotRequired[str]
    houseNumberSuffix: NotRequired[str]
    landmark: NotRequired[str]
    location: NotRequired[str]
    floor: NotRequired[str]
    occupantName: NotRequired[str]
    postalCode: NotRequired[str]
    relatedPolicies: NotRequired[Any]


H323Gateway = TypedDict("H323Gateway", {
    "name": NotRequired[str],
    "description": NotRequired[str],
    "product": NotRequired["Product"],
    "class": NotRequired["Class"],
    "protocol": NotRequired["DeviceProtocol"],
    "protocolSide": NotRequired["ProtocolSide"],
    "callingSearchSpaceName": NotRequired[str],
    "devicePoolName": NotRequired[str],
    "commonDeviceConfigName": NotRequired[str],
    "networkLocation": NotRequired["NetworkLocation"],
    "locationName": NotRequired[str],
    "mediaResourceListName": NotRequired[str],
    "automatedAlternateRoutingCssName": NotRequired[str],
    "aarNeighborhoodName": NotRequired[str],
    "loadInformation": NotRequired["LoadInformation"],
    "tunneledProtocol": NotRequired["TunneledProtocol"],
    "asn1RoseOidEncoding": NotRequired["ASN1RoseOidEncoding"],
    "qsigVariant": NotRequired["QSIGVariant"],
    "vendorConfig": NotRequired["VendorConfig"],
    "pathReplacementSupport": NotRequired[bool],
    "traceFlag": NotRequired[bool],
    "mlppDomainId": NotRequired[str],
    "useTrustedRelayPoint": NotRequired["Status"],
    "retryVideoCallAsAudio": NotRequired[bool],
    "cgpnTransformationCssName": NotRequired[str],
    "useDevicePoolCgpnTransformCss": NotRequired[bool],
    "geoLocationName": NotRequired[str],
    "geoLocationFilterName": NotRequired[str],
    "cdpnTransformationCssName": NotRequired[str],
    "useDevicePoolCdpnTransformCss": NotRequired[bool],
    "packetCaptureMode": NotRequired["PacketCaptureMode"],
    "packetCaptureDuration": NotRequired[Any],
    "srtpAllowed": NotRequired[bool],
    "waitForFarEndH245TerminalSet": NotRequired[bool],
    "mtpRequired": NotRequired[bool],
    "callerIdDn": NotRequired[str],
    "callingPartySelection": NotRequired["CallingPartySelection"],
    "callingLineIdPresentation": NotRequired["PresentationBit"],
    "enableInboundFaststart": NotRequired[bool],
    "enableOutboundFaststart": NotRequired[bool],
    "codecForOutboundFaststart": NotRequired["MediaPayload"],
    "transmitUtf8": NotRequired[bool],
    "signalingPort": NotRequired[Any],
    "allowH235PassThrough": NotRequired[bool],
    "sigDigits": NotRequired[Any],
    "prefixDn": NotRequired[str],
    "calledPartyIeNumberType": NotRequired["PriOfNumber"],
    "callingPartyIeNumberType": NotRequired["PriOfNumber"],
    "calledNumberingPlan": NotRequired["NumberingPlan"],
    "callingNumberingPlan": NotRequired["NumberingPlan"],
    "callingPartyNationalPrefix": NotRequired[str],
    "callingPartyInternationalPrefix": NotRequired[str],
    "callingPartyUnknownPrefix": NotRequired[str],
    "callingPartySubscriberPrefix": NotRequired[str],
    "callingPartyNationalStripDigits": NotRequired[Any],
    "callingPartyInternationalStripDigits": NotRequired[Any],
    "callingPartyUnknownStripDigits": NotRequired[Any],
    "callingPartySubscriberStripDigits": NotRequired[Any],
    "callingPartyNationalTransformationCssName": NotRequired[str],
    "callingPartyInternationalTransformationCssName": NotRequired[str],
    "callingPartyUnknownTransformationCssName": NotRequired[str],
    "callingPartySubscriberTransformationCssName": NotRequired[str],
    "calledPartyNationalPrefix": NotRequired[str],
    "calledPartyInternationalPrefix": NotRequired[str],
    "calledPartyUnknownPrefix": NotRequired[str],
    "calledPartySubscriberPrefix": NotRequired[str],
    "calledPartyNationalStripDigits": NotRequired[Any],
    "calledPartyInternationalStripDigits": NotRequired[Any],
    "calledPartyUnknownStripDigits": NotRequired[Any],
    "calledPartySubscriberStripDigits": NotRequired[Any],
    "calledPartyNationalTransformationCssName": NotRequired[str],
    "calledPartyInternationalTransformationCssName": NotRequired[str],
    "calledPartyUnknownTransformationCssName": NotRequired[str],
    "calledPartySubscriberTransformationCssName": NotRequired[str],
    "pstnAccess": NotRequired[bool],
    "imeE164TransformationName": NotRequired[str],
    "displayIeDelivery": NotRequired[bool],
    "redirectOutboundNumberIe": NotRequired[bool],
    "redirectInboundNumberIe": NotRequired[bool],
    "useDevicePoolCgpnTransformCssNatl": NotRequired[bool],
    "useDevicePoolCgpnTransformCssIntl": NotRequired[bool],
    "useDevicePoolCgpnTransformCssUnkn": NotRequired[bool],
    "useDevicePoolCgpnTransformCssSubs": NotRequired[bool],
    "useDevicePoolCalledCssNatl": NotRequired[bool],
    "useDevicePoolCalledCssIntl": NotRequired[bool],
    "useDevicePoolCalledCssUnkn": NotRequired[bool],
    "useDevicePoolCalledCssSubs": NotRequired[bool],
    "useDevicePoolCntdPnTransformationCss": NotRequired[bool],
    "cntdPnTransformationCssName": NotRequired[str],
    "confidentialAccess": NotRequired[Any],
    "redirectingPartyTransformationCSS": NotRequired[str],
    "connectCallBeforePlayingAnnouncement": NotRequired[bool],
}, total=False)
H323Gateway.__doc__ = '"""AXL model — ``XH323Gateway``.\n\n     Used by ``AXLClient.add_h323gateway()``."""'


H323Phone = TypedDict("H323Phone", {
    "name": NotRequired[str],
    "description": NotRequired[str],
    "product": NotRequired["Product"],
    "class": NotRequired["Class"],
    "protocol": NotRequired["DeviceProtocol"],
    "protocolSide": NotRequired["ProtocolSide"],
    "callingSearchSpaceName": NotRequired[str],
    "devicePoolName": NotRequired[str],
    "commonDeviceConfigName": NotRequired[str],
    "commonPhoneConfigName": NotRequired[str],
    "locationName": NotRequired[str],
    "mediaResourceListName": NotRequired[str],
    "automatedAlternateRoutingCssName": NotRequired[str],
    "aarNeighborhoodName": NotRequired[str],
    "traceFlag": NotRequired[bool],
    "mlppDomainId": NotRequired[str],
    "useTrustedRelayPoint": NotRequired["Status"],
    "retryVideoCallAsAudio": NotRequired[bool],
    "remoteDevice": NotRequired[bool],
    "cgpnTransformationCssName": NotRequired[str],
    "useDevicePoolCgpnTransformCss": NotRequired[bool],
    "geoLocationName": NotRequired[str],
    "alwaysUsePrimeLine": NotRequired["Status"],
    "alwaysUsePrimeLineForVoiceMessage": NotRequired["Status"],
    "srtpAllowed": NotRequired[bool],
    "unattendedPort": NotRequired[bool],
    "subscribeCallingSearchSpaceName": NotRequired[str],
    "waitForFarEndH245TerminalSet": NotRequired[bool],
    "mtpRequired": NotRequired[bool],
    "mtpPreferredCodec": NotRequired["SIPCodec"],
    "callerIdDn": NotRequired[str],
    "callingPartySelection": NotRequired["CallingPartySelection"],
    "callingLineIdPresentation": NotRequired["PresentationBit"],
    "displayIEDelivery": NotRequired[bool],
    "redirectOutboundNumberIe": NotRequired[bool],
    "redirectInboundNumberIe": NotRequired[bool],
    "presenceGroupName": NotRequired[str],
    "hlogStatus": NotRequired[bool],
    "ownerUserName": NotRequired[str],
    "signalingPort": NotRequired[Any],
    "gateKeeperInfo": NotRequired[Any],
    "lines": NotRequired[Any],
    "ignorePresentationIndicators": NotRequired[bool],
    "elinGroup": NotRequired[str],
}, total=False)
H323Phone.__doc__ = '"""AXL model — ``XH323Phone``.\n\n     Used by ``AXLClient.add_h323phone()``."""'


H323Trunk = TypedDict("H323Trunk", {
    "name": NotRequired[str],
    "description": NotRequired[str],
    "product": NotRequired["Product"],
    "class": NotRequired["Class"],
    "protocol": NotRequired["DeviceProtocol"],
    "protocolSide": NotRequired["ProtocolSide"],
    "callingSearchSpaceName": NotRequired[str],
    "devicePoolName": NotRequired[str],
    "commonDeviceConfigName": NotRequired[str],
    "networkLocation": NotRequired["NetworkLocation"],
    "locationName": NotRequired[str],
    "mediaResourceListName": NotRequired[str],
    "aarNeighborhoodName": NotRequired[str],
    "traceFlag": NotRequired[bool],
    "mlppDomainId": NotRequired[str],
    "mlppIndicationStatus": NotRequired["Status"],
    "preemption": NotRequired["Preemption"],
    "useTrustedRelayPoint": NotRequired["Status"],
    "retryVideoCallAsAudio": NotRequired[bool],
    "cgpnTransformationCssName": NotRequired[str],
    "useDevicePoolCgpnTransformCss": NotRequired[bool],
    "rdnTransformationCssName": NotRequired[str],
    "useDevicePoolRdnTransformCss": NotRequired[bool],
    "geoLocationName": NotRequired[str],
    "geoLocationFilterName": NotRequired[str],
    "sendGeoLocation": NotRequired[bool],
    "cdpnTransformationCssName": NotRequired[str],
    "useDevicePoolCdpnTransformCss": NotRequired[bool],
    "packetCaptureMode": NotRequired["PacketCaptureMode"],
    "packetCaptureDuration": NotRequired[Any],
    "srtpAllowed": NotRequired[bool],
    "unattendedPort": NotRequired[bool],
    "waitForFarEndH245TerminalSet": NotRequired[bool],
    "mtpRequired": NotRequired[bool],
    "callerIdDn": NotRequired[str],
    "callingPartySelection": NotRequired["CallingPartySelection"],
    "callingLineIdPresentation": NotRequired["PresentationBit"],
    "displayIEDelivery": NotRequired[bool],
    "redirectOutboundNumberIe": NotRequired[bool],
    "redirectInboundNumberIe": NotRequired[bool],
    "enableInboundFaststart": NotRequired[bool],
    "enableOutboundFaststart": NotRequired[bool],
    "codecForOutboundFaststart": NotRequired["MediaPayload"],
    "allowH235PassThrough": NotRequired[bool],
    "tunneledProtocol": NotRequired["TunneledProtocol"],
    "asn1RoseOidEncoding": NotRequired["ASN1RoseOidEncoding"],
    "qsigVariant": NotRequired["QSIGVariant"],
    "transmitUtf8": NotRequired[bool],
    "signalingPort": NotRequired[Any],
    "nationalPrefix": NotRequired[str],
    "internationalPrefix": NotRequired[str],
    "unknownPrefix": NotRequired[str],
    "subscriberPrefix": NotRequired[str],
    "sigDigits": NotRequired[Any],
    "prefixDn": NotRequired[str],
    "calledPartyIeNumberType": NotRequired["PriOfNumber"],
    "callingPartyIeNumberType": NotRequired["PriOfNumber"],
    "calledNumberingPlan": NotRequired["NumberingPlan"],
    "callingNumberingPlan": NotRequired["NumberingPlan"],
    "pathReplacementSupport": NotRequired[bool],
    "gateKeeperInfo": NotRequired[Any],
    "ictPassingPrecedenceLevelThroughUuie": NotRequired[bool],
    "ictSecurityAccessLevel": NotRequired[Any],
    "isSafEnabled": NotRequired[bool],
    "callingPartyNationalStripDigits": NotRequired[Any],
    "callingPartyInternationalStripDigits": NotRequired[Any],
    "callingPartyUnknownStripDigits": NotRequired[Any],
    "callingPartySubscriberStripDigits": NotRequired[Any],
    "callingPartyNationalTransformationCssName": NotRequired[str],
    "callingPartyInternationalTransformationCssName": NotRequired[str],
    "callingPartyUnknownTransformationCssName": NotRequired[str],
    "callingPartySubscriberTransformationCssName": NotRequired[str],
    "calledPartyNationalPrefix": NotRequired[str],
    "calledPartyInternationalPrefix": NotRequired[str],
    "calledPartyUnknownPrefix": NotRequired[str],
    "calledPartySubscriberPrefix": NotRequired[str],
    "pstnAccess": NotRequired[bool],
    "imeE164TransformationName": NotRequired[str],
    "automatedAlternateRoutingCssName": NotRequired[str],
    "useDevicePoolCgpnTransformCssNatl": NotRequired[bool],
    "useDevicePoolCgpnTransformCssIntl": NotRequired[bool],
    "useDevicePoolCgpnTransformCssUnkn": NotRequired[bool],
    "useDevicePoolCgpnTransformCssSubs": NotRequired[bool],
    "useDevicePoolCalledCssNatl": NotRequired[bool],
    "useDevicePoolCalledCssIntl": NotRequired[bool],
    "useDevicePoolCalledCssUnkn": NotRequired[bool],
    "useDevicePoolCalledCssSubs": NotRequired[bool],
    "calledPartyNationalStripDigits": NotRequired[Any],
    "calledPartyInternationalStripDigits": NotRequired[Any],
    "calledPartyUnknownStripDigits": NotRequired[Any],
    "calledPartySubscriberStripDigits": NotRequired[Any],
    "calledPartyNationalTransformationCssName": NotRequired[str],
    "calledPartyInternationalTransformationCssName": NotRequired[str],
    "calledPartyUnknownTransformationCssName": NotRequired[str],
    "calledPartySubscriberTransformationCssName": NotRequired[str],
    "runOnEveryNode": NotRequired[bool],
    "destinations": NotRequired[Any],
    "useDevicePoolCntdPnTransformationCss": NotRequired[bool],
    "cntdPnTransformationCssName": NotRequired[str],
    "confidentialAccess": NotRequired[Any],
    "connectCallBeforePlayingAnnouncement": NotRequired[bool],
}, total=False)
H323Trunk.__doc__ = '"""AXL model — ``XH323Trunk``.\n\n     Used by ``AXLClient.add_h323trunk()``."""'


class HandoffConfiguration(TypedDict, total=False):
    """AXL model — ``XHandoffConfiguration``.

     Used by ``AXLClient.add_handoff_configuration()``.
    """

    pattern: NotRequired[str]
    routePartitionName: NotRequired[str]


class HttpProfile(TypedDict, total=False):
    """AXL model — ``XHttpProfile``.

     Used by ``AXLClient.add_http_profile()``.
    """

    name: NotRequired[str]
    userName: NotRequired[str]
    password: NotRequired[str]
    requestTimeout: NotRequired[Any]
    retryCount: NotRequired[Any]
    webServiceRootUri: NotRequired[str]


class HuntList(TypedDict, total=False):
    """AXL model — ``XHuntList``.

     Used by ``AXLClient.add_hunt_list()``.
    """

    description: NotRequired[str]
    callManagerGroupName: NotRequired[str]
    routeListEnabled: NotRequired[bool]
    voiceMailUsage: NotRequired[bool]
    members: NotRequired[Any]
    name: NotRequired[str]


class HuntPilot(TypedDict, total=False):
    """AXL model — ``XHuntPilot``.

     Used by ``AXLClient.add_hunt_pilot()``.
    """

    pattern: NotRequired[str]
    description: NotRequired[str]
    routePartitionName: NotRequired[str]
    blockEnable: NotRequired[bool]
    calledPartyTransformationMask: NotRequired[str]
    callingPartyTransformationMask: NotRequired[str]
    useCallingPartyPhoneMask: NotRequired["Status"]
    callingPartyPrefixDigits: NotRequired[str]
    dialPlanName: NotRequired[str]
    digitDiscardInstructionName: NotRequired[str]
    patternUrgency: NotRequired[bool]
    prefixDigitsOut: NotRequired[str]
    routeFilterName: NotRequired[str]
    callingLinePresentationBit: NotRequired["PresentationBit"]
    callingNamePresentationBit: NotRequired["PresentationBit"]
    connectedLinePresentationBit: NotRequired["PresentationBit"]
    connectedNamePresentationBit: NotRequired["PresentationBit"]
    patternPrecedence: NotRequired["PatternPrecedence"]
    provideOutsideDialtone: NotRequired[bool]
    callingPartyNumberingPlan: NotRequired["NumberingPlan"]
    callingPartyNumberType: NotRequired["PriOfNumber"]
    calledPartyNumberingPlan: NotRequired["NumberingPlan"]
    calledPartyNumberType: NotRequired["PriOfNumber"]
    huntListName: NotRequired[str]
    parkMonForwardNoRetrieve: NotRequired[Any]
    alertingName: NotRequired[str]
    asciiAlertingName: NotRequired[Any]
    e164Mask: NotRequired[str]
    aarNeighborhoodName: NotRequired[str]
    forwardHuntNoAnswer: NotRequired[Any]
    forwardHuntBusy: NotRequired[Any]
    callPickupGroupName: NotRequired[str]
    maxHuntduration: NotRequired[Any]
    releaseClause: NotRequired["ReleaseCauseValue"]
    displayConnectedNumber: NotRequired[bool]
    queueCalls: NotRequired["CallsQueue"]


class ImeClient(TypedDict, total=False):
    """AXL model — ``XImeClient``.

     Used by ``AXLClient.add_ime_client()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    domain: NotRequired[str]
    isActivated: NotRequired[bool]
    sipTrunkName: NotRequired[str]
    primaryImeServerName: NotRequired[str]
    secondaryImeServerName: NotRequired[str]
    learnedRouteFilterGroupName: NotRequired[str]
    exclusionNumberGroupName: NotRequired[str]
    firewallName: NotRequired[str]
    members: NotRequired[Any]
    ccmExternalIpMaps: NotRequired[Any]


class ImeE164Transformation(TypedDict, total=False):
    """AXL model — ``XImeE164Transformation``.

     Used by ``AXLClient.add_ime_e164transformation()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    cgpnTransformationCssName: NotRequired[str]
    isCgpnPreTransformation: NotRequired[bool]
    cdpnTransformationCssName: NotRequired[str]
    isCdpnPreTransformation: NotRequired[bool]
    incomingCgpnTransformationProfileName: NotRequired[str]
    incomingCdpnTransformationProfileName: NotRequired[str]


class ImeEnrolledPattern(TypedDict, total=False):
    """AXL model — ``XImeEnrolledPattern``.

     Used by ``AXLClient.add_ime_enrolled_pattern()``.
    """

    pattern: NotRequired[str]
    description: NotRequired[str]
    imeEnrolledPatternGroupName: NotRequired[str]


class ImeEnrolledPatternGroup(TypedDict, total=False):
    """AXL model — ``XImeEnrolledPatternGroup``.

     Used by ``AXLClient.add_ime_enrolled_pattern_group()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    fallbackProfileName: NotRequired[str]
    isPatternAllAlias: NotRequired[bool]


class ImeExclusionNumber(TypedDict, total=False):
    """AXL model — ``XImeExclusionNumber``.

     Used by ``AXLClient.add_ime_exclusion_number()``.
    """

    pattern: NotRequired[str]
    description: NotRequired[str]
    imeExclusionNumberGroupName: NotRequired[str]


class ImeExclusionNumberGroup(TypedDict, total=False):
    """AXL model — ``XImeExclusionNumberGroup``.

     Used by ``AXLClient.add_ime_exclusion_number_group()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]


class ImeFirewall(TypedDict, total=False):
    """AXL model — ``XImeFirewall``.

     Used by ``AXLClient.add_ime_firewall()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    ipAddress: NotRequired[Any]
    port: NotRequired[Any]


class ImeRouteFilterElement(TypedDict, total=False):
    """AXL model — ``XImeRouteFilterElement``.

     Used by ``AXLClient.add_ime_route_filter_element()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    elementType: NotRequired["ViprFilterElement"]
    imeRouteFilterGroupName: NotRequired[str]


class ImeRouteFilterGroup(TypedDict, total=False):
    """AXL model — ``XImeRouteFilterGroup``.

     Used by ``AXLClient.add_ime_route_filter_group()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    groupTrustSetting: NotRequired[bool]


class ImeServer(TypedDict, total=False):
    """AXL model — ``XImeServer``.

     Used by ``AXLClient.add_ime_server()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    ipAddress: NotRequired[str]
    port: NotRequired[Any]
    deviceSecurityMode: NotRequired["ServerSecurityMode"]
    applicationUser: NotRequired[str]
    reconnectInterval: NotRequired[Any]


class ImportedDirectoryUriCatalogs(TypedDict, total=False):
    """AXL model — ``XImportedDirectoryUriCatalogs``.

     Used by ``AXLClient.add_imported_directory_uri_catalogs()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    routeString: NotRequired[str]
    lastLoadedFileName: NotRequired[str]
    fileLoadDateTime: NotRequired[Any]


class InfrastructureDevice(TypedDict, total=False):
    """AXL model — ``XInfrastructureDevice``.

     Used by ``AXLClient.add_infrastructure_device()``.
    """

    name: NotRequired[str]
    ipv4Address: NotRequired[str]
    ipv6Address: NotRequired[str]
    bssidWithMask: NotRequired[str]
    wapLocation: NotRequired[str]
    isActive: NotRequired[bool]


class IpPhoneServices(TypedDict, total=False):
    """AXL model — ``XIpPhoneServices``.

     Used by ``AXLClient.add_ip_phone_services()``.
    """

    serviceName: NotRequired[str]
    asciiServiceName: NotRequired[str]
    serviceDescription: NotRequired[str]
    serviceUrl: NotRequired[str]
    secureServiceUrl: NotRequired[str]
    serviceCategory: NotRequired["PhoneServiceCategory"]
    serviceType: NotRequired["PhoneService"]
    serviceVendor: NotRequired[str]
    serviceVersion: NotRequired[str]
    enabled: NotRequired[bool]
    enterpriseSubscription: NotRequired[bool]
    parameters: NotRequired[Any]


class IvrUserLocale(TypedDict, total=False):
    """AXL model — ``XIvrUserLocale``.

     Used by ``AXLClient.add_ivr_user_locale()``.
    """

    userLocale: NotRequired["UserLocale"]
    orderIndex: NotRequired[Any]


class LbmGroup(TypedDict, total=False):
    """AXL model — ``XLbmGroup``.

     Used by ``AXLClient.add_lbm_group()``.
    """

    name: NotRequired[str]
    Description: NotRequired[str]
    ProcessnodeActive: NotRequired[str]
    ProcessnodeStandby: NotRequired[str]


class LbmHubGroup(TypedDict, total=False):
    """AXL model — ``XLbmHubGroup``.

     Used by ``AXLClient.add_lbm_hub_group()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    member1: NotRequired[str]
    member2: NotRequired[str]
    member3: NotRequired[str]
    members: NotRequired[Any]


class LdapDirectory(TypedDict, total=False):
    """AXL model — ``XLdapDirectory``.

     Used by ``AXLClient.add_ldap_directory()``.
    """

    name: NotRequired[str]
    ldapDn: NotRequired[str]
    ldapPassword: NotRequired[str]
    userSearchBase: NotRequired[str]
    repeatable: NotRequired[bool]
    intervalValue: NotRequired[Any]
    scheduleUnit: NotRequired["ScheduleUnit"]
    nextExecTime: NotRequired[Any]
    servers: NotRequired[Any]
    middleName: NotRequired[str]
    phoneNumber: NotRequired[str]
    mailId: NotRequired[str]
    ldapFilter: NotRequired[str]
    synchronize: NotRequired[bool]
    ldapFilterForGroups: NotRequired[str]
    directoryUri: NotRequired[str]
    accessControlGroupInfo: NotRequired[Any]
    featureGroupTemplate: NotRequired[str]
    applyMask: NotRequired[bool]
    mask: NotRequired[str]
    applyPoolList: NotRequired[bool]
    addDns: NotRequired[Any]


class LdapFilter(TypedDict, total=False):
    """AXL model — ``XLdapFilter``.

     Used by ``AXLClient.add_ldap_filter()``.
    """

    name: NotRequired[str]
    filter: NotRequired[str]


class LdapSyncCustomField(TypedDict, total=False):
    """AXL model — ``XLdapSyncCustomField``.

     Used by ``AXLClient.add_ldap_sync_custom_field()``.
    """

    ldapConfigurationName: NotRequired[str]
    customUserField: NotRequired[str]
    ldapUserField: NotRequired[str]


class Line(TypedDict, total=False):
    """AXL model — ``XLine``.

     Used by ``AXLClient.add_line()``.
    """

    pattern: NotRequired[str]
    description: NotRequired[str]
    usage: NotRequired["PatternUsage"]
    routePartitionName: NotRequired[str]
    aarNeighborhoodName: NotRequired[str]
    aarDestinationMask: NotRequired[str]
    aarKeepCallHistory: NotRequired[bool]
    aarVoiceMailEnabled: NotRequired[bool]
    callForwardAll: NotRequired["CallForwardAll"]
    callForwardBusy: NotRequired["CallForwardBusy"]
    callForwardBusyInt: NotRequired["CallForwardBusyInt"]
    callForwardNoAnswer: NotRequired["CallForwardNoAnswer"]
    callForwardNoAnswerInt: NotRequired["CallForwardNoAnswerInt"]
    callForwardNoCoverage: NotRequired["CallForwardNoCoverage"]
    callForwardNoCoverageInt: NotRequired["CallForwardNoCoverageInt"]
    callForwardOnFailure: NotRequired["CallForwardOnFailure"]
    callForwardAlternateParty: NotRequired["CallForwardAlternateParty"]
    callForwardNotRegistered: NotRequired["CallForwardNotRegistered"]
    callForwardNotRegisteredInt: NotRequired["CallForwardNotRegisteredInt"]
    callPickupGroupName: NotRequired[str]
    autoAnswer: NotRequired["AutoAnswer"]
    networkHoldMohAudioSourceId: NotRequired[Any]
    userHoldMohAudioSourceId: NotRequired[Any]
    callingIdPresentationWhenDiverted: NotRequired["PresentationBit"]
    alertingName: NotRequired[str]
    asciiAlertingName: NotRequired[Any]
    presenceGroupName: NotRequired[str]
    shareLineAppearanceCssName: NotRequired[str]
    voiceMailProfileName: NotRequired[str]
    patternPrecedence: NotRequired["PatternPrecedence"]
    releaseClause: NotRequired["ReleaseCauseValue"]
    hrDuration: NotRequired[Any]
    hrInterval: NotRequired[Any]
    cfaCssPolicy: NotRequired["CFACSSActivationPolicy"]
    defaultActivatedDeviceName: NotRequired[str]
    parkMonForwardNoRetrieveDn: NotRequired[str]
    parkMonForwardNoRetrieveIntDn: NotRequired[str]
    parkMonForwardNoRetrieveVmEnabled: NotRequired[bool]
    parkMonForwardNoRetrieveIntVmEnabled: NotRequired[bool]
    parkMonForwardNoRetrieveCssName: NotRequired[str]
    parkMonForwardNoRetrieveIntCssName: NotRequired[str]
    parkMonReversionTimer: NotRequired[Any]
    partyEntranceTone: NotRequired["Status"]
    directoryURIs: NotRequired[Any]
    allowCtiControlFlag: NotRequired[bool]
    rejectAnonymousCall: NotRequired[bool]
    patternUrgency: NotRequired[bool]
    confidentialAccess: NotRequired[Any]
    externalCallControlProfile: NotRequired[str]
    enterpriseAltNum: NotRequired[Any]
    e164AltNum: NotRequired[Any]
    pstnFailover: NotRequired[str]
    callControlAgentProfile: NotRequired[str]
    useEnterpriseAltNum: NotRequired[bool]
    useE164AltNum: NotRequired[bool]
    active: NotRequired[bool]
    externalPresentationInfo: NotRequired[Any]


class LineGroup(TypedDict, total=False):
    """AXL model — ``XLineGroup``.

     Used by ``AXLClient.add_line_group()``.
    """

    distributionAlgorithm: NotRequired["DistributeAlgorithm"]
    rnaReversionTimeOut: NotRequired[Any]
    huntAlgorithmNoAnswer: NotRequired["HuntAlgorithm"]
    huntAlgorithmBusy: NotRequired["HuntAlgorithm"]
    huntAlgorithmNotAvailable: NotRequired["HuntAlgorithm"]
    members: NotRequired[Any]
    name: NotRequired[str]
    autoLogOffHunt: NotRequired[bool]


class LocalRouteGroup(TypedDict, total=False):
    """AXL model — ``XLocalRouteGroup``.

     Used by ``AXLClient.add_local_route_group()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]


class Location(TypedDict, total=False):
    """AXL model — ``XLocation``.

     Used by ``AXLClient.add_location()``.
    """

    name: NotRequired[str]
    relatedLocations: NotRequired[Any]
    withinAudioBandwidth: NotRequired[Any]
    withinVideoBandwidth: NotRequired[Any]
    withinImmersiveKbits: NotRequired[Any]
    betweenLocations: NotRequired[Any]


class MediaResourceGroup(TypedDict, total=False):
    """AXL model — ``XMediaResourceGroup``.

     Used by ``AXLClient.add_media_resource_group()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    multicast: NotRequired[bool]
    members: NotRequired[Any]


class MediaResourceList(TypedDict, total=False):
    """AXL model — ``XMediaResourceList``.

     Used by ``AXLClient.add_media_resource_list()``.
    """

    name: NotRequired[str]
    members: NotRequired[Any]


class MeetMe(TypedDict, total=False):
    """AXL model — ``XMeetMe``.

     Used by ``AXLClient.add_meet_me()``.
    """

    pattern: NotRequired[str]
    description: NotRequired[str]
    routePartitionName: NotRequired[str]
    minimumSecurityLevel: NotRequired["DeviceSecurityMode"]


class MessageWaiting(TypedDict, total=False):
    """AXL model — ``XMessageWaiting``.

     Used by ``AXLClient.add_message_waiting()``.
    """

    pattern: NotRequired[str]
    routePartitionName: NotRequired[str]
    description: NotRequired[str]
    messageWaitingIndicator: NotRequired[bool]
    callingSearchSpaceName: NotRequired[str]


class MlppDomain(TypedDict, total=False):
    """AXL model — ``XMlppDomain``.

     Used by ``AXLClient.add_mlpp_domain()``.
    """

    domainName: NotRequired[str]
    domainId: NotRequired[str]


class MobileVoiceAccess(TypedDict, total=False):
    """AXL model — ``XMobileVoiceAccess``.

     Used by ``AXLClient.add_mobile_voice_access()``.
    """

    pattern: NotRequired[str]
    routePartitionName: NotRequired[str]
    locales: NotRequired[Any]


class Mobility(TypedDict, total=False):
    """AXL model — ``XMobility``.

     Used by ``AXLClient.add_mobility()``.
    """

    handoffNumber: Required[str]
    handoffPartitionName: NotRequired[str]
    DTMFNumber: Required[str]
    DTMFPartitionName: NotRequired[str]


class MobilityProfile(TypedDict, total=False):
    """AXL model — ``XMobilityProfile``.

     Used by ``AXLClient.add_mobility_profile()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    mobileClientCallingOption: NotRequired["DialViaOffice"]
    dvofServiceAccessNumber: NotRequired[str]
    dirn: NotRequired["Dirn"]
    dvorCallerId: NotRequired[str]


class MraServiceDomain(TypedDict, total=False):
    """AXL model — ``XMraServiceDomain``.

     Used by ``AXLClient.add_mra_service_domain()``.
    """

    name: NotRequired[str]
    isDefault: NotRequired[bool]
    serviceDomains: NotRequired[str]


class Mtp(TypedDict, total=False):
    """AXL model — ``XMtp``.

     Used by ``AXLClient.add_mtp()``.
    """

    mtpType: NotRequired["Product"]
    name: NotRequired[str]
    description: NotRequired[str]
    devicePoolName: NotRequired[str]
    trustedRelayPoint: NotRequired[bool]


class NetworkAccessProfile(TypedDict, total=False):
    """AXL model — ``XNetworkAccessProfile``.

     Used by ``AXLClient.add_network_access_profile()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    vpnRequired: NotRequired["Status"]
    proxySettings: NotRequired["HTTPProxy"]
    proxyHostname: NotRequired[str]
    proxyPort: NotRequired[Any]
    proxyRequiresAuthentication: NotRequired[bool]
    provideSharedCredentials: NotRequired[bool]
    username: NotRequired[str]
    password: NotRequired[str]


Phone = TypedDict("Phone", {
    "name": NotRequired[str],
    "description": NotRequired[str],
    "product": NotRequired["Product"],
    "class": NotRequired["Class"],
    "protocol": NotRequired["DeviceProtocol"],
    "protocolSide": NotRequired["ProtocolSide"],
    "callingSearchSpaceName": NotRequired[str],
    "devicePoolName": NotRequired[str],
    "commonDeviceConfigName": NotRequired[str],
    "commonPhoneConfigName": NotRequired[str],
    "networkLocation": NotRequired["NetworkLocation"],
    "locationName": NotRequired[str],
    "mediaResourceListName": NotRequired[str],
    "networkHoldMohAudioSourceId": NotRequired[Any],
    "userHoldMohAudioSourceId": NotRequired[Any],
    "automatedAlternateRoutingCssName": NotRequired[str],
    "aarNeighborhoodName": NotRequired[str],
    "loadInformation": NotRequired["LoadInformation"],
    "vendorConfig": NotRequired["VendorConfig"],
    "versionStamp": NotRequired[str],
    "traceFlag": NotRequired[bool],
    "mlppDomainId": NotRequired[str],
    "mlppIndicationStatus": NotRequired["Status"],
    "preemption": NotRequired["Preemption"],
    "useTrustedRelayPoint": NotRequired["Status"],
    "retryVideoCallAsAudio": NotRequired[bool],
    "securityProfileName": NotRequired[str],
    "sipProfileName": NotRequired[str],
    "cgpnTransformationCssName": NotRequired[str],
    "useDevicePoolCgpnTransformCss": NotRequired[bool],
    "geoLocationName": NotRequired[str],
    "geoLocationFilterName": NotRequired[str],
    "sendGeoLocation": NotRequired[bool],
    "lines": NotRequired[Any],
    "phoneTemplateName": NotRequired[str],
    "speeddials": NotRequired[Any],
    "busyLampFields": NotRequired[Any],
    "primaryPhoneName": NotRequired[str],
    "ringSettingIdleBlfAudibleAlert": NotRequired["Status"],
    "ringSettingBusyBlfAudibleAlert": NotRequired["Status"],
    "blfDirectedCallParks": NotRequired[Any],
    "addOnModules": NotRequired[Any],
    "userLocale": NotRequired["UserLocale"],
    "networkLocale": NotRequired["Country"],
    "idleTimeout": NotRequired[Any],
    "authenticationUrl": NotRequired[str],
    "directoryUrl": NotRequired[str],
    "idleUrl": NotRequired[str],
    "informationUrl": NotRequired[str],
    "messagesUrl": NotRequired[str],
    "proxyServerUrl": NotRequired[str],
    "servicesUrl": NotRequired[str],
    "services": NotRequired[Any],
    "softkeyTemplateName": NotRequired[str],
    "defaultProfileName": NotRequired[str],
    "enableExtensionMobility": NotRequired[bool],
    "singleButtonBarge": NotRequired["Barge"],
    "joinAcrossLines": NotRequired["Status"],
    "builtInBridgeStatus": NotRequired["Status"],
    "callInfoPrivacyStatus": NotRequired["Status"],
    "hlogStatus": NotRequired["Status"],
    "ownerUserName": NotRequired[str],
    "ignorePresentationIndicators": NotRequired[bool],
    "packetCaptureMode": NotRequired["PacketCaptureMode"],
    "packetCaptureDuration": NotRequired[Any],
    "subscribeCallingSearchSpaceName": NotRequired[str],
    "rerouteCallingSearchSpaceName": NotRequired[str],
    "allowCtiControlFlag": NotRequired[bool],
    "presenceGroupName": NotRequired[str],
    "unattendedPort": NotRequired[bool],
    "requireDtmfReception": NotRequired[bool],
    "rfc2833Disabled": NotRequired[bool],
    "certificateOperation": NotRequired["CertificateOperation"],
    "authenticationMode": NotRequired["AuthenticationMode"],
    "keySize": NotRequired["KeySize"],
    "keyOrder": NotRequired["KeyOrder"],
    "ecKeySize": NotRequired["ECKeySize"],
    "authenticationString": NotRequired[str],
    "upgradeFinishTime": NotRequired[str],
    "deviceMobilityMode": NotRequired["Status"],
    "remoteDevice": NotRequired[bool],
    "dndOption": NotRequired["DNDOption"],
    "dndRingSetting": NotRequired["RingSetting"],
    "dndStatus": NotRequired[bool],
    "isActive": NotRequired[bool],
    "isDualMode": NotRequired[bool],
    "mobilityUserIdName": NotRequired[str],
    "phoneSuite": NotRequired["PhonePersonalization"],
    "phoneServiceDisplay": NotRequired["PhoneServiceDisplay"],
    "isProtected": NotRequired[bool],
    "mtpRequired": NotRequired[bool],
    "mtpPreferedCodec": NotRequired["SIPCodec"],
    "dialRulesName": NotRequired[str],
    "sshUserId": NotRequired[str],
    "sshPwd": NotRequired[str],
    "digestUser": NotRequired[str],
    "outboundCallRollover": NotRequired["OutboundCallRollover"],
    "hotlineDevice": NotRequired[bool],
    "secureInformationUrl": NotRequired[str],
    "secureDirectoryUrl": NotRequired[str],
    "secureMessageUrl": NotRequired[str],
    "secureServicesUrl": NotRequired[str],
    "secureAuthenticationUrl": NotRequired[str],
    "secureIdleUrl": NotRequired[str],
    "alwaysUsePrimeLine": NotRequired["Status"],
    "alwaysUsePrimeLineForVoiceMessage": NotRequired["Status"],
    "featureControlPolicy": NotRequired[str],
    "deviceTrustMode": NotRequired["DeviceTrustMode"],
    "earlyOfferSupportForVoiceCall": NotRequired[bool],
    "requireThirdPartyRegistration": NotRequired[bool],
    "blockIncomingCallsWhenRoaming": NotRequired[bool],
    "homeNetworkId": NotRequired[str],
    "AllowPresentationSharingUsingBfcp": NotRequired[bool],
    "confidentialAccess": NotRequired[Any],
    "requireOffPremiseLocation": NotRequired[bool],
    "allowiXApplicableMedia": NotRequired[bool],
    "cgpnIngressDN": NotRequired[str],
    "useDevicePoolCgpnIngressDN": NotRequired[bool],
    "msisdn": NotRequired[str],
    "enableCallRoutingToRdWhenNoneIsActive": NotRequired[bool],
    "wifiHotspotProfile": NotRequired[str],
    "wirelessLanProfileGroup": NotRequired[str],
    "elinGroup": NotRequired[str],
    "enableActivationID": NotRequired[bool],
    "mraServiceDomain": NotRequired[str],
    "allowMraMode": NotRequired[bool],
}, total=False)
Phone.__doc__ = '"""AXL model — ``XPhone``.\n\n     Used by ``AXLClient.add_phone()``."""'


class PhoneActivationCode(TypedDict, total=False):
    """AXL model — ``XPhoneActivationCode``.

     Used by ``AXLClient.add_phone_activation_code()``.
    """

    activationCodeExpiry: NotRequired[Any]
    phoneName: NotRequired[str]


class PhoneButtonTemplate(TypedDict, total=False):
    """AXL model — ``XPhoneButtonTemplate``.

     Used by ``AXLClient.add_phone_button_template()``.
    """

    name: NotRequired[str]
    basePhoneTemplateName: NotRequired[str]
    buttons: NotRequired[Any]


class PhoneNtp(TypedDict, total=False):
    """AXL model — ``XPhoneNtp``.

     Used by ``AXLClient.add_phone_ntp()``.
    """

    ipAddress: NotRequired[str]
    ipv6Address: NotRequired[str]
    description: NotRequired[str]
    mode: NotRequired["Zzntpmode"]


class PhoneSecurityProfile(TypedDict, total=False):
    """AXL model — ``XPhoneSecurityProfile``.

     Used by ``AXLClient.add_phone_security_profile()``.
    """

    phoneType: NotRequired["Model"]
    protocol: NotRequired["DeviceProtocol"]
    name: NotRequired[str]
    description: NotRequired[str]
    deviceSecurityMode: NotRequired["DeviceSecurityMode"]
    authenticationMode: NotRequired["AuthenticationMode"]
    keySize: NotRequired["KeySize"]
    keyOrder: NotRequired["KeyOrder"]
    ecKeySize: NotRequired["ECKeySize"]
    tftpEncryptedConfig: NotRequired[bool]
    EnableOAuthAuthentication: NotRequired[bool]
    nonceValidityTime: NotRequired[Any]
    transportType: NotRequired["Transport"]
    sipPhonePort: NotRequired[Any]
    enableDigestAuthentication: NotRequired[bool]
    excludeDigestCredentials: NotRequired[bool]


class PhysicalLocation(TypedDict, total=False):
    """AXL model — ``XPhysicalLocation``.

     Used by ``AXLClient.add_physical_location()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]


class PresenceGroup(TypedDict, total=False):
    """AXL model — ``XPresenceGroup``.

     Used by ``AXLClient.add_presence_group()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    presenceGroups: NotRequired[Any]


class PresenceRedundancyGroup(TypedDict, total=False):
    """AXL model — ``XPresenceRedundancyGroup``.

     Used by ``AXLClient.add_presence_redundancy_group()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    server1: NotRequired[str]
    server2: NotRequired[str]
    haEnabled: NotRequired[bool]


class ProcessNode(TypedDict, total=False):
    """AXL model — ``XProcessNode``.

     Used by ``AXLClient.add_process_node()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    mac: NotRequired[Any]
    ipv6Name: NotRequired[str]
    lbmHubGroup: NotRequired[str]
    processNodeRole: NotRequired["ProcessNodeRole"]
    cupDomain: NotRequired[str]


class RecordingProfile(TypedDict, total=False):
    """AXL model — ``XRecordingProfile``.

     Used by ``AXLClient.add_recording_profile()``.
    """

    name: NotRequired[str]
    recordingCssName: NotRequired[str]
    recorderDestination: NotRequired[str]


class Region(TypedDict, total=False):
    """AXL model — ``XRegion``.

     Used by ``AXLClient.add_region()``.
    """

    name: NotRequired[str]
    relatedRegions: NotRequired[Any]
    defaultCodec: NotRequired[str]


class RemoteClusterMember(TypedDict, total=False):
    """AXL model — ``XRemoteClusterMember``.
    """

    enabled: NotRequired[bool]


class RemoteCluster(TypedDict, total=False):
    """AXL model — ``XRemoteCluster``.

     Used by ``AXLClient.add_remote_cluster()``.
    """

    clusterId: NotRequired[str]
    description: NotRequired[str]
    fullyQualifiedName: NotRequired[str]
    emcc: NotRequired["RemoteClusterMember"]
    pstnAccess: NotRequired["RemoteClusterMember"]
    rsvpAgent: NotRequired["RemoteClusterMember"]
    tftp: NotRequired["RemoteClusterMember"]
    lbm: NotRequired["RemoteClusterMember"]
    uds: NotRequired["RemoteClusterMember"]


class RemoteDestination(TypedDict, total=False):
    """AXL model — ``XRemoteDestination``.

     Used by ``AXLClient.add_remote_destination()``.
    """

    name: NotRequired[str]
    destination: NotRequired[str]
    answerTooSoonTimer: NotRequired[Any]
    answerTooLateTimer: NotRequired[Any]
    delayBeforeRingingCell: NotRequired[Any]
    ownerUserId: NotRequired[str]
    enableUnifiedMobility: NotRequired[bool]
    remoteDestinationProfileName: NotRequired[str]
    enableExtendAndConnect: NotRequired[bool]
    ctiRemoteDeviceName: NotRequired[str]
    dualModeDeviceName: NotRequired[str]
    isMobilePhone: NotRequired[bool]
    enableMobileConnect: NotRequired[bool]
    lineAssociations: NotRequired[Any]
    timeZone: NotRequired["TimeZone"]
    todAccessName: NotRequired[str]
    mobileSmartClientName: NotRequired[str]
    mobilityProfileName: NotRequired[str]
    singleNumberReachVoicemail: NotRequired["VMAvoidancePolicy"]
    dialViaOfficeReverseVoicemail: NotRequired["VMAvoidancePolicy"]
    ringSchedule: NotRequired[Any]
    accessListName: NotRequired[str]


RemoteDestinationProfile = TypedDict("RemoteDestinationProfile", {
    "name": NotRequired[str],
    "description": NotRequired[str],
    "product": NotRequired["Product"],
    "class": NotRequired["Class"],
    "protocol": NotRequired["DeviceProtocol"],
    "protocolSide": NotRequired["ProtocolSide"],
    "callingSearchSpaceName": NotRequired[str],
    "devicePoolName": NotRequired[str],
    "networkHoldMohAudioSourceId": NotRequired[Any],
    "userHoldMohAudioSourceId": NotRequired[Any],
    "lines": NotRequired[Any],
    "callInfoPrivacyStatus": NotRequired["Status"],
    "userId": NotRequired[str],
    "ignorePresentationIndicators": NotRequired[bool],
    "rerouteCallingSearchSpaceName": NotRequired[str],
    "cgpnTransformationCssName": NotRequired[str],
    "automatedAlternateRoutingCssName": NotRequired[str],
    "useDevicePoolCgpnTransformCss": NotRequired[bool],
    "userLocale": NotRequired["UserLocale"],
    "networkLocale": NotRequired["Country"],
    "primaryPhoneName": NotRequired[str],
    "dndOption": NotRequired["DNDOption"],
    "dndStatus": NotRequired[bool],
    "mobileSmartClientProfileName": NotRequired[str],
}, total=False)
RemoteDestinationProfile.__doc__ = '"""AXL model — ``XRemoteDestinationProfile``.\n\n     Used by ``AXLClient.add_remote_destination_profile()``."""'


class ResourcePriorityNamespace(TypedDict, total=False):
    """AXL model — ``XResourcePriorityNamespace``.

     Used by ``AXLClient.add_resource_priority_namespace()``.
    """

    namespace: NotRequired[Any]
    description: NotRequired[str]
    isDefault: NotRequired[bool]


class ResourcePriorityNamespaceList(TypedDict, total=False):
    """AXL model — ``XResourcePriorityNamespaceList``.

     Used by ``AXLClient.add_resource_priority_namespace_list()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    members: NotRequired[Any]


class RouteFilter(TypedDict, total=False):
    """AXL model — ``XRouteFilter``.

     Used by ``AXLClient.add_route_filter()``.
    """

    name: NotRequired[str]
    dialPlanName: NotRequired[str]
    members: NotRequired[Any]


class RouteGroup(TypedDict, total=False):
    """AXL model — ``XRouteGroup``.

     Used by ``AXLClient.add_route_group()``.
    """

    distributionAlgorithm: NotRequired["DistributeAlgorithm"]
    members: NotRequired[Any]
    name: NotRequired[str]


class RouteList(TypedDict, total=False):
    """AXL model — ``XRouteList``.

     Used by ``AXLClient.add_route_list()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    callManagerGroupName: NotRequired[str]
    routeListEnabled: NotRequired[bool]
    members: NotRequired[Any]
    runOnEveryNode: NotRequired[bool]


class RoutePartition(TypedDict, total=False):
    """AXL model — ``XRoutePartition``.

     Used by ``AXLClient.add_route_partition()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    timeScheduleIdName: NotRequired[str]
    useOriginatingDeviceTimeZone: NotRequired[bool]
    timeZone: NotRequired["TimeZone"]
    partitionUsage: NotRequired["PartitionUsage"]


class RoutePattern(TypedDict, total=False):
    """AXL model — ``XRoutePattern``.

     Used by ``AXLClient.add_route_pattern()``.
    """

    pattern: NotRequired[str]
    description: NotRequired[str]
    routePartitionName: NotRequired[str]
    blockEnable: NotRequired[bool]
    calledPartyTransformationMask: NotRequired[str]
    callingPartyTransformationMask: NotRequired[str]
    useCallingPartyPhoneMask: NotRequired["Status"]
    callingPartyPrefixDigits: NotRequired[str]
    dialPlanName: NotRequired[str]
    digitDiscardInstructionName: NotRequired[str]
    networkLocation: NotRequired["NetworkLocation"]
    patternUrgency: NotRequired[bool]
    prefixDigitsOut: NotRequired[str]
    routeFilterName: NotRequired[str]
    callingLinePresentationBit: NotRequired["PresentationBit"]
    callingNamePresentationBit: NotRequired["PresentationBit"]
    connectedLinePresentationBit: NotRequired["PresentationBit"]
    connectedNamePresentationBit: NotRequired["PresentationBit"]
    supportOverlapSending: NotRequired[bool]
    patternPrecedence: NotRequired["PatternPrecedence"]
    releaseClause: NotRequired["ReleaseCauseValue"]
    allowDeviceOverride: NotRequired[bool]
    provideOutsideDialtone: NotRequired[bool]
    callingPartyNumberingPlan: NotRequired["NumberingPlan"]
    callingPartyNumberType: NotRequired["PriOfNumber"]
    calledPartyNumberingPlan: NotRequired["NumberingPlan"]
    calledPartyNumberType: NotRequired["PriOfNumber"]
    destination: NotRequired[Any]
    authorizationCodeRequired: NotRequired[bool]
    authorizationLevelRequired: NotRequired[Any]
    clientCodeRequired: NotRequired[bool]
    isdnNsfInfoElement: NotRequired[Any]
    resourcePriorityNamespaceName: NotRequired[str]
    routeClass: NotRequired["PatternRouteClass"]
    enableDccEnforcement: NotRequired[bool]
    blockedCallPercentage: NotRequired[str]
    externalCallControl: NotRequired[str]
    isEmergencyServiceNumber: NotRequired[bool]


class SIPNormalizationScript(TypedDict, total=False):
    """AXL model — ``XSIPNormalizationScript``.

     Used by ``AXLClient.add_sipnormalization_script()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    content: NotRequired[str]
    scriptExecutionErrorRecoveryAction: NotRequired["SIPScriptErrorHandling"]
    systemResourceErrorRecoveryAction: NotRequired["SIPScriptErrorHandling"]
    maxMemoryThreshold: NotRequired[str]
    maxLuaInstructionsThreshold: NotRequired[str]
    isStandard: NotRequired[bool]


class SafCcdPurgeBlockLearnedRoutes(TypedDict, total=False):
    """AXL model — ``XSafCcdPurgeBlockLearnedRoutes``.

     Used by ``AXLClient.add_saf_ccd_purge_block_learned_routes()``.
    """

    learnedPattern: NotRequired[str]
    learnedPatternPrefix: NotRequired[str]
    callControlIdentity: NotRequired[str]
    ipAddress: NotRequired[str]


class SafForwarder(TypedDict, total=False):
    """AXL model — ``XSafForwarder``.

     Used by ``AXLClient.add_saf_forwarder()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    clientLabel: NotRequired[str]
    safSecurityProfile: NotRequired[str]
    ipAddress: NotRequired[str]
    port: NotRequired[Any]
    enableTcpKeepAlive: NotRequired[bool]
    safReconnectInterval: NotRequired[Any]
    safNotificationsWindowSize: NotRequired[Any]
    associatedCucms: NotRequired[Any]


class SafSecurityProfile(TypedDict, total=False):
    """AXL model — ``XSafSecurityProfile``.

     Used by ``AXLClient.add_saf_security_profile()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    userid: NotRequired[str]
    password: NotRequired[str]


class SdpTransparencyProfile(TypedDict, total=False):
    """AXL model — ``XSdpTransparencyProfile``.

     Used by ``AXLClient.add_sdp_transparency_profile()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    attributeSet: NotRequired[List[Any]]


class ServiceProfile(TypedDict, total=False):
    """AXL model — ``XServiceProfile``.

     Used by ``AXLClient.add_service_profile()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    isDefault: NotRequired[bool]
    serviceProfileInfos: NotRequired[Any]


class SipDialRules(TypedDict, total=False):
    """AXL model — ``XSipDialRules``.

     Used by ``AXLClient.add_sip_dial_rules()``.
    """

    dialPattern: NotRequired["DialPattern"]
    name: NotRequired[str]
    description: NotRequired[str]
    patterns: NotRequired[Any]
    plars: NotRequired[Any]


class SipProfile(TypedDict, total=False):
    """AXL model — ``XSipProfile``.

     Used by ``AXLClient.add_sip_profile()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    defaultTelephonyEventPayloadType: NotRequired[Any]
    redirectByApplication: NotRequired[bool]
    ringing180: NotRequired[bool]
    timerInvite: NotRequired[Any]
    timerRegisterDelta: NotRequired[Any]
    timerRegister: NotRequired[Any]
    timerT1: NotRequired[Any]
    timerT2: NotRequired[Any]
    retryInvite: NotRequired[Any]
    retryNotInvite: NotRequired[Any]
    startMediaPort: NotRequired[Any]
    stopMediaPort: NotRequired[Any]
    startVideoPort: NotRequired[Any]
    stopVideoPort: NotRequired[Any]
    dscpForAudioCalls: NotRequired[str]
    dscpForVideoCalls: NotRequired[str]
    dscpForAudioPortionOfVideoCalls: NotRequired[str]
    dscpForTelePresenceCalls: NotRequired[str]
    dscpForAudioPortionOfTelePresenceCalls: NotRequired[str]
    callpickupListUri: NotRequired[str]
    callpickupGroupUri: NotRequired[str]
    meetmeServiceUrl: NotRequired[str]
    userInfo: NotRequired["ZzuserInfo"]
    dtmfDbLevel: NotRequired["ZzdtmfDbLevel"]
    callHoldRingback: NotRequired["Zzpreff"]
    anonymousCallBlock: NotRequired["Zzpreff"]
    callerIdBlock: NotRequired["Zzpreff"]
    dndControl: NotRequired["Zzdndcontrol"]
    telnetLevel: NotRequired["TelnetLevel"]
    timerKeepAlive: NotRequired[Any]
    timerSubscribe: NotRequired[Any]
    timerSubscribeDelta: NotRequired[Any]
    maxRedirects: NotRequired[Any]
    timerOffHookToFirstDigit: NotRequired[Any]
    callForwardUri: NotRequired[str]
    abbreviatedDialUri: NotRequired[str]
    confJointEnable: NotRequired[bool]
    rfc2543Hold: NotRequired[bool]
    semiAttendedTransfer: NotRequired[bool]
    enableVad: NotRequired[bool]
    stutterMsgWaiting: NotRequired[bool]
    callStats: NotRequired[bool]
    t38Invite: NotRequired[bool]
    faxInvite: NotRequired[bool]
    rerouteIncomingRequest: NotRequired["SIPReroute"]
    resourcePriorityNamespaceListName: NotRequired[str]
    enableAnatForEarlyOfferCalls: NotRequired[bool]
    rsvpOverSip: NotRequired["RSVPOverSIP"]
    fallbackToLocalRsvp: NotRequired[bool]
    sipRe11XxEnabled: NotRequired["SIPRel1XXOptions"]
    gClear: NotRequired["GClear"]
    sendRecvSDPInMidCallInvite: NotRequired[bool]
    enableOutboundOptionsPing: NotRequired[bool]
    optionsPingIntervalWhenStatusOK: NotRequired[Any]
    optionsPingIntervalWhenStatusNotOK: NotRequired[Any]
    deliverConferenceBridgeIdentifier: NotRequired[bool]
    sipOptionsRetryCount: NotRequired[Any]
    sipOptionsRetryTimer: NotRequired[Any]
    sipBandwidthModifier: NotRequired["SIPBandwidthModifier"]
    enableUriOutdialSupport: NotRequired[str]
    userAgentServerHeaderInfo: NotRequired["UserAgentServerHeaderInfo"]
    allowPresentationSharingUsingBfcp: NotRequired[bool]
    scriptParameters: NotRequired[str]
    isScriptTraceEnabled: NotRequired[bool]
    sipNormalizationScript: NotRequired[str]
    allowiXApplicationMedia: NotRequired[bool]
    dialStringInterpretation: NotRequired["URIDisambiguationPolicy"]
    acceptAudioCodecPreferences: NotRequired["Status"]
    mlppUserAuthorization: NotRequired[bool]
    isAssuredSipServiceEnabled: NotRequired[bool]
    enableExternalQoS: NotRequired[bool]
    resourcePriorityNamespace: NotRequired[str]
    useCallerIdCallerNameinUriOutgoingRequest: NotRequired[bool]
    externalPresentationInfo: NotRequired[Any]
    callingLineIdentification: NotRequired["CallingLineIdentification"]
    rejectAnonymousIncomingCall: NotRequired[bool]
    callpickupUri: NotRequired[str]
    rejectAnonymousOutgoingCall: NotRequired[bool]
    videoCallTrafficClass: NotRequired["VideoCallTrafficClass"]
    sdpTransparency: NotRequired[str]
    allowMultipleCodecs: NotRequired[bool]
    sipSessionRefreshMethod: NotRequired["SipSessionRefreshMethod"]
    earlyOfferSuppVoiceCall: NotRequired["EOSuppVoiceCall"]
    cucmVersionInSipHeader: NotRequired["CUCMVersionInSipHeader"]
    confidentialAccessLevelHeaders: NotRequired["CALHeaders"]
    destRouteString: NotRequired[bool]
    inactiveSDPRequired: NotRequired[bool]
    allowRRAndRSBandwidthModifier: NotRequired[bool]
    connectCallBeforePlayingAnnouncement: NotRequired[bool]


class SipRealm(TypedDict, total=False):
    """AXL model — ``XSipRealm``.

     Used by ``AXLClient.add_sip_realm()``.
    """

    realm: NotRequired[str]
    userid: NotRequired[str]
    digestCredentials: NotRequired[str]


class SipRoutePattern(TypedDict, total=False):
    """AXL model — ``XSipRoutePattern``.

     Used by ``AXLClient.add_sip_route_pattern()``.
    """

    pattern: NotRequired[str]
    description: NotRequired[str]
    usage: NotRequired["PatternUsage"]
    routePartitionName: NotRequired[str]
    blockEnable: NotRequired[bool]
    callingPartyTransformationMask: NotRequired[str]
    useCallingPartyPhoneMask: NotRequired["Status"]
    callingPartyPrefixDigits: NotRequired[str]
    callingLinePresentationBit: NotRequired["PresentationBit"]
    callingNamePresentationBit: NotRequired["PresentationBit"]
    connectedLinePresentationBit: NotRequired["PresentationBit"]
    connectedNamePresentationBit: NotRequired["PresentationBit"]
    sipTrunkName: NotRequired[str]
    dnOrPatternIpv6: NotRequired[str]
    routeOnUserPart: NotRequired[bool]
    useCallerCss: NotRequired[bool]
    domainRoutingCssName: NotRequired[str]


SipTrunk = TypedDict("SipTrunk", {
    "name": NotRequired[str],
    "description": NotRequired[str],
    "product": NotRequired["Product"],
    "class": NotRequired["Class"],
    "protocol": NotRequired["DeviceProtocol"],
    "protocolSide": NotRequired["ProtocolSide"],
    "callingSearchSpaceName": NotRequired[str],
    "devicePoolName": NotRequired[str],
    "commonDeviceConfigName": NotRequired[str],
    "networkLocation": NotRequired["NetworkLocation"],
    "locationName": NotRequired[str],
    "mediaResourceListName": NotRequired[str],
    "networkHoldMohAudioSourceId": NotRequired[Any],
    "userHoldMohAudioSourceId": NotRequired[Any],
    "automatedAlternateRoutingCssName": NotRequired[str],
    "aarNeighborhoodName": NotRequired[str],
    "packetCaptureMode": NotRequired["PacketCaptureMode"],
    "packetCaptureDuration": NotRequired[Any],
    "loadInformation": NotRequired["LoadInformation"],
    "traceFlag": NotRequired[bool],
    "mlppDomainId": NotRequired[str],
    "mlppIndicationStatus": NotRequired["Status"],
    "preemption": NotRequired["Preemption"],
    "useTrustedRelayPoint": NotRequired["Status"],
    "retryVideoCallAsAudio": NotRequired[bool],
    "securityProfileName": NotRequired[str],
    "sipProfileName": NotRequired[str],
    "cgpnTransformationCssName": NotRequired[str],
    "useDevicePoolCgpnTransformCss": NotRequired[bool],
    "geoLocationName": NotRequired[str],
    "geoLocationFilterName": NotRequired[str],
    "sendGeoLocation": NotRequired[bool],
    "cdpnTransformationCssName": NotRequired[str],
    "useDevicePoolCdpnTransformCss": NotRequired[bool],
    "unattendedPort": NotRequired[bool],
    "transmitUtf8": NotRequired[bool],
    "subscribeCallingSearchSpaceName": NotRequired[str],
    "rerouteCallingSearchSpaceName": NotRequired[str],
    "referCallingSearchSpaceName": NotRequired[str],
    "mtpRequired": NotRequired[bool],
    "presenceGroupName": NotRequired[str],
    "unknownPrefix": NotRequired[str],
    "destAddrIsSrv": NotRequired[bool],
    "tkSipCodec": NotRequired["SIPCodec"],
    "sigDigits": NotRequired[Any],
    "connectedNamePresentation": NotRequired["PresentationBit"],
    "connectedPartyIdPresentation": NotRequired["PresentationBit"],
    "callingPartySelection": NotRequired["CallingPartySelection"],
    "callingname": NotRequired["PresentationBit"],
    "callingLineIdPresentation": NotRequired["PresentationBit"],
    "prefixDn": NotRequired[str],
    "externalPresentationInfo": NotRequired[Any],
    "acceptInboundRdnis": NotRequired[bool],
    "acceptOutboundRdnis": NotRequired[bool],
    "srtpAllowed": NotRequired[bool],
    "srtpFallbackAllowed": NotRequired[bool],
    "isPaiEnabled": NotRequired[bool],
    "sipPrivacy": NotRequired["SipPrivacy"],
    "isRpidEnabled": NotRequired[bool],
    "sipAssertedType": NotRequired["SipAssertedType"],
    "trustReceivedIdentity": NotRequired["TrustReceivedIdentity"],
    "dtmfSignalingMethod": NotRequired["DTMFSignaling"],
    "routeClassSignalling": NotRequired["Status"],
    "sipTrunkType": NotRequired["TrunkService"],
    "pstnAccess": NotRequired[bool],
    "imeE164TransformationName": NotRequired[str],
    "useImePublicIpPort": NotRequired[bool],
    "useDevicePoolCntdPnTransformationCss": NotRequired[bool],
    "cntdPnTransformationCssName": NotRequired[str],
    "useDevicePoolCgpnTransformCssUnkn": NotRequired[bool],
    "rdnTransformationCssName": NotRequired[str],
    "useDevicePoolRdnTransformCss": NotRequired[bool],
    "useOrigCallingPartyPresOnDivert": NotRequired[bool],
    "sipNormalizationScriptName": NotRequired[str],
    "runOnEveryNode": NotRequired[bool],
    "destinations": NotRequired[Any],
    "unknownStripDigits": NotRequired[Any],
    "cgpnTransformationUnknownCssName": NotRequired[str],
    "tunneledProtocol": NotRequired["TunneledProtocol"],
    "asn1RoseOidEncoding": NotRequired["ASN1RoseOidEncoding"],
    "qsigVariant": NotRequired["QSIGVariant"],
    "pathReplacementSupport": NotRequired[bool],
    "enableQsigUtf8": NotRequired[bool],
    "scriptParameters": NotRequired[str],
    "scriptTraceEnabled": NotRequired[bool],
    "trunkTrafficSecure": NotRequired["SIPTrunkCallLegSecurity"],
    "callingAndCalledPartyInfoFormat": NotRequired["SIPIdentityBlend"],
    "useCallerIdCallerNameinUriOutgoingRequest": NotRequired[bool],
    "service": NotRequired[str],
    "parameterLabel": NotRequired[str],
    "originatingParameterValue": NotRequired[str],
    "terminatingParameterValue": NotRequired[str],
    "outboundUriRoutingInstructions": NotRequired[str],
    "requestUriDomainName": NotRequired[str],
    "enableCiscoRecordingQsigTunneling": NotRequired[bool],
    "recordingInformation": NotRequired[str],
    "calledPartyUnknownTransformationCssName": NotRequired[str],
    "calledPartyUnknownPrefix": NotRequired[str],
    "calledPartyUnknownStripDigits": NotRequired[Any],
    "useDevicePoolCalledCssUnkn": NotRequired[bool],
    "confidentialAccess": NotRequired[Any],
}, total=False)
SipTrunk.__doc__ = '"""AXL model — ``XSipTrunk``.\n\n     Used by ``AXLClient.add_sip_trunk()``."""'


class SipTrunkSecurityProfile(TypedDict, total=False):
    """AXL model — ``XSipTrunkSecurityProfile``.

     Used by ``AXLClient.add_sip_trunk_security_profile()``.
    """

    name: NotRequired[Any]
    description: NotRequired[str]
    securityMode: NotRequired["DeviceSecurityMode"]
    incomingTransport: NotRequired["Transport"]
    outgoingTransport: NotRequired["Transport"]
    digestAuthentication: NotRequired[bool]
    noncePolicyTime: NotRequired[Any]
    x509SubjectName: NotRequired[str]
    incomingPort: NotRequired[Any]
    applLevelAuthentication: NotRequired[bool]
    acceptPresenceSubscription: NotRequired[bool]
    acceptOutOfDialogRefer: NotRequired[bool]
    acceptUnsolicitedNotification: NotRequired[bool]
    allowReplaceHeader: NotRequired[bool]
    transmitSecurityStatus: NotRequired[bool]
    sipV150OutboundSdpOfferFiltering: NotRequired["V150SDPFilter"]
    allowChargingHeader: NotRequired[bool]


class SoftKeyTemplate(TypedDict, total=False):
    """AXL model — ``XSoftKeyTemplate``.

     Used by ``AXLClient.add_soft_key_template()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    baseSoftkeyTemplateName: NotRequired[str]
    isDefault: NotRequired[bool]


class Srst(TypedDict, total=False):
    """AXL model — ``XSrst``.

     Used by ``AXLClient.add_srst()``.
    """

    name: NotRequired[str]
    port: NotRequired[Any]
    ipAddress: NotRequired[str]
    ipv6Address: NotRequired[str]
    SipNetwork: NotRequired[str]
    SipPort: NotRequired[Any]
    isSecure: NotRequired[bool]


class TimePeriod(TypedDict, total=False):
    """AXL model — ``XTimePeriod``.

     Used by ``AXLClient.add_time_period()``.
    """

    name: NotRequired[str]
    startTime: NotRequired["TimeOfDay"]
    endTime: NotRequired["TimeOfDay"]
    startDay: NotRequired["DayOfWeek"]
    endDay: NotRequired["DayOfWeek"]
    monthOfYear: NotRequired["MonthOfYear"]
    dayOfMonth: NotRequired[Any]
    description: NotRequired[str]
    isPublished: NotRequired[bool]
    todOwnerIdName: NotRequired[str]
    dayOfMonthEnd: NotRequired[Any]
    monthOfYearEnd: NotRequired["MonthOfYear"]


class TimeSchedule(TypedDict, total=False):
    """AXL model — ``XTimeSchedule``.

     Used by ``AXLClient.add_time_schedule()``.
    """

    name: NotRequired[str]
    members: NotRequired[Any]
    description: NotRequired[str]
    isPublished: NotRequired[bool]
    timeScheduleCategory: NotRequired["TimeScheduleCategory"]
    todOwnerIdName: NotRequired[str]


class TodAccess(TypedDict, total=False):
    """AXL model — ``XTodAccess``.

     Used by ``AXLClient.add_tod_access()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    ownerIdName: NotRequired[str]
    members: NotRequired[Any]


class TransPattern(TypedDict, total=False):
    """AXL model — ``XTransPattern``.

     Used by ``AXLClient.add_trans_pattern()``.
    """

    pattern: NotRequired[str]
    description: NotRequired[str]
    usage: NotRequired["PatternUsage"]
    routePartitionName: NotRequired[str]
    blockEnable: NotRequired[bool]
    calledPartyTransformationMask: NotRequired[str]
    callingPartyTransformationMask: NotRequired[str]
    useCallingPartyPhoneMask: NotRequired["Status"]
    callingPartyPrefixDigits: NotRequired[str]
    dialPlanName: NotRequired[str]
    digitDiscardInstructionName: NotRequired[str]
    patternUrgency: NotRequired[bool]
    prefixDigitsOut: NotRequired[str]
    routeFilterName: NotRequired[str]
    callingLinePresentationBit: NotRequired["PresentationBit"]
    callingNamePresentationBit: NotRequired["PresentationBit"]
    connectedLinePresentationBit: NotRequired["PresentationBit"]
    connectedNamePresentationBit: NotRequired["PresentationBit"]
    patternPrecedence: NotRequired["PatternPrecedence"]
    provideOutsideDialtone: NotRequired[bool]
    callingPartyNumberingPlan: NotRequired["NumberingPlan"]
    callingPartyNumberType: NotRequired["PriOfNumber"]
    calledPartyNumberingPlan: NotRequired["NumberingPlan"]
    calledPartyNumberType: NotRequired["PriOfNumber"]
    callingSearchSpaceName: NotRequired[str]
    resourcePriorityNamespaceName: NotRequired[str]
    routeNextHopByCgpn: NotRequired[bool]
    routeClass: NotRequired["PatternRouteClass"]
    callInterceptProfileName: NotRequired[str]
    releaseClause: NotRequired["ReleaseCauseValue"]
    useOriginatorCss: NotRequired[bool]
    dontWaitForIDTOnSubsequentHops: NotRequired[bool]
    isEmergencyServiceNumber: NotRequired[bool]


class Transcoder(TypedDict, total=False):
    """AXL model — ``XTranscoder``.

     Used by ``AXLClient.add_transcoder()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    product: NotRequired["Product"]
    subUnit: NotRequired[Any]
    devicePoolName: NotRequired[str]
    commonDeviceConfigName: NotRequired[str]
    loadInformation: NotRequired["LoadInformation"]
    vendorConfig: NotRequired["VendorConfig"]
    isTrustedRelayPoint: NotRequired[bool]
    maximumCapacity: NotRequired[Any]


class TransformationProfile(TypedDict, total=False):
    """AXL model — ``XTransformationProfile``.

     Used by ``AXLClient.add_transformation_profile()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    nationalStripDigits: NotRequired[Any]
    internationalStripDigits: NotRequired[Any]
    unknownStripDigits: NotRequired[Any]
    subscriberStripDigits: NotRequired[Any]
    nationalPrefix: NotRequired[str]
    internationalPrefix: NotRequired[str]
    unknownPrefix: NotRequired[str]
    subscriberPrefix: NotRequired[str]
    nationalCssName: NotRequired[str]
    internationalCssName: NotRequired[str]
    unknownCssName: NotRequired[str]
    subscriberCssName: NotRequired[str]


class UcService(TypedDict, total=False):
    """AXL model — ``XUcService``.

     Used by ``AXLClient.add_uc_service()``.
    """

    serviceType: NotRequired["UCService"]
    productType: NotRequired["UCProduct"]
    name: NotRequired[str]
    description: NotRequired[str]
    hostnameorip: NotRequired[str]
    port: NotRequired[Any]
    protocol: NotRequired["ConnectProtocol"]
    ucServiceXml: NotRequired["VendorConfig"]


class UnitsToGateway(TypedDict, total=False):
    """AXL model — ``XUnitsToGateway``.

     Used by ``AXLClient.add_units_to_gateway()``.
    """

    domainName: NotRequired[str]
    gatewayUuid: NotRequired[str]
    units: NotRequired[Any]


class UniversalDeviceTemplate(TypedDict, total=False):
    """AXL model — ``XUniversalDeviceTemplate``.

     Used by ``AXLClient.add_universal_device_template()``.
    """

    name: NotRequired[str]
    deviceDescription: NotRequired[str]
    devicePool: NotRequired[str]
    deviceSecurityProfile: NotRequired[str]
    sipProfile: NotRequired[str]
    phoneButtonTemplate: NotRequired[str]
    sipDialRules: NotRequired[str]
    callingSearchSpace: NotRequired[str]
    callingPartyTransformationCSSForInboundCalls: NotRequired[str]
    callingPartyTransformationCSSForOutboundCalls: NotRequired[str]
    reroutingCallingSearchSpace: NotRequired[str]
    subscribeCallingSearchSpaceName: NotRequired[str]
    useDevicePoolCallingPartyTransformationCSSforInboundCalls: NotRequired[bool]
    useDevicePoolCallingPartyTransformationCSSforOutboundCalls: NotRequired[bool]
    commonPhoneProfile: NotRequired[str]
    commonDeviceConfiguration: NotRequired[str]
    softkeyTemplate: NotRequired[str]
    featureControlPolicy: NotRequired[str]
    phonePersonalization: NotRequired["PhonePersonalization"]
    mtpPreferredOriginatingCodec: NotRequired["SIPCodec"]
    outboundCallRollover: NotRequired["OutboundCallRollover"]
    mediaTerminationPointRequired: NotRequired[bool]
    unattendedPort: NotRequired[bool]
    requiredDtmfReception: NotRequired[bool]
    rfc2833Disabled: NotRequired[bool]
    speeddials: NotRequired[Any]
    lines: NotRequired[Any]
    blfDirectedCallParks: NotRequired[Any]
    busyLampFields: NotRequired[Any]
    useTrustedRelayPoint: NotRequired["Status"]
    protectedDevice: NotRequired[bool]
    certificateOperation: NotRequired["CertificateOperation"]
    authenticationMode: NotRequired["AuthenticationMode"]
    authenticationString: NotRequired[str]
    keySize: NotRequired["KeySize"]
    keyOrder: NotRequired["KeyOrder"]
    ecKeySize: NotRequired["ECKeySize"]
    servicesProvisioning: NotRequired["PhoneServiceDisplay"]
    packetCaptureMode: NotRequired["PacketCaptureMode"]
    packetCaptureDuration: NotRequired[Any]
    secureShellUser: NotRequired[str]
    secureShellPassword: NotRequired[str]
    userLocale: NotRequired["UserLocale"]
    networkLocale: NotRequired["Country"]
    mlppDomain: NotRequired[str]
    mlppIndication: NotRequired["Status"]
    mlppPreemption: NotRequired["Preemption"]
    doNotDisturb: NotRequired[bool]
    dndOption: NotRequired["DNDOption"]
    dndIncomingCallAlert: NotRequired["RingSetting"]
    aarGroup: NotRequired[str]
    aarCallingSearchSpace: NotRequired[str]
    blfPresenceGroup: NotRequired[str]
    blfAudibleAlertSettingPhoneBusy: NotRequired["Status"]
    blfAudibleAlertSettingPhoneIdle: NotRequired["Status"]
    userHoldMohAudioSource: NotRequired[Any]
    networkHoldMohAudioSource: NotRequired[Any]
    location: NotRequired[str]
    geoLocation: NotRequired[str]
    deviceMobilityMode: NotRequired["Status"]
    mediaResourceGroupList: NotRequired[str]
    remoteDevice: NotRequired[bool]
    hotlineDevice: NotRequired[bool]
    retryVideoCallAsAudio: NotRequired[bool]
    requireOffPremiseLocation: NotRequired[bool]
    ownerUserId: NotRequired[str]
    mobilityUserId: NotRequired[str]
    joinAcrossLines: NotRequired["Status"]
    alwaysUsePrimeLine: NotRequired["Status"]
    alwaysUsePrimeLineForVoiceMessage: NotRequired["Status"]
    singleButtonBarge: NotRequired["Barge"]
    builtInBridge: NotRequired["Status"]
    allowControlOfDeviceFromCti: NotRequired[bool]
    ignorePresentationIndicators: NotRequired[bool]
    enableExtensionMobility: NotRequired[bool]
    privacy: NotRequired["Status"]
    loggedIntoHuntGroup: NotRequired[bool]
    proxyServer: NotRequired[str]
    servicesUrl: NotRequired[str]
    idle: NotRequired[str]
    idleTimer: NotRequired[Any]
    secureDirUrl: NotRequired[str]
    messages: NotRequired[str]
    secureIdleUrl: NotRequired[str]
    authenticationServer: NotRequired[str]
    directory: NotRequired[str]
    secureServicesUrl: NotRequired[str]
    information: NotRequired[str]
    secureMessagesUrl: NotRequired[str]
    secureInformationUrl: NotRequired[str]
    secureAuthenticationUrl: NotRequired[str]
    confidentialAccess: NotRequired[Any]
    services: NotRequired[Any]


class UniversalLineTemplate(TypedDict, total=False):
    """AXL model — ``XUniversalLineTemplate``.

     Used by ``AXLClient.add_universal_line_template()``.
    """

    name: NotRequired[str]
    urgentPriority: NotRequired[bool]
    lineDescription: NotRequired[str]
    routePartition: NotRequired[str]
    voiceMailProfile: NotRequired[str]
    callingSearchSpace: NotRequired[str]
    alertingName: NotRequired[str]
    extCallControlProfile: NotRequired[str]
    blfPresenceGroup: NotRequired[str]
    callPickupGroup: NotRequired[str]
    partyEntranceTone: NotRequired["Status"]
    autoAnswer: NotRequired["AutoAnswer"]
    rejectAnonymousCall: NotRequired[bool]
    userHoldMohAudioSource: NotRequired[Any]
    networkHoldMohAudioSource: NotRequired[Any]
    aarDestinationMask: NotRequired[str]
    aarGroup: NotRequired[str]
    retainDestInCallFwdHistory: NotRequired[bool]
    forwardDestAllCalls: NotRequired[str]
    primaryCssForwardingAllCalls: NotRequired[str]
    secondaryCssForwardingAllCalls: NotRequired[str]
    CssActivationPolicy: NotRequired["CFACSSActivationPolicy"]
    fwdDestExtCallsWhenNotRetrieved: NotRequired[str]
    cssFwdExtCallsWhenNotRetrieved: NotRequired[str]
    fwdDestInternalCallsWhenNotRetrieved: NotRequired[str]
    cssFwdInternalCallsWhenNotRetrieved: NotRequired[str]
    parkMonitorReversionTime: NotRequired[Any]
    target: NotRequired[str]
    mlppCss: NotRequired[str]
    mlppNoAnsRingDuration: NotRequired[Any]
    confidentialAccess: NotRequired[Any]
    holdReversionRingDuration: NotRequired[Any]
    holdReversionNotificationInterval: NotRequired[Any]
    busyIntCallsDestination: NotRequired[str]
    busyIntCallsCss: NotRequired[str]
    busyExtCallsDestination: NotRequired[str]
    busyExtCallsCss: NotRequired[str]
    noAnsIntCallsDestination: NotRequired[str]
    noAnsIntCallsCss: NotRequired[str]
    noAnsExtCallsDestination: NotRequired[str]
    noAnsExtCallsCss: NotRequired[str]
    noCoverageIntCallsDestination: NotRequired[str]
    noCoverageIntCallsCss: NotRequired[str]
    noCoverageExtCallsDestination: NotRequired[str]
    noCoverageExtCallsCss: NotRequired[str]
    unregisteredIntCallsDestination: NotRequired[str]
    unregisteredIntCallsCss: NotRequired[str]
    unregisteredExtCallsDestination: NotRequired[str]
    unregisteredExtCallsCss: NotRequired[str]
    ctiFailureDestination: NotRequired[str]
    ctiFailureCss: NotRequired[str]
    callControlAgentProfile: NotRequired[str]
    noAnswerRingDuration: NotRequired[Any]
    enterpriseAltNum: NotRequired[Any]
    e164AltNum: NotRequired[Any]
    advertisedFailoverNumber: NotRequired[str]


class User(TypedDict, total=False):
    """AXL model — ``XUser``.

     Used by ``AXLClient.add_user()``.
    """

    firstName: NotRequired[str]
    displayName: NotRequired[str]
    middleName: NotRequired[str]
    lastName: NotRequired[str]
    emMaxLoginTime: NotRequired[Any]
    userid: NotRequired[str]
    password: NotRequired[str]
    pin: NotRequired[str]
    mailid: NotRequired[str]
    department: NotRequired[str]
    manager: NotRequired[str]
    userLocale: NotRequired["UserLocale"]
    associatedDevices: NotRequired[Any]
    primaryExtension: NotRequired[Any]
    associatedPc: NotRequired[str]
    associatedGroups: NotRequired[Any]
    enableCti: NotRequired[bool]
    digestCredentials: NotRequired[str]
    phoneProfiles: NotRequired[Any]
    defaultProfile: NotRequired[str]
    presenceGroupName: NotRequired[str]
    subscribeCallingSearchSpaceName: NotRequired[str]
    enableMobility: NotRequired[bool]
    enableMobileVoiceAccess: NotRequired[bool]
    maxDeskPickupWaitTime: NotRequired[Any]
    remoteDestinationLimit: NotRequired[Any]
    passwordCredentials: NotRequired[Any]
    pinCredentials: NotRequired[Any]
    enableEmcc: NotRequired[bool]
    ctiControlledDeviceProfiles: NotRequired[Any]
    patternPrecedence: NotRequired["PatternPrecedence"]
    numericUserId: NotRequired[str]
    mlppPassword: NotRequired[str]
    customUserFields: NotRequired[Any]
    homeCluster: NotRequired[bool]
    imAndPresenceEnable: NotRequired[bool]
    serviceProfile: NotRequired[str]
    lineAppearanceAssociationForPresences: NotRequired[Any]
    directoryUri: NotRequired[str]
    telephoneNumber: NotRequired[str]
    title: NotRequired[str]
    mobileNumber: NotRequired[str]
    homeNumber: NotRequired[str]
    pagerNumber: NotRequired[str]
    extensionsInfo: NotRequired[Any]
    selfService: NotRequired[str]
    userProfile: NotRequired[str]
    calendarPresence: NotRequired[bool]
    ldapDirectoryName: NotRequired[str]
    userIdentity: NotRequired[str]
    nameDialing: NotRequired[str]
    ipccExtension: NotRequired[str]
    ipccRoutePartition: NotRequired[str]
    convertUserAccount: NotRequired[str]
    enableUserToHostConferenceNow: NotRequired[bool]
    attendeesAccessCode: NotRequired[str]
    zeroHop: NotRequired[bool]
    customerName: NotRequired[str]
    associatedHeadsets: NotRequired[Any]


class UserGroup(TypedDict, total=False):
    """AXL model — ``XUserGroup``.

     Used by ``AXLClient.add_user_group()``.
    """

    members: NotRequired[Any]
    userRoles: NotRequired[Any]
    name: NotRequired[str]


class UserPhoneAssociation(TypedDict, total=False):
    """AXL model — ``XUserPhoneAssociation``.

     Used by ``AXLClient.add_user_phone_association()``.
    """

    userId: NotRequired[str]
    password: NotRequired[str]
    pin: NotRequired[Any]
    lastName: NotRequired[str]
    middleName: NotRequired[str]
    firstName: NotRequired[str]
    productType: NotRequired["Model"]
    name: NotRequired[str]
    dnCssName: NotRequired[str]
    phoneCssName: NotRequired[str]
    e164Mask: NotRequired[str]
    extension: NotRequired[str]
    routePartitionName: NotRequired[str]
    voiceMailProfileName: NotRequired[str]
    enableExtensionMobility: NotRequired[bool]
    DirectoryURI: NotRequired[str]
    DirectoryNumberURIPartition: NotRequired[str]


class UserProfileProvision(TypedDict, total=False):
    """AXL model — ``XUserProfileProvision``.

     Used by ``AXLClient.add_user_profile_provision()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    deskPhones: NotRequired[str]
    mobileDevices: NotRequired[str]
    profile: NotRequired[str]
    universalLineTemplate: NotRequired[str]
    allowProvision: NotRequired[bool]
    limitProvision: NotRequired[Any]
    allowPhoneReassign: NotRequired[bool]
    defaultUserProfile: NotRequired[str]
    enableMra: NotRequired[bool]
    mraPolicy_Desktop: NotRequired["MRAPolicy"]
    mraPolicy_Mobile: NotRequired["MRAPolicy"]
    allowProvisionEMMaxLoginTime: NotRequired[bool]


class Vg224(TypedDict, total=False):
    """AXL model — ``XVg224``.

     Used by ``AXLClient.add_vg224()``.
    """

    domainName: NotRequired[str]
    description: NotRequired[str]
    product: NotRequired["Product"]
    protocol: NotRequired["DeviceProtocol"]
    callManagerGroupName: NotRequired[str]
    units: NotRequired[Any]
    vendorConfig: NotRequired["VendorConfig"]
    versionStamp: NotRequired[str]


class VmPilot(TypedDict, total=False):
    """AXL model — ``XVmPilot``.
    """

    dirn: NotRequired[str]
    cssName: NotRequired[str]


class VohServer(TypedDict, total=False):
    """AXL model — ``XVohServer``.

     Used by ``AXLClient.add_voh_server()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    sipTrunkName: NotRequired[str]
    defaultVideoStreamId: NotRequired[str]


class VoiceMailPilot(TypedDict, total=False):
    """AXL model — ``XVoiceMailPilot``.

     Used by ``AXLClient.add_voice_mail_pilot()``.
    """

    dirn: NotRequired[str]
    description: NotRequired[str]
    cssName: NotRequired[str]
    isDefault: NotRequired[bool]


VoiceMailPort = TypedDict("VoiceMailPort", {
    "name": NotRequired[str],
    "description": NotRequired[str],
    "product": NotRequired["Product"],
    "class": NotRequired["Class"],
    "protocol": NotRequired["DeviceProtocol"],
    "protocolSide": NotRequired["ProtocolSide"],
    "callingSearchSpaceName": NotRequired[str],
    "devicePoolName": NotRequired[str],
    "commonDeviceConfigName": NotRequired[str],
    "locationName": NotRequired[str],
    "preemption": NotRequired["Preemption"],
    "useTrustedRelayPoint": NotRequired["Status"],
    "securityProfileName": NotRequired[str],
    "geoLocationName": NotRequired[str],
    "automatedAlternateRoutingCssName": NotRequired[str],
    "dnPattern": NotRequired[str],
    "routePartition": NotRequired[str],
    "dnCallingSearchSpace": NotRequired[str],
    "aarNeighborhoodName": NotRequired[str],
    "callerIdDisplay": NotRequired[str],
    "callerIdDisplayAscii": NotRequired[str],
    "externalMask": NotRequired[str],
}, total=False)
VoiceMailPort.__doc__ = '"""AXL model — ``XVoiceMailPort``.\n\n     Used by ``AXLClient.add_voice_mail_port()``."""'


class VoiceMailProfile(TypedDict, total=False):
    """AXL model — ``XVoiceMailProfile``.

     Used by ``AXLClient.add_voice_mail_profile()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    isDefault: NotRequired[bool]
    voiceMailboxMask: NotRequired[str]
    voiceMailPilot: NotRequired["VmPilot"]


class VpnGateway(TypedDict, total=False):
    """AXL model — ``XVpnGateway``.

     Used by ``AXLClient.add_vpn_gateway()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    url: NotRequired[str]
    certificates: NotRequired[Any]


class VpnGroup(TypedDict, total=False):
    """AXL model — ``XVpnGroup``.

     Used by ``AXLClient.add_vpn_group()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    vpnGateways: NotRequired[Any]


class VpnProfile(TypedDict, total=False):
    """AXL model — ``XVpnProfile``.

     Used by ``AXLClient.add_vpn_profile()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    autoNetworkDetection: NotRequired[bool]
    mtu: NotRequired[Any]
    failToConnect: NotRequired[Any]
    clientAuthentication: NotRequired["VPNClientAuthentication"]
    pwdPersistant: NotRequired[bool]
    enableHostIdCheck: NotRequired[bool]


class WLANProfile(TypedDict, total=False):
    """AXL model — ``XWLANProfile``.

     Used by ``AXLClient.add_wlanprofile()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    ssid: NotRequired[str]
    frequencyBand: NotRequired["WiFiFrequency"]
    userModifiable: NotRequired["WLANProfileChanges"]
    authMethod: NotRequired["WiFiAuthenticationMethod"]
    userName: NotRequired[str]
    password: NotRequired[str]
    pskPassphrase: NotRequired[str]
    wepKey: NotRequired[str]
    passwordDescription: NotRequired[str]
    networkAccessProfile: NotRequired[str]


class WifiHotspot(TypedDict, total=False):
    """AXL model — ``XWifiHotspot``.

     Used by ``AXLClient.add_wifi_hotspot()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    ssidPrefix: NotRequired[str]
    userModifiable: NotRequired["WLANProfileChanges"]
    frequencyBand: NotRequired["WiFiFrequency"]
    authenticationMethod: NotRequired["HotspotAuthenticationMethod"]
    hostName: NotRequired[Any]
    port: NotRequired[Any]
    sharedSecret: NotRequired[str]
    pskPassPhrase: NotRequired[str]
    wepKey: NotRequired[str]
    passwordDescription: NotRequired[str]


class WirelessAccessPointControllers(TypedDict, total=False):
    """AXL model — ``XWirelessAccessPointControllers``.

     Used by ``AXLClient.add_wireless_access_point_controllers()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    snmpVersion: NotRequired["SNMPVersion"]
    snmpUserIdOrCommunityString: NotRequired[str]
    snmpAuthenticationProtocol: NotRequired["SNMPAuthenticationProtocol"]
    snmpAuthenticationPassword: NotRequired[str]
    snmpPrivacyProtocol: NotRequired["SNMPPrivacyProtocol"]
    snmpPrivacyPassword: NotRequired[str]
    syncNow: NotRequired[bool]
    resyncInterval: NotRequired[Any]
    nextSyncTime: NotRequired[Any]
    scheduleUnit: NotRequired["ScheduleUnit"]


class WlanProfileGroup(TypedDict, total=False):
    """AXL model — ``XWlanProfileGroup``.

     Used by ``AXLClient.add_wlan_profile_group()``.
    """

    name: NotRequired[str]
    description: NotRequired[str]
    members: NotRequired[Any]



# ═══════════════════════════════════════════════════════════════════
#  Update models — used with Unpack for update_* method kwargs
# ═══════════════════════════════════════════════════════════════════


class UpdateAarGroup(TypedDict, total=False):
    """AXL update model — ``UpdateAarGroupReq``.

     Used by ``AXLClient.update_aar_group()``.
    """

    name: str
    uuid: str
    newName: Any


class UpdateAarGroupMatrix(TypedDict, total=False):
    """AXL update model — ``UpdateAarGroupMatrixReq``.

     Used by ``AXLClient.update_aar_group_matrix()``.
    """

    uuid: str
    aarGroupFromName: str
    aarGroupToName: str
    prefixDigit: str


class UpdateAdvertisedPatterns(TypedDict, total=False):
    """AXL update model — ``UpdateAdvertisedPatternsReq``.

     Used by ``AXLClient.update_advertised_patterns()``.
    """

    uuid: str
    pattern: str
    description: str
    newPattern: str
    patternType: "GlobalNumber"
    hostedRoutePSTNRule: "HostedRoutePatternPSTNRule"
    pstnFailStrip: Any
    pstnFailPrepend: str


class UpdateAnnouncement(TypedDict, total=False):
    """AXL update model — ``UpdateAnnouncementReq``.

     Used by ``AXLClient.update_announcement()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    announcementFile: "AnnouncementFile"


class UpdateAnnunciator(TypedDict, total=False):
    """AXL update model — ``UpdateAnnunciatorReq``.

     Used by ``AXLClient.update_annunciator()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    devicePoolName: str
    locationName: str
    useTrustedRelayPoint: "Status"


class UpdateAppServerInfo(TypedDict, total=False):
    """AXL update model — ``UpdateAppServerInfoReq``.

     Used by ``AXLClient.update_app_server_info()``.
    """

    uuid: str
    appServerName: str
    appServerContent: "AppServerContent"
    content: "Content"


class UpdateAppUser(TypedDict, total=False):
    """AXL update model — ``UpdateAppUserReq``.

     Used by ``AXLClient.update_app_user()``.
    """

    uuid: str
    userid: str
    newUserid: str
    password: str
    passwordCredentials: Any
    digestCredentials: str
    presenceGroupName: str
    acceptPresenceSubscription: bool
    acceptOutOfDialogRefer: bool
    acceptUnsolicitedNotification: bool
    allowReplaceHeader: bool
    associatedDevices: Any
    associatedGroups: Any
    ctiControlledDeviceProfiles: Any


class UpdateApplicationDialRules(TypedDict, total=False):
    """AXL update model — ``UpdateApplicationDialRulesReq``.

     Used by ``AXLClient.update_application_dial_rules()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    numberBeginWith: str
    numberOfDigits: Any
    digitsToBeRemoved: Any
    prefixPattern: str
    priority: Any


class UpdateApplicationServer(TypedDict, total=False):
    """AXL update model — ``UpdateApplicationServerReq``.

     Used by ``AXLClient.update_application_server()``.
    """

    uuid: str
    newName: str
    ipAddress: str
    removeAppUsers: Any
    addAppUsers: Any
    appUsers: Any
    url: str
    endUserUrl: str
    processNodeName: str
    removeEndUsers: Any
    addEndUsers: Any
    endUsers: Any


class UpdateApplicationUserCapfProfile(TypedDict, total=False):
    """AXL update model — ``UpdateApplicationUserCapfProfileReq``.

     Used by ``AXLClient.update_application_user_capf_profile()``.
    """

    uuid: str
    instanceId: str
    certificateOperation: "CertificateOperation"
    authenticationMode: "AuthenticationMode"
    authenticationString: str
    keySize: "KeySize"
    keyOrder: "KeyOrder"
    ecKeySize: "ECKeySize"
    operationCompletion: str


class UpdateAudioCodecPreferenceList(TypedDict, total=False):
    """AXL update model — ``UpdateAudioCodecPreferenceListReq``.

     Used by ``AXLClient.update_audio_codec_preference_list()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    codecsInList: Any


class UpdateBillingServer(TypedDict, total=False):
    """AXL update model — ``UpdateBillingServerReq``.

     Used by ``AXLClient.update_billing_server()``.
    """

    uuid: str
    userId: str
    password: str
    resendOnFailure: bool
    billingServerProtocol: "Billingserverprotocol"


class UpdateBlockedLearnedPatterns(TypedDict, total=False):
    """AXL update model — ``UpdateBlockedLearnedPatternsReq``.

     Used by ``AXLClient.update_blocked_learned_patterns()``.
    """

    uuid: str
    pattern: str
    description: str
    newPattern: str
    prefix: str
    clusterId: str
    patternType: "GlobalNumber"


class UpdateCCAProfiles(TypedDict, total=False):
    """AXL update model — ``UpdateCCAProfilesReq``.

     Used by ``AXLClient.update_ccaprofiles()``.
    """

    uuid: str
    ccaId: str
    newCcaId: str
    primarySoftSwitchId: str
    secondarySoftSwitchId: str
    objectClass: str
    subscriberType: str
    sipAliasSuffix: str
    sipUserNameSuffix: str


class UpdateCallManager(TypedDict, total=False):
    """AXL update model — ``UpdateCallManagerReq``.

     Used by ``AXLClient.update_call_manager()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    autoRegistration: Any
    ports: Any
    lbmGroup: str


class UpdateCallManagerGroup(TypedDict, total=False):
    """AXL update model — ``UpdateCallManagerGroupReq``.

     Used by ``AXLClient.update_call_manager_group()``.
    """

    name: str
    uuid: str
    newName: str
    tftpDefault: bool
    removeMembers: Any
    addMembers: Any
    members: Any


class UpdateCallPark(TypedDict, total=False):
    """AXL update model — ``UpdateCallParkReq``.

     Used by ``AXLClient.update_call_park()``.
    """

    uuid: str
    pattern: str
    routePartitionName: str
    newPattern: str
    description: str
    newRoutePartitionName: str
    callManagerName: str


class UpdateCallPickupGroup(TypedDict, total=False):
    """AXL update model — ``UpdateCallPickupGroupReq``.

     Used by ``AXLClient.update_call_pickup_group()``.
    """

    uuid: str
    name: Any
    pattern: str
    routePartitionName: str
    newPattern: str
    description: str
    newRoutePartitionName: str
    removeMembers: Any
    addMembers: Any
    members: Any
    pickupNotification: "PickupNotification"
    pickupNotificationTimer: Any
    callInfoForPickupNotification: Any
    newName: str


class UpdateCalledPartyTransformationPattern(TypedDict, total=False):
    """AXL update model — ``UpdateCalledPartyTransformationPatternReq``.

     Used by ``AXLClient.update_called_party_transformation_pattern()``.
    """

    uuid: str
    pattern: str
    routePartitionName: str
    dialPlanName: str
    routeFilterName: str
    newPattern: str
    description: str
    newRoutePartitionName: str
    calledPartyTransformationMask: str
    newDialPlanName: str
    digitDiscardInstructionName: str
    newRouteFilterName: str
    calledPartyPrefixDigits: str
    calledPartyNumberingPlan: "NumberingPlan"
    calledPartyNumberType: "PriOfNumber"
    mlppPreemptionDisabled: bool


class UpdateCallerFilterList(TypedDict, total=False):
    """AXL update model — ``UpdateCallerFilterListReq``.

     Used by ``AXLClient.update_caller_filter_list()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    removeMembers: Any
    addMembers: Any
    members: Any


class UpdateCallingPartyTransformationPattern(TypedDict, total=False):
    """AXL update model — ``UpdateCallingPartyTransformationPatternReq``.

     Used by ``AXLClient.update_calling_party_transformation_pattern()``.
    """

    uuid: str
    pattern: str
    routePartitionName: str
    dialPlanName: str
    routeFilterName: str
    newPattern: str
    description: str
    newRoutePartitionName: str
    callingPartyTransformationMask: str
    useCallingPartyPhoneMask: "Status"
    newDialPlanName: str
    digitDiscardInstructionName: str
    callingPartyPrefixDigits: str
    newRouteFilterName: str
    callingLinePresentationBit: "PresentationBit"
    callingPartyNumberingPlan: "NumberingPlan"
    callingPartyNumberType: "PriOfNumber"
    mlppPreemptionDisabled: bool


class UpdateCcdAdvertisingService(TypedDict, total=False):
    """AXL update model — ``UpdateCcdAdvertisingServiceReq``.

     Used by ``AXLClient.update_ccd_advertising_service()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    isActivated: bool
    hostDnGroup: str
    safSipTrunk: str
    safH323Trunk: str


class UpdateCcdFeatureConfig(TypedDict, total=False):
    """AXL update model — ``UpdateCcdFeatureConfigReq``.

     Used by ``AXLClient.update_ccd_feature_config()``.
    """

    ccdParam: List["RCcdParam"]


class UpdateCcdHostedDN(TypedDict, total=False):
    """AXL update model — ``UpdateCcdHostedDNReq``.

     Used by ``AXLClient.update_ccd_hosted_dn()``.
    """

    uuid: str
    hostedPattern: str
    newHostedPattern: str
    description: str
    CcdHostedDnGroup: str
    pstnFailoverStripDigits: Any
    pstnFailoverPrependDigits: str
    usePstnFailover: bool


class UpdateCcdHostedDNGroup(TypedDict, total=False):
    """AXL update model — ``UpdateCcdHostedDNGroupReq``.

     Used by ``AXLClient.update_ccd_hosted_dngroup()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    pstnFailoverStripDigits: Any
    pstnFailoverPrependDigits: str
    usePstnFailover: bool


class UpdateCcdRequestingService(TypedDict, total=False):
    """AXL update model — ``UpdateCcdRequestingServiceReq``.

     Used by ``AXLClient.update_ccd_requesting_service()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    isActivated: bool
    routePartitionName: str
    learnedPatternPrefix: str
    pstnPrefix: str
    removeAssociatedTrunks: Any
    addAssociatedTrunks: Any
    associatedTrunks: Any


class UpdateCiscoCatalyst600024PortFXSGateway(TypedDict, total=False):
    """AXL update model — ``UpdateCiscoCatalyst600024PortFXSGatewayReq``.

     Used by ``AXLClient.update_cisco_catalyst600024_port_fxsgateway()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    callingSearchSpaceName: str
    devicePoolName: str
    commonDeviceConfigName: str
    networkLocale: "Country"
    locationName: str
    mediaResourceListName: str
    automatedAlternateRoutingCssName: str
    aarNeighborhoodName: str
    loadInformation: "LoadInformation"
    vendorConfig: "VendorConfig"
    traceFlag: bool
    mlppDomainId: str
    useTrustedRelayPoint: "Status"
    cgpnTransformationCssName: str
    useDevicePoolCgpnTransformCss: bool
    geoLocationName: str
    ports: Any
    portSelectionOrder: "TrunkSelectionOrder"
    transmitUtf8: bool
    geoLocationFilterName: str


class UpdateCiscoCatalyst6000E1VoIPGateway(TypedDict, total=False):
    """AXL update model — ``UpdateCiscoCatalyst6000E1VoIPGatewayReq``.

     Used by ``AXLClient.update_cisco_catalyst6000_e1_vo_ipgateway()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    callingSearchSpaceName: str
    devicePoolName: str
    commonDeviceConfigName: str
    networkLocation: "NetworkLocation"
    locationName: str
    networkLocale: "Country"
    mediaResourceListName: str
    automatedAlternateRoutingCssName: str
    aarNeighborhoodName: str
    loadInformation: "LoadInformation"
    vendorConfig: "VendorConfig"
    mlppDomainId: str
    useTrustedRelayPoint: "Status"
    cgpnTransformationCssName: str
    useDevicePoolCgpnTransformCss: bool
    geoLocationName: str
    redirectInboundNumberIe: bool
    calledPlan: "NumberingPlan"
    calledPri: "PriOfNumber"
    callerIdDn: str
    callingPartySelection: "CallingPartySelection"
    callingPlan: "NumberingPlan"
    callingPri: "PriOfNumber"
    chanIe: "PRIChanIE"
    clockReference: "ClockReference"
    dChannelEnable: bool
    channelSelectionOrder: "TrunkSelectionOrder"
    displayIE: bool
    pcmType: "Encode"
    csuParam: "CSUParam"
    firstDelay: Any
    interfaceIdPresent: bool
    interfaceId: Any
    intraDelay: Any
    mcdnEnable: bool
    redirectOutboundNumberIe: bool
    numDigitsToStrip: Any
    passingPrecedenceLevelThrough: bool
    prefix: str
    callingLinePresentationBit: "PresentationBit"
    connectedLineIdPresentation: "PresentationBit"
    priProtocol: "PriProtocol"
    securityAccessLevel: Any
    sendCallingNameInFacilityIe: bool
    sendExLeadingCharInDispIe: bool
    sendRestart: bool
    setupNonIsdnPi: bool
    sigDigits: Any
    span: Any
    statusPoll: bool
    smdiBasePort: Any
    packetCaptureMode: "PacketCaptureMode"
    packetCaptureDuration: Any
    transmitUtf8: bool
    v150: bool
    asn1RoseOidEncoding: "ASN1RoseOidEncoding"
    QSIGVariant: "QSIGVariant"
    unattendedPort: bool
    cdpnTransformationCssName: str
    useDevicePoolCdpnTransformCss: bool
    nationalPrefix: str
    internationalPrefix: str
    unknownPrefix: str
    subscriberPrefix: str
    geoLocationFilterName: str
    nationalStripDigits: Any
    internationalStripDigits: Any
    unknownStripDigits: Any
    subscriberStripDigits: Any
    nationalTransformationCssName: str
    internationalTransformationCssName: str
    unknownTransformationCssName: str
    subscriberTransformationCssName: str
    useDevicePoolCgpnTransformCssNatl: bool
    useDevicePoolCgpnTransformCssIntl: bool
    useDevicePoolCgpnTransformCssUnkn: bool
    useDevicePoolCgpnTransformCssSubs: bool
    pstnAccess: bool
    imeE164TransformationName: str


class UpdateCiscoCatalyst6000T1VoIPGatewayPri(TypedDict, total=False):
    """AXL update model — ``UpdateCiscoCatalyst6000T1VoIPGatewayPriReq``.

     Used by ``AXLClient.update_cisco_catalyst6000_t1_vo_ipgateway_pri()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    callingSearchSpaceName: str
    devicePoolName: str
    commonDeviceConfigName: str
    networkLocation: "NetworkLocation"
    locationName: str
    networkLocale: "Country"
    mediaResourceListName: str
    automatedAlternateRoutingCssName: str
    aarNeighborhoodName: str
    loadInformation: "LoadInformation"
    vendorConfig: "VendorConfig"
    mlppDomainId: str
    mlppIndicationStatus: "Status"
    mlppPreemption: "Preemption"
    useTrustedRelayPoint: "Status"
    cgpnTransformationCssName: str
    useDevicePoolCgpnTransformCss: bool
    geoLocationName: str
    redirectInboundNumberIe: bool
    calledPlan: "NumberingPlan"
    calledPri: "PriOfNumber"
    callerIdDn: str
    callingPartySelection: "CallingPartySelection"
    callingPlan: "NumberingPlan"
    callingPri: "PriOfNumber"
    chanIe: "PRIChanIE"
    clockReference: "ClockReference"
    dChannelEnable: bool
    channelSelectionOrder: "TrunkSelectionOrder"
    displayIE: bool
    pcmType: "Encode"
    csuParam: "CSUParam"
    firstDelay: Any
    interfaceIdPresent: bool
    interfaceId: Any
    intraDelay: Any
    mcdnEnable: bool
    redirectOutboundNumberIe: bool
    numDigitsToStrip: Any
    passingPrecedenceLevelThrough: bool
    prefix: str
    callingLinePresentationBit: "PresentationBit"
    connectedLineIdPresentation: "PresentationBit"
    priProtocol: "PriProtocol"
    securityAccessLevel: Any
    sendCallingNameInFacilityIe: bool
    sendExLeadingCharInDispIe: bool
    sendRestart: bool
    setupNonIsdnPi: bool
    sigDigits: Any
    span: Any
    statusPoll: bool
    smdiBasePort: Any
    packetCaptureMode: "PacketCaptureMode"
    packetCaptureDuration: Any
    transmitUtf8: bool
    v150: bool
    asn1RoseOidEncoding: "ASN1RoseOidEncoding"
    QSIGVariant: "QSIGVariant"
    unattendedPort: bool
    cdpnTransformationCssName: str
    useDevicePoolCdpnTransformCss: bool
    nationalPrefix: str
    internationalPrefix: str
    unknownPrefix: str
    subscriberPrefix: str
    geoLocationFilterName: str
    nationalStripDigits: Any
    internationalStripDigits: Any
    unknownStripDigits: Any
    subscriberStripDigits: Any
    nationalTransformationCssName: str
    internationalTransformationCssName: str
    unknownTransformationCssName: str
    subscriberTransformationCssName: str
    useDevicePoolCgpnTransformCssNatl: bool
    useDevicePoolCgpnTransformCssIntl: bool
    useDevicePoolCgpnTransformCssUnkn: bool
    useDevicePoolCgpnTransformCssSubs: bool
    pstnAccess: bool
    imeE164TransformationName: str


class UpdateCiscoCatalyst6000T1VoIPGatewayT1(TypedDict, total=False):
    """AXL update model — ``UpdateCiscoCatalyst6000T1VoIPGatewayT1Req``.

     Used by ``AXLClient.update_cisco_catalyst6000_t1_vo_ipgateway_t1()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    callingSearchSpaceName: str
    devicePoolName: str
    commonDeviceConfigName: str
    networkLocation: "NetworkLocation"
    locationName: str
    mediaResourceListName: str
    automatedAlternateRoutingCssName: str
    aarNeighborhoodName: str
    loadInformation: "LoadInformation"
    vendorConfig: "VendorConfig"
    traceFlag: bool
    mlppDomainId: str
    mlppIndicationStatus: "Status"
    preemption: "Preemption"
    useTrustedRelayPoint: "Status"
    retryVideoCallAsAudio: bool
    cgpnTransformationCssName: str
    useDevicePoolCgpnTransformCss: bool
    geoLocationName: str
    sendGeoLocation: bool
    ports: Any
    trunkSelectionOrder: "TrunkSelectionOrder"
    clockReference: "ClockReference"
    csuParam: "CSUParam"
    digitSending: "DigitSending"
    pcmType: "Encode"
    fdlChannel: "FDLChannel"
    yellowAlarm: "YellowAlarm"
    zeroSupression: "ZeroSuppression"
    smdiBasePort: Any
    handleDtmfPrecedenceSignals: bool
    cdpnTransformationCssName: str
    useDevicePoolCdpnTransformCss: bool
    geoLocationFilterName: str
    pstnAccess: bool
    imeE164TransformationName: str


class UpdateCiscoCloudOnboarding(TypedDict, total=False):
    """AXL update model — ``UpdateCiscoCloudOnboardingReq``.

     Used by ``AXLClient.update_cisco_cloud_onboarding()``.
    """

    uuid: str
    voucherExists: bool
    enablePushNotifications: bool
    enableHttpProxy: bool
    httpProxyAddress: str
    proxyUsername: str
    proxyPassword: str
    enableTrustCACertificate: bool
    allowAnalyticsCollection: bool
    enableTroubleshooting: bool
    alarmSendEncryptedData: bool
    orgId: str
    serviceAddress: str
    orgName: str
    enableGDSCommunication: bool
    mraActivationDomain: str


class UpdateCmcInfo(TypedDict, total=False):
    """AXL update model — ``UpdateCmcInfoReq``.

     Used by ``AXLClient.update_cmc_info()``.
    """

    uuid: str
    code: str
    newCode: str
    description: str


class UpdateCommonDeviceConfig(TypedDict, total=False):
    """AXL update model — ``UpdateCommonDeviceConfigReq``.

     Used by ``AXLClient.update_common_device_config()``.
    """

    name: str
    uuid: str
    newName: str
    softkeyTemplateName: str
    userLocale: "UserLocale"
    networkHoldMohAudioSourceId: Any
    userHoldMohAudioSourceId: Any
    mlppDomainId: str
    mlppIndicationStatus: "Status"
    useTrustedRelayPoint: bool
    preemption: "Preemption"
    ipAddressingMode: "IPAddressingMode"
    ipAddressingModePreferenceControl: "IPAddressingModePrefControl"
    allowAutoConfigurationForPhones: "Status"
    useImeForOutboundCalls: "Status"
    confidentialAccess: Any
    allowDuplicateAddressDetection: "Status"
    acceptRedirectMessages: "Status"
    replyMulticastEchoRequest: "Status"


class UpdateCommonPhoneConfig(TypedDict, total=False):
    """AXL update model — ``UpdateCommonPhoneConfigReq``.

     Used by ``AXLClient.update_common_phone_config()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    unlockPwd: str
    dndOption: "DNDOption"
    dndAlertingType: "RingSetting"
    backgroundImage: bool
    phonePersonalization: "PhonePersonalization"
    phoneServiceDisplay: "PhoneServiceDisplay"
    sshUserId: str
    sshPwd: str
    vendorConfig: "VendorConfig"
    alwaysUsePrimeLine: "Status"
    alwaysUsePrimeLineForVoiceMessage: "Status"
    vpnGroupName: str
    vpnProfileName: str
    featureControlPolicy: str
    wifiHotspotProfile: str


class UpdateConferenceBridge(TypedDict, total=False):
    """AXL update model — ``UpdateConferenceBridgeReq``.

     Used by ``AXLClient.update_conference_bridge()``.
    """

    name: str
    uuid: str
    newName: Any
    description: str
    product: "Product"
    devicePoolName: str
    commonDeviceConfigName: str
    locationName: str
    loadInformation: "LoadInformation"
    vendorConfig: "VendorConfig"
    maximumCapacity: Any
    useTrustedRelayPoint: "Status"
    securityProfileName: str
    destinationAddress: str
    mcuConferenceBridgeSipPort: Any
    sipProfile: str
    srtpAllowed: bool
    normalizationScript: str
    enableTrace: bool
    normalizationScriptInfos: Any
    userName: str
    password: str
    httpPort: Any
    useHttps: bool
    addresses: Any
    conferenceBridgePrefix: str
    allowCFBControlOfCallSecurityIcon: bool
    overrideSIPTrunkAddress: bool
    sipTrunkName: str


class UpdateConferenceNow(TypedDict, total=False):
    """AXL update model — ``UpdateConferenceNowReq``.

     Used by ``AXLClient.update_conference_now()``.
    """

    uuid: str
    conferenceNowNumber: str
    routePartitionName: str
    newConferenceNowNumber: str
    newRoutePartitionName: str
    description: str
    maxWaitTimeForHost: Any
    MohAudioSourceId: Any


class UpdateCredentialPolicy(TypedDict, total=False):
    """AXL update model — ``UpdateCredentialPolicyReq``.

     Used by ``AXLClient.update_credential_policy()``.
    """

    name: str
    uuid: str
    newName: str
    failedLogon: Any
    resetFailedLogonAttempts: Any
    lockoutDuration: Any
    credChangeDuration: Any
    credExpiresAfter: Any
    minCredLength: Any
    prevCredStoredNum: Any
    inactiveDaysAllowed: Any
    expiryWarningDays: Any
    trivialCredCheck: bool
    minCharsToChange: Any


class UpdateCredentialPolicyDefault(TypedDict, total=False):
    """AXL update model — ``UpdateCredentialPolicyDefaultReq``.

     Used by ``AXLClient.update_credential_policy_default()``.
    """

    credentialUser: "CredentialUser"
    credentialType: "Credential"
    credPolicyName: str
    newCredPolicyName: str
    credentials: str
    confirmCredentials: str
    credUserCantChange: bool
    credUserMustChange: bool
    credDoesNotExpire: bool


class UpdateCss(TypedDict, total=False):
    """AXL update model — ``UpdateCssReq``.

     Used by ``AXLClient.update_css()``.
    """

    name: str
    uuid: str
    description: str
    removeMembers: Any
    addMembers: Any
    members: Any
    newName: str


class UpdateCtiRoutePoint(TypedDict, total=False):
    """AXL update model — ``UpdateCtiRoutePointReq``.

     Used by ``AXLClient.update_cti_route_point()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    protocol: "DeviceProtocol"
    protocolSide: "ProtocolSide"
    callingSearchSpaceName: str
    devicePoolName: str
    commonDeviceConfigName: str
    locationName: str
    mediaResourceListName: str
    networkHoldMohAudioSourceId: Any
    userHoldMohAudioSourceId: Any
    useTrustedRelayPoint: "Status"
    cgpnTransformationCssName: str
    useDevicePoolCgpnTransformCss: bool
    geoLocationName: str
    userLocale: "UserLocale"
    lines: Any


class UpdateCumaServerSecurityProfile(TypedDict, total=False):
    """AXL update model — ``UpdateCumaServerSecurityProfileReq``.

     Used by ``AXLClient.update_cuma_server_security_profile()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    securityMode: "DeviceSecurityMode"
    transportType: "Transport"
    x509SubjectName: str
    serverIpHostName: str


class UpdateCustomUserField(TypedDict, total=False):
    """AXL update model — ``UpdateCustomUserFieldReq``.

     Used by ``AXLClient.update_custom_user_field()``.
    """

    uuid: str
    field: str
    newField: str


class UpdateCustomer(TypedDict, total=False):
    """AXL update model — ``UpdateCustomerReq``.

     Used by ``AXLClient.update_customer()``.
    """

    name: str
    uuid: str
    newName: str


class UpdateDateTimeGroup(TypedDict, total=False):
    """AXL update model — ``UpdateDateTimeGroupReq``.

     Used by ``AXLClient.update_date_time_group()``.
    """

    name: str
    uuid: str
    newName: str
    timeZone: "TimeZone"
    separator: str
    dateformat: str
    timeFormat: str
    removePhoneNtpReferences: Any
    addPhoneNtpReferences: Any
    phoneNtpReferences: Any


class UpdateDefaultDeviceProfile(TypedDict, total=False):
    """AXL update model — ``UpdateDefaultDeviceProfileReq``.

     Used by ``AXLClient.update_default_device_profile()``.
    """

    name: str
    uuid: str
    description: str
    userHoldMohAudioSourceId: Any
    userLocale: "UserLocale"
    phoneButtonTemplate: str
    softkeyTemplate: str
    privacy: "Status"
    singleButtonBarge: "Barge"
    joinAcrossLines: "Status"
    ignorePi: bool
    dndStatus: bool
    dndRingSetting: "RingSetting"
    dndOption: "DNDOption"
    mlppDomainId: str
    mlppIndication: "Status"
    preemption: "Preemption"
    alwaysUsePrimeLine: "Status"
    alwaysUsePrimeLineForVoiceMessage: "Status"
    emccCallingSearchSpace: str


class UpdateDeviceDefaults(TypedDict, total=False):
    """AXL update model — ``UpdateDeviceDefaultsReq``.

     Used by ``AXLClient.update_device_defaults()``.
    """

    uuid: str
    Model: "Model"
    Protocol: "DeviceProtocol"
    LoadInformation: "LoadInformation"
    InactiveLoadInformation: "LoadInformation"
    DevicePoolName: str
    PhoneButtonTemplate: str
    VersionStamp: str
    PreferActCodeOverAutoReg: bool


class UpdateDeviceMobility(TypedDict, total=False):
    """AXL update model — ``UpdateDeviceMobilityReq``.

     Used by ``AXLClient.update_device_mobility()``.
    """

    name: str
    uuid: str
    newName: str
    subNetDetails: Any
    removeMembers: Any
    addMembers: Any
    members: Any


class UpdateDeviceMobilityGroup(TypedDict, total=False):
    """AXL update model — ``UpdateDeviceMobilityGroupReq``.

     Used by ``AXLClient.update_device_mobility_group()``.
    """

    name: str
    uuid: str
    newName: str
    description: str


class UpdateDevicePool(TypedDict, total=False):
    """AXL update model — ``UpdateDevicePoolReq``.

     Used by ``AXLClient.update_device_pool()``.
    """

    name: str
    uuid: str
    newName: str
    autoSearchSpaceName: str
    dateTimeSettingName: str
    callManagerGroupName: str
    mediaResourceListName: str
    regionName: str
    networkLocale: "Country"
    srstName: str
    connectionMonitorDuration: Any
    automatedAlternateRoutingCssName: str
    aarNeighborhoodName: str
    locationName: str
    mobilityCssName: str
    physicalLocationName: str
    deviceMobilityGroupName: str
    revertPriority: "RevertPriority"
    singleButtonBarge: "Barge"
    joinAcrossLines: "Status"
    cgpnTransformationCssName: str
    cdpnTransformationCssName: str
    localRouteGroupName: str
    geoLocationName: str
    geoLocationFilterName: str
    callingPartyNationalPrefix: str
    callingPartyInternationalPrefix: str
    callingPartyUnknownPrefix: str
    callingPartySubscriberPrefix: str
    adjunctCallingSearchSpace: str
    callingPartyNationalStripDigits: Any
    callingPartyInternationalStripDigits: Any
    callingPartyUnknownStripDigits: Any
    callingPartySubscriberStripDigits: Any
    callingPartyNationalTransformationCssName: str
    callingPartyInternationalTransformationCssName: str
    callingPartyUnknownTransformationCssName: str
    callingPartySubscriberTransformationCssName: str
    calledPartyNationalPrefix: str
    calledPartyInternationalPrefix: str
    calledPartyUnknownPrefix: str
    calledPartySubscriberPrefix: str
    calledPartyNationalStripDigits: Any
    calledPartyInternationalStripDigits: Any
    calledPartyUnknownStripDigits: Any
    calledPartySubscriberStripDigits: Any
    calledPartyNationalTransformationCssName: str
    calledPartyInternationalTransformationCssName: str
    calledPartyUnknownTransformationCssName: str
    calledPartySubscriberTransformationCssName: str
    imeEnrolledPatternGroupName: str
    cntdPnTransformationCssName: str
    localRouteGroup: List[Any]
    redirectingPartyTransformationCSS: str
    callingPartyTransformationCSS: str
    wirelessLanProfileGroup: str
    elinGroup: str
    mraServiceDomain: str


class UpdateDeviceProfile(TypedDict, total=False):
    """AXL update model — ``UpdateDeviceProfileReq``.

     Used by ``AXLClient.update_device_profile()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    userHoldMohAudioSourceId: Any
    vendorConfig: "VendorConfig"
    mlppDomainId: str
    mlppIndicationStatus: "Status"
    preemption: "Preemption"
    lines: Any
    phoneTemplateName: str
    speeddials: Any
    busyLampFields: Any
    blfDirectedCallParks: Any
    addOnModules: Any
    userLocale: "UserLocale"
    singleButtonBarge: "Barge"
    joinAcrossLines: "Status"
    loginUserId: str
    ignorePresentationIndicators: bool
    dndOption: "DNDOption"
    dndRingSetting: "RingSetting"
    dndStatus: bool
    emccCallingSearchSpace: str
    alwaysUsePrimeLine: "Status"
    alwaysUsePrimeLineForVoiceMessage: "Status"
    softkeyTemplateName: str
    callInfoPrivacyStatus: "Status"
    services: Any
    featureControlPolicy: str


class UpdateDhcpServer(TypedDict, total=False):
    """AXL update model — ``UpdateDhcpServerReq``.

     Used by ``AXLClient.update_dhcp_server()``.
    """

    uuid: str
    processNodeName: str
    newProcessNodeName: str
    primaryDnsIpAddress: str
    secondaryDnsIpAddress: str
    primaryTftpServerIpAddress: str
    secondaryTftpServerIpAddress: str
    bootstrapServerIpAddress: str
    domainName: str
    tftpServerName: str
    arpCacheTimeout: Any
    ipAddressLeaseTime: Any
    renewalTime: Any
    rebindingTime: Any


class UpdateDhcpSubnet(TypedDict, total=False):
    """AXL update model — ``UpdateDhcpSubnetReq``.

     Used by ``AXLClient.update_dhcp_subnet()``.
    """

    uuid: str
    dhcpServerName: str
    subnetIpAddress: str
    newDhcpServerName: str
    newSubnetIpAddress: str
    primaryStartIpAddress: str
    primaryEndIpAddress: str
    secondaryStartIpAddress: str
    secondaryEndIpAddress: str
    primaryRouterIpAddress: str
    secondaryRouterIpAddress: str
    subnetMask: str
    domainName: str
    primaryDnsIpAddress: str
    secondaryDnsIpAddress: str
    tftpServerName: str
    primaryTftpServerIpAddress: str
    secondaryTftpServerIpAddress: str
    bootstrapServerIpAddress: str
    arpCacheTimeout: Any
    ipAddressLeaseTime: Any
    renewalTime: Any
    rebindingTime: Any


class UpdateDirNumberAliasLookupandSync(TypedDict, total=False):
    """AXL update model — ``UpdateDirNumberAliasLookupandSyncReq``.

     Used by ``AXLClient.update_dir_number_alias_lookupand_sync()``.
    """

    name: str
    uuid: str
    ldapConfigName: str
    ldapManagerDisgName: str
    ldapPassword: str
    ldapUserSearch: str
    ldapDirectoryServerUsage: "LDAPDirectoryFunction"
    keepAliveSearch: str
    keepAliveTime: "KeepAliveTimeInterval"
    sipAliasSuffix: str
    enableCachingofRecords: bool
    servers: Any
    cacheSizeforAliasLookup: Any
    cacheAgeforAliasLookup: Any


class UpdateDirectedCallPark(TypedDict, total=False):
    """AXL update model — ``UpdateDirectedCallParkReq``.

     Used by ``AXLClient.update_directed_call_park()``.
    """

    uuid: str
    pattern: str
    routePartitionName: str
    newPattern: str
    description: str
    newRoutePartitionName: str
    retrievalPrefix: str
    reversionPattern: str
    revertCssName: str


class UpdateDirectoryLookupDialRules(TypedDict, total=False):
    """AXL update model — ``UpdateDirectoryLookupDialRulesReq``.

     Used by ``AXLClient.update_directory_lookup_dial_rules()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    numberBeginWith: str
    numberOfDigits: Any
    digitsToBeRemoved: Any
    prefixPattern: str
    priority: Any


class UpdateElinGroup(TypedDict, total=False):
    """AXL update model — ``UpdateElinGroupReq``.

     Used by ``AXLClient.update_elin_group()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    removeElinNumbers: Any
    addElinNumbers: Any
    elinNumbers: Any


class UpdateEmccFeatureConfig(TypedDict, total=False):
    """AXL update model — ``UpdateEmccFeatureConfigReq``.

     Used by ``AXLClient.update_emcc_feature_config()``.
    """

    uuid: str
    parameterName: str
    value: str


class UpdateEndUserCapfProfile(TypedDict, total=False):
    """AXL update model — ``UpdateEndUserCapfProfileReq``.

     Used by ``AXLClient.update_end_user_capf_profile()``.
    """

    uuid: str
    instanceId: str
    certificationOperation: "CertificateOperation"
    authenticationMode: "AuthenticationMode"
    authenticationString: str
    keySize: "KeySize"
    keyOrder: "KeyOrder"
    ecKeySize: "ECKeySize"
    operationCompletion: str


class UpdateEnterpriseFeatureAccessConfiguration(TypedDict, total=False):
    """AXL update model — ``UpdateEnterpriseFeatureAccessConfigurationReq``.

     Used by ``AXLClient.update_enterprise_feature_access_configuration()``.
    """

    uuid: str
    pattern: str
    routePartitionName: str
    newPattern: str
    newRoutePartitionName: str
    description: str
    isDefaultEafNumber: bool


class UpdateEnterprisePhoneConfig(TypedDict, total=False):
    """AXL update model — ``UpdateEnterprisePhoneConfigReq``.

     Used by ``AXLClient.update_enterprise_phone_config()``.
    """

    vendorConfig: "VendorConfig"


class UpdateExpresswayCConfiguration(TypedDict, total=False):
    """AXL update model — ``UpdateExpresswayCConfigurationReq``.

     Used by ``AXLClient.update_expressway_cconfiguration()``.
    """

    uuid: str
    HostNameOrIP: str
    newHostNameOrIP: str
    description: str
    X509SubjectNameorSubjectAlternateName: str


class UpdateExternalCallControlProfile(TypedDict, total=False):
    """AXL update model — ``UpdateExternalCallControlProfileReq``.

     Used by ``AXLClient.update_external_call_control_profile()``.
    """

    name: str
    uuid: str
    newName: str
    primaryUri: str
    secondaryUri: str
    enableLoadBalancing: bool
    routingRequestTimer: Any
    diversionReroutingCssName: str
    callTreatmentOnFailure: "CallTreatmentOnFailure"


class UpdateFacInfo(TypedDict, total=False):
    """AXL update model — ``UpdateFacInfoReq``.

     Used by ``AXLClient.update_fac_info()``.
    """

    name: str
    uuid: str
    newName: str
    code: str
    authorizationLevel: Any


class UpdateFallbackFeatureConfig(TypedDict, total=False):
    """AXL update model — ``UpdateFallbackFeatureConfigReq``.

     Used by ``AXLClient.update_fallback_feature_config()``.
    """

    enableFallbackForImeCalls: bool
    qosSensistivityLevel: Any
    dtmfCorrelationDigits: Any
    dtmfCollectionTimer: Any
    callAnswerTimer: Any
    clearImeCallDelayTimer: Any
    dtmfInterDigitDelayTimer: Any
    postConnectFallbackDelayTimer: Any
    fallbackSplitDelayTimer: Any
    callCss: Any


class UpdateFallbackProfile(TypedDict, total=False):
    """AXL update model — ``UpdateFallbackProfileReq``.

     Used by ``AXLClient.update_fallback_profile()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    advertisedFallbackDirectoryE164Number: str
    qosSensistivityLevel: Any
    callCss: "FallBackCSSSelection"
    callAnswerTimer: Any
    directoryNumberPartition: str
    directoryNumber: str
    numberOfDigitsForCallerIDPartialMatch: Any


class UpdateFeatureControlPolicy(TypedDict, total=False):
    """AXL update model — ``UpdateFeatureControlPolicyReq``.

     Used by ``AXLClient.update_feature_control_policy()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    features: Any


class UpdateFeatureGroupTemplate(TypedDict, total=False):
    """AXL update model — ``UpdateFeatureGroupTemplateReq``.

     Used by ``AXLClient.update_feature_group_template()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    homeCluster: bool
    imAndUcPresenceEnable: bool
    serviceProfile: str
    enableUserToHostConferenceNow: bool
    allowCTIControl: bool
    enableEMCC: bool
    enableMobility: bool
    enableMobileVoiceAccess: bool
    maxDeskPickupWait: Any
    remoteDestinationLimit: Any
    BLFPresenceGp: str
    subscribeCallingSearch: str
    userLocale: "UserLocale"
    userProfile: str
    meetingInformation: bool


class UpdateFixedMohAudioSource(TypedDict, total=False):
    """AXL update model — ``UpdateFixedMohAudioSourceReq``.

     Used by ``AXLClient.update_fixed_moh_audio_source()``.
    """

    name: str
    uuid: str
    newName: str
    multicast: bool
    enable: str
    initialAnnouncement: str
    periodicAnnouncement: str
    periodicAnnouncementInterval: Any
    localeAnnouncement: "UserLocale"
    initialAnnouncementPlayed: bool


class UpdateGatekeeper(TypedDict, total=False):
    """AXL update model — ``UpdateGatekeeperReq``.

     Used by ``AXLClient.update_gatekeeper()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    rrqTimeToLive: Any
    retryTimeout: Any
    enableDevice: bool


class UpdateGateway(TypedDict, total=False):
    """AXL update model — ``UpdateGatewayReq``.

     Used by ``AXLClient.update_gateway()``.
    """

    uuid: str
    domainName: str
    newDomainName: str
    description: str
    product: "Product"
    protocol: "DeviceProtocol"
    callManagerGroupName: str
    vendorConfig: "VendorConfig"


class UpdateGatewayEndpointAnalogAccess(TypedDict, total=False):
    """AXL update model — ``UpdateGatewayEndpointAnalogAccessReq``.

     Used by ``AXLClient.update_gateway_endpoint_analog_access()``.
    """

    name: str
    uuid: str
    endpoint: "GatewayEndpointAnalog"


class UpdateGatewayEndpointDigitalAccessBri(TypedDict, total=False):
    """AXL update model — ``UpdateGatewayEndpointDigitalAccessBriReq``.

     Used by ``AXLClient.update_gateway_endpoint_digital_access_bri()``.
    """

    name: str
    uuid: str
    endpoint: "GatewayEndpointDigitalBri"


class UpdateGatewayEndpointDigitalAccessPri(TypedDict, total=False):
    """AXL update model — ``UpdateGatewayEndpointDigitalAccessPriReq``.

     Used by ``AXLClient.update_gateway_endpoint_digital_access_pri()``.
    """

    name: str
    uuid: str
    endpoint: "GatewayEndpointDigitalPri"


class UpdateGatewayEndpointDigitalAccessT1(TypedDict, total=False):
    """AXL update model — ``UpdateGatewayEndpointDigitalAccessT1Req``.

     Used by ``AXLClient.update_gateway_endpoint_digital_access_t1()``.
    """

    name: str
    uuid: str
    endpoint: "UGatewayEndpointDigitalT1"


class UpdateGatewaySccpEndpoints(TypedDict, total=False):
    """AXL update model — ``UpdateGatewaySccpEndpointsReq``.

     Used by ``AXLClient.update_gateway_sccp_endpoints()``.
    """

    name: str
    uuid: str
    endpoint: "GatewaySccp"


class UpdateGeoLocation(TypedDict, total=False):
    """AXL update model — ``UpdateGeoLocationReq``.

     Used by ``AXLClient.update_geo_location()``.
    """

    name: str
    uuid: str
    newName: str
    country: str
    description: str
    nationalSubDivision: str
    district: str
    communityName: str
    cityDivision: str
    neighbourhood: str
    street: str
    leadingStreetDirection: str
    trailingStreetSuffix: str
    streetSuffix: str
    houseNumber: str
    houseNumberSuffix: str
    landmark: str
    location: str
    floor: str
    occupantName: str
    postalCode: str


class UpdateGeoLocationFilter(TypedDict, total=False):
    """AXL update model — ``UpdateGeoLocationFilterReq``.

     Used by ``AXLClient.update_geo_location_filter()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    useCountry: bool
    useNationalSubDivision: bool
    useDistrict: bool
    useCommunityName: bool
    useCityDivision: bool
    useNeighbourhood: bool
    useStreet: bool
    useLeadingStreetDirection: bool
    useTrailingStreetSuffix: bool
    useStreetSuffix: bool
    useHouseNumber: bool
    useHouseNumberSuffix: bool
    useLandmark: bool
    useLocation: bool
    useFloor: bool
    useOccupantName: bool
    usePostalCode: bool


class UpdateGeoLocationPolicy(TypedDict, total=False):
    """AXL update model — ``UpdateGeoLocationPolicyReq``.

     Used by ``AXLClient.update_geo_location_policy()``.
    """

    name: str
    uuid: str
    newName: str
    country: str
    description: str
    nationalSubDivision: str
    district: str
    communityName: str
    cityDivision: str
    neighbourhood: str
    street: str
    leadingStreetDirection: str
    trailingStreetSuffix: str
    streetSuffix: str
    houseNumber: str
    houseNumberSuffix: str
    landmark: str
    location: str
    floor: str
    occupantName: str
    postalCode: str
    removeRelatedPolicies: Any
    addRelatedPolicies: Any
    relatedPolicies: Any


class UpdateH323Gateway(TypedDict, total=False):
    """AXL update model — ``UpdateH323GatewayReq``.

     Used by ``AXLClient.update_h323_gateway()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    callingSearchSpaceName: str
    devicePoolName: str
    commonDeviceConfigName: str
    networkLocation: "NetworkLocation"
    locationName: str
    mediaResourceListName: str
    automatedAlternateRoutingCssName: str
    aarNeighborhoodName: str
    loadInformation: "LoadInformation"
    tunneledProtocol: "TunneledProtocol"
    asn1RoseOidEncoding: "ASN1RoseOidEncoding"
    qsigVariant: "QSIGVariant"
    vendorConfig: "VendorConfig"
    pathReplacementSupport: bool
    traceFlag: bool
    mlppDomainId: str
    useTrustedRelayPoint: "Status"
    retryVideoCallAsAudio: bool
    cgpnTransformationCssName: str
    useDevicePoolCgpnTransformCss: bool
    geoLocationName: str
    geoLocationFilterName: str
    cdpnTransformationCssName: str
    useDevicePoolCdpnTransformCss: bool
    packetCaptureMode: "PacketCaptureMode"
    packetCaptureDuration: Any
    srtpAllowed: bool
    waitForFarEndH245TerminalSet: bool
    mtpRequired: bool
    callerIdDn: str
    callingPartySelection: "CallingPartySelection"
    callingLineIdPresentation: "PresentationBit"
    enableInboundFaststart: bool
    enableOutboundFaststart: bool
    codecForOutboundFaststart: "MediaPayload"
    transmitUtf8: bool
    signalingPort: Any
    allowH235PassThrough: bool
    sigDigits: Any
    prefixDn: str
    calledPartyIeNumberType: "PriOfNumber"
    callingPartyIeNumberType: "PriOfNumber"
    calledNumberingPlan: "NumberingPlan"
    callingNumberingPlan: "NumberingPlan"
    callingPartyNationalPrefix: str
    callingPartyInternationalPrefix: str
    callingPartyUnknownPrefix: str
    callingPartySubscriberPrefix: str
    callingPartyNationalStripDigits: Any
    callingPartyInternationalStripDigits: Any
    callingPartyUnknownStripDigits: Any
    callingPartySubscriberStripDigits: Any
    callingPartyNationalTransformationCssName: str
    callingPartyInternationalTransformationCssName: str
    callingPartyUnknownTransformationCssName: str
    callingPartySubscriberTransformationCssName: str
    calledPartyNationalPrefix: str
    calledPartyInternationalPrefix: str
    calledPartyUnknownPrefix: str
    calledPartySubscriberPrefix: str
    calledPartyNationalStripDigits: Any
    calledPartyInternationalStripDigits: Any
    calledPartyUnknownStripDigits: Any
    calledPartySubscriberStripDigits: Any
    calledPartyNationalTransformationCssName: str
    calledPartyInternationalTransformationCssName: str
    calledPartyUnknownTransformationCssName: str
    calledPartySubscriberTransformationCssName: str
    pstnAccess: bool
    imeE164TransformationName: str
    displayIeDelivery: bool
    redirectOutboundNumberIe: bool
    redirectInboundNumberIe: bool
    useDevicePoolCgpnTransformCssNatl: bool
    useDevicePoolCgpnTransformCssIntl: bool
    useDevicePoolCgpnTransformCssUnkn: bool
    useDevicePoolCgpnTransformCssSubs: bool
    useDevicePoolCalledCssNatl: bool
    useDevicePoolCalledCssIntl: bool
    useDevicePoolCalledCssUnkn: bool
    useDevicePoolCalledCssSubs: bool
    useDevicePoolCntdPnTransformationCss: bool
    cntdPnTransformationCssName: str
    confidentialAccess: Any
    redirectingPartyTransformationCSS: str
    connectCallBeforePlayingAnnouncement: bool


class UpdateH323Phone(TypedDict, total=False):
    """AXL update model — ``UpdateH323PhoneReq``.

     Used by ``AXLClient.update_h323_phone()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    callingSearchSpaceName: str
    devicePoolName: str
    commonDeviceConfigName: str
    commonPhoneConfigName: str
    locationName: str
    mediaResourceListName: str
    automatedAlternateRoutingCssName: str
    aarNeighborhoodName: str
    traceFlag: bool
    mlppDomainId: str
    useTrustedRelayPoint: "Status"
    retryVideoCallAsAudio: bool
    remoteDevice: bool
    cgpnTransformationCssName: str
    useDevicePoolCgpnTransformCss: bool
    geoLocationName: str
    alwaysUsePrimeLine: "Status"
    alwaysUsePrimeLineForVoiceMessage: "Status"
    srtpAllowed: bool
    unattendedPort: bool
    subscribeCallingSearchSpaceName: str
    waitForFarEndH245TerminalSet: bool
    mtpRequired: bool
    mtpPreferredCodec: "SIPCodec"
    callerIdDn: str
    callingPartySelection: "CallingPartySelection"
    callingLineIdPresentation: "PresentationBit"
    displayIEDelivery: bool
    redirectOutboundNumberIe: bool
    redirectInboundNumberIe: bool
    presenceGroupName: str
    hlogStatus: bool
    ownerUserName: str
    signalingPort: Any
    gateKeeperInfo: Any
    lines: Any
    ignorePresentationIndicators: bool
    elinGroup: str


class UpdateH323Trunk(TypedDict, total=False):
    """AXL update model — ``UpdateH323TrunkReq``.

     Used by ``AXLClient.update_h323_trunk()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    callingSearchSpaceName: str
    devicePoolName: str
    commonDeviceConfigName: str
    networkLocation: "NetworkLocation"
    locationName: str
    mediaResourceListName: str
    aarNeighborhoodName: str
    traceFlag: bool
    mlppDomainId: str
    mlppIndicationStatus: "Status"
    preemption: "Preemption"
    useTrustedRelayPoint: "Status"
    retryVideoCallAsAudio: bool
    cgpnTransformationCssName: str
    useDevicePoolCgpnTransformCss: bool
    rdnTransformationCssName: str
    useDevicePoolRdnTransformCss: bool
    geoLocationName: str
    geoLocationFilterName: str
    sendGeoLocation: bool
    cdpnTransformationCssName: str
    useDevicePoolCdpnTransformCss: bool
    packetCaptureMode: "PacketCaptureMode"
    packetCaptureDuration: Any
    srtpAllowed: bool
    unattendedPort: bool
    waitForFarEndH245TerminalSet: bool
    mtpRequired: bool
    callerIdDn: str
    callingPartySelection: "CallingPartySelection"
    callingLineIdPresentation: "PresentationBit"
    displayIEDelivery: bool
    redirectOutboundNumberIe: bool
    redirectInboundNumberIe: bool
    enableInboundFaststart: bool
    enableOutboundFaststart: bool
    codecForOutboundFaststart: "MediaPayload"
    allowH235PassThrough: bool
    tunneledProtocol: "TunneledProtocol"
    asn1RoseOidEncoding: "ASN1RoseOidEncoding"
    qsigVariant: "QSIGVariant"
    transmitUtf8: bool
    signalingPort: Any
    nationalPrefix: str
    internationalPrefix: str
    unknownPrefix: str
    subscriberPrefix: str
    sigDigits: Any
    prefixDn: str
    calledPartyIeNumberType: "PriOfNumber"
    callingPartyIeNumberType: "PriOfNumber"
    calledNumberingPlan: "NumberingPlan"
    callingNumberingPlan: "NumberingPlan"
    pathReplacementSupport: bool
    gateKeeperInfo: Any
    ictPassingPrecedenceLevelThroughUuie: bool
    ictSecurityAccessLevel: Any
    isSafEnabled: bool
    callingPartyNationalStripDigits: Any
    callingPartyInternationalStripDigits: Any
    callingPartyUnknownStripDigits: Any
    callingPartySubscriberStripDigits: Any
    callingPartyNationalTransformationCssName: str
    callingPartyInternationalTransformationCssName: str
    callingPartyUnknownTransformationCssName: str
    callingPartySubscriberTransformationCssName: str
    calledPartyNationalPrefix: str
    calledPartyInternationalPrefix: str
    calledPartyUnknownPrefix: str
    calledPartySubscriberPrefix: str
    pstnAccess: bool
    imeE164TransformationName: str
    automatedAlternateRoutingCssName: str
    useDevicePoolCgpnTransformCssNatl: bool
    useDevicePoolCgpnTransformCssIntl: bool
    useDevicePoolCgpnTransformCssUnkn: bool
    useDevicePoolCgpnTransformCssSubs: bool
    useDevicePoolCalledCssNatl: bool
    useDevicePoolCalledCssIntl: bool
    useDevicePoolCalledCssUnkn: bool
    useDevicePoolCalledCssSubs: bool
    calledPartyNationalStripDigits: Any
    calledPartyInternationalStripDigits: Any
    calledPartyUnknownStripDigits: Any
    calledPartySubscriberStripDigits: Any
    calledPartyNationalTransformationCssName: str
    calledPartyInternationalTransformationCssName: str
    calledPartyUnknownTransformationCssName: str
    calledPartySubscriberTransformationCssName: str
    runOnEveryNode: bool
    removeDestinations: Any
    addDestinations: Any
    destinations: Any
    useDevicePoolCntdPnTransformationCss: bool
    cntdPnTransformationCssName: str
    confidentialAccess: Any
    connectCallBeforePlayingAnnouncement: bool


class UpdateHandoffConfiguration(TypedDict, total=False):
    """AXL update model — ``UpdateHandoffConfigurationReq``.

     Used by ``AXLClient.update_handoff_configuration()``.
    """

    uuid: str
    pattern: str
    routePartitionName: str
    newPattern: str
    newRoutePartitionName: str


class UpdateHttpProfile(TypedDict, total=False):
    """AXL update model — ``UpdateHttpProfileReq``.

     Used by ``AXLClient.update_http_profile()``.
    """

    name: str
    uuid: str
    newName: str
    userName: str
    password: str
    requestTimeout: Any
    retryCount: Any
    webServiceRootUri: str


class UpdateHuntList(TypedDict, total=False):
    """AXL update model — ``UpdateHuntListReq``.

     Used by ``AXLClient.update_hunt_list()``.
    """

    name: str
    uuid: str
    description: str
    callManagerGroupName: str
    routeListEnabled: bool
    voiceMailUsage: bool
    removeMembers: Any
    addMembers: Any
    members: Any
    newName: str


class UpdateHuntPilot(TypedDict, total=False):
    """AXL update model — ``UpdateHuntPilotReq``.

     Used by ``AXLClient.update_hunt_pilot()``.
    """

    uuid: str
    pattern: str
    routePartitionName: str
    newPattern: str
    description: str
    newRoutePartitionName: str
    blockEnable: bool
    calledPartyTransformationMask: str
    callingPartyTransformationMask: str
    useCallingPartyPhoneMask: "Status"
    callingPartyPrefixDigits: str
    dialPlanName: str
    digitDiscardInstructionName: str
    patternUrgency: bool
    prefixDigitsOut: str
    routeFilterName: str
    callingLinePresentationBit: "PresentationBit"
    callingNamePresentationBit: "PresentationBit"
    connectedLinePresentationBit: "PresentationBit"
    connectedNamePresentationBit: "PresentationBit"
    patternPrecedence: "PatternPrecedence"
    provideOutsideDialtone: bool
    callingPartyNumberingPlan: "NumberingPlan"
    callingPartyNumberType: "PriOfNumber"
    calledPartyNumberingPlan: "NumberingPlan"
    calledPartyNumberType: "PriOfNumber"
    huntListName: str
    parkMonForwardNoRetrieve: Any
    alertingName: str
    asciiAlertingName: Any
    e164Mask: str
    aarNeighborhoodName: str
    forwardHuntNoAnswer: Any
    forwardHuntBusy: Any
    callPickupGroupName: str
    maxHuntduration: Any
    releaseClause: "ReleaseCauseValue"
    displayConnectedNumber: bool
    queueCalls: "CallsQueue"


class UpdateIlsConfig(TypedDict, total=False):
    """AXL update model — ``UpdateIlsConfigReq``.

     Used by ``AXLClient.update_ils_config()``.
    """

    role: str
    registrationServer: str
    activateIls: bool
    synchronizeClustersEvery: str
    activatedServers: str
    deactivatedServers: str
    useTls: bool
    enableUsePassword: bool
    usePassword: str


class UpdateImeClient(TypedDict, total=False):
    """AXL update model — ``UpdateImeClientReq``.

     Used by ``AXLClient.update_ime_client()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    domain: str
    isActivated: bool
    sipTrunkName: str
    primaryImeServerName: str
    secondaryImeServerName: str
    learnedRouteFilterGroupName: str
    exclusionNumberGroupName: str
    firewallName: str
    removeMembers: Any
    addMembers: Any
    members: Any
    removeCcmExternalIpMaps: Any
    addCcmExternalIpMaps: Any
    ccmExternalIpMaps: Any


class UpdateImeE164Transformation(TypedDict, total=False):
    """AXL update model — ``UpdateImeE164TransformationReq``.

     Used by ``AXLClient.update_ime_e164_transformation()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    cgpnTransformationCssName: str
    isCgpnPreTransformation: bool
    cdpnTransformationCssName: str
    isCdpnPreTransformation: bool
    incomingCgpnTransformationProfileName: str
    incomingCdpnTransformationProfileName: str


class UpdateImeEnrolledPattern(TypedDict, total=False):
    """AXL update model — ``UpdateImeEnrolledPatternReq``.

     Used by ``AXLClient.update_ime_enrolled_pattern()``.
    """

    uuid: str
    pattern: str
    newPattern: str
    description: str
    imeEnrolledPatternGroupName: str


class UpdateImeEnrolledPatternGroup(TypedDict, total=False):
    """AXL update model — ``UpdateImeEnrolledPatternGroupReq``.

     Used by ``AXLClient.update_ime_enrolled_pattern_group()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    fallbackProfileName: str
    isPatternAllAlias: bool


class UpdateImeExclusionNumber(TypedDict, total=False):
    """AXL update model — ``UpdateImeExclusionNumberReq``.

     Used by ``AXLClient.update_ime_exclusion_number()``.
    """

    uuid: str
    pattern: str
    newPattern: str
    description: str
    imeExclusionNumberGroupName: str


class UpdateImeExclusionNumberGroup(TypedDict, total=False):
    """AXL update model — ``UpdateImeExclusionNumberGroupReq``.

     Used by ``AXLClient.update_ime_exclusion_number_group()``.
    """

    name: str
    uuid: str
    newName: str
    description: str


class UpdateImeFeatureConfig(TypedDict, total=False):
    """AXL update model — ``UpdateImeFeatureConfigReq``.

     Used by ``AXLClient.update_ime_feature_config()``.
    """

    preventImeCallsFromAnalogGateways: bool
    enableIntraDomain: bool
    allowMwiNotification: bool
    trunkConnectionTimer: Any
    firewallConnectionTimer: Any
    firewallTranscationTimer: Any
    firewallIdleTimer: Any
    failedCallAttemptThreshold: Any
    callFallbackAttemptThreshold: Any
    qualityTimer: Any
    useImeForOutboundCalls: bool


class UpdateImeFirewall(TypedDict, total=False):
    """AXL update model — ``UpdateImeFirewallReq``.

     Used by ``AXLClient.update_ime_firewall()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    ipAddress: Any
    port: Any


class UpdateImeLearnedRoutes(TypedDict, total=False):
    """AXL update model — ``UpdateImeLearnedRoutesReq``.

     Used by ``AXLClient.update_ime_learned_routes()``.
    """

    uuid: str
    e164Did: Any
    adminEnabled: bool


class UpdateImeRouteFilterElement(TypedDict, total=False):
    """AXL update model — ``UpdateImeRouteFilterElementReq``.

     Used by ``AXLClient.update_ime_route_filter_element()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    elementType: "ViprFilterElement"
    imeRouteFilterGroupName: str


class UpdateImeRouteFilterGroup(TypedDict, total=False):
    """AXL update model — ``UpdateImeRouteFilterGroupReq``.

     Used by ``AXLClient.update_ime_route_filter_group()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    groupTrustSetting: bool


class UpdateImeServer(TypedDict, total=False):
    """AXL update model — ``UpdateImeServerReq``.

     Used by ``AXLClient.update_ime_server()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    ipAddress: str
    port: Any
    deviceSecurityMode: "ServerSecurityMode"
    applicationUser: str
    reconnectInterval: Any


class UpdateImportedDirectoryUriCatalogs(TypedDict, total=False):
    """AXL update model — ``UpdateImportedDirectoryUriCatalogsReq``.

     Used by ``AXLClient.update_imported_directory_uri_catalogs()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    routeString: str


class UpdateInfrastructureDevice(TypedDict, total=False):
    """AXL update model — ``UpdateInfrastructureDeviceReq``.

     Used by ``AXLClient.update_infrastructure_device()``.
    """

    uuid: str
    newName: str
    ipv4Address: str
    ipv6Address: str
    bssidWithMask: str
    wapLocation: str
    isActive: bool


class UpdateInterClusterDirectoryUri(TypedDict, total=False):
    """AXL update model — ``UpdateInterClusterDirectoryUriReq``.

     Used by ``AXLClient.update_inter_cluster_directory_uri()``.
    """

    exchangeDirectoryUri: bool
    routeString: str


class UpdateInterClusterServiceProfile(TypedDict, total=False):
    """AXL update model — ``UpdateInterClusterServiceProfileReq``.

     Used by ``AXLClient.update_inter_cluster_service_profile()``.
    """

    uuid: str
    interClusterService: "InterClusterService"
    isActivated: bool
    sipTrunkName: str


class UpdateInteractiveVoiceResponse(TypedDict, total=False):
    """AXL update model — ``UpdateInteractiveVoiceResponseReq``.

     Used by ``AXLClient.update_interactive_voice_response()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    devicePoolName: str
    locationName: str
    useTrustedRelayPoint: "Status"


class UpdateIpPhoneServices(TypedDict, total=False):
    """AXL update model — ``UpdateIpPhoneServicesReq``.

     Used by ``AXLClient.update_ip_phone_services()``.
    """

    uuid: str
    serviceName: str
    newServiceName: str
    asciiServiceName: str
    serviceDescription: str
    serviceUrl: str
    secureServiceUrl: str
    serviceCategory: "PhoneServiceCategory"
    serviceType: "PhoneService"
    serviceVendor: str
    serviceVersion: str
    enabled: bool
    removeParameters: Any
    addParameters: Any
    parameters: Any


class UpdateIvrUserLocale(TypedDict, total=False):
    """AXL update model — ``UpdateIvrUserLocaleReq``.

     Used by ``AXLClient.update_ivr_user_locale()``.
    """

    uuid: str
    userLocale: "UserLocale"
    newUserLocale: "UserLocale"
    orderIndex: Any


class UpdateLbmGroup(TypedDict, total=False):
    """AXL update model — ``UpdateLbmGroupReq``.

     Used by ``AXLClient.update_lbm_group()``.
    """

    name: str
    uuid: str
    newName: str
    Description: str
    ProcessnodeActive: str
    ProcessnodeStandby: str


class UpdateLbmHubGroup(TypedDict, total=False):
    """AXL update model — ``UpdateLbmHubGroupReq``.

     Used by ``AXLClient.update_lbm_hub_group()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    member1: str
    member2: str
    member3: str
    removeMembers: Any
    addMembers: Any
    members: Any


class UpdateLdapAuthentication(TypedDict, total=False):
    """AXL update model — ``UpdateLdapAuthenticationReq``.

     Used by ``AXLClient.update_ldap_authentication()``.
    """

    authenticateEndUsers: bool
    distinguishedName: str
    ldapPassword: str
    userSearchBase: str
    servers: Any


class UpdateLdapDirectory(TypedDict, total=False):
    """AXL update model — ``UpdateLdapDirectoryReq``.

     Used by ``AXLClient.update_ldap_directory()``.
    """

    name: str
    uuid: str
    newName: str
    ldapDn: str
    ldapPassword: str
    userSearchBase: str
    repeatable: bool
    intervalValue: Any
    scheduleUnit: "ScheduleUnit"
    nextExecTime: Any
    servers: Any
    ldapFilter: str
    synchronize: bool
    ldapFilterForGroups: str
    removeAccessControlGroupInfo: Any
    addAccessControlGroupInfo: Any
    accessControlGroupInfo: Any
    featureGroupTemplate: str
    applyMask: bool
    mask: str
    applyPoolList: bool
    addDns: Any


class UpdateLdapFilter(TypedDict, total=False):
    """AXL update model — ``UpdateLdapFilterReq``.

     Used by ``AXLClient.update_ldap_filter()``.
    """

    name: str
    uuid: str
    newName: str
    filter: str


class UpdateLdapSearch(TypedDict, total=False):
    """AXL update model — ``UpdateLdapSearchReq``.

     Used by ``AXLClient.update_ldap_search()``.
    """

    uuid: str
    enableDirectorySearch: bool
    distinguishedName: str
    password: str
    userSearchBase1: str
    userSearchBase2: str
    userSearchBase3: str
    ldapFilterForUser: str
    ldapFilterForGroups: str
    enableRecursiveSearch: bool
    primary: str
    secondary: str
    tertiary: str


class UpdateLdapSyncCustomField(TypedDict, total=False):
    """AXL update model — ``UpdateLdapSyncCustomFieldReq``.

     Used by ``AXLClient.update_ldap_sync_custom_field()``.
    """

    uuid: str
    ldapConfigurationName: str
    customUserField: str
    ldapUserField: str


class UpdateLdapSystem(TypedDict, total=False):
    """AXL update model — ``UpdateLdapSystemReq``.

     Used by ``AXLClient.update_ldap_system()``.
    """

    syncEnabled: bool
    ldapServer: "LdapServer"
    userIdAttribute: Any


class UpdateLine(TypedDict, total=False):
    """AXL update model — ``UpdateLineReq``.

     Used by ``AXLClient.update_line()``.
    """

    uuid: str
    pattern: str
    routePartitionName: str
    newPattern: str
    description: str
    newRoutePartitionName: str
    aarNeighborhoodName: str
    aarDestinationMask: str
    aarKeepCallHistory: bool
    aarVoiceMailEnabled: bool
    callForwardAll: "CallForwardAll"
    callForwardBusy: "CallForwardBusy"
    callForwardBusyInt: "CallForwardBusyInt"
    callForwardNoAnswer: "CallForwardNoAnswer"
    callForwardNoAnswerInt: "CallForwardNoAnswerInt"
    callForwardNoCoverage: "CallForwardNoCoverage"
    callForwardNoCoverageInt: "CallForwardNoCoverageInt"
    callForwardOnFailure: "CallForwardOnFailure"
    callForwardAlternateParty: "CallForwardAlternateParty"
    callForwardNotRegistered: "CallForwardNotRegistered"
    callForwardNotRegisteredInt: "CallForwardNotRegisteredInt"
    callPickupGroupName: str
    autoAnswer: "AutoAnswer"
    networkHoldMohAudioSourceId: Any
    userHoldMohAudioSourceId: Any
    callingIdPresentationWhenDiverted: "PresentationBit"
    alertingName: str
    asciiAlertingName: Any
    presenceGroupName: str
    shareLineAppearanceCssName: str
    voiceMailProfileName: str
    patternPrecedence: "PatternPrecedence"
    releaseClause: "ReleaseCauseValue"
    hrDuration: Any
    hrInterval: Any
    cfaCssPolicy: "CFACSSActivationPolicy"
    defaultActivatedDeviceName: str
    parkMonForwardNoRetrieveDn: str
    parkMonForwardNoRetrieveIntDn: str
    parkMonForwardNoRetrieveVmEnabled: bool
    parkMonForwardNoRetrieveIntVmEnabled: bool
    parkMonForwardNoRetrieveCssName: str
    parkMonForwardNoRetrieveIntCssName: str
    parkMonReversionTimer: Any
    partyEntranceTone: "Status"
    directoryURIs: Any
    allowCtiControlFlag: bool
    rejectAnonymousCall: bool
    patternUrgency: bool
    confidentialAccess: Any
    externalCallControlProfile: str
    enterpriseAltNum: Any
    e164AltNum: Any
    pstnFailover: str
    callControlAgentProfile: str
    useEnterpriseAltNum: bool
    useE164AltNum: bool
    active: bool
    externalPresentationInfo: Any


class UpdateLineGroup(TypedDict, total=False):
    """AXL update model — ``UpdateLineGroupReq``.

     Used by ``AXLClient.update_line_group()``.
    """

    name: str
    uuid: str
    distributionAlgorithm: "DistributeAlgorithm"
    rnaReversionTimeOut: Any
    huntAlgorithmNoAnswer: "HuntAlgorithm"
    huntAlgorithmBusy: "HuntAlgorithm"
    huntAlgorithmNotAvailable: "HuntAlgorithm"
    removeMembers: Any
    addMembers: Any
    members: Any
    newName: str
    autoLogOffHunt: bool


class UpdateLocalRouteGroup(TypedDict, total=False):
    """AXL update model — ``UpdateLocalRouteGroupReq``.

     Used by ``AXLClient.update_local_route_group()``.
    """

    localRouteGroup: Any


class UpdateLocation(TypedDict, total=False):
    """AXL update model — ``UpdateLocationReq``.

     Used by ``AXLClient.update_location()``.
    """

    name: str
    uuid: str
    newName: str
    relatedLocations: Any
    withinAudioBandwidth: Any
    withinVideoBandwidth: Any
    withinImmersiveKbits: Any
    betweenLocations: Any


class UpdateMediaResourceGroup(TypedDict, total=False):
    """AXL update model — ``UpdateMediaResourceGroupReq``.

     Used by ``AXLClient.update_media_resource_group()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    multicast: bool
    removeMembers: Any
    addMembers: Any
    members: Any


class UpdateMediaResourceList(TypedDict, total=False):
    """AXL update model — ``UpdateMediaResourceListReq``.

     Used by ``AXLClient.update_media_resource_list()``.
    """

    name: str
    uuid: str
    newName: str
    removeMembers: Any
    addMembers: Any
    members: Any


class UpdateMeetMe(TypedDict, total=False):
    """AXL update model — ``UpdateMeetMeReq``.

     Used by ``AXLClient.update_meet_me()``.
    """

    uuid: str
    pattern: str
    routePartitionName: str
    newPattern: str
    description: str
    newRoutePartitionName: str
    minimumSecurityLevel: "DeviceSecurityMode"


class UpdateMessageWaiting(TypedDict, total=False):
    """AXL update model — ``UpdateMessageWaitingReq``.

     Used by ``AXLClient.update_message_waiting()``.
    """

    uuid: str
    pattern: str
    routePartitionName: str
    newPattern: str
    newRoutePartitionName: str
    description: str
    messageWaitingIndicator: bool
    callingSearchSpaceName: str


class UpdateMlppDomain(TypedDict, total=False):
    """AXL update model — ``UpdateMlppDomainReq``.

     Used by ``AXLClient.update_mlpp_domain()``.
    """

    uuid: str
    domainName: str
    newDomainName: str
    domainId: str


class UpdateMobileVoiceAccess(TypedDict, total=False):
    """AXL update model — ``UpdateMobileVoiceAccessReq``.

     Used by ``AXLClient.update_mobile_voice_access()``.
    """

    uuid: str
    pattern: str
    newPattern: str
    routePartitionName: str
    removeLocales: Any
    addLocales: Any
    locales: Any


class UpdateMobility(TypedDict, total=False):
    """AXL update model — ``UpdateMobilityReq``.

     Used by ``AXLClient.update_mobility()``.
    """

    handoffNumber: str
    DTMFNumber: str
    newHandoffNumber: str
    newHandoffPartitionName: str
    newDTMFNumber: str
    newDTMFPartitionName: str


class UpdateMobilityProfile(TypedDict, total=False):
    """AXL update model — ``UpdateMobilityProfileReq``.

     Used by ``AXLClient.update_mobility_profile()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    mobileClientCallingOption: "DialViaOffice"
    dvofServiceAccessNumber: str
    dirn: "Dirn"
    dvorCallerId: str


class UpdateMohAudioSource(TypedDict, total=False):
    """AXL update model — ``UpdateMohAudioSourceReq``.

     Used by ``AXLClient.update_moh_audio_source()``.
    """

    uuid: str
    sourceId: Any
    newName: str
    sourceFile: str
    multicast: bool
    mohFileStatus: Any
    initialAnnouncement: str
    periodicAnnouncement: str
    periodicAnnouncementInterval: Any
    localeAnnouncement: "UserLocale"
    initialAnnouncementPlayed: bool
    isExternalSource: bool


class UpdateMohServer(TypedDict, total=False):
    """AXL update model — ``UpdateMohServerReq``.

     Used by ``AXLClient.update_moh_server()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    devicePoolName: str
    locationName: str
    maxUnicastConnections: Any
    maxMulticastConnections: Any
    fixedAudioSourceDevice: str
    runFlag: bool
    useTrustedRelayPoint: "Status"
    isMultiCastEnabled: bool
    baseMulticastIpaddress: str
    baseMulticastPort: Any
    multicastIncrementOnIp: bool
    audioSources: Any


class UpdateMraServiceDomain(TypedDict, total=False):
    """AXL update model — ``UpdateMraServiceDomainReq``.

     Used by ``AXLClient.update_mra_service_domain()``.
    """

    name: str
    uuid: str
    newName: str
    isDefault: bool
    serviceDomains: str


class UpdateMtp(TypedDict, total=False):
    """AXL update model — ``UpdateMtpReq``.

     Used by ``AXLClient.update_mtp()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    devicePoolName: str
    trustedRelayPoint: bool


class UpdateNetworkAccessProfile(TypedDict, total=False):
    """AXL update model — ``UpdateNetworkAccessProfileReq``.

     Used by ``AXLClient.update_network_access_profile()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    vpnRequired: "Status"
    proxySettings: "HTTPProxy"
    proxyHostname: str
    proxyPort: Any
    proxyRequiresAuthentication: bool
    provideSharedCredentials: bool
    username: str
    password: str


class UpdatePageLayoutPreferences(TypedDict, total=False):
    """AXL update model — ``UpdatePageLayoutPreferencesReq``.

     Used by ``AXLClient.update_page_layout_preferences()``.
    """

    pageName: str
    pageSections: Any


class UpdatePhone(TypedDict, total=False):
    """AXL update model — ``UpdatePhoneReq``.

     Used by ``AXLClient.update_phone()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    callingSearchSpaceName: str
    devicePoolName: str
    commonDeviceConfigName: str
    commonPhoneConfigName: str
    networkLocation: "NetworkLocation"
    locationName: str
    mediaResourceListName: str
    networkHoldMohAudioSourceId: Any
    userHoldMohAudioSourceId: Any
    automatedAlternateRoutingCssName: str
    aarNeighborhoodName: str
    loadInformation: "LoadInformation"
    vendorConfig: "VendorConfig"
    versionStamp: str
    traceFlag: bool
    mlppDomainId: str
    mlppIndicationStatus: "Status"
    preemption: "Preemption"
    useTrustedRelayPoint: "Status"
    retryVideoCallAsAudio: bool
    securityProfileName: str
    sipProfileName: str
    cgpnTransformationCssName: str
    useDevicePoolCgpnTransformCss: bool
    geoLocationName: str
    geoLocationFilterName: str
    sendGeoLocation: bool
    removeLines: Any
    addLines: Any
    lines: Any
    phoneTemplateName: str
    speeddials: Any
    busyLampFields: Any
    primaryPhoneName: str
    ringSettingIdleBlfAudibleAlert: "Status"
    ringSettingBusyBlfAudibleAlert: "Status"
    blfDirectedCallParks: Any
    addOnModules: Any
    userLocale: "UserLocale"
    networkLocale: "Country"
    idleTimeout: Any
    authenticationUrl: str
    directoryUrl: str
    idleUrl: str
    informationUrl: str
    messagesUrl: str
    proxyServerUrl: str
    servicesUrl: str
    services: Any
    softkeyTemplateName: str
    defaultProfileName: str
    enableExtensionMobility: bool
    singleButtonBarge: "Barge"
    joinAcrossLines: "Status"
    builtInBridgeStatus: "Status"
    callInfoPrivacyStatus: "Status"
    hlogStatus: "Status"
    ownerUserName: str
    ignorePresentationIndicators: bool
    packetCaptureMode: "PacketCaptureMode"
    packetCaptureDuration: Any
    subscribeCallingSearchSpaceName: str
    rerouteCallingSearchSpaceName: str
    allowCtiControlFlag: bool
    presenceGroupName: str
    unattendedPort: bool
    requireDtmfReception: bool
    rfc2833Disabled: bool
    certificateOperation: "CertificateOperation"
    authenticationMode: "AuthenticationMode"
    keySize: "KeySize"
    keyOrder: "KeyOrder"
    ecKeySize: "ECKeySize"
    authenticationString: str
    upgradeFinishTime: str
    deviceMobilityMode: "Status"
    remoteDevice: bool
    dndOption: "DNDOption"
    dndRingSetting: "RingSetting"
    dndStatus: bool
    isActive: bool
    mobilityUserIdName: str
    phoneSuite: "PhonePersonalization"
    phoneServiceDisplay: "PhoneServiceDisplay"
    isProtected: bool
    mtpRequired: bool
    mtpPreferedCodec: "SIPCodec"
    dialRulesName: str
    sshUserId: str
    sshPwd: str
    digestUser: str
    outboundCallRollover: "OutboundCallRollover"
    hotlineDevice: bool
    secureInformationUrl: str
    secureDirectoryUrl: str
    secureMessageUrl: str
    secureServicesUrl: str
    secureAuthenticationUrl: str
    secureIdleUrl: str
    alwaysUsePrimeLine: "Status"
    alwaysUsePrimeLineForVoiceMessage: "Status"
    featureControlPolicy: str
    deviceTrustMode: "DeviceTrustMode"
    earlyOfferSupportForVoiceCall: bool
    requireThirdPartyRegistration: bool
    blockIncomingCallsWhenRoaming: bool
    homeNetworkId: str
    AllowPresentationSharingUsingBfcp: bool
    confidentialAccess: Any
    requireOffPremiseLocation: bool
    allowiXApplicableMedia: bool
    cgpnIngressDN: str
    useDevicePoolCgpnIngressDN: bool
    msisdn: str
    enableCallRoutingToRdWhenNoneIsActive: bool
    wifiHotspotProfile: str
    wirelessLanProfileGroup: str
    elinGroup: str
    enableActivationID: bool
    mraServiceDomain: str
    allowMraMode: bool


class UpdatePhoneButtonTemplate(TypedDict, total=False):
    """AXL update model — ``UpdatePhoneButtonTemplateReq``.

     Used by ``AXLClient.update_phone_button_template()``.
    """

    name: str
    uuid: str
    newName: str
    buttons: Any


class UpdatePhoneNtp(TypedDict, total=False):
    """AXL update model — ``UpdatePhoneNtpReq``.

     Used by ``AXLClient.update_phone_ntp()``.
    """

    uuid: str
    ipAddress: str
    ipv6Address: str
    newIpAddress: str
    newIpv6Address: str
    description: str
    mode: "Zzntpmode"


class UpdatePhoneSecurityProfile(TypedDict, total=False):
    """AXL update model — ``UpdatePhoneSecurityProfileReq``.

     Used by ``AXLClient.update_phone_security_profile()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    deviceSecurityMode: "DeviceSecurityMode"
    authenticationMode: "AuthenticationMode"
    keySize: "KeySize"
    keyOrder: "KeyOrder"
    ecKeySize: "ECKeySize"
    tftpEncryptedConfig: bool
    EnableOAuthAuthentication: bool
    nonceValidityTime: Any
    transportType: "Transport"
    sipPhonePort: Any
    enableDigestAuthentication: bool
    excludeDigestCredentials: bool


class UpdatePhysicalLocation(TypedDict, total=False):
    """AXL update model — ``UpdatePhysicalLocationReq``.

     Used by ``AXLClient.update_physical_location()``.
    """

    name: str
    uuid: str
    newName: str
    description: str


class UpdatePresenceGroup(TypedDict, total=False):
    """AXL update model — ``UpdatePresenceGroupReq``.

     Used by ``AXLClient.update_presence_group()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    presenceGroups: Any


class UpdatePresenceRedundancyGroup(TypedDict, total=False):
    """AXL update model — ``UpdatePresenceRedundancyGroupReq``.

     Used by ``AXLClient.update_presence_redundancy_group()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    server1: str
    server2: str
    haEnabled: bool


class UpdateProcessNode(TypedDict, total=False):
    """AXL update model — ``UpdateProcessNodeReq``.

     Used by ``AXLClient.update_process_node()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    mac: Any
    ipv6Name: str
    lbmHubGroup: str
    cupDomain: str


class UpdateProcessNodeService(TypedDict, total=False):
    """AXL update model — ``UpdateProcessNodeServiceReq``.

     Used by ``AXLClient.update_process_node_service()``.
    """

    uuid: str
    processNodeName: str
    service: "Service"
    traceLevel: Any
    userCategories: Any
    enable: bool
    numFiles: Any
    maxFileSize: Any


class UpdateRecordingProfile(TypedDict, total=False):
    """AXL update model — ``UpdateRecordingProfileReq``.

     Used by ``AXLClient.update_recording_profile()``.
    """

    name: str
    uuid: str
    newName: str
    recordingCssName: str
    recorderDestination: str


class UpdateRegion(TypedDict, total=False):
    """AXL update model — ``UpdateRegionReq``.

     Used by ``AXLClient.update_region()``.
    """

    name: str
    uuid: str
    newName: str
    relatedRegions: Any


class UpdateRegionMatrix(TypedDict, total=False):
    """AXL update model — ``UpdateRegionMatrixReq``.

     Used by ``AXLClient.update_region_matrix()``.
    """

    uuid: str
    regionAName: str
    regionBName: str
    bandwidth: str
    videoBandwidth: Any
    codecPreference: str


class UpdateRemoteCluster(TypedDict, total=False):
    """AXL update model — ``UpdateRemoteClusterReq``.

     Used by ``AXLClient.update_remote_cluster()``.
    """

    uuid: str
    clusterId: str
    emcc: "RemoteClusterMember"
    pstnAccess: "RemoteClusterMember"
    rsvpAgent: "RemoteClusterMember"
    tftp: "RemoteClusterMember"
    lbm: "RemoteClusterMember"
    uds: "RemoteClusterMember"


class UpdateRemoteDestination(TypedDict, total=False):
    """AXL update model — ``UpdateRemoteDestinationReq``.

     Used by ``AXLClient.update_remote_destination()``.
    """

    uuid: str
    destination: str
    newName: str
    newDestination: str
    answerTooSoonTimer: Any
    answerTooLateTimer: Any
    delayBeforeRingingCell: Any
    ownerUserId: str
    enableUnifiedMobility: bool
    remoteDestinationProfileName: str
    enableExtendAndConnect: bool
    ctiRemoteDeviceName: str
    dualModeDeviceName: str
    isMobilePhone: bool
    enableMobileConnect: bool
    lineAssociations: Any
    timeZone: "TimeZone"
    todAccessName: str
    mobileSmartClientName: str
    mobilityProfileName: str
    singleNumberReachVoicemail: "VMAvoidancePolicy"
    dialViaOfficeReverseVoicemail: "VMAvoidancePolicy"
    removeRingSchedule: Any
    addRingSchedule: Any
    ringSchedule: Any
    accessListName: str


class UpdateRemoteDestinationProfile(TypedDict, total=False):
    """AXL update model — ``UpdateRemoteDestinationProfileReq``.

     Used by ``AXLClient.update_remote_destination_profile()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    callingSearchSpaceName: str
    devicePoolName: str
    networkHoldMohAudioSourceId: Any
    userHoldMohAudioSourceId: Any
    lines: Any
    callInfoPrivacyStatus: "Status"
    userId: str
    ignorePresentationIndicators: bool
    rerouteCallingSearchSpaceName: str
    cgpnTransformationCssName: str
    automatedAlternateRoutingCssName: str
    useDevicePoolCgpnTransformCss: bool
    userLocale: "UserLocale"
    networkLocale: "Country"
    primaryPhoneName: str
    dndOption: "DNDOption"
    dndStatus: bool
    mobileSmartClientProfileName: str


class UpdateResourcePriorityNamespace(TypedDict, total=False):
    """AXL update model — ``UpdateResourcePriorityNamespaceReq``.

     Used by ``AXLClient.update_resource_priority_namespace()``.
    """

    uuid: str
    namespace: Any
    newNamespace: Any
    description: str
    isDefault: bool


class UpdateResourcePriorityNamespaceList(TypedDict, total=False):
    """AXL update model — ``UpdateResourcePriorityNamespaceListReq``.

     Used by ``AXLClient.update_resource_priority_namespace_list()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    removeMembers: Any
    addMembers: Any
    members: Any


class UpdateRouteFilter(TypedDict, total=False):
    """AXL update model — ``UpdateRouteFilterReq``.

     Used by ``AXLClient.update_route_filter()``.
    """

    name: str
    uuid: str
    newName: str
    dialPlanName: str
    removeMembers: Any
    addMembers: Any
    members: Any


class UpdateRouteGroup(TypedDict, total=False):
    """AXL update model — ``UpdateRouteGroupReq``.

     Used by ``AXLClient.update_route_group()``.
    """

    name: str
    uuid: str
    distributionAlgorithm: "DistributeAlgorithm"
    removeMembers: Any
    addMembers: Any
    members: Any
    newName: str


class UpdateRouteList(TypedDict, total=False):
    """AXL update model — ``UpdateRouteListReq``.

     Used by ``AXLClient.update_route_list()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    callManagerGroupName: str
    routeListEnabled: bool
    removeMembers: Any
    addMembers: Any
    members: Any
    runOnEveryNode: bool


class UpdateRoutePartition(TypedDict, total=False):
    """AXL update model — ``UpdateRoutePartitionReq``.

     Used by ``AXLClient.update_route_partition()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    timeScheduleIdName: str
    useOriginatingDeviceTimeZone: bool
    timeZone: "TimeZone"


class UpdateRoutePartitionsForLearnedPatterns(TypedDict, total=False):
    """AXL update model — ``UpdateRoutePartitionsForLearnedPatternsReq``.

     Used by ``AXLClient.update_route_partitions_for_learned_patterns()``.
    """

    partitionForEnterpriseANo: str
    partitionForE164ANo: str
    partitionForEnterprisePatterns: str
    partitionForE164Pattern: str
    markLearnedEntAltNumbers: bool
    markLearnedE164AltNumbers: bool
    markFixedLengthEntPatterns: bool
    markVariableLengthEntPatterns: bool
    markFixedLengthE164Patterns: bool
    markVariableLengthE164Patterns: bool


class UpdateRoutePattern(TypedDict, total=False):
    """AXL update model — ``UpdateRoutePatternReq``.

     Used by ``AXLClient.update_route_pattern()``.
    """

    uuid: str
    pattern: str
    routePartitionName: str
    dialPlanName: str
    routeFilterName: str
    newPattern: str
    description: str
    newRoutePartitionName: str
    blockEnable: bool
    calledPartyTransformationMask: str
    callingPartyTransformationMask: str
    useCallingPartyPhoneMask: "Status"
    callingPartyPrefixDigits: str
    newDialPlanName: str
    digitDiscardInstructionName: str
    networkLocation: "NetworkLocation"
    patternUrgency: bool
    prefixDigitsOut: str
    newRouteFilterName: str
    callingLinePresentationBit: "PresentationBit"
    callingNamePresentationBit: "PresentationBit"
    connectedLinePresentationBit: "PresentationBit"
    connectedNamePresentationBit: "PresentationBit"
    supportOverlapSending: bool
    patternPrecedence: "PatternPrecedence"
    releaseClause: "ReleaseCauseValue"
    allowDeviceOverride: bool
    provideOutsideDialtone: bool
    callingPartyNumberingPlan: "NumberingPlan"
    callingPartyNumberType: "PriOfNumber"
    calledPartyNumberingPlan: "NumberingPlan"
    calledPartyNumberType: "PriOfNumber"
    destination: Any
    authorizationCodeRequired: bool
    authorizationLevelRequired: Any
    clientCodeRequired: bool
    isdnNsfInfoElement: Any
    resourcePriorityNamespaceName: str
    routeClass: "PatternRouteClass"
    enableDccEnforcement: bool
    blockedCallPercentage: str
    externalCallControl: str
    isEmergencyServiceNumber: bool


class UpdateSIPNormalizationScript(TypedDict, total=False):
    """AXL update model — ``UpdateSIPNormalizationScriptReq``.

     Used by ``AXLClient.update_sipnormalization_script()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    content: str
    scriptExecutionErrorRecoveryAction: "SIPScriptErrorHandling"
    systemResourceErrorRecoveryAction: "SIPScriptErrorHandling"
    maxMemoryThreshold: str
    maxLuaInstructionsThreshold: str


class UpdateSNMPCommunityString(TypedDict, total=False):
    """AXL update model — ``UpdateSNMPCommunityStringReq``.

     Used by ``AXLClient.update_snmpcommunity_string()``.
    """

    communityName: str
    newValues: "RSNMPCommunityString1"


class UpdateSNMPMIB2List(TypedDict, total=False):
    """AXL update model — ``UpdateSNMPMIB2ListReq``.

     Used by ``AXLClient.update_snmpmib2_list()``.
    """

    sysLocation: str
    sysContact: str


class UpdateSNMPUser(TypedDict, total=False):
    """AXL update model — ``UpdateSNMPUserReq``.

     Used by ``AXLClient.update_snmpuser()``.
    """

    user: "RSNMPUser"


class UpdateSafCcdPurgeBlockLearnedRoutes(TypedDict, total=False):
    """AXL update model — ``UpdateSafCcdPurgeBlockLearnedRoutesReq``.

     Used by ``AXLClient.update_saf_ccd_purge_block_learned_routes()``.
    """

    uuid: str
    learnedPattern: str
    learnedPatternPrefix: str
    callControlIdentity: str
    ipAddress: str
    newLearnedPattern: str
    newLearnedPatternPrefix: str
    newCallControlIdentity: str
    newIpAddress: str


class UpdateSafForwarder(TypedDict, total=False):
    """AXL update model — ``UpdateSafForwarderReq``.

     Used by ``AXLClient.update_saf_forwarder()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    clientLabel: str
    safSecurityProfile: str
    ipAddress: str
    port: Any
    enableTcpKeepAlive: bool
    safReconnectInterval: Any
    safNotificationsWindowSize: Any
    removeAssociatedCucms: Any
    addAssociatedCucms: Any
    associatedCucms: Any


class UpdateSafSecurityProfile(TypedDict, total=False):
    """AXL update model — ``UpdateSafSecurityProfileReq``.

     Used by ``AXLClient.update_saf_security_profile()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    userid: str
    password: str


class UpdateSdpTransparencyProfile(TypedDict, total=False):
    """AXL update model — ``UpdateSdpTransparencyProfileReq``.

     Used by ``AXLClient.update_sdp_transparency_profile()``.
    """

    name: str
    uuid: str
    newName: str
    description: str


class UpdateSecureConfig(TypedDict, total=False):
    """AXL update model — ``UpdateSecureConfigReq``.

     Used by ``AXLClient.update_secure_config()``.
    """

    name: str
    uuid: str
    value: str


class UpdateSelfProvisioning(TypedDict, total=False):
    """AXL update model — ``UpdateSelfProvisioningReq``.

     Used by ``AXLClient.update_self_provisioning()``.
    """

    requireAuthentication: str
    allowAuthentication: str
    authenticationCode: str
    ctiRoutePoint: str
    applicationUser: str
    removeLanguages: Any
    addLanguages: Any
    languages: Any


class UpdateServiceParameter(TypedDict, total=False):
    """AXL update model — ``UpdateServiceParameterReq``.

     Used by ``AXLClient.update_service_parameter()``.
    """

    uuid: str
    processNodeName: str
    name: str
    service: "Service"
    value: str


class UpdateServiceProfile(TypedDict, total=False):
    """AXL update model — ``UpdateServiceProfileReq``.

     Used by ``AXLClient.update_service_profile()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    isDefault: bool
    serviceProfileInfos: Any


class UpdateSipDialRules(TypedDict, total=False):
    """AXL update model — ``UpdateSipDialRulesReq``.

     Used by ``AXLClient.update_sip_dial_rules()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    removePatterns: Any
    addPatterns: Any
    patterns: Any
    removePlars: Any
    addPlars: Any
    plars: Any


class UpdateSipProfile(TypedDict, total=False):
    """AXL update model — ``UpdateSipProfileReq``.

     Used by ``AXLClient.update_sip_profile()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    defaultTelephonyEventPayloadType: Any
    redirectByApplication: bool
    ringing180: bool
    timerInvite: Any
    timerRegisterDelta: Any
    timerRegister: Any
    timerT1: Any
    timerT2: Any
    retryInvite: Any
    retryNotInvite: Any
    startMediaPort: Any
    stopMediaPort: Any
    startVideoPort: Any
    stopVideoPort: Any
    dscpForAudioCalls: str
    dscpForVideoCalls: str
    dscpForAudioPortionOfVideoCalls: str
    dscpForTelePresenceCalls: str
    dscpForAudioPortionOfTelePresenceCalls: str
    callpickupListUri: str
    callpickupGroupUri: str
    meetmeServiceUrl: str
    userInfo: "ZzuserInfo"
    dtmfDbLevel: "ZzdtmfDbLevel"
    callHoldRingback: "Zzpreff"
    anonymousCallBlock: "Zzpreff"
    callerIdBlock: "Zzpreff"
    dndControl: "Zzdndcontrol"
    telnetLevel: "TelnetLevel"
    timerKeepAlive: Any
    timerSubscribe: Any
    timerSubscribeDelta: Any
    maxRedirects: Any
    timerOffHookToFirstDigit: Any
    callForwardUri: str
    abbreviatedDialUri: str
    confJointEnable: bool
    rfc2543Hold: bool
    semiAttendedTransfer: bool
    enableVad: bool
    stutterMsgWaiting: bool
    callStats: bool
    t38Invite: bool
    faxInvite: bool
    rerouteIncomingRequest: "SIPReroute"
    resourcePriorityNamespaceListName: str
    enableAnatForEarlyOfferCalls: bool
    rsvpOverSip: "RSVPOverSIP"
    fallbackToLocalRsvp: bool
    sipRe11XxEnabled: "SIPRel1XXOptions"
    gClear: "GClear"
    sendRecvSDPInMidCallInvite: bool
    enableOutboundOptionsPing: bool
    optionsPingIntervalWhenStatusOK: Any
    optionsPingIntervalWhenStatusNotOK: Any
    deliverConferenceBridgeIdentifier: bool
    sipOptionsRetryCount: Any
    sipOptionsRetryTimer: Any
    sipBandwidthModifier: "SIPBandwidthModifier"
    enableUriOutdialSupport: str
    userAgentServerHeaderInfo: "UserAgentServerHeaderInfo"
    allowPresentationSharingUsingBfcp: bool
    scriptParameters: str
    isScriptTraceEnabled: bool
    sipNormalizationScript: str
    allowiXApplicationMedia: bool
    dialStringInterpretation: "URIDisambiguationPolicy"
    acceptAudioCodecPreferences: "Status"
    mlppUserAuthorization: bool
    isAssuredSipServiceEnabled: bool
    enableExternalQoS: bool
    resourcePriorityNamespace: str
    useCallerIdCallerNameinUriOutgoingRequest: bool
    externalPresentationInfo: Any
    callingLineIdentification: "CallingLineIdentification"
    rejectAnonymousIncomingCall: bool
    callpickupUri: str
    rejectAnonymousOutgoingCall: bool
    videoCallTrafficClass: "VideoCallTrafficClass"
    sdpTransparency: str
    allowMultipleCodecs: bool
    sipSessionRefreshMethod: "SipSessionRefreshMethod"
    earlyOfferSuppVoiceCall: "EOSuppVoiceCall"
    cucmVersionInSipHeader: "CUCMVersionInSipHeader"
    confidentialAccessLevelHeaders: "CALHeaders"
    destRouteString: bool
    inactiveSDPRequired: bool
    allowRRAndRSBandwidthModifier: bool
    connectCallBeforePlayingAnnouncement: bool


class UpdateSipRealm(TypedDict, total=False):
    """AXL update model — ``UpdateSipRealmReq``.

     Used by ``AXLClient.update_sip_realm()``.
    """

    uuid: str
    realm: str
    newRealm: str
    userid: str
    digestCredentials: str


class UpdateSipRoutePattern(TypedDict, total=False):
    """AXL update model — ``UpdateSipRoutePatternReq``.

     Used by ``AXLClient.update_sip_route_pattern()``.
    """

    uuid: str
    pattern: str
    routePartitionName: str
    newPattern: str
    description: str
    newRoutePartitionName: str
    blockEnable: bool
    callingPartyTransformationMask: str
    useCallingPartyPhoneMask: "Status"
    callingPartyPrefixDigits: str
    callingLinePresentationBit: "PresentationBit"
    callingNamePresentationBit: "PresentationBit"
    connectedLinePresentationBit: "PresentationBit"
    connectedNamePresentationBit: "PresentationBit"
    sipTrunkName: str
    dnOrPatternIpv6: str
    routeOnUserPart: bool
    useCallerCss: bool
    domainRoutingCssName: str


class UpdateSipTrunk(TypedDict, total=False):
    """AXL update model — ``UpdateSipTrunkReq``.

     Used by ``AXLClient.update_sip_trunk()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    callingSearchSpaceName: str
    devicePoolName: str
    commonDeviceConfigName: str
    networkLocation: "NetworkLocation"
    locationName: str
    mediaResourceListName: str
    networkHoldMohAudioSourceId: Any
    userHoldMohAudioSourceId: Any
    automatedAlternateRoutingCssName: str
    aarNeighborhoodName: str
    packetCaptureMode: "PacketCaptureMode"
    packetCaptureDuration: Any
    mlppDomainId: str
    mlppIndicationStatus: "Status"
    preemption: "Preemption"
    useTrustedRelayPoint: "Status"
    retryVideoCallAsAudio: bool
    securityProfileName: str
    sipProfileName: str
    cgpnTransformationCssName: str
    useDevicePoolCgpnTransformCss: bool
    geoLocationName: str
    geoLocationFilterName: str
    sendGeoLocation: bool
    cdpnTransformationCssName: str
    useDevicePoolCdpnTransformCss: bool
    unattendedPort: bool
    transmitUtf8: bool
    subscribeCallingSearchSpaceName: str
    rerouteCallingSearchSpaceName: str
    referCallingSearchSpaceName: str
    mtpRequired: bool
    presenceGroupName: str
    unknownPrefix: str
    destAddrIsSrv: bool
    tkSipCodec: "SIPCodec"
    sigDigits: Any
    connectedNamePresentation: "PresentationBit"
    connectedPartyIdPresentation: "PresentationBit"
    callingPartySelection: "CallingPartySelection"
    callingname: "PresentationBit"
    callingLineIdPresentation: "PresentationBit"
    prefixDn: str
    externalPresentationInfo: Any
    acceptInboundRdnis: bool
    acceptOutboundRdnis: bool
    srtpAllowed: bool
    srtpFallbackAllowed: bool
    isPaiEnabled: bool
    sipPrivacy: "SipPrivacy"
    isRpidEnabled: bool
    sipAssertedType: "SipAssertedType"
    trustReceivedIdentity: "TrustReceivedIdentity"
    dtmfSignalingMethod: "DTMFSignaling"
    routeClassSignalling: "Status"
    sipTrunkType: "TrunkService"
    pstnAccess: bool
    imeE164TransformationName: str
    useImePublicIpPort: bool
    useDevicePoolCntdPnTransformationCss: bool
    cntdPnTransformationCssName: str
    useDevicePoolCgpnTransformCssUnkn: bool
    rdnTransformationCssName: str
    useDevicePoolRdnTransformCss: bool
    useOrigCallingPartyPresOnDivert: bool
    sipNormalizationScriptName: str
    runOnEveryNode: bool
    removeDestinations: Any
    addDestinations: Any
    destinations: Any
    unknownStripDigits: Any
    cgpnTransformationUnknownCssName: str
    tunneledProtocol: "TunneledProtocol"
    asn1RoseOidEncoding: "ASN1RoseOidEncoding"
    qsigVariant: "QSIGVariant"
    pathReplacementSupport: bool
    enableQsigUtf8: bool
    scriptParameters: str
    scriptTraceEnabled: bool
    trunkTrafficSecure: "SIPTrunkCallLegSecurity"
    callingAndCalledPartyInfoFormat: "SIPIdentityBlend"
    useCallerIdCallerNameinUriOutgoingRequest: bool
    service: str
    parameterLabel: str
    originatingParameterValue: str
    terminatingParameterValue: str
    outboundUriRoutingInstructions: str
    requestUriDomainName: str
    enableCiscoRecordingQsigTunneling: bool
    recordingInformation: str
    calledPartyUnknownTransformationCssName: str
    calledPartyUnknownPrefix: str
    calledPartyUnknownStripDigits: Any
    useDevicePoolCalledCssUnkn: bool
    confidentialAccess: Any


class UpdateSipTrunkSecurityProfile(TypedDict, total=False):
    """AXL update model — ``UpdateSipTrunkSecurityProfileReq``.

     Used by ``AXLClient.update_sip_trunk_security_profile()``.
    """

    name: str
    uuid: str
    newName: Any
    description: str
    securityMode: "DeviceSecurityMode"
    incomingTransport: "Transport"
    outgoingTransport: "Transport"
    digestAuthentication: bool
    noncePolicyTime: Any
    x509SubjectName: str
    incomingPort: Any
    applLevelAuthentication: bool
    acceptPresenceSubscription: bool
    acceptOutOfDialogRefer: bool
    acceptUnsolicitedNotification: bool
    allowReplaceHeader: bool
    transmitSecurityStatus: bool
    sipV150OutboundSdpOfferFiltering: "V150SDPFilter"
    allowChargingHeader: bool


class UpdateSoftKeySet(TypedDict, total=False):
    """AXL update model — ``UpdateSoftKeySetReq``.

     Used by ``AXLClient.update_soft_key_set()``.
    """

    name: str
    uuid: str
    removeCallStates: Any
    addCallStates: Any
    callStates: Any


class UpdateSoftKeyTemplate(TypedDict, total=False):
    """AXL update model — ``UpdateSoftKeyTemplateReq``.

     Used by ``AXLClient.update_soft_key_template()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    isDefault: bool


class UpdateSrst(TypedDict, total=False):
    """AXL update model — ``UpdateSrstReq``.

     Used by ``AXLClient.update_srst()``.
    """

    name: str
    uuid: str
    newName: str
    port: Any
    ipAddress: str
    ipv6Address: str
    SipNetwork: str
    SipPort: Any
    isSecure: bool


class UpdateSyslogConfiguration(TypedDict, total=False):
    """AXL update model — ``UpdateSyslogConfigurationReq``.

     Used by ``AXLClient.update_syslog_configuration()``.
    """

    serverName: str
    serviceGroup: "ServiceGrouping"
    service: str
    alarmConfigs: Any
    EndPointAlarm: bool


class UpdateTimePeriod(TypedDict, total=False):
    """AXL update model — ``UpdateTimePeriodReq``.

     Used by ``AXLClient.update_time_period()``.
    """

    name: str
    uuid: str
    newName: str
    startTime: "TimeOfDay"
    endTime: "TimeOfDay"
    startDay: "DayOfWeek"
    endDay: "DayOfWeek"
    monthOfYear: "MonthOfYear"
    dayOfMonth: Any
    description: str
    dayOfMonthEnd: Any
    monthOfYearEnd: "MonthOfYear"


class UpdateTimeSchedule(TypedDict, total=False):
    """AXL update model — ``UpdateTimeScheduleReq``.

     Used by ``AXLClient.update_time_schedule()``.
    """

    name: str
    uuid: str
    newName: str
    removeMembers: Any
    addMembers: Any
    members: Any
    description: str
    timeScheduleCategory: "TimeScheduleCategory"


class UpdateTodAccess(TypedDict, total=False):
    """AXL update model — ``UpdateTodAccessReq``.

     Used by ``AXLClient.update_tod_access()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    members: Any


class UpdateTransPattern(TypedDict, total=False):
    """AXL update model — ``UpdateTransPatternReq``.

     Used by ``AXLClient.update_trans_pattern()``.
    """

    uuid: str
    pattern: str
    routePartitionName: str
    dialPlanName: str
    routeFilterName: str
    newPattern: str
    description: str
    newRoutePartitionName: str
    blockEnable: bool
    calledPartyTransformationMask: str
    callingPartyTransformationMask: str
    useCallingPartyPhoneMask: "Status"
    callingPartyPrefixDigits: str
    newDialPlanName: str
    digitDiscardInstructionName: str
    patternUrgency: bool
    prefixDigitsOut: str
    newRouteFilterName: str
    callingLinePresentationBit: "PresentationBit"
    callingNamePresentationBit: "PresentationBit"
    connectedLinePresentationBit: "PresentationBit"
    connectedNamePresentationBit: "PresentationBit"
    patternPrecedence: "PatternPrecedence"
    provideOutsideDialtone: bool
    callingPartyNumberingPlan: "NumberingPlan"
    callingPartyNumberType: "PriOfNumber"
    calledPartyNumberingPlan: "NumberingPlan"
    calledPartyNumberType: "PriOfNumber"
    callingSearchSpaceName: str
    resourcePriorityNamespaceName: str
    routeNextHopByCgpn: bool
    routeClass: "PatternRouteClass"
    callInterceptProfileName: str
    releaseClause: "ReleaseCauseValue"
    useOriginatorCss: bool
    dontWaitForIDTOnSubsequentHops: bool
    isEmergencyServiceNumber: bool


class UpdateTranscoder(TypedDict, total=False):
    """AXL update model — ``UpdateTranscoderReq``.

     Used by ``AXLClient.update_transcoder()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    devicePoolName: str
    commonDeviceConfigName: str
    loadInformation: "LoadInformation"
    vendorConfig: "VendorConfig"
    isTrustedRelayPoint: bool
    maximumCapacity: Any


class UpdateTransformationProfile(TypedDict, total=False):
    """AXL update model — ``UpdateTransformationProfileReq``.

     Used by ``AXLClient.update_transformation_profile()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    nationalStripDigits: Any
    internationalStripDigits: Any
    unknownStripDigits: Any
    subscriberStripDigits: Any
    nationalPrefix: str
    internationalPrefix: str
    unknownPrefix: str
    subscriberPrefix: str
    nationalCssName: str
    internationalCssName: str
    unknownCssName: str
    subscriberCssName: str


class UpdateTvsCertificate(TypedDict, total=False):
    """AXL update model — ``UpdateTvsCertificateReq``.

     Used by ``AXLClient.update_tvs_certificate()``.
    """

    uuid: str
    issuerName: str
    serialNumber: str
    timeToLive: int


class UpdateUcService(TypedDict, total=False):
    """AXL update model — ``UpdateUcServiceReq``.

     Used by ``AXLClient.update_uc_service()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    hostnameorip: str
    port: Any
    protocol: "ConnectProtocol"
    ucServiceXml: "VendorConfig"


class UpdateUniversalDeviceTemplate(TypedDict, total=False):
    """AXL update model — ``UpdateUniversalDeviceTemplateReq``.

     Used by ``AXLClient.update_universal_device_template()``.
    """

    name: str
    uuid: str
    newName: str
    deviceDescription: str
    devicePool: str
    deviceSecurityProfile: str
    sipProfile: str
    phoneButtonTemplate: str
    sipDialRules: str
    callingSearchSpace: str
    callingPartyTransformationCSSForInboundCalls: str
    callingPartyTransformationCSSForOutboundCalls: str
    reroutingCallingSearchSpace: str
    subscribeCallingSearchSpaceName: str
    useDevicePoolCallingPartyTransformationCSSforInboundCalls: bool
    useDevicePoolCallingPartyTransformationCSSforOutboundCalls: bool
    commonPhoneProfile: str
    commonDeviceConfiguration: str
    softkeyTemplate: str
    featureControlPolicy: str
    phonePersonalization: "PhonePersonalization"
    mtpPreferredOriginatingCodec: "SIPCodec"
    outboundCallRollover: "OutboundCallRollover"
    mediaTerminationPointRequired: bool
    unattendedPort: bool
    requiredDtmfReception: bool
    rfc2833Disabled: bool
    speeddials: Any
    lines: Any
    blfDirectedCallParks: Any
    busyLampFields: Any
    useTrustedRelayPoint: "Status"
    protectedDevice: bool
    certificateOperation: "CertificateOperation"
    authenticationMode: "AuthenticationMode"
    authenticationString: str
    keySize: "KeySize"
    keyOrder: "KeyOrder"
    ecKeySize: "ECKeySize"
    servicesProvisioning: "PhoneServiceDisplay"
    packetCaptureMode: "PacketCaptureMode"
    packetCaptureDuration: Any
    secureShellUser: str
    secureShellPassword: str
    userLocale: "UserLocale"
    networkLocale: "Country"
    mlppDomain: str
    mlppIndication: "Status"
    mlppPreemption: "Preemption"
    doNotDisturb: bool
    dndOption: "DNDOption"
    dndIncomingCallAlert: "RingSetting"
    aarGroup: str
    aarCallingSearchSpace: str
    blfPresenceGroup: str
    blfAudibleAlertSettingPhoneBusy: "Status"
    blfAudibleAlertSettingPhoneIdle: "Status"
    userHoldMohAudioSource: Any
    networkHoldMohAudioSource: Any
    location: str
    geoLocation: str
    deviceMobilityMode: "Status"
    mediaResourceGroupList: str
    remoteDevice: bool
    hotlineDevice: bool
    retryVideoCallAsAudio: bool
    requireOffPremiseLocation: bool
    ownerUserId: str
    mobilityUserId: str
    joinAcrossLines: "Status"
    alwaysUsePrimeLine: "Status"
    alwaysUsePrimeLineForVoiceMessage: "Status"
    singleButtonBarge: "Barge"
    builtInBridge: "Status"
    allowControlOfDeviceFromCti: bool
    ignorePresentationIndicators: bool
    enableExtensionMobility: bool
    privacy: "Status"
    loggedIntoHuntGroup: bool
    proxyServer: str
    servicesUrl: str
    idle: str
    idleTimer: Any
    secureDirUrl: str
    messages: str
    secureIdleUrl: str
    authenticationServer: str
    directory: str
    secureServicesUrl: str
    information: str
    secureMessagesUrl: str
    secureInformationUrl: str
    secureAuthenticationUrl: str
    confidentialAccess: Any
    services: Any


class UpdateUniversalLineTemplate(TypedDict, total=False):
    """AXL update model — ``UpdateUniversalLineTemplateReq``.

     Used by ``AXLClient.update_universal_line_template()``.
    """

    name: str
    uuid: str
    newName: str
    urgentPriority: bool
    lineDescription: str
    routePartition: str
    voiceMailProfile: str
    callingSearchSpace: str
    alertingName: str
    extCallControlProfile: str
    blfPresenceGroup: str
    callPickupGroup: str
    partyEntranceTone: "Status"
    autoAnswer: "AutoAnswer"
    rejectAnonymousCall: bool
    userHoldMohAudioSource: Any
    networkHoldMohAudioSource: Any
    aarDestinationMask: str
    aarGroup: str
    retainDestInCallFwdHistory: bool
    forwardDestAllCalls: str
    primaryCssForwardingAllCalls: str
    secondaryCssForwardingAllCalls: str
    CssActivationPolicy: "CFACSSActivationPolicy"
    fwdDestExtCallsWhenNotRetrieved: str
    cssFwdExtCallsWhenNotRetrieved: str
    fwdDestInternalCallsWhenNotRetrieved: str
    cssFwdInternalCallsWhenNotRetrieved: str
    parkMonitorReversionTime: Any
    target: str
    mlppCss: str
    mlppNoAnsRingDuration: Any
    confidentialAccess: Any
    holdReversionRingDuration: Any
    holdReversionNotificationInterval: Any
    busyIntCallsDestination: str
    busyIntCallsCss: str
    busyExtCallsDestination: str
    busyExtCallsCss: str
    noAnsIntCallsDestination: str
    noAnsIntCallsCss: str
    noAnsExtCallsDestination: str
    noAnsExtCallsCss: str
    noCoverageIntCallsDestination: str
    noCoverageIntCallsCss: str
    noCoverageExtCallsDestination: str
    noCoverageExtCallsCss: str
    unregisteredIntCallsDestination: str
    unregisteredIntCallsCss: str
    unregisteredExtCallsDestination: str
    unregisteredExtCallsCss: str
    ctiFailureDestination: str
    ctiFailureCss: str
    callControlAgentProfile: str
    noAnswerRingDuration: Any
    enterpriseAltNum: Any
    e164AltNum: Any
    advertisedFailoverNumber: str


class UpdateUser(TypedDict, total=False):
    """AXL update model — ``UpdateUserReq``.

     Used by ``AXLClient.update_user()``.
    """

    uuid: str
    userid: str
    firstName: str
    displayName: str
    middleName: str
    lastName: str
    emMaxLoginTime: Any
    newUserid: str
    password: str
    pin: str
    mailid: str
    department: str
    manager: str
    userLocale: "UserLocale"
    associatedDevices: Any
    primaryExtension: Any
    associatedPc: str
    associatedGroups: Any
    enableCti: bool
    digestCredentials: str
    phoneProfiles: Any
    defaultProfile: str
    presenceGroupName: str
    subscribeCallingSearchSpaceName: str
    enableMobility: bool
    enableMobileVoiceAccess: bool
    maxDeskPickupWaitTime: Any
    remoteDestinationLimit: Any
    passwordCredentials: Any
    pinCredentials: Any
    enableEmcc: bool
    ctiControlledDeviceProfiles: Any
    patternPrecedence: "PatternPrecedence"
    numericUserId: str
    mlppPassword: str
    customUserFields: Any
    homeCluster: bool
    imAndPresenceEnable: bool
    serviceProfile: str
    lineAppearanceAssociationForPresences: Any
    directoryUri: str
    telephoneNumber: str
    title: str
    mobileNumber: str
    homeNumber: str
    pagerNumber: str
    removeExtensionsInfo: Any
    addExtensionsInfo: Any
    extensionsInfo: Any
    selfService: str
    userProfile: str
    calendarPresence: bool
    ldapDirectoryName: str
    userIdentity: str
    nameDialing: str
    ipccExtension: str
    ipccRoutePartition: str
    convertUserAccount: str
    enableUserToHostConferenceNow: bool
    attendeesAccessCode: str
    zeroHop: bool
    customerName: str
    removeAssociatedHeadsets: Any
    addAssociatedHeadsets: Any
    associatedHeadsets: Any


class UpdateUserGroup(TypedDict, total=False):
    """AXL update model — ``UpdateUserGroupReq``.

     Used by ``AXLClient.update_user_group()``.
    """

    name: str
    uuid: str
    removeMembers: Any
    addMembers: Any
    members: Any
    removeUserRoles: Any
    addUserRoles: Any
    userRoles: Any
    newName: str


class UpdateUserProfileProvision(TypedDict, total=False):
    """AXL update model — ``UpdateUserProfileProvisionReq``.

     Used by ``AXLClient.update_user_profile_provision()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    deskPhones: str
    mobileDevices: str
    profile: str
    universalLineTemplate: str
    allowProvision: bool
    limitProvision: Any
    allowPhoneReassign: bool
    defaultUserProfile: str
    enableMra: bool
    mraPolicy_Desktop: "MRAPolicy"
    mraPolicy_Mobile: "MRAPolicy"
    allowProvisionEMMaxLoginTime: bool


class UpdateVg224(TypedDict, total=False):
    """AXL update model — ``UpdateVg224Req``.

     Used by ``AXLClient.update_vg224()``.
    """

    uuid: str
    domainName: str
    newDomainName: str
    description: str
    callManagerGroupName: str
    vendorConfig: "VendorConfig"


class UpdateVohServer(TypedDict, total=False):
    """AXL update model — ``UpdateVohServerReq``.

     Used by ``AXLClient.update_voh_server()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    sipTrunkName: str
    defaultVideoStreamId: str


class UpdateVoiceMailPilot(TypedDict, total=False):
    """AXL update model — ``UpdateVoiceMailPilotReq``.

     Used by ``AXLClient.update_voice_mail_pilot()``.
    """

    uuid: str
    dirn: str
    cssName: str
    newDirn: str
    description: str
    newCssName: str
    isDefault: bool


class UpdateVoiceMailPort(TypedDict, total=False):
    """AXL update model — ``UpdateVoiceMailPortReq``.

     Used by ``AXLClient.update_voice_mail_port()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    callingSearchSpaceName: str
    devicePoolName: str
    commonDeviceConfigName: str
    locationName: str
    useTrustedRelayPoint: "Status"
    securityProfileName: str
    geoLocationName: str
    automatedAlternateRoutingCssName: str
    dnPattern: str
    routePartition: str
    dnCallingSearchSpace: str
    aarNeighborhoodName: str
    callerIdDisplay: str
    callerIdDisplayAscii: str
    externalMask: str


class UpdateVoiceMailProfile(TypedDict, total=False):
    """AXL update model — ``UpdateVoiceMailProfileReq``.

     Used by ``AXLClient.update_voice_mail_profile()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    isDefault: bool
    voiceMailboxMask: str
    voiceMailPilot: "VmPilot"


class UpdateVpnGateway(TypedDict, total=False):
    """AXL update model — ``UpdateVpnGatewayReq``.

     Used by ``AXLClient.update_vpn_gateway()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    url: str
    certificates: Any


class UpdateVpnGroup(TypedDict, total=False):
    """AXL update model — ``UpdateVpnGroupReq``.

     Used by ``AXLClient.update_vpn_group()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    vpnGateways: Any


class UpdateVpnProfile(TypedDict, total=False):
    """AXL update model — ``UpdateVpnProfileReq``.

     Used by ``AXLClient.update_vpn_profile()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    autoNetworkDetection: bool
    mtu: Any
    failToConnect: Any
    clientAuthentication: "VPNClientAuthentication"
    pwdPersistant: bool
    enableHostIdCheck: bool


class UpdateWLANProfile(TypedDict, total=False):
    """AXL update model — ``UpdateWLANProfileReq``.

     Used by ``AXLClient.update_wlanprofile()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    ssid: str
    frequencyBand: "WiFiFrequency"
    userModifiable: "WLANProfileChanges"
    authMethod: "WiFiAuthenticationMethod"
    userName: str
    password: str
    pskPassphrase: str
    wepKey: str
    passwordDescription: str
    networkAccessProfile: str


class UpdateWifiHotspot(TypedDict, total=False):
    """AXL update model — ``UpdateWifiHotspotReq``.

     Used by ``AXLClient.update_wifi_hotspot()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    ssidPrefix: str
    userModifiable: "WLANProfileChanges"
    frequencyBand: "WiFiFrequency"
    authenticationMethod: "HotspotAuthenticationMethod"
    hostName: Any
    port: Any
    sharedSecret: str
    pskPassPhrase: str
    wepKey: str
    passwordDescription: str


class UpdateWirelessAccessPointControllers(TypedDict, total=False):
    """AXL update model — ``UpdateWirelessAccessPointControllersReq``.

     Used by ``AXLClient.update_wireless_access_point_controllers()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    snmpVersion: "SNMPVersion"
    snmpUserIdOrCommunityString: str
    snmpAuthenticationProtocol: "SNMPAuthenticationProtocol"
    snmpAuthenticationPassword: str
    snmpPrivacyProtocol: "SNMPPrivacyProtocol"
    snmpPrivacyPassword: str
    syncNow: bool
    resyncInterval: Any
    nextSyncTime: Any
    scheduleUnit: "ScheduleUnit"


class UpdateWlanProfileGroup(TypedDict, total=False):
    """AXL update model — ``UpdateWlanProfileGroupReq``.

     Used by ``AXLClient.update_wlan_profile_group()``.
    """

    name: str
    uuid: str
    newName: str
    description: str
    removeMembers: Any
    addMembers: Any
    members: Any

