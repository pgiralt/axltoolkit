# Models Reference

## Add Models

Types used as the data parameter for `add_*` methods.
Fields marked **Required** must be present; others are optional.

### AarGroup { #AarGroup }

Used by AXLClient.add_aar_group().

| Field | Type | Required |
|-------|------|:--------:|
| name | Any |  |

### AdvertisedPatterns { #AdvertisedPatterns }

Used by AXLClient.add_advertised_patterns().

| Field | Type | Required |
|-------|------|:--------:|
| description | str |  |
| pattern | str |  |
| patternType | [GlobalNumber](#GlobalNumber) |  |
| hostedRoutePSTNRule | [HostedRoutePatternPSTNRule](#HostedRoutePatternPSTNRule) |  |
| pstnFailStrip | Any |  |
| pstnFailPrepend | str |  |

### Announcement { #Announcement }

Used by AXLClient.add_announcement().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| announcementFile | [AnnouncementFile](#AnnouncementFile) |  |

### AppServerInfo { #AppServerInfo }

Used by AXLClient.add_app_server_info().

| Field | Type | Required |
|-------|------|:--------:|
| appServerName | str |  |
| appServerContent | [AppServerContent](#AppServerContent) |  |
| content | [Content](#Content) |  |

### AppUser { #AppUser }

Used by AXLClient.add_app_user().

| Field | Type | Required |
|-------|------|:--------:|
| userid | str |  |
| password | str |  |
| passwordCredentials | Any |  |
| digestCredentials | str |  |
| presenceGroupName | str |  |
| acceptPresenceSubscription | bool |  |
| acceptOutOfDialogRefer | bool |  |
| acceptUnsolicitedNotification | bool |  |
| allowReplaceHeader | bool |  |
| associatedDevices | Any |  |
| associatedGroups | Any |  |
| ctiControlledDeviceProfiles | Any |  |

### ApplicationDialRules { #ApplicationDialRules }

Used by AXLClient.add_application_dial_rules().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| numberBeginWith | str |  |
| numberOfDigits | Any |  |
| digitsToBeRemoved | Any |  |
| prefixPattern | str |  |
| priority | Any |  |

### ApplicationServer { #ApplicationServer }

Used by AXLClient.add_application_server().

| Field | Type | Required |
|-------|------|:--------:|
| appServerType | [AppServer](#AppServer) |  |
| name | str |  |
| ipAddress | str |  |
| appUsers | Any |  |
| url | str |  |
| endUserUrl | str |  |
| processNodeName | str |  |
| endUsers | Any |  |

### ApplicationToSoftKeyTemplate { #ApplicationToSoftKeyTemplate }

Used by AXLClient.add_application_to_softkey_template().

| Field | Type | Required |
|-------|------|:--------:|
| softKeyTemplateName | str | ✅ |
| standardSoftKeyTemplateName | str | ✅ |

### ApplicationUserCapfProfile { #ApplicationUserCapfProfile }

Used by AXLClient.add_application_user_capf_profile().

| Field | Type | Required |
|-------|------|:--------:|
| applicationUser | str |  |
| instanceId | str |  |
| certificateOperation | [CertificateOperation](#CertificateOperation) |  |
| authenticationMode | [AuthenticationMode](#AuthenticationMode) |  |
| authenticationString | str |  |
| keySize | [KeySize](#KeySize) |  |
| keyOrder | [KeyOrder](#KeyOrder) |  |
| ecKeySize | [ECKeySize](#ECKeySize) |  |
| operationCompletion | str |  |

### AudioCodecPreferenceList { #AudioCodecPreferenceList }

Used by AXLClient.add_audio_codec_preference_list().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| codecsInList | Any |  |

### BillingServer { #BillingServer }

Used by AXLClient.add_billing_server().

| Field | Type | Required |
|-------|------|:--------:|
| hostName | str |  |
| userId | str |  |
| password | str |  |
| directory | str |  |
| resendOnFailure | bool |  |
| billingServerProtocol | [Billingserverprotocol](#Billingserverprotocol) |  |

### BlockedLearnedPatterns { #BlockedLearnedPatterns }

Used by AXLClient.add_blocked_learned_patterns().

| Field | Type | Required |
|-------|------|:--------:|
| description | str |  |
| pattern | str |  |
| prefix | str |  |
| clusterId | str |  |
| patternType | [GlobalNumber](#GlobalNumber) |  |

### CCAProfiles { #CCAProfiles }

Used by AXLClient.add_ccaprofiles().

| Field | Type | Required |
|-------|------|:--------:|
| ccaId | str |  |
| primarySoftSwitchId | str |  |
| secondarySoftSwitchId | str |  |
| objectClass | str |  |
| subscriberType | str |  |
| sipAliasSuffix | str |  |
| sipUserNameSuffix | str |  |

### CallManagerGroup { #CallManagerGroup }

Used by AXLClient.add_call_manager_group().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| tftpDefault | bool |  |
| members | Any |  |

### CallPark { #CallPark }

Used by AXLClient.add_call_park().

| Field | Type | Required |
|-------|------|:--------:|
| pattern | str |  |
| description | str |  |
| routePartitionName | str |  |
| callManagerName | str |  |

### CallPickupGroup { #CallPickupGroup }

Used by AXLClient.add_call_pickup_group().

| Field | Type | Required |
|-------|------|:--------:|
| pattern | str |  |
| description | str |  |
| routePartitionName | str |  |
| members | Any |  |
| pickupNotification | [PickupNotification](#PickupNotification) |  |
| pickupNotificationTimer | Any |  |
| callInfoForPickupNotification | Any |  |
| name | str |  |

### CalledPartyTracing { #CalledPartyTracing }

Used by AXLClient.add_called_party_tracing().

| Field | Type | Required |
|-------|------|:--------:|
| directorynumber | str |  |
| description | str |  |

### CalledPartyTransformationPattern { #CalledPartyTransformationPattern }

Used by AXLClient.add_called_party_transformation_pattern().

| Field | Type | Required |
|-------|------|:--------:|
| pattern | str |  |
| description | str |  |
| routePartitionName | str |  |
| calledPartyTransformationMask | str |  |
| dialPlanName | str |  |
| digitDiscardInstructionName | str |  |
| routeFilterName | str |  |
| calledPartyPrefixDigits | str |  |
| calledPartyNumberingPlan | [NumberingPlan](#NumberingPlan) |  |
| calledPartyNumberType | [PriOfNumber](#PriOfNumber) |  |
| mlppPreemptionDisabled | bool |  |

### CallerFilterList { #CallerFilterList }

Used by AXLClient.add_caller_filter_list().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| isAllowedType | bool |  |
| endUserIdName | str |  |
| members | Any |  |

### CallingPartyTransformationPattern { #CallingPartyTransformationPattern }

Used by AXLClient.add_calling_party_transformation_pattern().

| Field | Type | Required |
|-------|------|:--------:|
| pattern | str |  |
| description | str |  |
| routePartitionName | str |  |
| callingPartyTransformationMask | str |  |
| useCallingPartyPhoneMask | [Status](#Status) |  |
| dialPlanName | str |  |
| digitDiscardInstructionName | str |  |
| callingPartyPrefixDigits | str |  |
| routeFilterName | str |  |
| callingLinePresentationBit | [PresentationBit](#PresentationBit) |  |
| callingPartyNumberingPlan | [NumberingPlan](#NumberingPlan) |  |
| callingPartyNumberType | [PriOfNumber](#PriOfNumber) |  |
| mlppPreemptionDisabled | bool |  |

### CcdAdvertisingService { #CcdAdvertisingService }

Used by AXLClient.add_ccd_advertising_service().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| isActivated | bool |  |
| hostDnGroup | str |  |
| safSipTrunk | str |  |
| safH323Trunk | str |  |

### CcdHostedDN { #CcdHostedDN }

Used by AXLClient.add_ccd_hosted_dn().

| Field | Type | Required |
|-------|------|:--------:|
| hostedPattern | str |  |
| description | str |  |
| CcdHostedDnGroup | str |  |
| pstnFailoverStripDigits | Any |  |
| pstnFailoverPrependDigits | str |  |
| usePstnFailover | bool |  |

### CcdHostedDNGroup { #CcdHostedDNGroup }

Used by AXLClient.add_ccd_hosted_dngroup().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| pstnFailoverStripDigits | Any |  |
| pstnFailoverPrependDigits | str |  |
| usePstnFailover | bool |  |

### CcdRequestingService { #CcdRequestingService }

Used by AXLClient.add_ccd_requesting_service().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| isActivated | bool |  |
| routePartitionName | str |  |
| learnedPatternPrefix | str |  |
| pstnPrefix | str |  |
| associatedTrunks | Any |  |

### CiscoCatalyst600024PortFXSGateway { #CiscoCatalyst600024PortFXSGateway }

Used by AXLClient.add_cisco_catalyst600024port_fxsgateway().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| product | [Product](#Product) |  |
| class | [Class](#Class) |  |
| protocol | [DeviceProtocol](#DeviceProtocol) |  |
| protocolSide | [ProtocolSide](#ProtocolSide) |  |
| callingSearchSpaceName | str |  |
| devicePoolName | str |  |
| commonDeviceConfigName | str |  |
| networkLocale | [Country](#Country) |  |
| locationName | str |  |
| mediaResourceListName | str |  |
| automatedAlternateRoutingCssName | str |  |
| aarNeighborhoodName | str |  |
| loadInformation | [LoadInformation](#LoadInformation) |  |
| vendorConfig | [VendorConfig](#VendorConfig) |  |
| traceFlag | bool |  |
| mlppDomainId | str |  |
| useTrustedRelayPoint | [Status](#Status) |  |
| cgpnTransformationCssName | str |  |
| useDevicePoolCgpnTransformCss | bool |  |
| geoLocationName | str |  |
| ports | Any |  |
| portSelectionOrder | [TrunkSelectionOrder](#TrunkSelectionOrder) |  |
| transmitUtf8 | bool |  |
| geoLocationFilterName | str |  |

### CiscoCatalyst6000E1VoIPGateway { #CiscoCatalyst6000E1VoIPGateway }

Used by AXLClient.add_cisco_catalyst6000e1vo_ipgateway().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| product | [Product](#Product) |  |
| class | [Class](#Class) |  |
| protocol | [DeviceProtocol](#DeviceProtocol) |  |
| protocolSide | [ProtocolSide](#ProtocolSide) |  |
| callingSearchSpaceName | str |  |
| devicePoolName | str |  |
| commonDeviceConfigName | str |  |
| networkLocation | [NetworkLocation](#NetworkLocation) |  |
| locationName | str |  |
| networkLocale | [Country](#Country) |  |
| mediaResourceListName | str |  |
| automatedAlternateRoutingCssName | str |  |
| aarNeighborhoodName | str |  |
| loadInformation | [LoadInformation](#LoadInformation) |  |
| vendorConfig | [VendorConfig](#VendorConfig) |  |
| mlppDomainId | str |  |
| useTrustedRelayPoint | [Status](#Status) |  |
| cgpnTransformationCssName | str |  |
| useDevicePoolCgpnTransformCss | bool |  |
| geoLocationName | str |  |
| redirectInboundNumberIe | bool |  |
| calledPlan | [NumberingPlan](#NumberingPlan) |  |
| calledPri | [PriOfNumber](#PriOfNumber) |  |
| callerIdDn | str |  |
| callingPartySelection | [CallingPartySelection](#CallingPartySelection) |  |
| callingPlan | [NumberingPlan](#NumberingPlan) |  |
| callingPri | [PriOfNumber](#PriOfNumber) |  |
| chanIe | [PRIChanIE](#PRIChanIE) |  |
| clockReference | [ClockReference](#ClockReference) |  |
| dChannelEnable | bool |  |
| channelSelectionOrder | [TrunkSelectionOrder](#TrunkSelectionOrder) |  |
| displayIE | bool |  |
| pcmType | [Encode](#Encode) |  |
| csuParam | [CSUParam](#CSUParam) |  |
| firstDelay | Any |  |
| interfaceIdPresent | bool |  |
| interfaceId | Any |  |
| intraDelay | Any |  |
| mcdnEnable | bool |  |
| redirectOutboundNumberIe | bool |  |
| numDigitsToStrip | Any |  |
| passingPrecedenceLevelThrough | bool |  |
| prefix | str |  |
| callingLinePresentationBit | [PresentationBit](#PresentationBit) |  |
| connectedLineIdPresentation | [PresentationBit](#PresentationBit) |  |
| priProtocol | [PriProtocol](#PriProtocol) |  |
| securityAccessLevel | Any |  |
| sendCallingNameInFacilityIe | bool |  |
| sendExLeadingCharInDispIe | bool |  |
| sendRestart | bool |  |
| setupNonIsdnPi | bool |  |
| sigDigits | Any |  |
| span | Any |  |
| statusPoll | bool |  |
| smdiBasePort | Any |  |
| packetCaptureMode | [PacketCaptureMode](#PacketCaptureMode) |  |
| packetCaptureDuration | Any |  |
| transmitUtf8 | bool |  |
| v150 | bool |  |
| asn1RoseOidEncoding | [ASN1RoseOidEncoding](#ASN1RoseOidEncoding) |  |
| QSIGVariant | [QSIGVariant](#QSIGVariant) |  |
| unattendedPort | bool |  |
| cdpnTransformationCssName | str |  |
| useDevicePoolCdpnTransformCss | bool |  |
| nationalPrefix | str |  |
| internationalPrefix | str |  |
| unknownPrefix | str |  |
| subscriberPrefix | str |  |
| geoLocationFilterName | str |  |
| nationalStripDigits | Any |  |
| internationalStripDigits | Any |  |
| unknownStripDigits | Any |  |
| subscriberStripDigits | Any |  |
| nationalTransformationCssName | str |  |
| internationalTransformationCssName | str |  |
| unknownTransformationCssName | str |  |
| subscriberTransformationCssName | str |  |
| useDevicePoolCgpnTransformCssNatl | bool |  |
| useDevicePoolCgpnTransformCssIntl | bool |  |
| useDevicePoolCgpnTransformCssUnkn | bool |  |
| useDevicePoolCgpnTransformCssSubs | bool |  |
| pstnAccess | bool |  |
| imeE164TransformationName | str |  |

### CiscoCatalyst6000T1VoIPGatewayPri { #CiscoCatalyst6000T1VoIPGatewayPri }

Used by AXLClient.add_cisco_catalyst6000t1vo_ipgateway_pri().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| product | [Product](#Product) |  |
| class | [Class](#Class) |  |
| protocol | [DeviceProtocol](#DeviceProtocol) |  |
| protocolSide | [ProtocolSide](#ProtocolSide) |  |
| callingSearchSpaceName | str |  |
| devicePoolName | str |  |
| commonDeviceConfigName | str |  |
| networkLocation | [NetworkLocation](#NetworkLocation) |  |
| locationName | str |  |
| networkLocale | [Country](#Country) |  |
| mediaResourceListName | str |  |
| automatedAlternateRoutingCssName | str |  |
| aarNeighborhoodName | str |  |
| loadInformation | [LoadInformation](#LoadInformation) |  |
| vendorConfig | [VendorConfig](#VendorConfig) |  |
| mlppDomainId | str |  |
| mlppIndicationStatus | [Status](#Status) |  |
| mlppPreemption | [Preemption](#Preemption) |  |
| useTrustedRelayPoint | [Status](#Status) |  |
| cgpnTransformationCssName | str |  |
| useDevicePoolCgpnTransformCss | bool |  |
| geoLocationName | str |  |
| redirectInboundNumberIe | bool |  |
| calledPlan | [NumberingPlan](#NumberingPlan) |  |
| calledPri | [PriOfNumber](#PriOfNumber) |  |
| callerIdDn | str |  |
| callingPartySelection | [CallingPartySelection](#CallingPartySelection) |  |
| callingPlan | [NumberingPlan](#NumberingPlan) |  |
| callingPri | [PriOfNumber](#PriOfNumber) |  |
| chanIe | [PRIChanIE](#PRIChanIE) |  |
| clockReference | [ClockReference](#ClockReference) |  |
| dChannelEnable | bool |  |
| channelSelectionOrder | [TrunkSelectionOrder](#TrunkSelectionOrder) |  |
| displayIE | bool |  |
| pcmType | [Encode](#Encode) |  |
| csuParam | [CSUParam](#CSUParam) |  |
| firstDelay | Any |  |
| interfaceIdPresent | bool |  |
| interfaceId | Any |  |
| intraDelay | Any |  |
| mcdnEnable | bool |  |
| redirectOutboundNumberIe | bool |  |
| numDigitsToStrip | Any |  |
| passingPrecedenceLevelThrough | bool |  |
| prefix | str |  |
| callingLinePresentationBit | [PresentationBit](#PresentationBit) |  |
| connectedLineIdPresentation | [PresentationBit](#PresentationBit) |  |
| priProtocol | [PriProtocol](#PriProtocol) |  |
| securityAccessLevel | Any |  |
| sendCallingNameInFacilityIe | bool |  |
| sendExLeadingCharInDispIe | bool |  |
| sendRestart | bool |  |
| setupNonIsdnPi | bool |  |
| sigDigits | Any |  |
| span | Any |  |
| statusPoll | bool |  |
| smdiBasePort | Any |  |
| packetCaptureMode | [PacketCaptureMode](#PacketCaptureMode) |  |
| packetCaptureDuration | Any |  |
| transmitUtf8 | bool |  |
| v150 | bool |  |
| asn1RoseOidEncoding | [ASN1RoseOidEncoding](#ASN1RoseOidEncoding) |  |
| QSIGVariant | [QSIGVariant](#QSIGVariant) |  |
| unattendedPort | bool |  |
| cdpnTransformationCssName | str |  |
| useDevicePoolCdpnTransformCss | bool |  |
| nationalPrefix | str |  |
| internationalPrefix | str |  |
| unknownPrefix | str |  |
| subscriberPrefix | str |  |
| geoLocationFilterName | str |  |
| nationalStripDigits | Any |  |
| internationalStripDigits | Any |  |
| unknownStripDigits | Any |  |
| subscriberStripDigits | Any |  |
| nationalTransformationCssName | str |  |
| internationalTransformationCssName | str |  |
| unknownTransformationCssName | str |  |
| subscriberTransformationCssName | str |  |
| useDevicePoolCgpnTransformCssNatl | bool |  |
| useDevicePoolCgpnTransformCssIntl | bool |  |
| useDevicePoolCgpnTransformCssUnkn | bool |  |
| useDevicePoolCgpnTransformCssSubs | bool |  |
| pstnAccess | bool |  |
| imeE164TransformationName | str |  |

### CiscoCatalyst6000T1VoIPGatewayT1 { #CiscoCatalyst6000T1VoIPGatewayT1 }

Used by AXLClient.add_cisco_catalyst6000t1vo_ipgateway_t1().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| product | [Product](#Product) |  |
| class | [Class](#Class) |  |
| protocol | [DeviceProtocol](#DeviceProtocol) |  |
| protocolSide | [ProtocolSide](#ProtocolSide) |  |
| callingSearchSpaceName | str |  |
| devicePoolName | str |  |
| commonDeviceConfigName | str |  |
| networkLocation | [NetworkLocation](#NetworkLocation) |  |
| locationName | str |  |
| mediaResourceListName | str |  |
| automatedAlternateRoutingCssName | str |  |
| aarNeighborhoodName | str |  |
| loadInformation | [LoadInformation](#LoadInformation) |  |
| vendorConfig | [VendorConfig](#VendorConfig) |  |
| traceFlag | bool |  |
| mlppDomainId | str |  |
| mlppIndicationStatus | [Status](#Status) |  |
| preemption | [Preemption](#Preemption) |  |
| useTrustedRelayPoint | [Status](#Status) |  |
| retryVideoCallAsAudio | bool |  |
| cgpnTransformationCssName | str |  |
| useDevicePoolCgpnTransformCss | bool |  |
| geoLocationName | str |  |
| sendGeoLocation | bool |  |
| ports | Any |  |
| trunkSelectionOrder | [TrunkSelectionOrder](#TrunkSelectionOrder) |  |
| clockReference | [ClockReference](#ClockReference) |  |
| csuParam | [CSUParam](#CSUParam) |  |
| digitSending | [DigitSending](#DigitSending) |  |
| pcmType | [Encode](#Encode) |  |
| fdlChannel | [FDLChannel](#FDLChannel) |  |
| yellowAlarm | [YellowAlarm](#YellowAlarm) |  |
| zeroSupression | [ZeroSuppression](#ZeroSuppression) |  |
| smdiBasePort | Any |  |
| handleDtmfPrecedenceSignals | bool |  |
| cdpnTransformationCssName | str |  |
| useDevicePoolCdpnTransformCss | bool |  |
| geoLocationFilterName | str |  |
| pstnAccess | bool |  |
| imeE164TransformationName | str |  |

### CmcInfo { #CmcInfo }

Used by AXLClient.add_cmc_info().

| Field | Type | Required |
|-------|------|:--------:|
| code | str |  |
| description | str |  |

### CommonDeviceConfig { #CommonDeviceConfig }

Used by AXLClient.add_common_device_config().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| softkeyTemplateName | str |  |
| userLocale | [UserLocale](#UserLocale) |  |
| networkHoldMohAudioSourceId | Any |  |
| userHoldMohAudioSourceId | Any |  |
| mlppDomainId | str |  |
| mlppIndicationStatus | [Status](#Status) |  |
| useTrustedRelayPoint | bool |  |
| preemption | [Preemption](#Preemption) |  |
| ipAddressingMode | [IPAddressingMode](#IPAddressingMode) |  |
| ipAddressingModePreferenceControl | [IPAddressingModePrefControl](#IPAddressingModePrefControl) |  |
| allowAutoConfigurationForPhones | [Status](#Status) |  |
| useImeForOutboundCalls | [Status](#Status) |  |
| confidentialAccess | Any |  |
| allowDuplicateAddressDetection | [Status](#Status) |  |
| acceptRedirectMessages | [Status](#Status) |  |
| replyMulticastEchoRequest | [Status](#Status) |  |

### CommonPhoneConfig { #CommonPhoneConfig }

Used by AXLClient.add_common_phone_config().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| unlockPwd | str |  |
| dndOption | [DNDOption](#DNDOption) |  |
| dndAlertingType | [RingSetting](#RingSetting) |  |
| backgroundImage | bool |  |
| phonePersonalization | [PhonePersonalization](#PhonePersonalization) |  |
| phoneServiceDisplay | [PhoneServiceDisplay](#PhoneServiceDisplay) |  |
| sshUserId | str |  |
| sshPwd | str |  |
| vendorConfig | [VendorConfig](#VendorConfig) |  |
| alwaysUsePrimeLine | [Status](#Status) |  |
| alwaysUsePrimeLineForVoiceMessage | [Status](#Status) |  |
| vpnGroupName | str |  |
| vpnProfileName | str |  |
| featureControlPolicy | str |  |
| wifiHotspotProfile | str |  |

### ConferenceBridge { #ConferenceBridge }

Used by AXLClient.add_conference_bridge().

| Field | Type | Required |
|-------|------|:--------:|
| name | Any |  |
| description | str |  |
| product | [Product](#Product) |  |
| devicePoolName | str |  |
| commonDeviceConfigName | str |  |
| locationName | str |  |
| subUnit | Any |  |
| loadInformation | [LoadInformation](#LoadInformation) |  |
| vendorConfig | [VendorConfig](#VendorConfig) |  |
| maximumCapacity | Any |  |
| useTrustedRelayPoint | [Status](#Status) |  |
| securityProfileName | str |  |
| destinationAddress | str |  |
| mcuConferenceBridgeSipPort | Any |  |
| sipProfile | str |  |
| srtpAllowed | bool |  |
| normalizationScript | str |  |
| enableTrace | bool |  |
| normalizationScriptInfos | Any |  |
| userName | str |  |
| password | str |  |
| httpPort | Any |  |
| useHttps | bool |  |
| addresses | Any |  |
| conferenceBridgePrefix | str |  |
| allowCFBControlOfCallSecurityIcon | bool |  |
| overrideSIPTrunkAddress | bool |  |
| sipTrunkName | str |  |

### ConferenceNow { #ConferenceNow }

Used by AXLClient.add_conference_now().

| Field | Type | Required |
|-------|------|:--------:|
| conferenceNowNumber | str |  |
| routePartitionName | str |  |
| description | str |  |
| maxWaitTimeForHost | Any |  |
| MohAudioSourceId | Any |  |

### CredentialPolicy { #CredentialPolicy }

Used by AXLClient.add_credential_policy().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| failedLogon | Any |  |
| resetFailedLogonAttempts | Any |  |
| lockoutDuration | Any |  |
| credChangeDuration | Any |  |
| credExpiresAfter | Any |  |
| minCredLength | Any |  |
| prevCredStoredNum | Any |  |
| inactiveDaysAllowed | Any |  |
| expiryWarningDays | Any |  |
| trivialCredCheck | bool |  |
| minCharsToChange | Any |  |

### Css { #Css }

Used by AXLClient.add_css().

| Field | Type | Required |
|-------|------|:--------:|
| description | str |  |
| members | Any |  |
| partitionUsage | [PartitionUsage](#PartitionUsage) |  |
| name | str |  |

### CtiRoutePoint { #CtiRoutePoint }

Used by AXLClient.add_cti_route_point().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| product | [Product](#Product) |  |
| class | [Class](#Class) |  |
| protocol | [DeviceProtocol](#DeviceProtocol) |  |
| protocolSide | [ProtocolSide](#ProtocolSide) |  |
| callingSearchSpaceName | str |  |
| devicePoolName | str |  |
| commonDeviceConfigName | str |  |
| locationName | str |  |
| mediaResourceListName | str |  |
| networkHoldMohAudioSourceId | Any |  |
| userHoldMohAudioSourceId | Any |  |
| useTrustedRelayPoint | [Status](#Status) |  |
| cgpnTransformationCssName | str |  |
| useDevicePoolCgpnTransformCss | bool |  |
| geoLocationName | str |  |
| userLocale | [UserLocale](#UserLocale) |  |
| lines | Any |  |

### CumaServerSecurityProfile { #CumaServerSecurityProfile }

Used by AXLClient.add_cuma_server_security_profile().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| securityMode | [DeviceSecurityMode](#DeviceSecurityMode) |  |
| transportType | [Transport](#Transport) |  |
| x509SubjectName | str |  |
| serverIpHostName | str |  |

### CustomUserField { #CustomUserField }

Used by AXLClient.add_custom_user_field().

| Field | Type | Required |
|-------|------|:--------:|
| field | str |  |

### Customer { #Customer }

Used by AXLClient.add_customer().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |

### DateTimeGroup { #DateTimeGroup }

Used by AXLClient.add_date_time_group().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| timeZone | [TimeZone](#TimeZone) |  |
| separator | str |  |
| dateformat | str |  |
| timeFormat | str |  |
| phoneNtpReferences | Any |  |

### DefaultDeviceProfile { #DefaultDeviceProfile }

Used by AXLClient.add_default_device_profile().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| product | [Product](#Product) |  |
| class | [Class](#Class) |  |
| protocol | [DeviceProtocol](#DeviceProtocol) |  |
| protocolSide | [ProtocolSide](#ProtocolSide) |  |
| userHoldMohAudioSourceId | Any |  |
| userLocale | [UserLocale](#UserLocale) |  |
| phoneButtonTemplate | str |  |
| softkeyTemplate | str |  |
| privacy | [Status](#Status) |  |
| singleButtonBarge | [Barge](#Barge) |  |
| joinAcrossLines | [Status](#Status) |  |
| ignorePi | bool |  |
| dndStatus | bool |  |
| dndRingSetting | [RingSetting](#RingSetting) |  |
| dndOption | [DNDOption](#DNDOption) |  |
| mlppDomainId | str |  |
| mlppIndication | [Status](#Status) |  |
| preemption | [Preemption](#Preemption) |  |
| alwaysUsePrimeLine | [Status](#Status) |  |
| alwaysUsePrimeLineForVoiceMessage | [Status](#Status) |  |
| emccCallingSearchSpace | str |  |

### DeviceMobility { #DeviceMobility }

Used by AXLClient.add_device_mobility().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| subNetDetails | Any |  |
| members | Any |  |

### DeviceMobilityGroup { #DeviceMobilityGroup }

Used by AXLClient.add_device_mobility_group().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |

### DevicePool { #DevicePool }

Used by AXLClient.add_device_pool().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| autoSearchSpaceName | str |  |
| dateTimeSettingName | str |  |
| callManagerGroupName | str |  |
| mediaResourceListName | str |  |
| regionName | str |  |
| networkLocale | [Country](#Country) |  |
| srstName | str |  |
| connectionMonitorDuration | Any |  |
| automatedAlternateRoutingCssName | str |  |
| aarNeighborhoodName | str |  |
| locationName | str |  |
| mobilityCssName | str |  |
| physicalLocationName | str |  |
| deviceMobilityGroupName | str |  |
| revertPriority | [RevertPriority](#RevertPriority) |  |
| singleButtonBarge | [Barge](#Barge) |  |
| joinAcrossLines | [Status](#Status) |  |
| cgpnTransformationCssName | str |  |
| cdpnTransformationCssName | str |  |
| localRouteGroupName | str |  |
| geoLocationName | str |  |
| geoLocationFilterName | str |  |
| callingPartyNationalPrefix | str |  |
| callingPartyInternationalPrefix | str |  |
| callingPartyUnknownPrefix | str |  |
| callingPartySubscriberPrefix | str |  |
| adjunctCallingSearchSpace | str |  |
| callingPartyNationalStripDigits | Any |  |
| callingPartyInternationalStripDigits | Any |  |
| callingPartyUnknownStripDigits | Any |  |
| callingPartySubscriberStripDigits | Any |  |
| callingPartyNationalTransformationCssName | str |  |
| callingPartyInternationalTransformationCssName | str |  |
| callingPartyUnknownTransformationCssName | str |  |
| callingPartySubscriberTransformationCssName | str |  |
| calledPartyNationalPrefix | str |  |
| calledPartyInternationalPrefix | str |  |
| calledPartyUnknownPrefix | str |  |
| calledPartySubscriberPrefix | str |  |
| calledPartyNationalStripDigits | Any |  |
| calledPartyInternationalStripDigits | Any |  |
| calledPartyUnknownStripDigits | Any |  |
| calledPartySubscriberStripDigits | Any |  |
| calledPartyNationalTransformationCssName | str |  |
| calledPartyInternationalTransformationCssName | str |  |
| calledPartyUnknownTransformationCssName | str |  |
| calledPartySubscriberTransformationCssName | str |  |
| imeEnrolledPatternGroupName | str |  |
| cntdPnTransformationCssName | str |  |
| localRouteGroup | List[Any] |  |
| redirectingPartyTransformationCSS | str |  |
| callingPartyTransformationCSS | str |  |
| wirelessLanProfileGroup | str |  |
| elinGroup | str |  |
| mraServiceDomain | str |  |

### DeviceProfile { #DeviceProfile }

Used by AXLClient.add_device_profile().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| product | [Product](#Product) |  |
| class | [Class](#Class) |  |
| protocol | [DeviceProtocol](#DeviceProtocol) |  |
| protocolSide | [ProtocolSide](#ProtocolSide) |  |
| userHoldMohAudioSourceId | Any |  |
| vendorConfig | [VendorConfig](#VendorConfig) |  |
| traceFlag | bool |  |
| mlppDomainId | str |  |
| mlppIndicationStatus | [Status](#Status) |  |
| preemption | [Preemption](#Preemption) |  |
| lines | Any |  |
| phoneTemplateName | str |  |
| speeddials | Any |  |
| busyLampFields | Any |  |
| blfDirectedCallParks | Any |  |
| addOnModules | Any |  |
| userLocale | [UserLocale](#UserLocale) |  |
| singleButtonBarge | [Barge](#Barge) |  |
| joinAcrossLines | [Status](#Status) |  |
| loginUserId | str |  |
| ignorePresentationIndicators | bool |  |
| dndOption | [DNDOption](#DNDOption) |  |
| dndRingSetting | [RingSetting](#RingSetting) |  |
| dndStatus | bool |  |
| emccCallingSearchSpace | str |  |
| alwaysUsePrimeLine | [Status](#Status) |  |
| alwaysUsePrimeLineForVoiceMessage | [Status](#Status) |  |
| softkeyTemplateName | str |  |
| callInfoPrivacyStatus | [Status](#Status) |  |
| services | Any |  |
| featureControlPolicy | str |  |

### DhcpServer { #DhcpServer }

Used by AXLClient.add_dhcp_server().

| Field | Type | Required |
|-------|------|:--------:|
| processNodeName | str |  |
| primaryDnsIpAddress | str |  |
| secondaryDnsIpAddress | str |  |
| primaryTftpServerIpAddress | str |  |
| secondaryTftpServerIpAddress | str |  |
| bootstrapServerIpAddress | str |  |
| domainName | str |  |
| tftpServerName | str |  |
| arpCacheTimeout | Any |  |
| ipAddressLeaseTime | Any |  |
| renewalTime | Any |  |
| rebindingTime | Any |  |

### DhcpSubnet { #DhcpSubnet }

Used by AXLClient.add_dhcp_subnet().

| Field | Type | Required |
|-------|------|:--------:|
| dhcpServerName | str |  |
| subnetIpAddress | str |  |
| primaryStartIpAddress | str |  |
| primaryEndIpAddress | str |  |
| secondaryStartIpAddress | str |  |
| secondaryEndIpAddress | str |  |
| primaryRouterIpAddress | str |  |
| secondaryRouterIpAddress | str |  |
| subnetMask | str |  |
| domainName | str |  |
| primaryDnsIpAddress | str |  |
| secondaryDnsIpAddress | str |  |
| tftpServerName | str |  |
| primaryTftpServerIpAddress | str |  |
| secondaryTftpServerIpAddress | str |  |
| bootstrapServerIpAddress | str |  |
| arpCacheTimeout | Any |  |
| ipAddressLeaseTime | Any |  |
| renewalTime | Any |  |
| rebindingTime | Any |  |

### DirNumberAliasLookupandSync { #DirNumberAliasLookupandSync }

Used by AXLClient.add_dir_number_alias_lookupand_sync().

| Field | Type | Required |
|-------|------|:--------:|
| ldapConfigName | str |  |
| ldapManagerDisgName | str |  |
| ldapPassword | str |  |
| ldapUserSearch | str |  |
| ldapDirectoryServerUsage | [LDAPDirectoryFunction](#LDAPDirectoryFunction) |  |
| keepAliveSearch | str |  |
| keepAliveTime | [KeepAliveTimeInterval](#KeepAliveTimeInterval) |  |
| sipAliasSuffix | str |  |
| enableCachingofRecords | bool |  |
| servers | Any |  |
| cacheSizeforAliasLookup | Any |  |
| cacheAgeforAliasLookup | Any |  |

### DirectedCallPark { #DirectedCallPark }

Used by AXLClient.add_directed_call_park().

| Field | Type | Required |
|-------|------|:--------:|
| pattern | str |  |
| description | str |  |
| routePartitionName | str |  |
| retrievalPrefix | str |  |
| reversionPattern | str |  |
| revertCssName | str |  |

### DirectoryLookupDialRules { #DirectoryLookupDialRules }

Used by AXLClient.add_directory_lookup_dial_rules().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| numberBeginWith | str |  |
| numberOfDigits | Any |  |
| digitsToBeRemoved | Any |  |
| prefixPattern | str |  |
| priority | Any |  |

### ElinGroup { #ElinGroup }

Used by AXLClient.add_elin_group().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| elinNumbers | Any |  |

### EndUserCapfProfile { #EndUserCapfProfile }

Used by AXLClient.add_end_user_capf_profile().

| Field | Type | Required |
|-------|------|:--------:|
| endUserId | str |  |
| instanceId | str |  |
| certificationOperation | [CertificateOperation](#CertificateOperation) |  |
| authenticationMode | [AuthenticationMode](#AuthenticationMode) |  |
| authenticationString | str |  |
| keySize | [KeySize](#KeySize) |  |
| keyOrder | [KeyOrder](#KeyOrder) |  |
| ecKeySize | [ECKeySize](#ECKeySize) |  |
| operationCompletion | str |  |

### EnterpriseFeatureAccessConfiguration { #EnterpriseFeatureAccessConfiguration }

Used by AXLClient.add_enterprise_feature_access_configuration().

| Field | Type | Required |
|-------|------|:--------:|
| pattern | str |  |
| routePartitionName | str |  |
| description | str |  |
| isDefaultEafNumber | bool |  |

### ExpresswayCConfiguration { #ExpresswayCConfiguration }

Used by AXLClient.add_expressway_cconfiguration().

| Field | Type | Required |
|-------|------|:--------:|
| HostNameOrIP | str |  |
| description | str |  |
| X509SubjectNameorSubjectAlternateName | str |  |

### ExternalCallControlProfile { #ExternalCallControlProfile }

Used by AXLClient.add_external_call_control_profile().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| primaryUri | str |  |
| secondaryUri | str |  |
| enableLoadBalancing | bool |  |
| routingRequestTimer | Any |  |
| diversionReroutingCssName | str |  |
| callTreatmentOnFailure | [CallTreatmentOnFailure](#CallTreatmentOnFailure) |  |

### FacInfo { #FacInfo }

Used by AXLClient.add_fac_info().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| code | str |  |
| authorizationLevel | Any |  |

### FallbackProfile { #FallbackProfile }

Used by AXLClient.add_fallback_profile().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| advertisedFallbackDirectoryE164Number | str |  |
| qosSensistivityLevel | Any |  |
| callCss | [FallBackCSSSelection](#FallBackCSSSelection) |  |
| callAnswerTimer | Any |  |
| directoryNumberPartition | str |  |
| directoryNumber | str |  |
| numberOfDigitsForCallerIDPartialMatch | Any |  |

### FeatureControlPolicy { #FeatureControlPolicy }

Used by AXLClient.add_feature_control_policy().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| features | Any |  |

### FeatureGroupTemplate { #FeatureGroupTemplate }

Used by AXLClient.add_feature_group_template().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| homeCluster | bool |  |
| imAndUcPresenceEnable | bool |  |
| serviceProfile | str |  |
| enableUserToHostConferenceNow | bool |  |
| allowCTIControl | bool |  |
| enableEMCC | bool |  |
| enableMobility | bool |  |
| enableMobileVoiceAccess | bool |  |
| maxDeskPickupWait | Any |  |
| remoteDestinationLimit | Any |  |
| BLFPresenceGp | str |  |
| subscribeCallingSearch | str |  |
| userLocale | [UserLocale](#UserLocale) |  |
| userProfile | str |  |
| meetingInformation | bool |  |

### Gatekeeper { #Gatekeeper }

Used by AXLClient.add_gatekeeper().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| rrqTimeToLive | Any |  |
| retryTimeout | Any |  |
| enableDevice | bool |  |

### Gateway { #Gateway }

Used by AXLClient.add_gateway().

| Field | Type | Required |
|-------|------|:--------:|
| domainName | str |  |
| description | str |  |
| product | [Product](#Product) |  |
| protocol | [DeviceProtocol](#DeviceProtocol) |  |
| callManagerGroupName | str |  |
| units | Any |  |
| vendorConfig | [VendorConfig](#VendorConfig) |  |

### GatewayEndpointAnalogAccess { #GatewayEndpointAnalogAccess }

Used by AXLClient.add_gateway_endpoint_analog_access().

| Field | Type | Required |
|-------|------|:--------:|
| domainName | str |  |
| gatewayUuid | str |  |
| unit | Any |  |
| subunit | Any |  |
| endpoint | [GatewayEndpointAnalog](#GatewayEndpointAnalog) |  |

### GatewayEndpointDigitalAccessBri { #GatewayEndpointDigitalAccessBri }

Used by AXLClient.add_gateway_endpoint_digital_access_bri().

| Field | Type | Required |
|-------|------|:--------:|
| domainName | str |  |
| gatewayUuid | str |  |
| unit | Any |  |
| subunit | Any |  |
| endpoint | [GatewayEndpointDigitalBri](#GatewayEndpointDigitalBri) |  |

### GatewayEndpointDigitalAccessPri { #GatewayEndpointDigitalAccessPri }

Used by AXLClient.add_gateway_endpoint_digital_access_pri().

| Field | Type | Required |
|-------|------|:--------:|
| domainName | str |  |
| gatewayUuid | str |  |
| unit | Any |  |
| subunit | Any |  |
| endpoint | [GatewayEndpointDigitalPri](#GatewayEndpointDigitalPri) |  |

### GatewayEndpointDigitalAccessT1 { #GatewayEndpointDigitalAccessT1 }

Used by AXLClient.add_gateway_endpoint_digital_access_t1().

| Field | Type | Required |
|-------|------|:--------:|
| domainName | str |  |
| gatewayUuid | str |  |
| unit | Any |  |
| subunit | Any |  |
| endpoint | [GatewayEndpointDigitalT1](#GatewayEndpointDigitalT1) |  |

### GatewaySccpEndpoints { #GatewaySccpEndpoints }

Used by AXLClient.add_gateway_sccp_endpoints().

| Field | Type | Required |
|-------|------|:--------:|
| domainName | str |  |
| gatewayUuid | str |  |
| unit | Any |  |
| subunit | Any |  |
| endpoint | [GatewaySccp](#GatewaySccp) |  |

### GatewaySubunits { #GatewaySubunits }

Used by AXLClient.add_gateway_subunits().

| Field | Type | Required |
|-------|------|:--------:|
| domainName | str |  |
| gatewayUuid | str |  |
| unit | Any |  |
| subunits | Any |  |

### GeoLocation { #GeoLocation }

Used by AXLClient.add_geo_location().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| country | str |  |
| description | str |  |
| nationalSubDivision | str |  |
| district | str |  |
| communityName | str |  |
| cityDivision | str |  |
| neighbourhood | str |  |
| street | str |  |
| leadingStreetDirection | str |  |
| trailingStreetSuffix | str |  |
| streetSuffix | str |  |
| houseNumber | str |  |
| houseNumberSuffix | str |  |
| landmark | str |  |
| location | str |  |
| floor | str |  |
| occupantName | str |  |
| postalCode | str |  |

### GeoLocationFilter { #GeoLocationFilter }

Used by AXLClient.add_geo_location_filter().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| useCountry | bool |  |
| useNationalSubDivision | bool |  |
| useDistrict | bool |  |
| useCommunityName | bool |  |
| useCityDivision | bool |  |
| useNeighbourhood | bool |  |
| useStreet | bool |  |
| useLeadingStreetDirection | bool |  |
| useTrailingStreetSuffix | bool |  |
| useStreetSuffix | bool |  |
| useHouseNumber | bool |  |
| useHouseNumberSuffix | bool |  |
| useLandmark | bool |  |
| useLocation | bool |  |
| useFloor | bool |  |
| useOccupantName | bool |  |
| usePostalCode | bool |  |

### GeoLocationPolicy { #GeoLocationPolicy }

Used by AXLClient.add_geo_location_policy().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| country | str |  |
| description | str |  |
| nationalSubDivision | str |  |
| district | str |  |
| communityName | str |  |
| cityDivision | str |  |
| neighbourhood | str |  |
| street | str |  |
| leadingStreetDirection | str |  |
| trailingStreetSuffix | str |  |
| streetSuffix | str |  |
| houseNumber | str |  |
| houseNumberSuffix | str |  |
| landmark | str |  |
| location | str |  |
| floor | str |  |
| occupantName | str |  |
| postalCode | str |  |
| relatedPolicies | Any |  |

### H323Gateway { #H323Gateway }

Used by AXLClient.add_h323gateway().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| product | [Product](#Product) |  |
| class | [Class](#Class) |  |
| protocol | [DeviceProtocol](#DeviceProtocol) |  |
| protocolSide | [ProtocolSide](#ProtocolSide) |  |
| callingSearchSpaceName | str |  |
| devicePoolName | str |  |
| commonDeviceConfigName | str |  |
| networkLocation | [NetworkLocation](#NetworkLocation) |  |
| locationName | str |  |
| mediaResourceListName | str |  |
| automatedAlternateRoutingCssName | str |  |
| aarNeighborhoodName | str |  |
| loadInformation | [LoadInformation](#LoadInformation) |  |
| tunneledProtocol | [TunneledProtocol](#TunneledProtocol) |  |
| asn1RoseOidEncoding | [ASN1RoseOidEncoding](#ASN1RoseOidEncoding) |  |
| qsigVariant | [QSIGVariant](#QSIGVariant) |  |
| vendorConfig | [VendorConfig](#VendorConfig) |  |
| pathReplacementSupport | bool |  |
| traceFlag | bool |  |
| mlppDomainId | str |  |
| useTrustedRelayPoint | [Status](#Status) |  |
| retryVideoCallAsAudio | bool |  |
| cgpnTransformationCssName | str |  |
| useDevicePoolCgpnTransformCss | bool |  |
| geoLocationName | str |  |
| geoLocationFilterName | str |  |
| cdpnTransformationCssName | str |  |
| useDevicePoolCdpnTransformCss | bool |  |
| packetCaptureMode | [PacketCaptureMode](#PacketCaptureMode) |  |
| packetCaptureDuration | Any |  |
| srtpAllowed | bool |  |
| waitForFarEndH245TerminalSet | bool |  |
| mtpRequired | bool |  |
| callerIdDn | str |  |
| callingPartySelection | [CallingPartySelection](#CallingPartySelection) |  |
| callingLineIdPresentation | [PresentationBit](#PresentationBit) |  |
| enableInboundFaststart | bool |  |
| enableOutboundFaststart | bool |  |
| codecForOutboundFaststart | [MediaPayload](#MediaPayload) |  |
| transmitUtf8 | bool |  |
| signalingPort | Any |  |
| allowH235PassThrough | bool |  |
| sigDigits | Any |  |
| prefixDn | str |  |
| calledPartyIeNumberType | [PriOfNumber](#PriOfNumber) |  |
| callingPartyIeNumberType | [PriOfNumber](#PriOfNumber) |  |
| calledNumberingPlan | [NumberingPlan](#NumberingPlan) |  |
| callingNumberingPlan | [NumberingPlan](#NumberingPlan) |  |
| callingPartyNationalPrefix | str |  |
| callingPartyInternationalPrefix | str |  |
| callingPartyUnknownPrefix | str |  |
| callingPartySubscriberPrefix | str |  |
| callingPartyNationalStripDigits | Any |  |
| callingPartyInternationalStripDigits | Any |  |
| callingPartyUnknownStripDigits | Any |  |
| callingPartySubscriberStripDigits | Any |  |
| callingPartyNationalTransformationCssName | str |  |
| callingPartyInternationalTransformationCssName | str |  |
| callingPartyUnknownTransformationCssName | str |  |
| callingPartySubscriberTransformationCssName | str |  |
| calledPartyNationalPrefix | str |  |
| calledPartyInternationalPrefix | str |  |
| calledPartyUnknownPrefix | str |  |
| calledPartySubscriberPrefix | str |  |
| calledPartyNationalStripDigits | Any |  |
| calledPartyInternationalStripDigits | Any |  |
| calledPartyUnknownStripDigits | Any |  |
| calledPartySubscriberStripDigits | Any |  |
| calledPartyNationalTransformationCssName | str |  |
| calledPartyInternationalTransformationCssName | str |  |
| calledPartyUnknownTransformationCssName | str |  |
| calledPartySubscriberTransformationCssName | str |  |
| pstnAccess | bool |  |
| imeE164TransformationName | str |  |
| displayIeDelivery | bool |  |
| redirectOutboundNumberIe | bool |  |
| redirectInboundNumberIe | bool |  |
| useDevicePoolCgpnTransformCssNatl | bool |  |
| useDevicePoolCgpnTransformCssIntl | bool |  |
| useDevicePoolCgpnTransformCssUnkn | bool |  |
| useDevicePoolCgpnTransformCssSubs | bool |  |
| useDevicePoolCalledCssNatl | bool |  |
| useDevicePoolCalledCssIntl | bool |  |
| useDevicePoolCalledCssUnkn | bool |  |
| useDevicePoolCalledCssSubs | bool |  |
| useDevicePoolCntdPnTransformationCss | bool |  |
| cntdPnTransformationCssName | str |  |
| confidentialAccess | Any |  |
| redirectingPartyTransformationCSS | str |  |
| connectCallBeforePlayingAnnouncement | bool |  |

### H323Phone { #H323Phone }

Used by AXLClient.add_h323phone().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| product | [Product](#Product) |  |
| class | [Class](#Class) |  |
| protocol | [DeviceProtocol](#DeviceProtocol) |  |
| protocolSide | [ProtocolSide](#ProtocolSide) |  |
| callingSearchSpaceName | str |  |
| devicePoolName | str |  |
| commonDeviceConfigName | str |  |
| commonPhoneConfigName | str |  |
| locationName | str |  |
| mediaResourceListName | str |  |
| automatedAlternateRoutingCssName | str |  |
| aarNeighborhoodName | str |  |
| traceFlag | bool |  |
| mlppDomainId | str |  |
| useTrustedRelayPoint | [Status](#Status) |  |
| retryVideoCallAsAudio | bool |  |
| remoteDevice | bool |  |
| cgpnTransformationCssName | str |  |
| useDevicePoolCgpnTransformCss | bool |  |
| geoLocationName | str |  |
| alwaysUsePrimeLine | [Status](#Status) |  |
| alwaysUsePrimeLineForVoiceMessage | [Status](#Status) |  |
| srtpAllowed | bool |  |
| unattendedPort | bool |  |
| subscribeCallingSearchSpaceName | str |  |
| waitForFarEndH245TerminalSet | bool |  |
| mtpRequired | bool |  |
| mtpPreferredCodec | [SIPCodec](#SIPCodec) |  |
| callerIdDn | str |  |
| callingPartySelection | [CallingPartySelection](#CallingPartySelection) |  |
| callingLineIdPresentation | [PresentationBit](#PresentationBit) |  |
| displayIEDelivery | bool |  |
| redirectOutboundNumberIe | bool |  |
| redirectInboundNumberIe | bool |  |
| presenceGroupName | str |  |
| hlogStatus | bool |  |
| ownerUserName | str |  |
| signalingPort | Any |  |
| gateKeeperInfo | Any |  |
| lines | Any |  |
| ignorePresentationIndicators | bool |  |
| elinGroup | str |  |

### H323Trunk { #H323Trunk }

Used by AXLClient.add_h323trunk().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| product | [Product](#Product) |  |
| class | [Class](#Class) |  |
| protocol | [DeviceProtocol](#DeviceProtocol) |  |
| protocolSide | [ProtocolSide](#ProtocolSide) |  |
| callingSearchSpaceName | str |  |
| devicePoolName | str |  |
| commonDeviceConfigName | str |  |
| networkLocation | [NetworkLocation](#NetworkLocation) |  |
| locationName | str |  |
| mediaResourceListName | str |  |
| aarNeighborhoodName | str |  |
| traceFlag | bool |  |
| mlppDomainId | str |  |
| mlppIndicationStatus | [Status](#Status) |  |
| preemption | [Preemption](#Preemption) |  |
| useTrustedRelayPoint | [Status](#Status) |  |
| retryVideoCallAsAudio | bool |  |
| cgpnTransformationCssName | str |  |
| useDevicePoolCgpnTransformCss | bool |  |
| rdnTransformationCssName | str |  |
| useDevicePoolRdnTransformCss | bool |  |
| geoLocationName | str |  |
| geoLocationFilterName | str |  |
| sendGeoLocation | bool |  |
| cdpnTransformationCssName | str |  |
| useDevicePoolCdpnTransformCss | bool |  |
| packetCaptureMode | [PacketCaptureMode](#PacketCaptureMode) |  |
| packetCaptureDuration | Any |  |
| srtpAllowed | bool |  |
| unattendedPort | bool |  |
| waitForFarEndH245TerminalSet | bool |  |
| mtpRequired | bool |  |
| callerIdDn | str |  |
| callingPartySelection | [CallingPartySelection](#CallingPartySelection) |  |
| callingLineIdPresentation | [PresentationBit](#PresentationBit) |  |
| displayIEDelivery | bool |  |
| redirectOutboundNumberIe | bool |  |
| redirectInboundNumberIe | bool |  |
| enableInboundFaststart | bool |  |
| enableOutboundFaststart | bool |  |
| codecForOutboundFaststart | [MediaPayload](#MediaPayload) |  |
| allowH235PassThrough | bool |  |
| tunneledProtocol | [TunneledProtocol](#TunneledProtocol) |  |
| asn1RoseOidEncoding | [ASN1RoseOidEncoding](#ASN1RoseOidEncoding) |  |
| qsigVariant | [QSIGVariant](#QSIGVariant) |  |
| transmitUtf8 | bool |  |
| signalingPort | Any |  |
| nationalPrefix | str |  |
| internationalPrefix | str |  |
| unknownPrefix | str |  |
| subscriberPrefix | str |  |
| sigDigits | Any |  |
| prefixDn | str |  |
| calledPartyIeNumberType | [PriOfNumber](#PriOfNumber) |  |
| callingPartyIeNumberType | [PriOfNumber](#PriOfNumber) |  |
| calledNumberingPlan | [NumberingPlan](#NumberingPlan) |  |
| callingNumberingPlan | [NumberingPlan](#NumberingPlan) |  |
| pathReplacementSupport | bool |  |
| gateKeeperInfo | Any |  |
| ictPassingPrecedenceLevelThroughUuie | bool |  |
| ictSecurityAccessLevel | Any |  |
| isSafEnabled | bool |  |
| callingPartyNationalStripDigits | Any |  |
| callingPartyInternationalStripDigits | Any |  |
| callingPartyUnknownStripDigits | Any |  |
| callingPartySubscriberStripDigits | Any |  |
| callingPartyNationalTransformationCssName | str |  |
| callingPartyInternationalTransformationCssName | str |  |
| callingPartyUnknownTransformationCssName | str |  |
| callingPartySubscriberTransformationCssName | str |  |
| calledPartyNationalPrefix | str |  |
| calledPartyInternationalPrefix | str |  |
| calledPartyUnknownPrefix | str |  |
| calledPartySubscriberPrefix | str |  |
| pstnAccess | bool |  |
| imeE164TransformationName | str |  |
| automatedAlternateRoutingCssName | str |  |
| useDevicePoolCgpnTransformCssNatl | bool |  |
| useDevicePoolCgpnTransformCssIntl | bool |  |
| useDevicePoolCgpnTransformCssUnkn | bool |  |
| useDevicePoolCgpnTransformCssSubs | bool |  |
| useDevicePoolCalledCssNatl | bool |  |
| useDevicePoolCalledCssIntl | bool |  |
| useDevicePoolCalledCssUnkn | bool |  |
| useDevicePoolCalledCssSubs | bool |  |
| calledPartyNationalStripDigits | Any |  |
| calledPartyInternationalStripDigits | Any |  |
| calledPartyUnknownStripDigits | Any |  |
| calledPartySubscriberStripDigits | Any |  |
| calledPartyNationalTransformationCssName | str |  |
| calledPartyInternationalTransformationCssName | str |  |
| calledPartyUnknownTransformationCssName | str |  |
| calledPartySubscriberTransformationCssName | str |  |
| runOnEveryNode | bool |  |
| destinations | Any |  |
| useDevicePoolCntdPnTransformationCss | bool |  |
| cntdPnTransformationCssName | str |  |
| confidentialAccess | Any |  |
| connectCallBeforePlayingAnnouncement | bool |  |

### HandoffConfiguration { #HandoffConfiguration }

Used by AXLClient.add_handoff_configuration().

| Field | Type | Required |
|-------|------|:--------:|
| pattern | str |  |
| routePartitionName | str |  |

### HttpProfile { #HttpProfile }

Used by AXLClient.add_http_profile().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| userName | str |  |
| password | str |  |
| requestTimeout | Any |  |
| retryCount | Any |  |
| webServiceRootUri | str |  |

### HuntList { #HuntList }

Used by AXLClient.add_hunt_list().

| Field | Type | Required |
|-------|------|:--------:|
| description | str |  |
| callManagerGroupName | str |  |
| routeListEnabled | bool |  |
| voiceMailUsage | bool |  |
| members | Any |  |
| name | str |  |

### HuntPilot { #HuntPilot }

Used by AXLClient.add_hunt_pilot().

| Field | Type | Required |
|-------|------|:--------:|
| pattern | str |  |
| description | str |  |
| routePartitionName | str |  |
| blockEnable | bool |  |
| calledPartyTransformationMask | str |  |
| callingPartyTransformationMask | str |  |
| useCallingPartyPhoneMask | [Status](#Status) |  |
| callingPartyPrefixDigits | str |  |
| dialPlanName | str |  |
| digitDiscardInstructionName | str |  |
| patternUrgency | bool |  |
| prefixDigitsOut | str |  |
| routeFilterName | str |  |
| callingLinePresentationBit | [PresentationBit](#PresentationBit) |  |
| callingNamePresentationBit | [PresentationBit](#PresentationBit) |  |
| connectedLinePresentationBit | [PresentationBit](#PresentationBit) |  |
| connectedNamePresentationBit | [PresentationBit](#PresentationBit) |  |
| patternPrecedence | [PatternPrecedence](#PatternPrecedence) |  |
| provideOutsideDialtone | bool |  |
| callingPartyNumberingPlan | [NumberingPlan](#NumberingPlan) |  |
| callingPartyNumberType | [PriOfNumber](#PriOfNumber) |  |
| calledPartyNumberingPlan | [NumberingPlan](#NumberingPlan) |  |
| calledPartyNumberType | [PriOfNumber](#PriOfNumber) |  |
| huntListName | str |  |
| parkMonForwardNoRetrieve | Any |  |
| alertingName | str |  |
| asciiAlertingName | Any |  |
| e164Mask | str |  |
| aarNeighborhoodName | str |  |
| forwardHuntNoAnswer | Any |  |
| forwardHuntBusy | Any |  |
| callPickupGroupName | str |  |
| maxHuntduration | Any |  |
| releaseClause | [ReleaseCauseValue](#ReleaseCauseValue) |  |
| displayConnectedNumber | bool |  |
| queueCalls | [CallsQueue](#CallsQueue) |  |

### ImeClient { #ImeClient }

Used by AXLClient.add_ime_client().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| domain | str |  |
| isActivated | bool |  |
| sipTrunkName | str |  |
| primaryImeServerName | str |  |
| secondaryImeServerName | str |  |
| learnedRouteFilterGroupName | str |  |
| exclusionNumberGroupName | str |  |
| firewallName | str |  |
| members | Any |  |
| ccmExternalIpMaps | Any |  |

### ImeE164Transformation { #ImeE164Transformation }

Used by AXLClient.add_ime_e164transformation().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| cgpnTransformationCssName | str |  |
| isCgpnPreTransformation | bool |  |
| cdpnTransformationCssName | str |  |
| isCdpnPreTransformation | bool |  |
| incomingCgpnTransformationProfileName | str |  |
| incomingCdpnTransformationProfileName | str |  |

### ImeEnrolledPattern { #ImeEnrolledPattern }

Used by AXLClient.add_ime_enrolled_pattern().

| Field | Type | Required |
|-------|------|:--------:|
| pattern | str |  |
| description | str |  |
| imeEnrolledPatternGroupName | str |  |

### ImeEnrolledPatternGroup { #ImeEnrolledPatternGroup }

Used by AXLClient.add_ime_enrolled_pattern_group().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| fallbackProfileName | str |  |
| isPatternAllAlias | bool |  |

### ImeExclusionNumber { #ImeExclusionNumber }

Used by AXLClient.add_ime_exclusion_number().

| Field | Type | Required |
|-------|------|:--------:|
| pattern | str |  |
| description | str |  |
| imeExclusionNumberGroupName | str |  |

### ImeExclusionNumberGroup { #ImeExclusionNumberGroup }

Used by AXLClient.add_ime_exclusion_number_group().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |

### ImeFirewall { #ImeFirewall }

Used by AXLClient.add_ime_firewall().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| ipAddress | Any |  |
| port | Any |  |

### ImeRouteFilterElement { #ImeRouteFilterElement }

Used by AXLClient.add_ime_route_filter_element().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| elementType | [ViprFilterElement](#ViprFilterElement) |  |
| imeRouteFilterGroupName | str |  |

### ImeRouteFilterGroup { #ImeRouteFilterGroup }

Used by AXLClient.add_ime_route_filter_group().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| groupTrustSetting | bool |  |

### ImeServer { #ImeServer }

Used by AXLClient.add_ime_server().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| ipAddress | str |  |
| port | Any |  |
| deviceSecurityMode | [ServerSecurityMode](#ServerSecurityMode) |  |
| applicationUser | str |  |
| reconnectInterval | Any |  |

### ImportedDirectoryUriCatalogs { #ImportedDirectoryUriCatalogs }

Used by AXLClient.add_imported_directory_uri_catalogs().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| routeString | str |  |
| lastLoadedFileName | str |  |
| fileLoadDateTime | Any |  |

### InfrastructureDevice { #InfrastructureDevice }

Used by AXLClient.add_infrastructure_device().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| ipv4Address | str |  |
| ipv6Address | str |  |
| bssidWithMask | str |  |
| wapLocation | str |  |
| isActive | bool |  |

### IpPhoneServices { #IpPhoneServices }

Used by AXLClient.add_ip_phone_services().

| Field | Type | Required |
|-------|------|:--------:|
| serviceName | str |  |
| asciiServiceName | str |  |
| serviceDescription | str |  |
| serviceUrl | str |  |
| secureServiceUrl | str |  |
| serviceCategory | [PhoneServiceCategory](#PhoneServiceCategory) |  |
| serviceType | [PhoneService](#PhoneService) |  |
| serviceVendor | str |  |
| serviceVersion | str |  |
| enabled | bool |  |
| enterpriseSubscription | bool |  |
| parameters | Any |  |

### IvrUserLocale { #IvrUserLocale }

Used by AXLClient.add_ivr_user_locale().

| Field | Type | Required |
|-------|------|:--------:|
| userLocale | [UserLocale](#UserLocale) |  |
| orderIndex | Any |  |

### LbmGroup { #LbmGroup }

Used by AXLClient.add_lbm_group().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| Description | str |  |
| ProcessnodeActive | str |  |
| ProcessnodeStandby | str |  |

### LbmHubGroup { #LbmHubGroup }

Used by AXLClient.add_lbm_hub_group().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| member1 | str |  |
| member2 | str |  |
| member3 | str |  |
| members | Any |  |

### LdapDirectory { #LdapDirectory }

Used by AXLClient.add_ldap_directory().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| ldapDn | str |  |
| ldapPassword | str |  |
| userSearchBase | str |  |
| repeatable | bool |  |
| intervalValue | Any |  |
| scheduleUnit | [ScheduleUnit](#ScheduleUnit) |  |
| nextExecTime | Any |  |
| servers | Any |  |
| middleName | str |  |
| phoneNumber | str |  |
| mailId | str |  |
| ldapFilter | str |  |
| synchronize | bool |  |
| ldapFilterForGroups | str |  |
| directoryUri | str |  |
| accessControlGroupInfo | Any |  |
| featureGroupTemplate | str |  |
| applyMask | bool |  |
| mask | str |  |
| applyPoolList | bool |  |
| addDns | Any |  |

### LdapFilter { #LdapFilter }

Used by AXLClient.add_ldap_filter().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| filter | str |  |

### LdapSyncCustomField { #LdapSyncCustomField }

Used by AXLClient.add_ldap_sync_custom_field().

| Field | Type | Required |
|-------|------|:--------:|
| ldapConfigurationName | str |  |
| customUserField | str |  |
| ldapUserField | str |  |

### Line { #Line }

Used by AXLClient.add_line().

| Field | Type | Required |
|-------|------|:--------:|
| pattern | str |  |
| description | str |  |
| usage | [PatternUsage](#PatternUsage) |  |
| routePartitionName | str |  |
| aarNeighborhoodName | str |  |
| aarDestinationMask | str |  |
| aarKeepCallHistory | bool |  |
| aarVoiceMailEnabled | bool |  |
| callForwardAll | [CallForwardAll](#CallForwardAll) |  |
| callForwardBusy | [CallForwardBusy](#CallForwardBusy) |  |
| callForwardBusyInt | [CallForwardBusyInt](#CallForwardBusyInt) |  |
| callForwardNoAnswer | [CallForwardNoAnswer](#CallForwardNoAnswer) |  |
| callForwardNoAnswerInt | [CallForwardNoAnswerInt](#CallForwardNoAnswerInt) |  |
| callForwardNoCoverage | [CallForwardNoCoverage](#CallForwardNoCoverage) |  |
| callForwardNoCoverageInt | [CallForwardNoCoverageInt](#CallForwardNoCoverageInt) |  |
| callForwardOnFailure | [CallForwardOnFailure](#CallForwardOnFailure) |  |
| callForwardAlternateParty | [CallForwardAlternateParty](#CallForwardAlternateParty) |  |
| callForwardNotRegistered | [CallForwardNotRegistered](#CallForwardNotRegistered) |  |
| callForwardNotRegisteredInt | [CallForwardNotRegisteredInt](#CallForwardNotRegisteredInt) |  |
| callPickupGroupName | str |  |
| autoAnswer | [AutoAnswer](#AutoAnswer) |  |
| networkHoldMohAudioSourceId | Any |  |
| userHoldMohAudioSourceId | Any |  |
| callingIdPresentationWhenDiverted | [PresentationBit](#PresentationBit) |  |
| alertingName | str |  |
| asciiAlertingName | Any |  |
| presenceGroupName | str |  |
| shareLineAppearanceCssName | str |  |
| voiceMailProfileName | str |  |
| patternPrecedence | [PatternPrecedence](#PatternPrecedence) |  |
| releaseClause | [ReleaseCauseValue](#ReleaseCauseValue) |  |
| hrDuration | Any |  |
| hrInterval | Any |  |
| cfaCssPolicy | [CFACSSActivationPolicy](#CFACSSActivationPolicy) |  |
| defaultActivatedDeviceName | str |  |
| parkMonForwardNoRetrieveDn | str |  |
| parkMonForwardNoRetrieveIntDn | str |  |
| parkMonForwardNoRetrieveVmEnabled | bool |  |
| parkMonForwardNoRetrieveIntVmEnabled | bool |  |
| parkMonForwardNoRetrieveCssName | str |  |
| parkMonForwardNoRetrieveIntCssName | str |  |
| parkMonReversionTimer | Any |  |
| partyEntranceTone | [Status](#Status) |  |
| directoryURIs | Any |  |
| allowCtiControlFlag | bool |  |
| rejectAnonymousCall | bool |  |
| patternUrgency | bool |  |
| confidentialAccess | Any |  |
| externalCallControlProfile | str |  |
| enterpriseAltNum | Any |  |
| e164AltNum | Any |  |
| pstnFailover | str |  |
| callControlAgentProfile | str |  |
| useEnterpriseAltNum | bool |  |
| useE164AltNum | bool |  |
| active | bool |  |
| externalPresentationInfo | Any |  |

### LineGroup { #LineGroup }

Used by AXLClient.add_line_group().

| Field | Type | Required |
|-------|------|:--------:|
| distributionAlgorithm | [DistributeAlgorithm](#DistributeAlgorithm) |  |
| rnaReversionTimeOut | Any |  |
| huntAlgorithmNoAnswer | [HuntAlgorithm](#HuntAlgorithm) |  |
| huntAlgorithmBusy | [HuntAlgorithm](#HuntAlgorithm) |  |
| huntAlgorithmNotAvailable | [HuntAlgorithm](#HuntAlgorithm) |  |
| members | Any |  |
| name | str |  |
| autoLogOffHunt | bool |  |

### LocalRouteGroup { #LocalRouteGroup }

Used by AXLClient.add_local_route_group().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |

### Location { #Location }

Used by AXLClient.add_location().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| relatedLocations | Any |  |
| withinAudioBandwidth | Any |  |
| withinVideoBandwidth | Any |  |
| withinImmersiveKbits | Any |  |
| betweenLocations | Any |  |

### MediaResourceGroup { #MediaResourceGroup }

Used by AXLClient.add_media_resource_group().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| multicast | bool |  |
| members | Any |  |

### MediaResourceList { #MediaResourceList }

Used by AXLClient.add_media_resource_list().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| members | Any |  |

### MeetMe { #MeetMe }

Used by AXLClient.add_meet_me().

| Field | Type | Required |
|-------|------|:--------:|
| pattern | str |  |
| description | str |  |
| routePartitionName | str |  |
| minimumSecurityLevel | [DeviceSecurityMode](#DeviceSecurityMode) |  |

### MessageWaiting { #MessageWaiting }

Used by AXLClient.add_message_waiting().

| Field | Type | Required |
|-------|------|:--------:|
| pattern | str |  |
| routePartitionName | str |  |
| description | str |  |
| messageWaitingIndicator | bool |  |
| callingSearchSpaceName | str |  |

### MlppDomain { #MlppDomain }

Used by AXLClient.add_mlpp_domain().

| Field | Type | Required |
|-------|------|:--------:|
| domainName | str |  |
| domainId | str |  |

### MobileVoiceAccess { #MobileVoiceAccess }

Used by AXLClient.add_mobile_voice_access().

| Field | Type | Required |
|-------|------|:--------:|
| pattern | str |  |
| routePartitionName | str |  |
| locales | Any |  |

### Mobility { #Mobility }

Used by AXLClient.add_mobility().

| Field | Type | Required |
|-------|------|:--------:|
| handoffNumber | str | ✅ |
| handoffPartitionName | str |  |
| DTMFNumber | str | ✅ |
| DTMFPartitionName | str |  |

### MobilityProfile { #MobilityProfile }

Used by AXLClient.add_mobility_profile().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| mobileClientCallingOption | [DialViaOffice](#DialViaOffice) |  |
| dvofServiceAccessNumber | str |  |
| dirn | [Dirn](#Dirn) |  |
| dvorCallerId | str |  |

### MraServiceDomain { #MraServiceDomain }

Used by AXLClient.add_mra_service_domain().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| isDefault | bool |  |
| serviceDomains | str |  |

### Mtp { #Mtp }

Used by AXLClient.add_mtp().

| Field | Type | Required |
|-------|------|:--------:|
| mtpType | [Product](#Product) |  |
| name | str |  |
| description | str |  |
| devicePoolName | str |  |
| trustedRelayPoint | bool |  |

### NetworkAccessProfile { #NetworkAccessProfile }

Used by AXLClient.add_network_access_profile().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| vpnRequired | [Status](#Status) |  |
| proxySettings | [HTTPProxy](#HTTPProxy) |  |
| proxyHostname | str |  |
| proxyPort | Any |  |
| proxyRequiresAuthentication | bool |  |
| provideSharedCredentials | bool |  |
| username | str |  |
| password | str |  |

### Phone { #Phone }

Used by AXLClient.add_phone().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| product | [Product](#Product) |  |
| class | [Class](#Class) |  |
| protocol | [DeviceProtocol](#DeviceProtocol) |  |
| protocolSide | [ProtocolSide](#ProtocolSide) |  |
| callingSearchSpaceName | str |  |
| devicePoolName | str |  |
| commonDeviceConfigName | str |  |
| commonPhoneConfigName | str |  |
| networkLocation | [NetworkLocation](#NetworkLocation) |  |
| locationName | str |  |
| mediaResourceListName | str |  |
| networkHoldMohAudioSourceId | Any |  |
| userHoldMohAudioSourceId | Any |  |
| automatedAlternateRoutingCssName | str |  |
| aarNeighborhoodName | str |  |
| loadInformation | [LoadInformation](#LoadInformation) |  |
| vendorConfig | [VendorConfig](#VendorConfig) |  |
| versionStamp | str |  |
| traceFlag | bool |  |
| mlppDomainId | str |  |
| mlppIndicationStatus | [Status](#Status) |  |
| preemption | [Preemption](#Preemption) |  |
| useTrustedRelayPoint | [Status](#Status) |  |
| retryVideoCallAsAudio | bool |  |
| securityProfileName | str |  |
| sipProfileName | str |  |
| cgpnTransformationCssName | str |  |
| useDevicePoolCgpnTransformCss | bool |  |
| geoLocationName | str |  |
| geoLocationFilterName | str |  |
| sendGeoLocation | bool |  |
| lines | Any |  |
| phoneTemplateName | str |  |
| speeddials | Any |  |
| busyLampFields | Any |  |
| primaryPhoneName | str |  |
| ringSettingIdleBlfAudibleAlert | [Status](#Status) |  |
| ringSettingBusyBlfAudibleAlert | [Status](#Status) |  |
| blfDirectedCallParks | Any |  |
| addOnModules | Any |  |
| userLocale | [UserLocale](#UserLocale) |  |
| networkLocale | [Country](#Country) |  |
| idleTimeout | Any |  |
| authenticationUrl | str |  |
| directoryUrl | str |  |
| idleUrl | str |  |
| informationUrl | str |  |
| messagesUrl | str |  |
| proxyServerUrl | str |  |
| servicesUrl | str |  |
| services | Any |  |
| softkeyTemplateName | str |  |
| defaultProfileName | str |  |
| enableExtensionMobility | bool |  |
| singleButtonBarge | [Barge](#Barge) |  |
| joinAcrossLines | [Status](#Status) |  |
| builtInBridgeStatus | [Status](#Status) |  |
| callInfoPrivacyStatus | [Status](#Status) |  |
| hlogStatus | [Status](#Status) |  |
| ownerUserName | str |  |
| ignorePresentationIndicators | bool |  |
| packetCaptureMode | [PacketCaptureMode](#PacketCaptureMode) |  |
| packetCaptureDuration | Any |  |
| subscribeCallingSearchSpaceName | str |  |
| rerouteCallingSearchSpaceName | str |  |
| allowCtiControlFlag | bool |  |
| presenceGroupName | str |  |
| unattendedPort | bool |  |
| requireDtmfReception | bool |  |
| rfc2833Disabled | bool |  |
| certificateOperation | [CertificateOperation](#CertificateOperation) |  |
| authenticationMode | [AuthenticationMode](#AuthenticationMode) |  |
| keySize | [KeySize](#KeySize) |  |
| keyOrder | [KeyOrder](#KeyOrder) |  |
| ecKeySize | [ECKeySize](#ECKeySize) |  |
| authenticationString | str |  |
| upgradeFinishTime | str |  |
| deviceMobilityMode | [Status](#Status) |  |
| remoteDevice | bool |  |
| dndOption | [DNDOption](#DNDOption) |  |
| dndRingSetting | [RingSetting](#RingSetting) |  |
| dndStatus | bool |  |
| isActive | bool |  |
| isDualMode | bool |  |
| mobilityUserIdName | str |  |
| phoneSuite | [PhonePersonalization](#PhonePersonalization) |  |
| phoneServiceDisplay | [PhoneServiceDisplay](#PhoneServiceDisplay) |  |
| isProtected | bool |  |
| mtpRequired | bool |  |
| mtpPreferedCodec | [SIPCodec](#SIPCodec) |  |
| dialRulesName | str |  |
| sshUserId | str |  |
| sshPwd | str |  |
| digestUser | str |  |
| outboundCallRollover | [OutboundCallRollover](#OutboundCallRollover) |  |
| hotlineDevice | bool |  |
| secureInformationUrl | str |  |
| secureDirectoryUrl | str |  |
| secureMessageUrl | str |  |
| secureServicesUrl | str |  |
| secureAuthenticationUrl | str |  |
| secureIdleUrl | str |  |
| alwaysUsePrimeLine | [Status](#Status) |  |
| alwaysUsePrimeLineForVoiceMessage | [Status](#Status) |  |
| featureControlPolicy | str |  |
| deviceTrustMode | [DeviceTrustMode](#DeviceTrustMode) |  |
| earlyOfferSupportForVoiceCall | bool |  |
| requireThirdPartyRegistration | bool |  |
| blockIncomingCallsWhenRoaming | bool |  |
| homeNetworkId | str |  |
| AllowPresentationSharingUsingBfcp | bool |  |
| confidentialAccess | Any |  |
| requireOffPremiseLocation | bool |  |
| allowiXApplicableMedia | bool |  |
| cgpnIngressDN | str |  |
| useDevicePoolCgpnIngressDN | bool |  |
| msisdn | str |  |
| enableCallRoutingToRdWhenNoneIsActive | bool |  |
| wifiHotspotProfile | str |  |
| wirelessLanProfileGroup | str |  |
| elinGroup | str |  |
| enableActivationID | bool |  |
| mraServiceDomain | str |  |
| allowMraMode | bool |  |

### PhoneActivationCode { #PhoneActivationCode }

Used by AXLClient.add_phone_activation_code().

| Field | Type | Required |
|-------|------|:--------:|
| activationCodeExpiry | Any |  |
| phoneName | str |  |

### PhoneButtonTemplate { #PhoneButtonTemplate }

Used by AXLClient.add_phone_button_template().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| basePhoneTemplateName | str |  |
| buttons | Any |  |

### PhoneNtp { #PhoneNtp }

Used by AXLClient.add_phone_ntp().

| Field | Type | Required |
|-------|------|:--------:|
| ipAddress | str |  |
| ipv6Address | str |  |
| description | str |  |
| mode | [Zzntpmode](#Zzntpmode) |  |

### PhoneSecurityProfile { #PhoneSecurityProfile }

Used by AXLClient.add_phone_security_profile().

| Field | Type | Required |
|-------|------|:--------:|
| phoneType | [Model](#Model) |  |
| protocol | [DeviceProtocol](#DeviceProtocol) |  |
| name | str |  |
| description | str |  |
| deviceSecurityMode | [DeviceSecurityMode](#DeviceSecurityMode) |  |
| authenticationMode | [AuthenticationMode](#AuthenticationMode) |  |
| keySize | [KeySize](#KeySize) |  |
| keyOrder | [KeyOrder](#KeyOrder) |  |
| ecKeySize | [ECKeySize](#ECKeySize) |  |
| tftpEncryptedConfig | bool |  |
| EnableOAuthAuthentication | bool |  |
| nonceValidityTime | Any |  |
| transportType | [Transport](#Transport) |  |
| sipPhonePort | Any |  |
| enableDigestAuthentication | bool |  |
| excludeDigestCredentials | bool |  |

### PhysicalLocation { #PhysicalLocation }

Used by AXLClient.add_physical_location().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |

### PresenceGroup { #PresenceGroup }

Used by AXLClient.add_presence_group().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| presenceGroups | Any |  |

### PresenceRedundancyGroup { #PresenceRedundancyGroup }

Used by AXLClient.add_presence_redundancy_group().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| server1 | str |  |
| server2 | str |  |
| haEnabled | bool |  |

### ProcessNode { #ProcessNode }

Used by AXLClient.add_process_node().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| mac | Any |  |
| ipv6Name | str |  |
| lbmHubGroup | str |  |
| processNodeRole | [ProcessNodeRole](#ProcessNodeRole) |  |
| cupDomain | str |  |

### RCommunityString { #RCommunityString }

Used by AXLClient.add_snmpcommunity_string().

| Field | Type | Required |
|-------|------|:--------:|
| communityName | str | ✅ |
| accessPrivilege | str | ✅ |
| ArrayOfHosts | [RArrayOfHosts](#RArrayOfHosts) | ✅ |

### RSNMPUser { #RSNMPUser }

Used by AXLClient.add_snmpuser().

| Field | Type | Required |
|-------|------|:--------:|
| userName | str | ✅ |
| authRequired | bool | ✅ |
| authPassword | str | ✅ |
| authProtocol | str | ✅ |
| privacyRequired | bool | ✅ |
| privacyPassword | str | ✅ |
| privacyProtocol | str | ✅ |
| accessPrivilege | str | ✅ |
| ArrayOfHosts | [RArrayOfHosts](#RArrayOfHosts) | ✅ |

### RecordingProfile { #RecordingProfile }

Used by AXLClient.add_recording_profile().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| recordingCssName | str |  |
| recorderDestination | str |  |

### Region { #Region }

Used by AXLClient.add_region().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| relatedRegions | Any |  |
| defaultCodec | str |  |

### RemoteCluster { #RemoteCluster }

Used by AXLClient.add_remote_cluster().

| Field | Type | Required |
|-------|------|:--------:|
| clusterId | str |  |
| description | str |  |
| fullyQualifiedName | str |  |
| emcc | [RemoteClusterMember](#RemoteClusterMember) |  |
| pstnAccess | [RemoteClusterMember](#RemoteClusterMember) |  |
| rsvpAgent | [RemoteClusterMember](#RemoteClusterMember) |  |
| tftp | [RemoteClusterMember](#RemoteClusterMember) |  |
| lbm | [RemoteClusterMember](#RemoteClusterMember) |  |
| uds | [RemoteClusterMember](#RemoteClusterMember) |  |

### RemoteDestination { #RemoteDestination }

Used by AXLClient.add_remote_destination().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| destination | str |  |
| answerTooSoonTimer | Any |  |
| answerTooLateTimer | Any |  |
| delayBeforeRingingCell | Any |  |
| ownerUserId | str |  |
| enableUnifiedMobility | bool |  |
| remoteDestinationProfileName | str |  |
| enableExtendAndConnect | bool |  |
| ctiRemoteDeviceName | str |  |
| dualModeDeviceName | str |  |
| isMobilePhone | bool |  |
| enableMobileConnect | bool |  |
| lineAssociations | Any |  |
| timeZone | [TimeZone](#TimeZone) |  |
| todAccessName | str |  |
| mobileSmartClientName | str |  |
| mobilityProfileName | str |  |
| singleNumberReachVoicemail | [VMAvoidancePolicy](#VMAvoidancePolicy) |  |
| dialViaOfficeReverseVoicemail | [VMAvoidancePolicy](#VMAvoidancePolicy) |  |
| ringSchedule | Any |  |
| accessListName | str |  |

### RemoteDestinationProfile { #RemoteDestinationProfile }

Used by AXLClient.add_remote_destination_profile().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| product | [Product](#Product) |  |
| class | [Class](#Class) |  |
| protocol | [DeviceProtocol](#DeviceProtocol) |  |
| protocolSide | [ProtocolSide](#ProtocolSide) |  |
| callingSearchSpaceName | str |  |
| devicePoolName | str |  |
| networkHoldMohAudioSourceId | Any |  |
| userHoldMohAudioSourceId | Any |  |
| lines | Any |  |
| callInfoPrivacyStatus | [Status](#Status) |  |
| userId | str |  |
| ignorePresentationIndicators | bool |  |
| rerouteCallingSearchSpaceName | str |  |
| cgpnTransformationCssName | str |  |
| automatedAlternateRoutingCssName | str |  |
| useDevicePoolCgpnTransformCss | bool |  |
| userLocale | [UserLocale](#UserLocale) |  |
| networkLocale | [Country](#Country) |  |
| primaryPhoneName | str |  |
| dndOption | [DNDOption](#DNDOption) |  |
| dndStatus | bool |  |
| mobileSmartClientProfileName | str |  |

### ResourcePriorityNamespace { #ResourcePriorityNamespace }

Used by AXLClient.add_resource_priority_namespace().

| Field | Type | Required |
|-------|------|:--------:|
| namespace | Any |  |
| description | str |  |
| isDefault | bool |  |

### ResourcePriorityNamespaceList { #ResourcePriorityNamespaceList }

Used by AXLClient.add_resource_priority_namespace_list().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| members | Any |  |

### RouteFilter { #RouteFilter }

Used by AXLClient.add_route_filter().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| dialPlanName | str |  |
| members | Any |  |

### RouteGroup { #RouteGroup }

Used by AXLClient.add_route_group().

| Field | Type | Required |
|-------|------|:--------:|
| distributionAlgorithm | [DistributeAlgorithm](#DistributeAlgorithm) |  |
| members | Any |  |
| name | str |  |

### RouteList { #RouteList }

Used by AXLClient.add_route_list().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| callManagerGroupName | str |  |
| routeListEnabled | bool |  |
| members | Any |  |
| runOnEveryNode | bool |  |

### RoutePartition { #RoutePartition }

Used by AXLClient.add_route_partition().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| timeScheduleIdName | str |  |
| useOriginatingDeviceTimeZone | bool |  |
| timeZone | [TimeZone](#TimeZone) |  |
| partitionUsage | [PartitionUsage](#PartitionUsage) |  |

### RoutePattern { #RoutePattern }

Used by AXLClient.add_route_pattern().

| Field | Type | Required |
|-------|------|:--------:|
| pattern | str |  |
| description | str |  |
| routePartitionName | str |  |
| blockEnable | bool |  |
| calledPartyTransformationMask | str |  |
| callingPartyTransformationMask | str |  |
| useCallingPartyPhoneMask | [Status](#Status) |  |
| callingPartyPrefixDigits | str |  |
| dialPlanName | str |  |
| digitDiscardInstructionName | str |  |
| networkLocation | [NetworkLocation](#NetworkLocation) |  |
| patternUrgency | bool |  |
| prefixDigitsOut | str |  |
| routeFilterName | str |  |
| callingLinePresentationBit | [PresentationBit](#PresentationBit) |  |
| callingNamePresentationBit | [PresentationBit](#PresentationBit) |  |
| connectedLinePresentationBit | [PresentationBit](#PresentationBit) |  |
| connectedNamePresentationBit | [PresentationBit](#PresentationBit) |  |
| supportOverlapSending | bool |  |
| patternPrecedence | [PatternPrecedence](#PatternPrecedence) |  |
| releaseClause | [ReleaseCauseValue](#ReleaseCauseValue) |  |
| allowDeviceOverride | bool |  |
| provideOutsideDialtone | bool |  |
| callingPartyNumberingPlan | [NumberingPlan](#NumberingPlan) |  |
| callingPartyNumberType | [PriOfNumber](#PriOfNumber) |  |
| calledPartyNumberingPlan | [NumberingPlan](#NumberingPlan) |  |
| calledPartyNumberType | [PriOfNumber](#PriOfNumber) |  |
| destination | Any |  |
| authorizationCodeRequired | bool |  |
| authorizationLevelRequired | Any |  |
| clientCodeRequired | bool |  |
| isdnNsfInfoElement | Any |  |
| resourcePriorityNamespaceName | str |  |
| routeClass | [PatternRouteClass](#PatternRouteClass) |  |
| enableDccEnforcement | bool |  |
| blockedCallPercentage | str |  |
| externalCallControl | str |  |
| isEmergencyServiceNumber | bool |  |

### SIPNormalizationScript { #SIPNormalizationScript }

Used by AXLClient.add_sipnormalization_script().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| content | str |  |
| scriptExecutionErrorRecoveryAction | [SIPScriptErrorHandling](#SIPScriptErrorHandling) |  |
| systemResourceErrorRecoveryAction | [SIPScriptErrorHandling](#SIPScriptErrorHandling) |  |
| maxMemoryThreshold | str |  |
| maxLuaInstructionsThreshold | str |  |
| isStandard | bool |  |

### SafCcdPurgeBlockLearnedRoutes { #SafCcdPurgeBlockLearnedRoutes }

Used by AXLClient.add_saf_ccd_purge_block_learned_routes().

| Field | Type | Required |
|-------|------|:--------:|
| learnedPattern | str |  |
| learnedPatternPrefix | str |  |
| callControlIdentity | str |  |
| ipAddress | str |  |

### SafForwarder { #SafForwarder }

Used by AXLClient.add_saf_forwarder().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| clientLabel | str |  |
| safSecurityProfile | str |  |
| ipAddress | str |  |
| port | Any |  |
| enableTcpKeepAlive | bool |  |
| safReconnectInterval | Any |  |
| safNotificationsWindowSize | Any |  |
| associatedCucms | Any |  |

### SafSecurityProfile { #SafSecurityProfile }

Used by AXLClient.add_saf_security_profile().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| userid | str |  |
| password | str |  |

### SdpTransparencyProfile { #SdpTransparencyProfile }

Used by AXLClient.add_sdp_transparency_profile().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| attributeSet | List[Any] |  |

### ServiceProfile { #ServiceProfile }

Used by AXLClient.add_service_profile().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| isDefault | bool |  |
| serviceProfileInfos | Any |  |

### SipDialRules { #SipDialRules }

Used by AXLClient.add_sip_dial_rules().

| Field | Type | Required |
|-------|------|:--------:|
| dialPattern | [DialPattern](#DialPattern) |  |
| name | str |  |
| description | str |  |
| patterns | Any |  |
| plars | Any |  |

### SipProfile { #SipProfile }

Used by AXLClient.add_sip_profile().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| defaultTelephonyEventPayloadType | Any |  |
| redirectByApplication | bool |  |
| ringing180 | bool |  |
| timerInvite | Any |  |
| timerRegisterDelta | Any |  |
| timerRegister | Any |  |
| timerT1 | Any |  |
| timerT2 | Any |  |
| retryInvite | Any |  |
| retryNotInvite | Any |  |
| startMediaPort | Any |  |
| stopMediaPort | Any |  |
| startVideoPort | Any |  |
| stopVideoPort | Any |  |
| dscpForAudioCalls | str |  |
| dscpForVideoCalls | str |  |
| dscpForAudioPortionOfVideoCalls | str |  |
| dscpForTelePresenceCalls | str |  |
| dscpForAudioPortionOfTelePresenceCalls | str |  |
| callpickupListUri | str |  |
| callpickupGroupUri | str |  |
| meetmeServiceUrl | str |  |
| userInfo | [ZzuserInfo](#ZzuserInfo) |  |
| dtmfDbLevel | [ZzdtmfDbLevel](#ZzdtmfDbLevel) |  |
| callHoldRingback | [Zzpreff](#Zzpreff) |  |
| anonymousCallBlock | [Zzpreff](#Zzpreff) |  |
| callerIdBlock | [Zzpreff](#Zzpreff) |  |
| dndControl | [Zzdndcontrol](#Zzdndcontrol) |  |
| telnetLevel | [TelnetLevel](#TelnetLevel) |  |
| timerKeepAlive | Any |  |
| timerSubscribe | Any |  |
| timerSubscribeDelta | Any |  |
| maxRedirects | Any |  |
| timerOffHookToFirstDigit | Any |  |
| callForwardUri | str |  |
| abbreviatedDialUri | str |  |
| confJointEnable | bool |  |
| rfc2543Hold | bool |  |
| semiAttendedTransfer | bool |  |
| enableVad | bool |  |
| stutterMsgWaiting | bool |  |
| callStats | bool |  |
| t38Invite | bool |  |
| faxInvite | bool |  |
| rerouteIncomingRequest | [SIPReroute](#SIPReroute) |  |
| resourcePriorityNamespaceListName | str |  |
| enableAnatForEarlyOfferCalls | bool |  |
| rsvpOverSip | [RSVPOverSIP](#RSVPOverSIP) |  |
| fallbackToLocalRsvp | bool |  |
| sipRe11XxEnabled | [SIPRel1XXOptions](#SIPRel1XXOptions) |  |
| gClear | [GClear](#GClear) |  |
| sendRecvSDPInMidCallInvite | bool |  |
| enableOutboundOptionsPing | bool |  |
| optionsPingIntervalWhenStatusOK | Any |  |
| optionsPingIntervalWhenStatusNotOK | Any |  |
| deliverConferenceBridgeIdentifier | bool |  |
| sipOptionsRetryCount | Any |  |
| sipOptionsRetryTimer | Any |  |
| sipBandwidthModifier | [SIPBandwidthModifier](#SIPBandwidthModifier) |  |
| enableUriOutdialSupport | str |  |
| userAgentServerHeaderInfo | [UserAgentServerHeaderInfo](#UserAgentServerHeaderInfo) |  |
| allowPresentationSharingUsingBfcp | bool |  |
| scriptParameters | str |  |
| isScriptTraceEnabled | bool |  |
| sipNormalizationScript | str |  |
| allowiXApplicationMedia | bool |  |
| dialStringInterpretation | [URIDisambiguationPolicy](#URIDisambiguationPolicy) |  |
| acceptAudioCodecPreferences | [Status](#Status) |  |
| mlppUserAuthorization | bool |  |
| isAssuredSipServiceEnabled | bool |  |
| enableExternalQoS | bool |  |
| resourcePriorityNamespace | str |  |
| useCallerIdCallerNameinUriOutgoingRequest | bool |  |
| externalPresentationInfo | Any |  |
| callingLineIdentification | [CallingLineIdentification](#CallingLineIdentification) |  |
| rejectAnonymousIncomingCall | bool |  |
| callpickupUri | str |  |
| rejectAnonymousOutgoingCall | bool |  |
| videoCallTrafficClass | [VideoCallTrafficClass](#VideoCallTrafficClass) |  |
| sdpTransparency | str |  |
| allowMultipleCodecs | bool |  |
| sipSessionRefreshMethod | [SipSessionRefreshMethod](#SipSessionRefreshMethod) |  |
| earlyOfferSuppVoiceCall | [EOSuppVoiceCall](#EOSuppVoiceCall) |  |
| cucmVersionInSipHeader | [CUCMVersionInSipHeader](#CUCMVersionInSipHeader) |  |
| confidentialAccessLevelHeaders | [CALHeaders](#CALHeaders) |  |
| destRouteString | bool |  |
| inactiveSDPRequired | bool |  |
| allowRRAndRSBandwidthModifier | bool |  |
| connectCallBeforePlayingAnnouncement | bool |  |

### SipRealm { #SipRealm }

Used by AXLClient.add_sip_realm().

| Field | Type | Required |
|-------|------|:--------:|
| realm | str |  |
| userid | str |  |
| digestCredentials | str |  |

### SipRoutePattern { #SipRoutePattern }

Used by AXLClient.add_sip_route_pattern().

| Field | Type | Required |
|-------|------|:--------:|
| pattern | str |  |
| description | str |  |
| usage | [PatternUsage](#PatternUsage) |  |
| routePartitionName | str |  |
| blockEnable | bool |  |
| callingPartyTransformationMask | str |  |
| useCallingPartyPhoneMask | [Status](#Status) |  |
| callingPartyPrefixDigits | str |  |
| callingLinePresentationBit | [PresentationBit](#PresentationBit) |  |
| callingNamePresentationBit | [PresentationBit](#PresentationBit) |  |
| connectedLinePresentationBit | [PresentationBit](#PresentationBit) |  |
| connectedNamePresentationBit | [PresentationBit](#PresentationBit) |  |
| sipTrunkName | str |  |
| dnOrPatternIpv6 | str |  |
| routeOnUserPart | bool |  |
| useCallerCss | bool |  |
| domainRoutingCssName | str |  |

### SipTrunk { #SipTrunk }

Used by AXLClient.add_sip_trunk().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| product | [Product](#Product) |  |
| class | [Class](#Class) |  |
| protocol | [DeviceProtocol](#DeviceProtocol) |  |
| protocolSide | [ProtocolSide](#ProtocolSide) |  |
| callingSearchSpaceName | str |  |
| devicePoolName | str |  |
| commonDeviceConfigName | str |  |
| networkLocation | [NetworkLocation](#NetworkLocation) |  |
| locationName | str |  |
| mediaResourceListName | str |  |
| networkHoldMohAudioSourceId | Any |  |
| userHoldMohAudioSourceId | Any |  |
| automatedAlternateRoutingCssName | str |  |
| aarNeighborhoodName | str |  |
| packetCaptureMode | [PacketCaptureMode](#PacketCaptureMode) |  |
| packetCaptureDuration | Any |  |
| loadInformation | [LoadInformation](#LoadInformation) |  |
| traceFlag | bool |  |
| mlppDomainId | str |  |
| mlppIndicationStatus | [Status](#Status) |  |
| preemption | [Preemption](#Preemption) |  |
| useTrustedRelayPoint | [Status](#Status) |  |
| retryVideoCallAsAudio | bool |  |
| securityProfileName | str |  |
| sipProfileName | str |  |
| cgpnTransformationCssName | str |  |
| useDevicePoolCgpnTransformCss | bool |  |
| geoLocationName | str |  |
| geoLocationFilterName | str |  |
| sendGeoLocation | bool |  |
| cdpnTransformationCssName | str |  |
| useDevicePoolCdpnTransformCss | bool |  |
| unattendedPort | bool |  |
| transmitUtf8 | bool |  |
| subscribeCallingSearchSpaceName | str |  |
| rerouteCallingSearchSpaceName | str |  |
| referCallingSearchSpaceName | str |  |
| mtpRequired | bool |  |
| presenceGroupName | str |  |
| unknownPrefix | str |  |
| destAddrIsSrv | bool |  |
| tkSipCodec | [SIPCodec](#SIPCodec) |  |
| sigDigits | Any |  |
| connectedNamePresentation | [PresentationBit](#PresentationBit) |  |
| connectedPartyIdPresentation | [PresentationBit](#PresentationBit) |  |
| callingPartySelection | [CallingPartySelection](#CallingPartySelection) |  |
| callingname | [PresentationBit](#PresentationBit) |  |
| callingLineIdPresentation | [PresentationBit](#PresentationBit) |  |
| prefixDn | str |  |
| externalPresentationInfo | Any |  |
| acceptInboundRdnis | bool |  |
| acceptOutboundRdnis | bool |  |
| srtpAllowed | bool |  |
| srtpFallbackAllowed | bool |  |
| isPaiEnabled | bool |  |
| sipPrivacy | [SipPrivacy](#SipPrivacy) |  |
| isRpidEnabled | bool |  |
| sipAssertedType | [SipAssertedType](#SipAssertedType) |  |
| trustReceivedIdentity | [TrustReceivedIdentity](#TrustReceivedIdentity) |  |
| dtmfSignalingMethod | [DTMFSignaling](#DTMFSignaling) |  |
| routeClassSignalling | [Status](#Status) |  |
| sipTrunkType | [TrunkService](#TrunkService) |  |
| pstnAccess | bool |  |
| imeE164TransformationName | str |  |
| useImePublicIpPort | bool |  |
| useDevicePoolCntdPnTransformationCss | bool |  |
| cntdPnTransformationCssName | str |  |
| useDevicePoolCgpnTransformCssUnkn | bool |  |
| rdnTransformationCssName | str |  |
| useDevicePoolRdnTransformCss | bool |  |
| useOrigCallingPartyPresOnDivert | bool |  |
| sipNormalizationScriptName | str |  |
| runOnEveryNode | bool |  |
| destinations | Any |  |
| unknownStripDigits | Any |  |
| cgpnTransformationUnknownCssName | str |  |
| tunneledProtocol | [TunneledProtocol](#TunneledProtocol) |  |
| asn1RoseOidEncoding | [ASN1RoseOidEncoding](#ASN1RoseOidEncoding) |  |
| qsigVariant | [QSIGVariant](#QSIGVariant) |  |
| pathReplacementSupport | bool |  |
| enableQsigUtf8 | bool |  |
| scriptParameters | str |  |
| scriptTraceEnabled | bool |  |
| trunkTrafficSecure | [SIPTrunkCallLegSecurity](#SIPTrunkCallLegSecurity) |  |
| callingAndCalledPartyInfoFormat | [SIPIdentityBlend](#SIPIdentityBlend) |  |
| useCallerIdCallerNameinUriOutgoingRequest | bool |  |
| service | str |  |
| parameterLabel | str |  |
| originatingParameterValue | str |  |
| terminatingParameterValue | str |  |
| outboundUriRoutingInstructions | str |  |
| requestUriDomainName | str |  |
| enableCiscoRecordingQsigTunneling | bool |  |
| recordingInformation | str |  |
| calledPartyUnknownTransformationCssName | str |  |
| calledPartyUnknownPrefix | str |  |
| calledPartyUnknownStripDigits | Any |  |
| useDevicePoolCalledCssUnkn | bool |  |
| confidentialAccess | Any |  |

### SipTrunkSecurityProfile { #SipTrunkSecurityProfile }

Used by AXLClient.add_sip_trunk_security_profile().

| Field | Type | Required |
|-------|------|:--------:|
| name | Any |  |
| description | str |  |
| securityMode | [DeviceSecurityMode](#DeviceSecurityMode) |  |
| incomingTransport | [Transport](#Transport) |  |
| outgoingTransport | [Transport](#Transport) |  |
| digestAuthentication | bool |  |
| noncePolicyTime | Any |  |
| x509SubjectName | str |  |
| incomingPort | Any |  |
| applLevelAuthentication | bool |  |
| acceptPresenceSubscription | bool |  |
| acceptOutOfDialogRefer | bool |  |
| acceptUnsolicitedNotification | bool |  |
| allowReplaceHeader | bool |  |
| transmitSecurityStatus | bool |  |
| sipV150OutboundSdpOfferFiltering | [V150SDPFilter](#V150SDPFilter) |  |
| allowChargingHeader | bool |  |

### SoftKeyTemplate { #SoftKeyTemplate }

Used by AXLClient.add_soft_key_template().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| baseSoftkeyTemplateName | str |  |
| isDefault | bool |  |

### Srst { #Srst }

Used by AXLClient.add_srst().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| port | Any |  |
| ipAddress | str |  |
| ipv6Address | str |  |
| SipNetwork | str |  |
| SipPort | Any |  |
| isSecure | bool |  |

### TimePeriod { #TimePeriod }

Used by AXLClient.add_time_period().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| startTime | [TimeOfDay](#TimeOfDay) |  |
| endTime | [TimeOfDay](#TimeOfDay) |  |
| startDay | [DayOfWeek](#DayOfWeek) |  |
| endDay | [DayOfWeek](#DayOfWeek) |  |
| monthOfYear | [MonthOfYear](#MonthOfYear) |  |
| dayOfMonth | Any |  |
| description | str |  |
| isPublished | bool |  |
| todOwnerIdName | str |  |
| dayOfMonthEnd | Any |  |
| monthOfYearEnd | [MonthOfYear](#MonthOfYear) |  |

### TimeSchedule { #TimeSchedule }

Used by AXLClient.add_time_schedule().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| members | Any |  |
| description | str |  |
| isPublished | bool |  |
| timeScheduleCategory | [TimeScheduleCategory](#TimeScheduleCategory) |  |
| todOwnerIdName | str |  |

### TodAccess { #TodAccess }

Used by AXLClient.add_tod_access().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| ownerIdName | str |  |
| members | Any |  |

### TransPattern { #TransPattern }

Used by AXLClient.add_trans_pattern().

| Field | Type | Required |
|-------|------|:--------:|
| pattern | str |  |
| description | str |  |
| usage | [PatternUsage](#PatternUsage) |  |
| routePartitionName | str |  |
| blockEnable | bool |  |
| calledPartyTransformationMask | str |  |
| callingPartyTransformationMask | str |  |
| useCallingPartyPhoneMask | [Status](#Status) |  |
| callingPartyPrefixDigits | str |  |
| dialPlanName | str |  |
| digitDiscardInstructionName | str |  |
| patternUrgency | bool |  |
| prefixDigitsOut | str |  |
| routeFilterName | str |  |
| callingLinePresentationBit | [PresentationBit](#PresentationBit) |  |
| callingNamePresentationBit | [PresentationBit](#PresentationBit) |  |
| connectedLinePresentationBit | [PresentationBit](#PresentationBit) |  |
| connectedNamePresentationBit | [PresentationBit](#PresentationBit) |  |
| patternPrecedence | [PatternPrecedence](#PatternPrecedence) |  |
| provideOutsideDialtone | bool |  |
| callingPartyNumberingPlan | [NumberingPlan](#NumberingPlan) |  |
| callingPartyNumberType | [PriOfNumber](#PriOfNumber) |  |
| calledPartyNumberingPlan | [NumberingPlan](#NumberingPlan) |  |
| calledPartyNumberType | [PriOfNumber](#PriOfNumber) |  |
| callingSearchSpaceName | str |  |
| resourcePriorityNamespaceName | str |  |
| routeNextHopByCgpn | bool |  |
| routeClass | [PatternRouteClass](#PatternRouteClass) |  |
| callInterceptProfileName | str |  |
| releaseClause | [ReleaseCauseValue](#ReleaseCauseValue) |  |
| useOriginatorCss | bool |  |
| dontWaitForIDTOnSubsequentHops | bool |  |
| isEmergencyServiceNumber | bool |  |

### Transcoder { #Transcoder }

Used by AXLClient.add_transcoder().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| product | [Product](#Product) |  |
| subUnit | Any |  |
| devicePoolName | str |  |
| commonDeviceConfigName | str |  |
| loadInformation | [LoadInformation](#LoadInformation) |  |
| vendorConfig | [VendorConfig](#VendorConfig) |  |
| isTrustedRelayPoint | bool |  |
| maximumCapacity | Any |  |

### TransformationProfile { #TransformationProfile }

Used by AXLClient.add_transformation_profile().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| nationalStripDigits | Any |  |
| internationalStripDigits | Any |  |
| unknownStripDigits | Any |  |
| subscriberStripDigits | Any |  |
| nationalPrefix | str |  |
| internationalPrefix | str |  |
| unknownPrefix | str |  |
| subscriberPrefix | str |  |
| nationalCssName | str |  |
| internationalCssName | str |  |
| unknownCssName | str |  |
| subscriberCssName | str |  |

### UcService { #UcService }

Used by AXLClient.add_uc_service().

| Field | Type | Required |
|-------|------|:--------:|
| serviceType | [UCService](#UCService) |  |
| productType | [UCProduct](#UCProduct) |  |
| name | str |  |
| description | str |  |
| hostnameorip | str |  |
| port | Any |  |
| protocol | [ConnectProtocol](#ConnectProtocol) |  |
| ucServiceXml | [VendorConfig](#VendorConfig) |  |

### UnitsToGateway { #UnitsToGateway }

Used by AXLClient.add_units_to_gateway().

| Field | Type | Required |
|-------|------|:--------:|
| domainName | str |  |
| gatewayUuid | str |  |
| units | Any |  |

### UniversalDeviceTemplate { #UniversalDeviceTemplate }

Used by AXLClient.add_universal_device_template().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| deviceDescription | str |  |
| devicePool | str |  |
| deviceSecurityProfile | str |  |
| sipProfile | str |  |
| phoneButtonTemplate | str |  |
| sipDialRules | str |  |
| callingSearchSpace | str |  |
| callingPartyTransformationCSSForInboundCalls | str |  |
| callingPartyTransformationCSSForOutboundCalls | str |  |
| reroutingCallingSearchSpace | str |  |
| subscribeCallingSearchSpaceName | str |  |
| useDevicePoolCallingPartyTransformationCSSforInboundCalls | bool |  |
| useDevicePoolCallingPartyTransformationCSSforOutboundCalls | bool |  |
| commonPhoneProfile | str |  |
| commonDeviceConfiguration | str |  |
| softkeyTemplate | str |  |
| featureControlPolicy | str |  |
| phonePersonalization | [PhonePersonalization](#PhonePersonalization) |  |
| mtpPreferredOriginatingCodec | [SIPCodec](#SIPCodec) |  |
| outboundCallRollover | [OutboundCallRollover](#OutboundCallRollover) |  |
| mediaTerminationPointRequired | bool |  |
| unattendedPort | bool |  |
| requiredDtmfReception | bool |  |
| rfc2833Disabled | bool |  |
| speeddials | Any |  |
| lines | Any |  |
| blfDirectedCallParks | Any |  |
| busyLampFields | Any |  |
| useTrustedRelayPoint | [Status](#Status) |  |
| protectedDevice | bool |  |
| certificateOperation | [CertificateOperation](#CertificateOperation) |  |
| authenticationMode | [AuthenticationMode](#AuthenticationMode) |  |
| authenticationString | str |  |
| keySize | [KeySize](#KeySize) |  |
| keyOrder | [KeyOrder](#KeyOrder) |  |
| ecKeySize | [ECKeySize](#ECKeySize) |  |
| servicesProvisioning | [PhoneServiceDisplay](#PhoneServiceDisplay) |  |
| packetCaptureMode | [PacketCaptureMode](#PacketCaptureMode) |  |
| packetCaptureDuration | Any |  |
| secureShellUser | str |  |
| secureShellPassword | str |  |
| userLocale | [UserLocale](#UserLocale) |  |
| networkLocale | [Country](#Country) |  |
| mlppDomain | str |  |
| mlppIndication | [Status](#Status) |  |
| mlppPreemption | [Preemption](#Preemption) |  |
| doNotDisturb | bool |  |
| dndOption | [DNDOption](#DNDOption) |  |
| dndIncomingCallAlert | [RingSetting](#RingSetting) |  |
| aarGroup | str |  |
| aarCallingSearchSpace | str |  |
| blfPresenceGroup | str |  |
| blfAudibleAlertSettingPhoneBusy | [Status](#Status) |  |
| blfAudibleAlertSettingPhoneIdle | [Status](#Status) |  |
| userHoldMohAudioSource | Any |  |
| networkHoldMohAudioSource | Any |  |
| location | str |  |
| geoLocation | str |  |
| deviceMobilityMode | [Status](#Status) |  |
| mediaResourceGroupList | str |  |
| remoteDevice | bool |  |
| hotlineDevice | bool |  |
| retryVideoCallAsAudio | bool |  |
| requireOffPremiseLocation | bool |  |
| ownerUserId | str |  |
| mobilityUserId | str |  |
| joinAcrossLines | [Status](#Status) |  |
| alwaysUsePrimeLine | [Status](#Status) |  |
| alwaysUsePrimeLineForVoiceMessage | [Status](#Status) |  |
| singleButtonBarge | [Barge](#Barge) |  |
| builtInBridge | [Status](#Status) |  |
| allowControlOfDeviceFromCti | bool |  |
| ignorePresentationIndicators | bool |  |
| enableExtensionMobility | bool |  |
| privacy | [Status](#Status) |  |
| loggedIntoHuntGroup | bool |  |
| proxyServer | str |  |
| servicesUrl | str |  |
| idle | str |  |
| idleTimer | Any |  |
| secureDirUrl | str |  |
| messages | str |  |
| secureIdleUrl | str |  |
| authenticationServer | str |  |
| directory | str |  |
| secureServicesUrl | str |  |
| information | str |  |
| secureMessagesUrl | str |  |
| secureInformationUrl | str |  |
| secureAuthenticationUrl | str |  |
| confidentialAccess | Any |  |
| services | Any |  |

### UniversalLineTemplate { #UniversalLineTemplate }

Used by AXLClient.add_universal_line_template().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| urgentPriority | bool |  |
| lineDescription | str |  |
| routePartition | str |  |
| voiceMailProfile | str |  |
| callingSearchSpace | str |  |
| alertingName | str |  |
| extCallControlProfile | str |  |
| blfPresenceGroup | str |  |
| callPickupGroup | str |  |
| partyEntranceTone | [Status](#Status) |  |
| autoAnswer | [AutoAnswer](#AutoAnswer) |  |
| rejectAnonymousCall | bool |  |
| userHoldMohAudioSource | Any |  |
| networkHoldMohAudioSource | Any |  |
| aarDestinationMask | str |  |
| aarGroup | str |  |
| retainDestInCallFwdHistory | bool |  |
| forwardDestAllCalls | str |  |
| primaryCssForwardingAllCalls | str |  |
| secondaryCssForwardingAllCalls | str |  |
| CssActivationPolicy | [CFACSSActivationPolicy](#CFACSSActivationPolicy) |  |
| fwdDestExtCallsWhenNotRetrieved | str |  |
| cssFwdExtCallsWhenNotRetrieved | str |  |
| fwdDestInternalCallsWhenNotRetrieved | str |  |
| cssFwdInternalCallsWhenNotRetrieved | str |  |
| parkMonitorReversionTime | Any |  |
| target | str |  |
| mlppCss | str |  |
| mlppNoAnsRingDuration | Any |  |
| confidentialAccess | Any |  |
| holdReversionRingDuration | Any |  |
| holdReversionNotificationInterval | Any |  |
| busyIntCallsDestination | str |  |
| busyIntCallsCss | str |  |
| busyExtCallsDestination | str |  |
| busyExtCallsCss | str |  |
| noAnsIntCallsDestination | str |  |
| noAnsIntCallsCss | str |  |
| noAnsExtCallsDestination | str |  |
| noAnsExtCallsCss | str |  |
| noCoverageIntCallsDestination | str |  |
| noCoverageIntCallsCss | str |  |
| noCoverageExtCallsDestination | str |  |
| noCoverageExtCallsCss | str |  |
| unregisteredIntCallsDestination | str |  |
| unregisteredIntCallsCss | str |  |
| unregisteredExtCallsDestination | str |  |
| unregisteredExtCallsCss | str |  |
| ctiFailureDestination | str |  |
| ctiFailureCss | str |  |
| callControlAgentProfile | str |  |
| noAnswerRingDuration | Any |  |
| enterpriseAltNum | Any |  |
| e164AltNum | Any |  |
| advertisedFailoverNumber | str |  |

### User { #User }

Used by AXLClient.add_user().

| Field | Type | Required |
|-------|------|:--------:|
| firstName | str |  |
| displayName | str |  |
| middleName | str |  |
| lastName | str |  |
| emMaxLoginTime | Any |  |
| userid | str |  |
| password | str |  |
| pin | str |  |
| mailid | str |  |
| department | str |  |
| manager | str |  |
| userLocale | [UserLocale](#UserLocale) |  |
| associatedDevices | Any |  |
| primaryExtension | Any |  |
| associatedPc | str |  |
| associatedGroups | Any |  |
| enableCti | bool |  |
| digestCredentials | str |  |
| phoneProfiles | Any |  |
| defaultProfile | str |  |
| presenceGroupName | str |  |
| subscribeCallingSearchSpaceName | str |  |
| enableMobility | bool |  |
| enableMobileVoiceAccess | bool |  |
| maxDeskPickupWaitTime | Any |  |
| remoteDestinationLimit | Any |  |
| passwordCredentials | Any |  |
| pinCredentials | Any |  |
| enableEmcc | bool |  |
| ctiControlledDeviceProfiles | Any |  |
| patternPrecedence | [PatternPrecedence](#PatternPrecedence) |  |
| numericUserId | str |  |
| mlppPassword | str |  |
| customUserFields | Any |  |
| homeCluster | bool |  |
| imAndPresenceEnable | bool |  |
| serviceProfile | str |  |
| lineAppearanceAssociationForPresences | Any |  |
| directoryUri | str |  |
| telephoneNumber | str |  |
| title | str |  |
| mobileNumber | str |  |
| homeNumber | str |  |
| pagerNumber | str |  |
| extensionsInfo | Any |  |
| selfService | str |  |
| userProfile | str |  |
| calendarPresence | bool |  |
| ldapDirectoryName | str |  |
| userIdentity | str |  |
| nameDialing | str |  |
| ipccExtension | str |  |
| ipccRoutePartition | str |  |
| convertUserAccount | str |  |
| enableUserToHostConferenceNow | bool |  |
| attendeesAccessCode | str |  |
| zeroHop | bool |  |
| customerName | str |  |
| associatedHeadsets | Any |  |

### UserGroup { #UserGroup }

Used by AXLClient.add_user_group().

| Field | Type | Required |
|-------|------|:--------:|
| members | Any |  |
| userRoles | Any |  |
| name | str |  |

### UserPhoneAssociation { #UserPhoneAssociation }

Used by AXLClient.add_user_phone_association().

| Field | Type | Required |
|-------|------|:--------:|
| userId | str |  |
| password | str |  |
| pin | Any |  |
| lastName | str |  |
| middleName | str |  |
| firstName | str |  |
| productType | [Model](#Model) |  |
| name | str |  |
| dnCssName | str |  |
| phoneCssName | str |  |
| e164Mask | str |  |
| extension | str |  |
| routePartitionName | str |  |
| voiceMailProfileName | str |  |
| enableExtensionMobility | bool |  |
| DirectoryURI | str |  |
| DirectoryNumberURIPartition | str |  |

### UserProfileProvision { #UserProfileProvision }

Used by AXLClient.add_user_profile_provision().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| deskPhones | str |  |
| mobileDevices | str |  |
| profile | str |  |
| universalLineTemplate | str |  |
| allowProvision | bool |  |
| limitProvision | Any |  |
| allowPhoneReassign | bool |  |
| defaultUserProfile | str |  |
| enableMra | bool |  |
| mraPolicy_Desktop | [MRAPolicy](#MRAPolicy) |  |
| mraPolicy_Mobile | [MRAPolicy](#MRAPolicy) |  |
| allowProvisionEMMaxLoginTime | bool |  |

### Vg224 { #Vg224 }

Used by AXLClient.add_vg224().

| Field | Type | Required |
|-------|------|:--------:|
| domainName | str |  |
| description | str |  |
| product | [Product](#Product) |  |
| protocol | [DeviceProtocol](#DeviceProtocol) |  |
| callManagerGroupName | str |  |
| units | Any |  |
| vendorConfig | [VendorConfig](#VendorConfig) |  |
| versionStamp | str |  |

### VohServer { #VohServer }

Used by AXLClient.add_voh_server().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| sipTrunkName | str |  |
| defaultVideoStreamId | str |  |

### VoiceMailPilot { #VoiceMailPilot }

Used by AXLClient.add_voice_mail_pilot().

| Field | Type | Required |
|-------|------|:--------:|
| dirn | str |  |
| description | str |  |
| cssName | str |  |
| isDefault | bool |  |

### VoiceMailPort { #VoiceMailPort }

Used by AXLClient.add_voice_mail_port().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| product | [Product](#Product) |  |
| class | [Class](#Class) |  |
| protocol | [DeviceProtocol](#DeviceProtocol) |  |
| protocolSide | [ProtocolSide](#ProtocolSide) |  |
| callingSearchSpaceName | str |  |
| devicePoolName | str |  |
| commonDeviceConfigName | str |  |
| locationName | str |  |
| preemption | [Preemption](#Preemption) |  |
| useTrustedRelayPoint | [Status](#Status) |  |
| securityProfileName | str |  |
| geoLocationName | str |  |
| automatedAlternateRoutingCssName | str |  |
| dnPattern | str |  |
| routePartition | str |  |
| dnCallingSearchSpace | str |  |
| aarNeighborhoodName | str |  |
| callerIdDisplay | str |  |
| callerIdDisplayAscii | str |  |
| externalMask | str |  |

### VoiceMailProfile { #VoiceMailProfile }

Used by AXLClient.add_voice_mail_profile().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| isDefault | bool |  |
| voiceMailboxMask | str |  |
| voiceMailPilot | [VmPilot](#VmPilot) |  |

### VpnGateway { #VpnGateway }

Used by AXLClient.add_vpn_gateway().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| url | str |  |
| certificates | Any |  |

### VpnGroup { #VpnGroup }

Used by AXLClient.add_vpn_group().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| vpnGateways | Any |  |

### VpnProfile { #VpnProfile }

Used by AXLClient.add_vpn_profile().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| autoNetworkDetection | bool |  |
| mtu | Any |  |
| failToConnect | Any |  |
| clientAuthentication | [VPNClientAuthentication](#VPNClientAuthentication) |  |
| pwdPersistant | bool |  |
| enableHostIdCheck | bool |  |

### WLANProfile { #WLANProfile }

Used by AXLClient.add_wlanprofile().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| ssid | str |  |
| frequencyBand | [WiFiFrequency](#WiFiFrequency) |  |
| userModifiable | [WLANProfileChanges](#WLANProfileChanges) |  |
| authMethod | [WiFiAuthenticationMethod](#WiFiAuthenticationMethod) |  |
| userName | str |  |
| password | str |  |
| pskPassphrase | str |  |
| wepKey | str |  |
| passwordDescription | str |  |
| networkAccessProfile | str |  |

### WifiHotspot { #WifiHotspot }

Used by AXLClient.add_wifi_hotspot().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| ssidPrefix | str |  |
| userModifiable | [WLANProfileChanges](#WLANProfileChanges) |  |
| frequencyBand | [WiFiFrequency](#WiFiFrequency) |  |
| authenticationMethod | [HotspotAuthenticationMethod](#HotspotAuthenticationMethod) |  |
| hostName | Any |  |
| port | Any |  |
| sharedSecret | str |  |
| pskPassPhrase | str |  |
| wepKey | str |  |
| passwordDescription | str |  |

### WirelessAccessPointControllers { #WirelessAccessPointControllers }

Used by AXLClient.add_wireless_access_point_controllers().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| snmpVersion | [SNMPVersion](#SNMPVersion) |  |
| snmpUserIdOrCommunityString | str |  |
| snmpAuthenticationProtocol | [SNMPAuthenticationProtocol](#SNMPAuthenticationProtocol) |  |
| snmpAuthenticationPassword | str |  |
| snmpPrivacyProtocol | [SNMPPrivacyProtocol](#SNMPPrivacyProtocol) |  |
| snmpPrivacyPassword | str |  |
| syncNow | bool |  |
| resyncInterval | Any |  |
| nextSyncTime | Any |  |
| scheduleUnit | [ScheduleUnit](#ScheduleUnit) |  |

### WlanProfileGroup { #WlanProfileGroup }

Used by AXLClient.add_wlan_profile_group().

| Field | Type | Required |
|-------|------|:--------:|
| name | str |  |
| description | str |  |
| members | Any |  |

## Supporting Models

Nested types referenced by the Add and Update models above.

### AnalogPort { #AnalogPort }

| Field | Type | Required |
|-------|------|:--------:|
| portNumber | Any |  |
| attendantDn | str |  |
| unattendedPort | bool |  |
| callerIdDn | str |  |
| callerIdEnable | bool |  |
| callingPartySelection | [CallingPartySelection](#CallingPartySelection) |  |
| digitSending | [DigitSending](#DigitSending) |  |
| expectedDigits | Any |  |
| sigDigits | Any |  |
| lines | Any |  |
| prefixDn | str |  |
| presentationBit | [PresentationBit](#PresentationBit) |  |
| silenceSuppressionThreshold | [SilenceSuppressionThreshold](#SilenceSuppressionThreshold) |  |
| smdiPortNumber | Any |  |
| startDialProtocol | [StartDialProtocol](#StartDialProtocol) |  |
| trunk | [Trunk](#Trunk) |  |
| trunkDirection | [TrunkDirection](#TrunkDirection) |  |
| trunkLevel | [TrunkLevel](#TrunkLevel) |  |
| trunkPadRx | [TrunkPad](#TrunkPad) |  |
| trunkPadTx | [TrunkPad](#TrunkPad) |  |
| vendorConfig | [VendorConfig](#VendorConfig) |  |
| timer1 | Any |  |
| timer2 | Any |  |
| timer3 | Any |  |
| timer4 | Any |  |
| timer5 | Any |  |
| timer6 | Any |  |

### CallForwardAll { #CallForwardAll }

| Field | Type | Required |
|-------|------|:--------:|
| forwardToVoiceMail | bool |  |
| callingSearchSpaceName | str |  |
| secondaryCallingSearchSpaceName | str |  |
| destination | str |  |

### CallForwardAlternateParty { #CallForwardAlternateParty }

| Field | Type | Required |
|-------|------|:--------:|
| callingSearchSpaceName | str |  |
| destination | str |  |
| duration | Any |  |

### CallForwardBusy { #CallForwardBusy }

| Field | Type | Required |
|-------|------|:--------:|
| forwardToVoiceMail | bool |  |
| callingSearchSpaceName | str |  |
| destination | str |  |

### CallForwardBusyInt { #CallForwardBusyInt }

| Field | Type | Required |
|-------|------|:--------:|
| forwardToVoiceMail | bool |  |
| callingSearchSpaceName | str |  |
| destination | str |  |

### CallForwardNoAnswer { #CallForwardNoAnswer }

| Field | Type | Required |
|-------|------|:--------:|
| forwardToVoiceMail | bool |  |
| callingSearchSpaceName | str |  |
| destination | str |  |
| duration | Any |  |

### CallForwardNoAnswerInt { #CallForwardNoAnswerInt }

| Field | Type | Required |
|-------|------|:--------:|
| forwardToVoiceMail | bool |  |
| callingSearchSpaceName | str |  |
| destination | str |  |
| duration | Any |  |

### CallForwardNoCoverage { #CallForwardNoCoverage }

| Field | Type | Required |
|-------|------|:--------:|
| forwardToVoiceMail | bool |  |
| callingSearchSpaceName | str |  |
| destination | str |  |

### CallForwardNoCoverageInt { #CallForwardNoCoverageInt }

| Field | Type | Required |
|-------|------|:--------:|
| forwardToVoiceMail | bool |  |
| callingSearchSpaceName | str |  |
| destination | str |  |

### CallForwardNotRegistered { #CallForwardNotRegistered }

| Field | Type | Required |
|-------|------|:--------:|
| forwardToVoiceMail | bool |  |
| callingSearchSpaceName | str |  |
| destination | str |  |

### CallForwardNotRegisteredInt { #CallForwardNotRegisteredInt }

| Field | Type | Required |
|-------|------|:--------:|
| forwardToVoiceMail | bool |  |
| callingSearchSpaceName | str |  |
| destination | str |  |

### CallForwardOnFailure { #CallForwardOnFailure }

| Field | Type | Required |
|-------|------|:--------:|
| forwardToVoiceMail | bool |  |
| callingSearchSpaceName | str |  |
| destination | str |  |

### CallsQueue { #CallsQueue }

| Field | Type | Required |
|-------|------|:--------:|
| maxCallersInQueue | Any |  |
| queueFullDestination | str |  |
| callingSearchSpacePilotQueueFull | str |  |
| maxWaitTimeInQueue | Any |  |
| maxWaitTimeDestination | str |  |
| callingSearchSpaceMaxWaitTime | str |  |
| noAgentDestination | str |  |
| callingSearchSpaceNoAgent | str |  |
| networkHoldMohAudioSourceID | Any |  |

### Content { #Content }

*No fields.*

### Dirn { #Dirn }

| Field | Type | Required |
|-------|------|:--------:|
| pattern | str |  |
| routePartitionName | str |  |

### FkType { #FkType }

*No fields.*

### GatewayEndpointAnalog { #GatewayEndpointAnalog }

| Field | Type | Required |
|-------|------|:--------:|
| index | Any |  |
| name | str |  |
| description | str |  |
| product | [Product](#Product) |  |
| model | [Model](#Model) |  |
| class | [Class](#Class) |  |
| protocol | [DeviceProtocol](#DeviceProtocol) |  |
| protocolSide | [ProtocolSide](#ProtocolSide) |  |
| callingSearchSpaceName | str |  |
| devicePoolName | str |  |
| commonDeviceConfigName | str |  |
| networkLocale | [Country](#Country) |  |
| locationName | str |  |
| mediaResourceListName | str |  |
| automatedAlternateRoutingCssName | str |  |
| aarNeighborhoodName | str |  |
| vendorConfig | [VendorConfig](#VendorConfig) |  |
| mlppDomainId | str |  |
| useTrustedRelayPoint | [Status](#Status) |  |
| retryVideoCallAsAudio | bool |  |
| cgpnTransformationCssName | str |  |
| useDevicePoolCgpnTransformCss | bool |  |
| geoLocationName | str |  |
| geoLocationFilterName | str |  |
| port | [AnalogPort](#AnalogPort) |  |
| trunkSelectionOrder | [TrunkSelectionOrder](#TrunkSelectionOrder) |  |
| transmitUtf8 | bool |  |
| cdpnTransformationCssName | str |  |
| useDevicePoolCdpnTransformCss | bool |  |
| callingPartyNumberPrefix | str |  |
| callingPartyStripDigits | Any |  |
| callingPartyUnknownTransformationCssName | str |  |
| useDevicePoolCgpnTransformCssUnknown | bool |  |
| hotlineDevice | bool |  |
| packetCaptureMode | [PacketCaptureMode](#PacketCaptureMode) |  |
| packetCaptureDuration | Any |  |
| pstnAccess | bool |  |
| imeE164TransformationName | str |  |
| imeE164DirectoryNumber | str |  |
| confidentialAccess | Any |  |
| elinGroup | str |  |

### GatewayEndpointDigitalBri { #GatewayEndpointDigitalBri }

| Field | Type | Required |
|-------|------|:--------:|
| index | Any |  |
| name | str |  |
| description | str |  |
| product | [Product](#Product) |  |
| class | [Class](#Class) |  |
| protocol | [DeviceProtocol](#DeviceProtocol) |  |
| protocolSide | [ProtocolSide](#ProtocolSide) |  |
| callingSearchSpaceName | str |  |
| devicePoolName | str |  |
| commonDeviceConfigName | str |  |
| networkLocation | [NetworkLocation](#NetworkLocation) |  |
| locationName | str |  |
| mediaResourceListName | str |  |
| networkLocale | [Country](#Country) |  |
| automatedAlternateRoutingCssName | str |  |
| aarNeighborhoodName | str |  |
| vendorConfig | [VendorConfig](#VendorConfig) |  |
| cgpnTransformationCssName | str |  |
| useDevicePoolCgpnTransformCss | bool |  |
| geoLocationName | str |  |
| redirectInboundNumberIe | bool |  |
| briProtocol | [BriProtocol](#BriProtocol) |  |
| calledPlan | [NumberingPlan](#NumberingPlan) |  |
| calledPri | [PriOfNumber](#PriOfNumber) |  |
| callerIdDn | str |  |
| callingPartySelection | [CallingPartySelection](#CallingPartySelection) |  |
| callingPlan | [NumberingPlan](#NumberingPlan) |  |
| callingPri | [PriOfNumber](#PriOfNumber) |  |
| clockReference | [ClockReference](#ClockReference) |  |
| csuParam | [CSUParam](#CSUParam) |  |
| dChannelEnable | bool |  |
| channelSelectionOrder | [TrunkSelectionOrder](#TrunkSelectionOrder) |  |
| pcmType | [Encode](#Encode) |  |
| firstDelay | Any |  |
| intraDelay | Any |  |
| redirectOutboundNumberIe | bool |  |
| numDigitsToStrip | Any |  |
| prefix | str |  |
| presentationBit | [PresentationBit](#PresentationBit) |  |
| sendRestart | bool |  |
| setupNonIsdnPi | bool |  |
| sigDigits | Any |  |
| statusPoll | bool |  |
| packetCaptureMode | [PacketCaptureMode](#PacketCaptureMode) |  |
| packetCaptureDuration | Any |  |
| cdpnTransformationCssName | str |  |
| useDevicePoolCdpnTransformCss | bool |  |
| geoLocationFilterName | str |  |
| nationalPrefix | str |  |
| internationalPrefix | str |  |
| unknownPrefix | str |  |
| subscriberPrefix | str |  |
| nationalStripDigits | Any |  |
| internationalStripDigits | Any |  |
| unknownStripDigits | Any |  |
| subscriberStripDigits | Any |  |
| nationalTransformationCssName | str |  |
| internationalTransformationCssName | str |  |
| unknownTransformationCssName | str |  |
| subscriberTransformationCssName | str |  |
| pstnAccess | bool |  |
| imeE164TransformationName | str |  |
| useDevicePoolCgpnTransformCssNatl | bool |  |
| useDevicePoolCgpnTransformCssIntl | bool |  |
| useDevicePoolCgpnTransformCssUnkn | bool |  |
| useDevicePoolCgpnTransformCssSubs | bool |  |
| unattendedPort | bool |  |
| GClearEnable | bool |  |
| enableDatalinkOnFirstCall | bool |  |
| calledPartyNationalPrefix | str |  |
| calledPartyInternationalPrefix | str |  |
| calledPartyUnknownPrefix | str |  |
| calledPartySubscriberPrefix | str |  |
| calledPartyNationalStripDigits | Any |  |
| calledPartyInternationalStripDigits | Any |  |
| calledPartyUnknownStripDigits | Any |  |
| calledPartySubscriberStripDigits | Any |  |
| calledPartyNationalTransformationCssName | str |  |
| calledPartyInternationalTransformationCssName | str |  |
| calledPartyUnknownTransformationCssName | str |  |
| calledPartySubscriberTransformationCssName | str |  |
| useDevicePoolCalledCssNatl | bool |  |
| useDevicePoolCalledCssIntl | bool |  |
| useDevicePoolCalledCssUnkn | bool |  |
| useDevicePoolCalledCssSubs | bool |  |
| connectCallBeforePlayingAnnouncement | bool |  |

### GatewayEndpointDigitalPri { #GatewayEndpointDigitalPri }

| Field | Type | Required |
|-------|------|:--------:|
| index | Any |  |
| name | str |  |
| description | str |  |
| product | [Product](#Product) |  |
| class | [Class](#Class) |  |
| protocol | [DeviceProtocol](#DeviceProtocol) |  |
| protocolSide | [ProtocolSide](#ProtocolSide) |  |
| callingSearchSpaceName | str |  |
| devicePoolName | str |  |
| commonDeviceConfigName | str |  |
| networkLocation | [NetworkLocation](#NetworkLocation) |  |
| locationName | str |  |
| networkLocale | [Country](#Country) |  |
| mediaResourceListName | str |  |
| automatedAlternateRoutingCssName | str |  |
| aarNeighborhoodName | str |  |
| loadInformation | [LoadInformation](#LoadInformation) |  |
| vendorConfig | [VendorConfig](#VendorConfig) |  |
| mlppDomainId | str |  |
| mlppIndicationStatus | [Status](#Status) |  |
| mlppPreemption | [Preemption](#Preemption) |  |
| useTrustedRelayPoint | [Status](#Status) |  |
| cgpnTransformationCssName | str |  |
| useDevicePoolCgpnTransformCss | bool |  |
| geoLocationName | str |  |
| redirectInboundNumberIe | bool |  |
| calledPlan | [NumberingPlan](#NumberingPlan) |  |
| calledPri | [PriOfNumber](#PriOfNumber) |  |
| callerIdDn | str |  |
| callingPartySelection | [CallingPartySelection](#CallingPartySelection) |  |
| callingPlan | [NumberingPlan](#NumberingPlan) |  |
| callingPri | [PriOfNumber](#PriOfNumber) |  |
| chanIE | [PRIChanIE](#PRIChanIE) |  |
| clockReference | [ClockReference](#ClockReference) |  |
| dChannelEnable | bool |  |
| channelSelectionOrder | [TrunkSelectionOrder](#TrunkSelectionOrder) |  |
| displayIe | bool |  |
| pcmType | [Encode](#Encode) |  |
| csuParam | [CSUParam](#CSUParam) |  |
| firstDelay | Any |  |
| interfaceIdPresent | bool |  |
| interfaceId | Any |  |
| intraDelay | Any |  |
| mcdnEnable | bool |  |
| redirectOutboundNumberIe | bool |  |
| numDigitsToStrip | Any |  |
| passingPrecedenceLevelThrough | bool |  |
| prefix | str |  |
| callingLinePresentationBit | [PresentationBit](#PresentationBit) |  |
| connectedLineIdPresentation | [PresentationBit](#PresentationBit) |  |
| priProtocol | [PriProtocol](#PriProtocol) |  |
| securityAccessLevel | Any |  |
| sendCallingNameInFacilityIe | bool |  |
| sendExLeadingCharInDispIe | bool |  |
| sendRestart | bool |  |
| setupNonIsdnPi | bool |  |
| sigDigits | Any |  |
| span | Any |  |
| statusPoll | bool |  |
| smdiBasePort | Any |  |
| GClearEnable | bool |  |
| packetCaptureMode | [PacketCaptureMode](#PacketCaptureMode) |  |
| packetCaptureDuration | Any |  |
| transmitUtf8 | bool |  |
| v150 | bool |  |
| asn1RoseOidEncoding | [ASN1RoseOidEncoding](#ASN1RoseOidEncoding) |  |
| qsigVariant | [QSIGVariant](#QSIGVariant) |  |
| unattendedPort | bool |  |
| cdpnTransformationCssName | str |  |
| useDevicePoolCdpnTransformCss | bool |  |
| nationalPrefix | str |  |
| internationalPrefix | str |  |
| unknownPrefix | str |  |
| subscriberPrefix | str |  |
| geoLocationFilterName | str |  |
| routeClassSignalling | [Status](#Status) |  |
| nationalStripDigits | Any |  |
| internationalStripDigits | Any |  |
| unknownStripDigits | Any |  |
| subscriberStripDigits | Any |  |
| nationalTransformationCssName | str |  |
| internationalTransformationCssName | str |  |
| unknownTransformationCssName | str |  |
| subscriberTransformationCssName | str |  |
| pstnAccess | bool |  |
| imeE164TransformationName | str |  |
| useDevicePoolCgpnTransformCssNatl | bool |  |
| useDevicePoolCgpnTransformCssIntl | bool |  |
| useDevicePoolCgpnTransformCssUnkn | bool |  |
| useDevicePoolCgpnTransformCssSubs | bool |  |
| calledPartyNationalPrefix | str |  |
| calledPartyInternationalPrefix | str |  |
| calledPartyUnknownPrefix | str |  |
| calledPartySubscriberPrefix | str |  |
| calledPartyNationalStripDigits | Any |  |
| calledPartyInternationalStripDigits | Any |  |
| calledPartyUnknownStripDigits | Any |  |
| calledPartySubscriberStripDigits | Any |  |
| calledPartyNationalTransformationCssName | str |  |
| calledPartyInternationalTransformationCssName | str |  |
| calledPartyUnknownTransformationCssName | str |  |
| calledPartySubscriberTransformationCssName | str |  |
| useDevicePoolCalledCssNatl | bool |  |
| useDevicePoolCalledCssIntl | bool |  |
| useDevicePoolCalledCssUnkn | bool |  |
| useDevicePoolCalledCssSubs | bool |  |
| useDevicePoolCntdPartyTransformationCss | bool |  |
| cntdPartyTransformationCssName | str |  |
| confidentialAccess | Any |  |
| connectCallBeforePlayingAnnouncement | bool |  |

### GatewayEndpointDigitalT1 { #GatewayEndpointDigitalT1 }

| Field | Type | Required |
|-------|------|:--------:|
| index | Any |  |
| name | str |  |
| description | str |  |
| product | [Product](#Product) |  |
| class | [Class](#Class) |  |
| protocol | [DeviceProtocol](#DeviceProtocol) |  |
| protocolSide | [ProtocolSide](#ProtocolSide) |  |
| callingSearchSpaceName | str |  |
| devicePoolName | str |  |
| commonDeviceConfigName | str |  |
| networkLocation | [NetworkLocation](#NetworkLocation) |  |
| locationName | str |  |
| mediaResourceListName | str |  |
| automatedAlternateRoutingCssName | str |  |
| aarNeighborhoodName | str |  |
| loadInformation | [LoadInformation](#LoadInformation) |  |
| vendorConfig | [VendorConfig](#VendorConfig) |  |
| traceFlag | bool |  |
| mlppDomainId | str |  |
| mlppIndicationStatus | [Status](#Status) |  |
| preemption | [Preemption](#Preemption) |  |
| useTrustedRelayPoint | [Status](#Status) |  |
| retryVideoCallAsAudio | bool |  |
| cgpnTransformationCssName | str |  |
| useDevicePoolCgpnTransformCss | bool |  |
| geoLocationName | str |  |
| sendGeoLocation | bool |  |
| cdpnTransformationCssName | str |  |
| useDevicePoolCdpnTransformCss | bool |  |
| v150 | bool |  |
| geoLocationFilterName | str |  |
| ports | Any |  |
| trunkSelectionOrder | [TrunkSelectionOrder](#TrunkSelectionOrder) |  |
| clockReference | [ClockReference](#ClockReference) |  |
| csuParam | [CSUParam](#CSUParam) |  |
| digitSending | [DigitSending](#DigitSending) |  |
| pcmType | [Encode](#Encode) |  |
| fdlChannel | [FDLChannel](#FDLChannel) |  |
| yellowAlarm | [YellowAlarm](#YellowAlarm) |  |
| zeroSupression | [ZeroSuppression](#ZeroSuppression) |  |
| smdiBasePort | Any |  |
| handleDtmfPrecedenceSignals | bool |  |
| encodeOutboundVoiceRouteClass | bool |  |
| routeClassSignalling | [Status](#Status) |  |
| pstnAccess | bool |  |
| imeE164TransformationName | str |  |
| confidentialAccess | Any |  |
| connectCallBeforePlayingAnnouncement | bool |  |
| calledPartyUnknownPrefix | str |  |
| calledPartyUnknownStripDigits | Any |  |
| calledPartyUnknownTransformationCssName | str |  |
| useDevicePoolCalledCssUnkn | bool |  |

### GatewaySccp { #GatewaySccp }

| Field | Type | Required |
|-------|------|:--------:|
| index | Any |  |
| name | str |  |
| description | str |  |
| product | [Product](#Product) |  |
| model | [Model](#Model) |  |
| class | [Class](#Class) |  |
| protocol | [DeviceProtocol](#DeviceProtocol) |  |
| protocolSide | [ProtocolSide](#ProtocolSide) |  |
| callingSearchSpaceName | str |  |
| devicePoolName | str |  |
| commonDeviceConfigName | str |  |
| networkLocale | [Country](#Country) |  |
| locationName | str |  |
| mediaResourceListName | str |  |
| automatedAlternateRoutingCssName | str |  |
| aarNeighborhoodName | str |  |
| vendorConfig | [VendorConfig](#VendorConfig) |  |
| mlppDomainId | str |  |
| useTrustedRelayPoint | [Status](#Status) |  |
| retryVideoCallAsAudio | bool |  |
| cgpnTransformationCssName | str |  |
| useDevicePoolCgpnTransformCss | bool |  |
| geoLocationName | str |  |
| geoLocationFilterName | str |  |
| transmitUtf8 | bool |  |
| cdpnTransformationCssName | str |  |
| useDevicePoolCdpnTransformCss | bool |  |
| callingPartyNumberPrefix | str |  |
| callingPartyStripDigits | Any |  |
| callingPartyUnknownTransformationCssName | str |  |
| useDevicePoolCgpnTransformCssUnknown | bool |  |
| hotlineDevice | bool |  |
| packetCaptureMode | [PacketCaptureMode](#PacketCaptureMode) |  |
| packetCaptureDuration | Any |  |
| pstnAccess | bool |  |
| imeE164TransformationName | str |  |
| phoneTemplateName | str |  |
| securityProfileName | str |  |
| userLocale | [UserLocale](#UserLocale) |  |
| deviceMobilityMode | [Status](#Status) |  |
| ownerUserId | str |  |
| commonPhoneConfigName | str |  |
| alwaysUsePrimeLine | [Status](#Status) |  |
| alwaysUsePrimeLineForVM | [Status](#Status) |  |
| allowCtiControlFlag | bool |  |
| remoteDevice | bool |  |
| subscribeCallingSearchSpaceName | str |  |
| unattendedPort | bool |  |
| presenceGroupName | str |  |
| mlppIndicationStatus | [Status](#Status) |  |
| preemption | [Preemption](#Preemption) |  |
| hlogStatus | bool |  |
| ignorePresentationIndicators | [PresentationBit](#PresentationBit) |  |
| lines | Any |  |
| confidentialAccess | Any |  |

### LoadInformation { #LoadInformation }

*No fields.*

### RArrayOfHosts { #RArrayOfHosts }

| Field | Type | Required |
|-------|------|:--------:|
| item | List[str] |  |

### RCcdParam { #RCcdParam }

| Field | Type | Required |
|-------|------|:--------:|
| ccdParamName | str |  |
| ccdParamValue | str |  |

### RSNMPCommunityString1 { #RSNMPCommunityString1 }

| Field | Type | Required |
|-------|------|:--------:|
| accessPrivilege | str |  |
| ArrayOfHosts | [RArrayOfHosts](#RArrayOfHosts) |  |

### RemoteClusterMember { #RemoteClusterMember }

| Field | Type | Required |
|-------|------|:--------:|
| enabled | bool |  |

### UGatewayEndpointDigitalT1 { #UGatewayEndpointDigitalT1 }

| Field | Type | Required |
|-------|------|:--------:|
| index | Any |  |
| description | str |  |
| callingSearchSpaceName | str |  |
| devicePoolName | str |  |
| commonDeviceConfigName | str |  |
| networkLocation | [NetworkLocation](#NetworkLocation) |  |
| locationName | str |  |
| mediaResourceListName | str |  |
| automatedAlternateRoutingCssName | str |  |
| aarNeighborhoodName | str |  |
| loadInformation | [LoadInformation](#LoadInformation) |  |
| vendorConfig | [VendorConfig](#VendorConfig) |  |
| traceFlag | bool |  |
| mlppDomainId | str |  |
| mlppIndicationStatus | [Status](#Status) |  |
| preemption | [Preemption](#Preemption) |  |
| useTrustedRelayPoint | [Status](#Status) |  |
| retryVideoCallAsAudio | bool |  |
| cgpnTransformationCssName | str |  |
| useDevicePoolCgpnTransformCss | bool |  |
| geoLocationName | str |  |
| sendGeoLocation | bool |  |
| cdpnTransformationCssName | str |  |
| useDevicePoolCdpnTransformCss | bool |  |
| v150 | bool |  |
| geoLocationFilterName | str |  |
| ports | Any |  |
| trunkSelectionOrder | [TrunkSelectionOrder](#TrunkSelectionOrder) |  |
| clockReference | [ClockReference](#ClockReference) |  |
| csuParam | [CSUParam](#CSUParam) |  |
| digitSending | [DigitSending](#DigitSending) |  |
| pcmType | [Encode](#Encode) |  |
| fdlChannel | [FDLChannel](#FDLChannel) |  |
| yellowAlarm | [YellowAlarm](#YellowAlarm) |  |
| zeroSupression | [ZeroSuppression](#ZeroSuppression) |  |
| smdiBasePort | Any |  |
| handleDtmfPrecedenceSignals | bool |  |
| encodeOutboundVoiceRouteClass | bool |  |
| routeClassSignalling | [Status](#Status) |  |
| pstnAccess | bool |  |
| imeE164TransformationName | str |  |
| confidentialAccess | Any |  |
| connectCallBeforePlayingAnnouncement | bool |  |
| calledPartyUnknownPrefix | str |  |
| calledPartyUnknownStripDigits | Any |  |
| calledPartyUnknownTransformationCssName | str |  |
| useDevicePoolCalledCssUnkn | bool |  |

### VendorConfig { #VendorConfig }

*No fields.*

### VmPilot { #VmPilot }

| Field | Type | Required |
|-------|------|:--------:|
| dirn | str |  |
| cssName | str |  |

## Update Models

Types used with `Unpack` for `update_*` method `**kwargs`.
All fields are optional — only send the fields you want to change.

### UpdateAarGroup { #UpdateAarGroup }

Used by AXLClient.update_aar_group().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | Any |

### UpdateAarGroupMatrix { #UpdateAarGroupMatrix }

Used by AXLClient.update_aar_group_matrix().

| Field | Type |
|-------|------|
| uuid | str |
| aarGroupFromName | str |
| aarGroupToName | str |
| prefixDigit | str |

### UpdateAdvertisedPatterns { #UpdateAdvertisedPatterns }

Used by AXLClient.update_advertised_patterns().

| Field | Type |
|-------|------|
| uuid | str |
| pattern | str |
| description | str |
| newPattern | str |
| patternType | [GlobalNumber](#GlobalNumber) |
| hostedRoutePSTNRule | [HostedRoutePatternPSTNRule](#HostedRoutePatternPSTNRule) |
| pstnFailStrip | Any |
| pstnFailPrepend | str |

### UpdateAnnouncement { #UpdateAnnouncement }

Used by AXLClient.update_announcement().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| announcementFile | [AnnouncementFile](#AnnouncementFile) |

### UpdateAnnunciator { #UpdateAnnunciator }

Used by AXLClient.update_annunciator().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| devicePoolName | str |
| locationName | str |
| useTrustedRelayPoint | [Status](#Status) |

### UpdateAppServerInfo { #UpdateAppServerInfo }

Used by AXLClient.update_app_server_info().

| Field | Type |
|-------|------|
| uuid | str |
| appServerName | str |
| appServerContent | [AppServerContent](#AppServerContent) |
| content | [Content](#Content) |

### UpdateAppUser { #UpdateAppUser }

Used by AXLClient.update_app_user().

| Field | Type |
|-------|------|
| uuid | str |
| userid | str |
| newUserid | str |
| password | str |
| passwordCredentials | Any |
| digestCredentials | str |
| presenceGroupName | str |
| acceptPresenceSubscription | bool |
| acceptOutOfDialogRefer | bool |
| acceptUnsolicitedNotification | bool |
| allowReplaceHeader | bool |
| associatedDevices | Any |
| associatedGroups | Any |
| ctiControlledDeviceProfiles | Any |

### UpdateApplicationDialRules { #UpdateApplicationDialRules }

Used by AXLClient.update_application_dial_rules().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| numberBeginWith | str |
| numberOfDigits | Any |
| digitsToBeRemoved | Any |
| prefixPattern | str |
| priority | Any |

### UpdateApplicationServer { #UpdateApplicationServer }

Used by AXLClient.update_application_server().

| Field | Type |
|-------|------|
| uuid | str |
| newName | str |
| ipAddress | str |
| removeAppUsers | Any |
| addAppUsers | Any |
| appUsers | Any |
| url | str |
| endUserUrl | str |
| processNodeName | str |
| removeEndUsers | Any |
| addEndUsers | Any |
| endUsers | Any |

### UpdateApplicationUserCapfProfile { #UpdateApplicationUserCapfProfile }

Used by AXLClient.update_application_user_capf_profile().

| Field | Type |
|-------|------|
| uuid | str |
| instanceId | str |
| certificateOperation | [CertificateOperation](#CertificateOperation) |
| authenticationMode | [AuthenticationMode](#AuthenticationMode) |
| authenticationString | str |
| keySize | [KeySize](#KeySize) |
| keyOrder | [KeyOrder](#KeyOrder) |
| ecKeySize | [ECKeySize](#ECKeySize) |
| operationCompletion | str |

### UpdateAudioCodecPreferenceList { #UpdateAudioCodecPreferenceList }

Used by AXLClient.update_audio_codec_preference_list().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| codecsInList | Any |

### UpdateBillingServer { #UpdateBillingServer }

Used by AXLClient.update_billing_server().

| Field | Type |
|-------|------|
| uuid | str |
| userId | str |
| password | str |
| resendOnFailure | bool |
| billingServerProtocol | [Billingserverprotocol](#Billingserverprotocol) |

### UpdateBlockedLearnedPatterns { #UpdateBlockedLearnedPatterns }

Used by AXLClient.update_blocked_learned_patterns().

| Field | Type |
|-------|------|
| uuid | str |
| pattern | str |
| description | str |
| newPattern | str |
| prefix | str |
| clusterId | str |
| patternType | [GlobalNumber](#GlobalNumber) |

### UpdateCCAProfiles { #UpdateCCAProfiles }

Used by AXLClient.update_ccaprofiles().

| Field | Type |
|-------|------|
| uuid | str |
| ccaId | str |
| newCcaId | str |
| primarySoftSwitchId | str |
| secondarySoftSwitchId | str |
| objectClass | str |
| subscriberType | str |
| sipAliasSuffix | str |
| sipUserNameSuffix | str |

### UpdateCallManager { #UpdateCallManager }

Used by AXLClient.update_call_manager().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| autoRegistration | Any |
| ports | Any |
| lbmGroup | str |

### UpdateCallManagerGroup { #UpdateCallManagerGroup }

Used by AXLClient.update_call_manager_group().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| tftpDefault | bool |
| removeMembers | Any |
| addMembers | Any |
| members | Any |

### UpdateCallPark { #UpdateCallPark }

Used by AXLClient.update_call_park().

| Field | Type |
|-------|------|
| uuid | str |
| pattern | str |
| routePartitionName | str |
| newPattern | str |
| description | str |
| newRoutePartitionName | str |
| callManagerName | str |

### UpdateCallPickupGroup { #UpdateCallPickupGroup }

Used by AXLClient.update_call_pickup_group().

| Field | Type |
|-------|------|
| uuid | str |
| name | Any |
| pattern | str |
| routePartitionName | str |
| newPattern | str |
| description | str |
| newRoutePartitionName | str |
| removeMembers | Any |
| addMembers | Any |
| members | Any |
| pickupNotification | [PickupNotification](#PickupNotification) |
| pickupNotificationTimer | Any |
| callInfoForPickupNotification | Any |
| newName | str |

### UpdateCalledPartyTransformationPattern { #UpdateCalledPartyTransformationPattern }

Used by AXLClient.update_called_party_transformation_pattern().

| Field | Type |
|-------|------|
| uuid | str |
| pattern | str |
| routePartitionName | str |
| dialPlanName | str |
| routeFilterName | str |
| newPattern | str |
| description | str |
| newRoutePartitionName | str |
| calledPartyTransformationMask | str |
| newDialPlanName | str |
| digitDiscardInstructionName | str |
| newRouteFilterName | str |
| calledPartyPrefixDigits | str |
| calledPartyNumberingPlan | [NumberingPlan](#NumberingPlan) |
| calledPartyNumberType | [PriOfNumber](#PriOfNumber) |
| mlppPreemptionDisabled | bool |

### UpdateCallerFilterList { #UpdateCallerFilterList }

Used by AXLClient.update_caller_filter_list().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| removeMembers | Any |
| addMembers | Any |
| members | Any |

### UpdateCallingPartyTransformationPattern { #UpdateCallingPartyTransformationPattern }

Used by AXLClient.update_calling_party_transformation_pattern().

| Field | Type |
|-------|------|
| uuid | str |
| pattern | str |
| routePartitionName | str |
| dialPlanName | str |
| routeFilterName | str |
| newPattern | str |
| description | str |
| newRoutePartitionName | str |
| callingPartyTransformationMask | str |
| useCallingPartyPhoneMask | [Status](#Status) |
| newDialPlanName | str |
| digitDiscardInstructionName | str |
| callingPartyPrefixDigits | str |
| newRouteFilterName | str |
| callingLinePresentationBit | [PresentationBit](#PresentationBit) |
| callingPartyNumberingPlan | [NumberingPlan](#NumberingPlan) |
| callingPartyNumberType | [PriOfNumber](#PriOfNumber) |
| mlppPreemptionDisabled | bool |

### UpdateCcdAdvertisingService { #UpdateCcdAdvertisingService }

Used by AXLClient.update_ccd_advertising_service().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| isActivated | bool |
| hostDnGroup | str |
| safSipTrunk | str |
| safH323Trunk | str |

### UpdateCcdFeatureConfig { #UpdateCcdFeatureConfig }

Used by AXLClient.update_ccd_feature_config().

| Field | Type |
|-------|------|
| ccdParam | List[[RCcdParam](#RCcdParam)] |

### UpdateCcdHostedDN { #UpdateCcdHostedDN }

Used by AXLClient.update_ccd_hosted_dn().

| Field | Type |
|-------|------|
| uuid | str |
| hostedPattern | str |
| newHostedPattern | str |
| description | str |
| CcdHostedDnGroup | str |
| pstnFailoverStripDigits | Any |
| pstnFailoverPrependDigits | str |
| usePstnFailover | bool |

### UpdateCcdHostedDNGroup { #UpdateCcdHostedDNGroup }

Used by AXLClient.update_ccd_hosted_dngroup().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| pstnFailoverStripDigits | Any |
| pstnFailoverPrependDigits | str |
| usePstnFailover | bool |

### UpdateCcdRequestingService { #UpdateCcdRequestingService }

Used by AXLClient.update_ccd_requesting_service().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| isActivated | bool |
| routePartitionName | str |
| learnedPatternPrefix | str |
| pstnPrefix | str |
| removeAssociatedTrunks | Any |
| addAssociatedTrunks | Any |
| associatedTrunks | Any |

### UpdateCiscoCatalyst600024PortFXSGateway { #UpdateCiscoCatalyst600024PortFXSGateway }

Used by AXLClient.update_cisco_catalyst600024_port_fxsgateway().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| callingSearchSpaceName | str |
| devicePoolName | str |
| commonDeviceConfigName | str |
| networkLocale | [Country](#Country) |
| locationName | str |
| mediaResourceListName | str |
| automatedAlternateRoutingCssName | str |
| aarNeighborhoodName | str |
| loadInformation | [LoadInformation](#LoadInformation) |
| vendorConfig | [VendorConfig](#VendorConfig) |
| traceFlag | bool |
| mlppDomainId | str |
| useTrustedRelayPoint | [Status](#Status) |
| cgpnTransformationCssName | str |
| useDevicePoolCgpnTransformCss | bool |
| geoLocationName | str |
| ports | Any |
| portSelectionOrder | [TrunkSelectionOrder](#TrunkSelectionOrder) |
| transmitUtf8 | bool |
| geoLocationFilterName | str |

### UpdateCiscoCatalyst6000E1VoIPGateway { #UpdateCiscoCatalyst6000E1VoIPGateway }

Used by AXLClient.update_cisco_catalyst6000_e1_vo_ipgateway().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| callingSearchSpaceName | str |
| devicePoolName | str |
| commonDeviceConfigName | str |
| networkLocation | [NetworkLocation](#NetworkLocation) |
| locationName | str |
| networkLocale | [Country](#Country) |
| mediaResourceListName | str |
| automatedAlternateRoutingCssName | str |
| aarNeighborhoodName | str |
| loadInformation | [LoadInformation](#LoadInformation) |
| vendorConfig | [VendorConfig](#VendorConfig) |
| mlppDomainId | str |
| useTrustedRelayPoint | [Status](#Status) |
| cgpnTransformationCssName | str |
| useDevicePoolCgpnTransformCss | bool |
| geoLocationName | str |
| redirectInboundNumberIe | bool |
| calledPlan | [NumberingPlan](#NumberingPlan) |
| calledPri | [PriOfNumber](#PriOfNumber) |
| callerIdDn | str |
| callingPartySelection | [CallingPartySelection](#CallingPartySelection) |
| callingPlan | [NumberingPlan](#NumberingPlan) |
| callingPri | [PriOfNumber](#PriOfNumber) |
| chanIe | [PRIChanIE](#PRIChanIE) |
| clockReference | [ClockReference](#ClockReference) |
| dChannelEnable | bool |
| channelSelectionOrder | [TrunkSelectionOrder](#TrunkSelectionOrder) |
| displayIE | bool |
| pcmType | [Encode](#Encode) |
| csuParam | [CSUParam](#CSUParam) |
| firstDelay | Any |
| interfaceIdPresent | bool |
| interfaceId | Any |
| intraDelay | Any |
| mcdnEnable | bool |
| redirectOutboundNumberIe | bool |
| numDigitsToStrip | Any |
| passingPrecedenceLevelThrough | bool |
| prefix | str |
| callingLinePresentationBit | [PresentationBit](#PresentationBit) |
| connectedLineIdPresentation | [PresentationBit](#PresentationBit) |
| priProtocol | [PriProtocol](#PriProtocol) |
| securityAccessLevel | Any |
| sendCallingNameInFacilityIe | bool |
| sendExLeadingCharInDispIe | bool |
| sendRestart | bool |
| setupNonIsdnPi | bool |
| sigDigits | Any |
| span | Any |
| statusPoll | bool |
| smdiBasePort | Any |
| packetCaptureMode | [PacketCaptureMode](#PacketCaptureMode) |
| packetCaptureDuration | Any |
| transmitUtf8 | bool |
| v150 | bool |
| asn1RoseOidEncoding | [ASN1RoseOidEncoding](#ASN1RoseOidEncoding) |
| QSIGVariant | [QSIGVariant](#QSIGVariant) |
| unattendedPort | bool |
| cdpnTransformationCssName | str |
| useDevicePoolCdpnTransformCss | bool |
| nationalPrefix | str |
| internationalPrefix | str |
| unknownPrefix | str |
| subscriberPrefix | str |
| geoLocationFilterName | str |
| nationalStripDigits | Any |
| internationalStripDigits | Any |
| unknownStripDigits | Any |
| subscriberStripDigits | Any |
| nationalTransformationCssName | str |
| internationalTransformationCssName | str |
| unknownTransformationCssName | str |
| subscriberTransformationCssName | str |
| useDevicePoolCgpnTransformCssNatl | bool |
| useDevicePoolCgpnTransformCssIntl | bool |
| useDevicePoolCgpnTransformCssUnkn | bool |
| useDevicePoolCgpnTransformCssSubs | bool |
| pstnAccess | bool |
| imeE164TransformationName | str |

### UpdateCiscoCatalyst6000T1VoIPGatewayPri { #UpdateCiscoCatalyst6000T1VoIPGatewayPri }

Used by AXLClient.update_cisco_catalyst6000_t1_vo_ipgateway_pri().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| callingSearchSpaceName | str |
| devicePoolName | str |
| commonDeviceConfigName | str |
| networkLocation | [NetworkLocation](#NetworkLocation) |
| locationName | str |
| networkLocale | [Country](#Country) |
| mediaResourceListName | str |
| automatedAlternateRoutingCssName | str |
| aarNeighborhoodName | str |
| loadInformation | [LoadInformation](#LoadInformation) |
| vendorConfig | [VendorConfig](#VendorConfig) |
| mlppDomainId | str |
| mlppIndicationStatus | [Status](#Status) |
| mlppPreemption | [Preemption](#Preemption) |
| useTrustedRelayPoint | [Status](#Status) |
| cgpnTransformationCssName | str |
| useDevicePoolCgpnTransformCss | bool |
| geoLocationName | str |
| redirectInboundNumberIe | bool |
| calledPlan | [NumberingPlan](#NumberingPlan) |
| calledPri | [PriOfNumber](#PriOfNumber) |
| callerIdDn | str |
| callingPartySelection | [CallingPartySelection](#CallingPartySelection) |
| callingPlan | [NumberingPlan](#NumberingPlan) |
| callingPri | [PriOfNumber](#PriOfNumber) |
| chanIe | [PRIChanIE](#PRIChanIE) |
| clockReference | [ClockReference](#ClockReference) |
| dChannelEnable | bool |
| channelSelectionOrder | [TrunkSelectionOrder](#TrunkSelectionOrder) |
| displayIE | bool |
| pcmType | [Encode](#Encode) |
| csuParam | [CSUParam](#CSUParam) |
| firstDelay | Any |
| interfaceIdPresent | bool |
| interfaceId | Any |
| intraDelay | Any |
| mcdnEnable | bool |
| redirectOutboundNumberIe | bool |
| numDigitsToStrip | Any |
| passingPrecedenceLevelThrough | bool |
| prefix | str |
| callingLinePresentationBit | [PresentationBit](#PresentationBit) |
| connectedLineIdPresentation | [PresentationBit](#PresentationBit) |
| priProtocol | [PriProtocol](#PriProtocol) |
| securityAccessLevel | Any |
| sendCallingNameInFacilityIe | bool |
| sendExLeadingCharInDispIe | bool |
| sendRestart | bool |
| setupNonIsdnPi | bool |
| sigDigits | Any |
| span | Any |
| statusPoll | bool |
| smdiBasePort | Any |
| packetCaptureMode | [PacketCaptureMode](#PacketCaptureMode) |
| packetCaptureDuration | Any |
| transmitUtf8 | bool |
| v150 | bool |
| asn1RoseOidEncoding | [ASN1RoseOidEncoding](#ASN1RoseOidEncoding) |
| QSIGVariant | [QSIGVariant](#QSIGVariant) |
| unattendedPort | bool |
| cdpnTransformationCssName | str |
| useDevicePoolCdpnTransformCss | bool |
| nationalPrefix | str |
| internationalPrefix | str |
| unknownPrefix | str |
| subscriberPrefix | str |
| geoLocationFilterName | str |
| nationalStripDigits | Any |
| internationalStripDigits | Any |
| unknownStripDigits | Any |
| subscriberStripDigits | Any |
| nationalTransformationCssName | str |
| internationalTransformationCssName | str |
| unknownTransformationCssName | str |
| subscriberTransformationCssName | str |
| useDevicePoolCgpnTransformCssNatl | bool |
| useDevicePoolCgpnTransformCssIntl | bool |
| useDevicePoolCgpnTransformCssUnkn | bool |
| useDevicePoolCgpnTransformCssSubs | bool |
| pstnAccess | bool |
| imeE164TransformationName | str |

### UpdateCiscoCatalyst6000T1VoIPGatewayT1 { #UpdateCiscoCatalyst6000T1VoIPGatewayT1 }

Used by AXLClient.update_cisco_catalyst6000_t1_vo_ipgateway_t1().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| callingSearchSpaceName | str |
| devicePoolName | str |
| commonDeviceConfigName | str |
| networkLocation | [NetworkLocation](#NetworkLocation) |
| locationName | str |
| mediaResourceListName | str |
| automatedAlternateRoutingCssName | str |
| aarNeighborhoodName | str |
| loadInformation | [LoadInformation](#LoadInformation) |
| vendorConfig | [VendorConfig](#VendorConfig) |
| traceFlag | bool |
| mlppDomainId | str |
| mlppIndicationStatus | [Status](#Status) |
| preemption | [Preemption](#Preemption) |
| useTrustedRelayPoint | [Status](#Status) |
| retryVideoCallAsAudio | bool |
| cgpnTransformationCssName | str |
| useDevicePoolCgpnTransformCss | bool |
| geoLocationName | str |
| sendGeoLocation | bool |
| ports | Any |
| trunkSelectionOrder | [TrunkSelectionOrder](#TrunkSelectionOrder) |
| clockReference | [ClockReference](#ClockReference) |
| csuParam | [CSUParam](#CSUParam) |
| digitSending | [DigitSending](#DigitSending) |
| pcmType | [Encode](#Encode) |
| fdlChannel | [FDLChannel](#FDLChannel) |
| yellowAlarm | [YellowAlarm](#YellowAlarm) |
| zeroSupression | [ZeroSuppression](#ZeroSuppression) |
| smdiBasePort | Any |
| handleDtmfPrecedenceSignals | bool |
| cdpnTransformationCssName | str |
| useDevicePoolCdpnTransformCss | bool |
| geoLocationFilterName | str |
| pstnAccess | bool |
| imeE164TransformationName | str |

### UpdateCiscoCloudOnboarding { #UpdateCiscoCloudOnboarding }

Used by AXLClient.update_cisco_cloud_onboarding().

| Field | Type |
|-------|------|
| uuid | str |
| voucherExists | bool |
| enablePushNotifications | bool |
| enableHttpProxy | bool |
| httpProxyAddress | str |
| proxyUsername | str |
| proxyPassword | str |
| enableTrustCACertificate | bool |
| allowAnalyticsCollection | bool |
| enableTroubleshooting | bool |
| alarmSendEncryptedData | bool |
| orgId | str |
| serviceAddress | str |
| orgName | str |
| enableGDSCommunication | bool |
| mraActivationDomain | str |

### UpdateCmcInfo { #UpdateCmcInfo }

Used by AXLClient.update_cmc_info().

| Field | Type |
|-------|------|
| uuid | str |
| code | str |
| newCode | str |
| description | str |

### UpdateCommonDeviceConfig { #UpdateCommonDeviceConfig }

Used by AXLClient.update_common_device_config().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| softkeyTemplateName | str |
| userLocale | [UserLocale](#UserLocale) |
| networkHoldMohAudioSourceId | Any |
| userHoldMohAudioSourceId | Any |
| mlppDomainId | str |
| mlppIndicationStatus | [Status](#Status) |
| useTrustedRelayPoint | bool |
| preemption | [Preemption](#Preemption) |
| ipAddressingMode | [IPAddressingMode](#IPAddressingMode) |
| ipAddressingModePreferenceControl | [IPAddressingModePrefControl](#IPAddressingModePrefControl) |
| allowAutoConfigurationForPhones | [Status](#Status) |
| useImeForOutboundCalls | [Status](#Status) |
| confidentialAccess | Any |
| allowDuplicateAddressDetection | [Status](#Status) |
| acceptRedirectMessages | [Status](#Status) |
| replyMulticastEchoRequest | [Status](#Status) |

### UpdateCommonPhoneConfig { #UpdateCommonPhoneConfig }

Used by AXLClient.update_common_phone_config().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| unlockPwd | str |
| dndOption | [DNDOption](#DNDOption) |
| dndAlertingType | [RingSetting](#RingSetting) |
| backgroundImage | bool |
| phonePersonalization | [PhonePersonalization](#PhonePersonalization) |
| phoneServiceDisplay | [PhoneServiceDisplay](#PhoneServiceDisplay) |
| sshUserId | str |
| sshPwd | str |
| vendorConfig | [VendorConfig](#VendorConfig) |
| alwaysUsePrimeLine | [Status](#Status) |
| alwaysUsePrimeLineForVoiceMessage | [Status](#Status) |
| vpnGroupName | str |
| vpnProfileName | str |
| featureControlPolicy | str |
| wifiHotspotProfile | str |

### UpdateConferenceBridge { #UpdateConferenceBridge }

Used by AXLClient.update_conference_bridge().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | Any |
| description | str |
| product | [Product](#Product) |
| devicePoolName | str |
| commonDeviceConfigName | str |
| locationName | str |
| loadInformation | [LoadInformation](#LoadInformation) |
| vendorConfig | [VendorConfig](#VendorConfig) |
| maximumCapacity | Any |
| useTrustedRelayPoint | [Status](#Status) |
| securityProfileName | str |
| destinationAddress | str |
| mcuConferenceBridgeSipPort | Any |
| sipProfile | str |
| srtpAllowed | bool |
| normalizationScript | str |
| enableTrace | bool |
| normalizationScriptInfos | Any |
| userName | str |
| password | str |
| httpPort | Any |
| useHttps | bool |
| addresses | Any |
| conferenceBridgePrefix | str |
| allowCFBControlOfCallSecurityIcon | bool |
| overrideSIPTrunkAddress | bool |
| sipTrunkName | str |

### UpdateConferenceNow { #UpdateConferenceNow }

Used by AXLClient.update_conference_now().

| Field | Type |
|-------|------|
| uuid | str |
| conferenceNowNumber | str |
| routePartitionName | str |
| newConferenceNowNumber | str |
| newRoutePartitionName | str |
| description | str |
| maxWaitTimeForHost | Any |
| MohAudioSourceId | Any |

### UpdateCredentialPolicy { #UpdateCredentialPolicy }

Used by AXLClient.update_credential_policy().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| failedLogon | Any |
| resetFailedLogonAttempts | Any |
| lockoutDuration | Any |
| credChangeDuration | Any |
| credExpiresAfter | Any |
| minCredLength | Any |
| prevCredStoredNum | Any |
| inactiveDaysAllowed | Any |
| expiryWarningDays | Any |
| trivialCredCheck | bool |
| minCharsToChange | Any |

### UpdateCredentialPolicyDefault { #UpdateCredentialPolicyDefault }

Used by AXLClient.update_credential_policy_default().

| Field | Type |
|-------|------|
| credentialUser | [CredentialUser](#CredentialUser) |
| credentialType | [Credential](#Credential) |
| credPolicyName | str |
| newCredPolicyName | str |
| credentials | str |
| confirmCredentials | str |
| credUserCantChange | bool |
| credUserMustChange | bool |
| credDoesNotExpire | bool |

### UpdateCss { #UpdateCss }

Used by AXLClient.update_css().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| description | str |
| removeMembers | Any |
| addMembers | Any |
| members | Any |
| newName | str |

### UpdateCtiRoutePoint { #UpdateCtiRoutePoint }

Used by AXLClient.update_cti_route_point().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| protocol | [DeviceProtocol](#DeviceProtocol) |
| protocolSide | [ProtocolSide](#ProtocolSide) |
| callingSearchSpaceName | str |
| devicePoolName | str |
| commonDeviceConfigName | str |
| locationName | str |
| mediaResourceListName | str |
| networkHoldMohAudioSourceId | Any |
| userHoldMohAudioSourceId | Any |
| useTrustedRelayPoint | [Status](#Status) |
| cgpnTransformationCssName | str |
| useDevicePoolCgpnTransformCss | bool |
| geoLocationName | str |
| userLocale | [UserLocale](#UserLocale) |
| lines | Any |

### UpdateCumaServerSecurityProfile { #UpdateCumaServerSecurityProfile }

Used by AXLClient.update_cuma_server_security_profile().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| securityMode | [DeviceSecurityMode](#DeviceSecurityMode) |
| transportType | [Transport](#Transport) |
| x509SubjectName | str |
| serverIpHostName | str |

### UpdateCustomUserField { #UpdateCustomUserField }

Used by AXLClient.update_custom_user_field().

| Field | Type |
|-------|------|
| uuid | str |
| field | str |
| newField | str |

### UpdateCustomer { #UpdateCustomer }

Used by AXLClient.update_customer().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |

### UpdateDateTimeGroup { #UpdateDateTimeGroup }

Used by AXLClient.update_date_time_group().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| timeZone | [TimeZone](#TimeZone) |
| separator | str |
| dateformat | str |
| timeFormat | str |
| removePhoneNtpReferences | Any |
| addPhoneNtpReferences | Any |
| phoneNtpReferences | Any |

### UpdateDefaultDeviceProfile { #UpdateDefaultDeviceProfile }

Used by AXLClient.update_default_device_profile().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| description | str |
| userHoldMohAudioSourceId | Any |
| userLocale | [UserLocale](#UserLocale) |
| phoneButtonTemplate | str |
| softkeyTemplate | str |
| privacy | [Status](#Status) |
| singleButtonBarge | [Barge](#Barge) |
| joinAcrossLines | [Status](#Status) |
| ignorePi | bool |
| dndStatus | bool |
| dndRingSetting | [RingSetting](#RingSetting) |
| dndOption | [DNDOption](#DNDOption) |
| mlppDomainId | str |
| mlppIndication | [Status](#Status) |
| preemption | [Preemption](#Preemption) |
| alwaysUsePrimeLine | [Status](#Status) |
| alwaysUsePrimeLineForVoiceMessage | [Status](#Status) |
| emccCallingSearchSpace | str |

### UpdateDeviceDefaults { #UpdateDeviceDefaults }

Used by AXLClient.update_device_defaults().

| Field | Type |
|-------|------|
| uuid | str |
| Model | [Model](#Model) |
| Protocol | [DeviceProtocol](#DeviceProtocol) |
| LoadInformation | [LoadInformation](#LoadInformation) |
| InactiveLoadInformation | [LoadInformation](#LoadInformation) |
| DevicePoolName | str |
| PhoneButtonTemplate | str |
| VersionStamp | str |
| PreferActCodeOverAutoReg | bool |

### UpdateDeviceMobility { #UpdateDeviceMobility }

Used by AXLClient.update_device_mobility().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| subNetDetails | Any |
| removeMembers | Any |
| addMembers | Any |
| members | Any |

### UpdateDeviceMobilityGroup { #UpdateDeviceMobilityGroup }

Used by AXLClient.update_device_mobility_group().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |

### UpdateDevicePool { #UpdateDevicePool }

Used by AXLClient.update_device_pool().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| autoSearchSpaceName | str |
| dateTimeSettingName | str |
| callManagerGroupName | str |
| mediaResourceListName | str |
| regionName | str |
| networkLocale | [Country](#Country) |
| srstName | str |
| connectionMonitorDuration | Any |
| automatedAlternateRoutingCssName | str |
| aarNeighborhoodName | str |
| locationName | str |
| mobilityCssName | str |
| physicalLocationName | str |
| deviceMobilityGroupName | str |
| revertPriority | [RevertPriority](#RevertPriority) |
| singleButtonBarge | [Barge](#Barge) |
| joinAcrossLines | [Status](#Status) |
| cgpnTransformationCssName | str |
| cdpnTransformationCssName | str |
| localRouteGroupName | str |
| geoLocationName | str |
| geoLocationFilterName | str |
| callingPartyNationalPrefix | str |
| callingPartyInternationalPrefix | str |
| callingPartyUnknownPrefix | str |
| callingPartySubscriberPrefix | str |
| adjunctCallingSearchSpace | str |
| callingPartyNationalStripDigits | Any |
| callingPartyInternationalStripDigits | Any |
| callingPartyUnknownStripDigits | Any |
| callingPartySubscriberStripDigits | Any |
| callingPartyNationalTransformationCssName | str |
| callingPartyInternationalTransformationCssName | str |
| callingPartyUnknownTransformationCssName | str |
| callingPartySubscriberTransformationCssName | str |
| calledPartyNationalPrefix | str |
| calledPartyInternationalPrefix | str |
| calledPartyUnknownPrefix | str |
| calledPartySubscriberPrefix | str |
| calledPartyNationalStripDigits | Any |
| calledPartyInternationalStripDigits | Any |
| calledPartyUnknownStripDigits | Any |
| calledPartySubscriberStripDigits | Any |
| calledPartyNationalTransformationCssName | str |
| calledPartyInternationalTransformationCssName | str |
| calledPartyUnknownTransformationCssName | str |
| calledPartySubscriberTransformationCssName | str |
| imeEnrolledPatternGroupName | str |
| cntdPnTransformationCssName | str |
| localRouteGroup | List[Any] |
| redirectingPartyTransformationCSS | str |
| callingPartyTransformationCSS | str |
| wirelessLanProfileGroup | str |
| elinGroup | str |
| mraServiceDomain | str |

### UpdateDeviceProfile { #UpdateDeviceProfile }

Used by AXLClient.update_device_profile().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| userHoldMohAudioSourceId | Any |
| vendorConfig | [VendorConfig](#VendorConfig) |
| mlppDomainId | str |
| mlppIndicationStatus | [Status](#Status) |
| preemption | [Preemption](#Preemption) |
| lines | Any |
| phoneTemplateName | str |
| speeddials | Any |
| busyLampFields | Any |
| blfDirectedCallParks | Any |
| addOnModules | Any |
| userLocale | [UserLocale](#UserLocale) |
| singleButtonBarge | [Barge](#Barge) |
| joinAcrossLines | [Status](#Status) |
| loginUserId | str |
| ignorePresentationIndicators | bool |
| dndOption | [DNDOption](#DNDOption) |
| dndRingSetting | [RingSetting](#RingSetting) |
| dndStatus | bool |
| emccCallingSearchSpace | str |
| alwaysUsePrimeLine | [Status](#Status) |
| alwaysUsePrimeLineForVoiceMessage | [Status](#Status) |
| softkeyTemplateName | str |
| callInfoPrivacyStatus | [Status](#Status) |
| services | Any |
| featureControlPolicy | str |

### UpdateDhcpServer { #UpdateDhcpServer }

Used by AXLClient.update_dhcp_server().

| Field | Type |
|-------|------|
| uuid | str |
| processNodeName | str |
| newProcessNodeName | str |
| primaryDnsIpAddress | str |
| secondaryDnsIpAddress | str |
| primaryTftpServerIpAddress | str |
| secondaryTftpServerIpAddress | str |
| bootstrapServerIpAddress | str |
| domainName | str |
| tftpServerName | str |
| arpCacheTimeout | Any |
| ipAddressLeaseTime | Any |
| renewalTime | Any |
| rebindingTime | Any |

### UpdateDhcpSubnet { #UpdateDhcpSubnet }

Used by AXLClient.update_dhcp_subnet().

| Field | Type |
|-------|------|
| uuid | str |
| dhcpServerName | str |
| subnetIpAddress | str |
| newDhcpServerName | str |
| newSubnetIpAddress | str |
| primaryStartIpAddress | str |
| primaryEndIpAddress | str |
| secondaryStartIpAddress | str |
| secondaryEndIpAddress | str |
| primaryRouterIpAddress | str |
| secondaryRouterIpAddress | str |
| subnetMask | str |
| domainName | str |
| primaryDnsIpAddress | str |
| secondaryDnsIpAddress | str |
| tftpServerName | str |
| primaryTftpServerIpAddress | str |
| secondaryTftpServerIpAddress | str |
| bootstrapServerIpAddress | str |
| arpCacheTimeout | Any |
| ipAddressLeaseTime | Any |
| renewalTime | Any |
| rebindingTime | Any |

### UpdateDirNumberAliasLookupandSync { #UpdateDirNumberAliasLookupandSync }

Used by AXLClient.update_dir_number_alias_lookupand_sync().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| ldapConfigName | str |
| ldapManagerDisgName | str |
| ldapPassword | str |
| ldapUserSearch | str |
| ldapDirectoryServerUsage | [LDAPDirectoryFunction](#LDAPDirectoryFunction) |
| keepAliveSearch | str |
| keepAliveTime | [KeepAliveTimeInterval](#KeepAliveTimeInterval) |
| sipAliasSuffix | str |
| enableCachingofRecords | bool |
| servers | Any |
| cacheSizeforAliasLookup | Any |
| cacheAgeforAliasLookup | Any |

### UpdateDirectedCallPark { #UpdateDirectedCallPark }

Used by AXLClient.update_directed_call_park().

| Field | Type |
|-------|------|
| uuid | str |
| pattern | str |
| routePartitionName | str |
| newPattern | str |
| description | str |
| newRoutePartitionName | str |
| retrievalPrefix | str |
| reversionPattern | str |
| revertCssName | str |

### UpdateDirectoryLookupDialRules { #UpdateDirectoryLookupDialRules }

Used by AXLClient.update_directory_lookup_dial_rules().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| numberBeginWith | str |
| numberOfDigits | Any |
| digitsToBeRemoved | Any |
| prefixPattern | str |
| priority | Any |

### UpdateElinGroup { #UpdateElinGroup }

Used by AXLClient.update_elin_group().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| removeElinNumbers | Any |
| addElinNumbers | Any |
| elinNumbers | Any |

### UpdateEmccFeatureConfig { #UpdateEmccFeatureConfig }

Used by AXLClient.update_emcc_feature_config().

| Field | Type |
|-------|------|
| uuid | str |
| parameterName | str |
| value | str |

### UpdateEndUserCapfProfile { #UpdateEndUserCapfProfile }

Used by AXLClient.update_end_user_capf_profile().

| Field | Type |
|-------|------|
| uuid | str |
| instanceId | str |
| certificationOperation | [CertificateOperation](#CertificateOperation) |
| authenticationMode | [AuthenticationMode](#AuthenticationMode) |
| authenticationString | str |
| keySize | [KeySize](#KeySize) |
| keyOrder | [KeyOrder](#KeyOrder) |
| ecKeySize | [ECKeySize](#ECKeySize) |
| operationCompletion | str |

### UpdateEnterpriseFeatureAccessConfiguration { #UpdateEnterpriseFeatureAccessConfiguration }

Used by AXLClient.update_enterprise_feature_access_configuration().

| Field | Type |
|-------|------|
| uuid | str |
| pattern | str |
| routePartitionName | str |
| newPattern | str |
| newRoutePartitionName | str |
| description | str |
| isDefaultEafNumber | bool |

### UpdateEnterprisePhoneConfig { #UpdateEnterprisePhoneConfig }

Used by AXLClient.update_enterprise_phone_config().

| Field | Type |
|-------|------|
| vendorConfig | [VendorConfig](#VendorConfig) |

### UpdateExpresswayCConfiguration { #UpdateExpresswayCConfiguration }

Used by AXLClient.update_expressway_cconfiguration().

| Field | Type |
|-------|------|
| uuid | str |
| HostNameOrIP | str |
| newHostNameOrIP | str |
| description | str |
| X509SubjectNameorSubjectAlternateName | str |

### UpdateExternalCallControlProfile { #UpdateExternalCallControlProfile }

Used by AXLClient.update_external_call_control_profile().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| primaryUri | str |
| secondaryUri | str |
| enableLoadBalancing | bool |
| routingRequestTimer | Any |
| diversionReroutingCssName | str |
| callTreatmentOnFailure | [CallTreatmentOnFailure](#CallTreatmentOnFailure) |

### UpdateFacInfo { #UpdateFacInfo }

Used by AXLClient.update_fac_info().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| code | str |
| authorizationLevel | Any |

### UpdateFallbackFeatureConfig { #UpdateFallbackFeatureConfig }

Used by AXLClient.update_fallback_feature_config().

| Field | Type |
|-------|------|
| enableFallbackForImeCalls | bool |
| qosSensistivityLevel | Any |
| dtmfCorrelationDigits | Any |
| dtmfCollectionTimer | Any |
| callAnswerTimer | Any |
| clearImeCallDelayTimer | Any |
| dtmfInterDigitDelayTimer | Any |
| postConnectFallbackDelayTimer | Any |
| fallbackSplitDelayTimer | Any |
| callCss | Any |

### UpdateFallbackProfile { #UpdateFallbackProfile }

Used by AXLClient.update_fallback_profile().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| advertisedFallbackDirectoryE164Number | str |
| qosSensistivityLevel | Any |
| callCss | [FallBackCSSSelection](#FallBackCSSSelection) |
| callAnswerTimer | Any |
| directoryNumberPartition | str |
| directoryNumber | str |
| numberOfDigitsForCallerIDPartialMatch | Any |

### UpdateFeatureControlPolicy { #UpdateFeatureControlPolicy }

Used by AXLClient.update_feature_control_policy().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| features | Any |

### UpdateFeatureGroupTemplate { #UpdateFeatureGroupTemplate }

Used by AXLClient.update_feature_group_template().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| homeCluster | bool |
| imAndUcPresenceEnable | bool |
| serviceProfile | str |
| enableUserToHostConferenceNow | bool |
| allowCTIControl | bool |
| enableEMCC | bool |
| enableMobility | bool |
| enableMobileVoiceAccess | bool |
| maxDeskPickupWait | Any |
| remoteDestinationLimit | Any |
| BLFPresenceGp | str |
| subscribeCallingSearch | str |
| userLocale | [UserLocale](#UserLocale) |
| userProfile | str |
| meetingInformation | bool |

### UpdateFixedMohAudioSource { #UpdateFixedMohAudioSource }

Used by AXLClient.update_fixed_moh_audio_source().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| multicast | bool |
| enable | str |
| initialAnnouncement | str |
| periodicAnnouncement | str |
| periodicAnnouncementInterval | Any |
| localeAnnouncement | [UserLocale](#UserLocale) |
| initialAnnouncementPlayed | bool |

### UpdateGatekeeper { #UpdateGatekeeper }

Used by AXLClient.update_gatekeeper().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| rrqTimeToLive | Any |
| retryTimeout | Any |
| enableDevice | bool |

### UpdateGateway { #UpdateGateway }

Used by AXLClient.update_gateway().

| Field | Type |
|-------|------|
| uuid | str |
| domainName | str |
| newDomainName | str |
| description | str |
| product | [Product](#Product) |
| protocol | [DeviceProtocol](#DeviceProtocol) |
| callManagerGroupName | str |
| vendorConfig | [VendorConfig](#VendorConfig) |

### UpdateGatewayEndpointAnalogAccess { #UpdateGatewayEndpointAnalogAccess }

Used by AXLClient.update_gateway_endpoint_analog_access().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| endpoint | [GatewayEndpointAnalog](#GatewayEndpointAnalog) |

### UpdateGatewayEndpointDigitalAccessBri { #UpdateGatewayEndpointDigitalAccessBri }

Used by AXLClient.update_gateway_endpoint_digital_access_bri().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| endpoint | [GatewayEndpointDigitalBri](#GatewayEndpointDigitalBri) |

### UpdateGatewayEndpointDigitalAccessPri { #UpdateGatewayEndpointDigitalAccessPri }

Used by AXLClient.update_gateway_endpoint_digital_access_pri().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| endpoint | [GatewayEndpointDigitalPri](#GatewayEndpointDigitalPri) |

### UpdateGatewayEndpointDigitalAccessT1 { #UpdateGatewayEndpointDigitalAccessT1 }

Used by AXLClient.update_gateway_endpoint_digital_access_t1().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| endpoint | [UGatewayEndpointDigitalT1](#UGatewayEndpointDigitalT1) |

### UpdateGatewaySccpEndpoints { #UpdateGatewaySccpEndpoints }

Used by AXLClient.update_gateway_sccp_endpoints().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| endpoint | [GatewaySccp](#GatewaySccp) |

### UpdateGeoLocation { #UpdateGeoLocation }

Used by AXLClient.update_geo_location().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| country | str |
| description | str |
| nationalSubDivision | str |
| district | str |
| communityName | str |
| cityDivision | str |
| neighbourhood | str |
| street | str |
| leadingStreetDirection | str |
| trailingStreetSuffix | str |
| streetSuffix | str |
| houseNumber | str |
| houseNumberSuffix | str |
| landmark | str |
| location | str |
| floor | str |
| occupantName | str |
| postalCode | str |

### UpdateGeoLocationFilter { #UpdateGeoLocationFilter }

Used by AXLClient.update_geo_location_filter().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| useCountry | bool |
| useNationalSubDivision | bool |
| useDistrict | bool |
| useCommunityName | bool |
| useCityDivision | bool |
| useNeighbourhood | bool |
| useStreet | bool |
| useLeadingStreetDirection | bool |
| useTrailingStreetSuffix | bool |
| useStreetSuffix | bool |
| useHouseNumber | bool |
| useHouseNumberSuffix | bool |
| useLandmark | bool |
| useLocation | bool |
| useFloor | bool |
| useOccupantName | bool |
| usePostalCode | bool |

### UpdateGeoLocationPolicy { #UpdateGeoLocationPolicy }

Used by AXLClient.update_geo_location_policy().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| country | str |
| description | str |
| nationalSubDivision | str |
| district | str |
| communityName | str |
| cityDivision | str |
| neighbourhood | str |
| street | str |
| leadingStreetDirection | str |
| trailingStreetSuffix | str |
| streetSuffix | str |
| houseNumber | str |
| houseNumberSuffix | str |
| landmark | str |
| location | str |
| floor | str |
| occupantName | str |
| postalCode | str |
| removeRelatedPolicies | Any |
| addRelatedPolicies | Any |
| relatedPolicies | Any |

### UpdateH323Gateway { #UpdateH323Gateway }

Used by AXLClient.update_h323_gateway().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| callingSearchSpaceName | str |
| devicePoolName | str |
| commonDeviceConfigName | str |
| networkLocation | [NetworkLocation](#NetworkLocation) |
| locationName | str |
| mediaResourceListName | str |
| automatedAlternateRoutingCssName | str |
| aarNeighborhoodName | str |
| loadInformation | [LoadInformation](#LoadInformation) |
| tunneledProtocol | [TunneledProtocol](#TunneledProtocol) |
| asn1RoseOidEncoding | [ASN1RoseOidEncoding](#ASN1RoseOidEncoding) |
| qsigVariant | [QSIGVariant](#QSIGVariant) |
| vendorConfig | [VendorConfig](#VendorConfig) |
| pathReplacementSupport | bool |
| traceFlag | bool |
| mlppDomainId | str |
| useTrustedRelayPoint | [Status](#Status) |
| retryVideoCallAsAudio | bool |
| cgpnTransformationCssName | str |
| useDevicePoolCgpnTransformCss | bool |
| geoLocationName | str |
| geoLocationFilterName | str |
| cdpnTransformationCssName | str |
| useDevicePoolCdpnTransformCss | bool |
| packetCaptureMode | [PacketCaptureMode](#PacketCaptureMode) |
| packetCaptureDuration | Any |
| srtpAllowed | bool |
| waitForFarEndH245TerminalSet | bool |
| mtpRequired | bool |
| callerIdDn | str |
| callingPartySelection | [CallingPartySelection](#CallingPartySelection) |
| callingLineIdPresentation | [PresentationBit](#PresentationBit) |
| enableInboundFaststart | bool |
| enableOutboundFaststart | bool |
| codecForOutboundFaststart | [MediaPayload](#MediaPayload) |
| transmitUtf8 | bool |
| signalingPort | Any |
| allowH235PassThrough | bool |
| sigDigits | Any |
| prefixDn | str |
| calledPartyIeNumberType | [PriOfNumber](#PriOfNumber) |
| callingPartyIeNumberType | [PriOfNumber](#PriOfNumber) |
| calledNumberingPlan | [NumberingPlan](#NumberingPlan) |
| callingNumberingPlan | [NumberingPlan](#NumberingPlan) |
| callingPartyNationalPrefix | str |
| callingPartyInternationalPrefix | str |
| callingPartyUnknownPrefix | str |
| callingPartySubscriberPrefix | str |
| callingPartyNationalStripDigits | Any |
| callingPartyInternationalStripDigits | Any |
| callingPartyUnknownStripDigits | Any |
| callingPartySubscriberStripDigits | Any |
| callingPartyNationalTransformationCssName | str |
| callingPartyInternationalTransformationCssName | str |
| callingPartyUnknownTransformationCssName | str |
| callingPartySubscriberTransformationCssName | str |
| calledPartyNationalPrefix | str |
| calledPartyInternationalPrefix | str |
| calledPartyUnknownPrefix | str |
| calledPartySubscriberPrefix | str |
| calledPartyNationalStripDigits | Any |
| calledPartyInternationalStripDigits | Any |
| calledPartyUnknownStripDigits | Any |
| calledPartySubscriberStripDigits | Any |
| calledPartyNationalTransformationCssName | str |
| calledPartyInternationalTransformationCssName | str |
| calledPartyUnknownTransformationCssName | str |
| calledPartySubscriberTransformationCssName | str |
| pstnAccess | bool |
| imeE164TransformationName | str |
| displayIeDelivery | bool |
| redirectOutboundNumberIe | bool |
| redirectInboundNumberIe | bool |
| useDevicePoolCgpnTransformCssNatl | bool |
| useDevicePoolCgpnTransformCssIntl | bool |
| useDevicePoolCgpnTransformCssUnkn | bool |
| useDevicePoolCgpnTransformCssSubs | bool |
| useDevicePoolCalledCssNatl | bool |
| useDevicePoolCalledCssIntl | bool |
| useDevicePoolCalledCssUnkn | bool |
| useDevicePoolCalledCssSubs | bool |
| useDevicePoolCntdPnTransformationCss | bool |
| cntdPnTransformationCssName | str |
| confidentialAccess | Any |
| redirectingPartyTransformationCSS | str |
| connectCallBeforePlayingAnnouncement | bool |

### UpdateH323Phone { #UpdateH323Phone }

Used by AXLClient.update_h323_phone().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| callingSearchSpaceName | str |
| devicePoolName | str |
| commonDeviceConfigName | str |
| commonPhoneConfigName | str |
| locationName | str |
| mediaResourceListName | str |
| automatedAlternateRoutingCssName | str |
| aarNeighborhoodName | str |
| traceFlag | bool |
| mlppDomainId | str |
| useTrustedRelayPoint | [Status](#Status) |
| retryVideoCallAsAudio | bool |
| remoteDevice | bool |
| cgpnTransformationCssName | str |
| useDevicePoolCgpnTransformCss | bool |
| geoLocationName | str |
| alwaysUsePrimeLine | [Status](#Status) |
| alwaysUsePrimeLineForVoiceMessage | [Status](#Status) |
| srtpAllowed | bool |
| unattendedPort | bool |
| subscribeCallingSearchSpaceName | str |
| waitForFarEndH245TerminalSet | bool |
| mtpRequired | bool |
| mtpPreferredCodec | [SIPCodec](#SIPCodec) |
| callerIdDn | str |
| callingPartySelection | [CallingPartySelection](#CallingPartySelection) |
| callingLineIdPresentation | [PresentationBit](#PresentationBit) |
| displayIEDelivery | bool |
| redirectOutboundNumberIe | bool |
| redirectInboundNumberIe | bool |
| presenceGroupName | str |
| hlogStatus | bool |
| ownerUserName | str |
| signalingPort | Any |
| gateKeeperInfo | Any |
| lines | Any |
| ignorePresentationIndicators | bool |
| elinGroup | str |

### UpdateH323Trunk { #UpdateH323Trunk }

Used by AXLClient.update_h323_trunk().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| callingSearchSpaceName | str |
| devicePoolName | str |
| commonDeviceConfigName | str |
| networkLocation | [NetworkLocation](#NetworkLocation) |
| locationName | str |
| mediaResourceListName | str |
| aarNeighborhoodName | str |
| traceFlag | bool |
| mlppDomainId | str |
| mlppIndicationStatus | [Status](#Status) |
| preemption | [Preemption](#Preemption) |
| useTrustedRelayPoint | [Status](#Status) |
| retryVideoCallAsAudio | bool |
| cgpnTransformationCssName | str |
| useDevicePoolCgpnTransformCss | bool |
| rdnTransformationCssName | str |
| useDevicePoolRdnTransformCss | bool |
| geoLocationName | str |
| geoLocationFilterName | str |
| sendGeoLocation | bool |
| cdpnTransformationCssName | str |
| useDevicePoolCdpnTransformCss | bool |
| packetCaptureMode | [PacketCaptureMode](#PacketCaptureMode) |
| packetCaptureDuration | Any |
| srtpAllowed | bool |
| unattendedPort | bool |
| waitForFarEndH245TerminalSet | bool |
| mtpRequired | bool |
| callerIdDn | str |
| callingPartySelection | [CallingPartySelection](#CallingPartySelection) |
| callingLineIdPresentation | [PresentationBit](#PresentationBit) |
| displayIEDelivery | bool |
| redirectOutboundNumberIe | bool |
| redirectInboundNumberIe | bool |
| enableInboundFaststart | bool |
| enableOutboundFaststart | bool |
| codecForOutboundFaststart | [MediaPayload](#MediaPayload) |
| allowH235PassThrough | bool |
| tunneledProtocol | [TunneledProtocol](#TunneledProtocol) |
| asn1RoseOidEncoding | [ASN1RoseOidEncoding](#ASN1RoseOidEncoding) |
| qsigVariant | [QSIGVariant](#QSIGVariant) |
| transmitUtf8 | bool |
| signalingPort | Any |
| nationalPrefix | str |
| internationalPrefix | str |
| unknownPrefix | str |
| subscriberPrefix | str |
| sigDigits | Any |
| prefixDn | str |
| calledPartyIeNumberType | [PriOfNumber](#PriOfNumber) |
| callingPartyIeNumberType | [PriOfNumber](#PriOfNumber) |
| calledNumberingPlan | [NumberingPlan](#NumberingPlan) |
| callingNumberingPlan | [NumberingPlan](#NumberingPlan) |
| pathReplacementSupport | bool |
| gateKeeperInfo | Any |
| ictPassingPrecedenceLevelThroughUuie | bool |
| ictSecurityAccessLevel | Any |
| isSafEnabled | bool |
| callingPartyNationalStripDigits | Any |
| callingPartyInternationalStripDigits | Any |
| callingPartyUnknownStripDigits | Any |
| callingPartySubscriberStripDigits | Any |
| callingPartyNationalTransformationCssName | str |
| callingPartyInternationalTransformationCssName | str |
| callingPartyUnknownTransformationCssName | str |
| callingPartySubscriberTransformationCssName | str |
| calledPartyNationalPrefix | str |
| calledPartyInternationalPrefix | str |
| calledPartyUnknownPrefix | str |
| calledPartySubscriberPrefix | str |
| pstnAccess | bool |
| imeE164TransformationName | str |
| automatedAlternateRoutingCssName | str |
| useDevicePoolCgpnTransformCssNatl | bool |
| useDevicePoolCgpnTransformCssIntl | bool |
| useDevicePoolCgpnTransformCssUnkn | bool |
| useDevicePoolCgpnTransformCssSubs | bool |
| useDevicePoolCalledCssNatl | bool |
| useDevicePoolCalledCssIntl | bool |
| useDevicePoolCalledCssUnkn | bool |
| useDevicePoolCalledCssSubs | bool |
| calledPartyNationalStripDigits | Any |
| calledPartyInternationalStripDigits | Any |
| calledPartyUnknownStripDigits | Any |
| calledPartySubscriberStripDigits | Any |
| calledPartyNationalTransformationCssName | str |
| calledPartyInternationalTransformationCssName | str |
| calledPartyUnknownTransformationCssName | str |
| calledPartySubscriberTransformationCssName | str |
| runOnEveryNode | bool |
| removeDestinations | Any |
| addDestinations | Any |
| destinations | Any |
| useDevicePoolCntdPnTransformationCss | bool |
| cntdPnTransformationCssName | str |
| confidentialAccess | Any |
| connectCallBeforePlayingAnnouncement | bool |

### UpdateHandoffConfiguration { #UpdateHandoffConfiguration }

Used by AXLClient.update_handoff_configuration().

| Field | Type |
|-------|------|
| uuid | str |
| pattern | str |
| routePartitionName | str |
| newPattern | str |
| newRoutePartitionName | str |

### UpdateHttpProfile { #UpdateHttpProfile }

Used by AXLClient.update_http_profile().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| userName | str |
| password | str |
| requestTimeout | Any |
| retryCount | Any |
| webServiceRootUri | str |

### UpdateHuntList { #UpdateHuntList }

Used by AXLClient.update_hunt_list().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| description | str |
| callManagerGroupName | str |
| routeListEnabled | bool |
| voiceMailUsage | bool |
| removeMembers | Any |
| addMembers | Any |
| members | Any |
| newName | str |

### UpdateHuntPilot { #UpdateHuntPilot }

Used by AXLClient.update_hunt_pilot().

| Field | Type |
|-------|------|
| uuid | str |
| pattern | str |
| routePartitionName | str |
| newPattern | str |
| description | str |
| newRoutePartitionName | str |
| blockEnable | bool |
| calledPartyTransformationMask | str |
| callingPartyTransformationMask | str |
| useCallingPartyPhoneMask | [Status](#Status) |
| callingPartyPrefixDigits | str |
| dialPlanName | str |
| digitDiscardInstructionName | str |
| patternUrgency | bool |
| prefixDigitsOut | str |
| routeFilterName | str |
| callingLinePresentationBit | [PresentationBit](#PresentationBit) |
| callingNamePresentationBit | [PresentationBit](#PresentationBit) |
| connectedLinePresentationBit | [PresentationBit](#PresentationBit) |
| connectedNamePresentationBit | [PresentationBit](#PresentationBit) |
| patternPrecedence | [PatternPrecedence](#PatternPrecedence) |
| provideOutsideDialtone | bool |
| callingPartyNumberingPlan | [NumberingPlan](#NumberingPlan) |
| callingPartyNumberType | [PriOfNumber](#PriOfNumber) |
| calledPartyNumberingPlan | [NumberingPlan](#NumberingPlan) |
| calledPartyNumberType | [PriOfNumber](#PriOfNumber) |
| huntListName | str |
| parkMonForwardNoRetrieve | Any |
| alertingName | str |
| asciiAlertingName | Any |
| e164Mask | str |
| aarNeighborhoodName | str |
| forwardHuntNoAnswer | Any |
| forwardHuntBusy | Any |
| callPickupGroupName | str |
| maxHuntduration | Any |
| releaseClause | [ReleaseCauseValue](#ReleaseCauseValue) |
| displayConnectedNumber | bool |
| queueCalls | [CallsQueue](#CallsQueue) |

### UpdateIlsConfig { #UpdateIlsConfig }

Used by AXLClient.update_ils_config().

| Field | Type |
|-------|------|
| role | str |
| registrationServer | str |
| activateIls | bool |
| synchronizeClustersEvery | str |
| activatedServers | str |
| deactivatedServers | str |
| useTls | bool |
| enableUsePassword | bool |
| usePassword | str |

### UpdateImeClient { #UpdateImeClient }

Used by AXLClient.update_ime_client().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| domain | str |
| isActivated | bool |
| sipTrunkName | str |
| primaryImeServerName | str |
| secondaryImeServerName | str |
| learnedRouteFilterGroupName | str |
| exclusionNumberGroupName | str |
| firewallName | str |
| removeMembers | Any |
| addMembers | Any |
| members | Any |
| removeCcmExternalIpMaps | Any |
| addCcmExternalIpMaps | Any |
| ccmExternalIpMaps | Any |

### UpdateImeE164Transformation { #UpdateImeE164Transformation }

Used by AXLClient.update_ime_e164_transformation().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| cgpnTransformationCssName | str |
| isCgpnPreTransformation | bool |
| cdpnTransformationCssName | str |
| isCdpnPreTransformation | bool |
| incomingCgpnTransformationProfileName | str |
| incomingCdpnTransformationProfileName | str |

### UpdateImeEnrolledPattern { #UpdateImeEnrolledPattern }

Used by AXLClient.update_ime_enrolled_pattern().

| Field | Type |
|-------|------|
| uuid | str |
| pattern | str |
| newPattern | str |
| description | str |
| imeEnrolledPatternGroupName | str |

### UpdateImeEnrolledPatternGroup { #UpdateImeEnrolledPatternGroup }

Used by AXLClient.update_ime_enrolled_pattern_group().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| fallbackProfileName | str |
| isPatternAllAlias | bool |

### UpdateImeExclusionNumber { #UpdateImeExclusionNumber }

Used by AXLClient.update_ime_exclusion_number().

| Field | Type |
|-------|------|
| uuid | str |
| pattern | str |
| newPattern | str |
| description | str |
| imeExclusionNumberGroupName | str |

### UpdateImeExclusionNumberGroup { #UpdateImeExclusionNumberGroup }

Used by AXLClient.update_ime_exclusion_number_group().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |

### UpdateImeFeatureConfig { #UpdateImeFeatureConfig }

Used by AXLClient.update_ime_feature_config().

| Field | Type |
|-------|------|
| preventImeCallsFromAnalogGateways | bool |
| enableIntraDomain | bool |
| allowMwiNotification | bool |
| trunkConnectionTimer | Any |
| firewallConnectionTimer | Any |
| firewallTranscationTimer | Any |
| firewallIdleTimer | Any |
| failedCallAttemptThreshold | Any |
| callFallbackAttemptThreshold | Any |
| qualityTimer | Any |
| useImeForOutboundCalls | bool |

### UpdateImeFirewall { #UpdateImeFirewall }

Used by AXLClient.update_ime_firewall().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| ipAddress | Any |
| port | Any |

### UpdateImeLearnedRoutes { #UpdateImeLearnedRoutes }

Used by AXLClient.update_ime_learned_routes().

| Field | Type |
|-------|------|
| uuid | str |
| e164Did | Any |
| adminEnabled | bool |

### UpdateImeRouteFilterElement { #UpdateImeRouteFilterElement }

Used by AXLClient.update_ime_route_filter_element().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| elementType | [ViprFilterElement](#ViprFilterElement) |
| imeRouteFilterGroupName | str |

### UpdateImeRouteFilterGroup { #UpdateImeRouteFilterGroup }

Used by AXLClient.update_ime_route_filter_group().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| groupTrustSetting | bool |

### UpdateImeServer { #UpdateImeServer }

Used by AXLClient.update_ime_server().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| ipAddress | str |
| port | Any |
| deviceSecurityMode | [ServerSecurityMode](#ServerSecurityMode) |
| applicationUser | str |
| reconnectInterval | Any |

### UpdateImportedDirectoryUriCatalogs { #UpdateImportedDirectoryUriCatalogs }

Used by AXLClient.update_imported_directory_uri_catalogs().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| routeString | str |

### UpdateInfrastructureDevice { #UpdateInfrastructureDevice }

Used by AXLClient.update_infrastructure_device().

| Field | Type |
|-------|------|
| uuid | str |
| newName | str |
| ipv4Address | str |
| ipv6Address | str |
| bssidWithMask | str |
| wapLocation | str |
| isActive | bool |

### UpdateInterClusterDirectoryUri { #UpdateInterClusterDirectoryUri }

Used by AXLClient.update_inter_cluster_directory_uri().

| Field | Type |
|-------|------|
| exchangeDirectoryUri | bool |
| routeString | str |

### UpdateInterClusterServiceProfile { #UpdateInterClusterServiceProfile }

Used by AXLClient.update_inter_cluster_service_profile().

| Field | Type |
|-------|------|
| uuid | str |
| interClusterService | [InterClusterService](#InterClusterService) |
| isActivated | bool |
| sipTrunkName | str |

### UpdateInteractiveVoiceResponse { #UpdateInteractiveVoiceResponse }

Used by AXLClient.update_interactive_voice_response().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| devicePoolName | str |
| locationName | str |
| useTrustedRelayPoint | [Status](#Status) |

### UpdateIpPhoneServices { #UpdateIpPhoneServices }

Used by AXLClient.update_ip_phone_services().

| Field | Type |
|-------|------|
| uuid | str |
| serviceName | str |
| newServiceName | str |
| asciiServiceName | str |
| serviceDescription | str |
| serviceUrl | str |
| secureServiceUrl | str |
| serviceCategory | [PhoneServiceCategory](#PhoneServiceCategory) |
| serviceType | [PhoneService](#PhoneService) |
| serviceVendor | str |
| serviceVersion | str |
| enabled | bool |
| removeParameters | Any |
| addParameters | Any |
| parameters | Any |

### UpdateIvrUserLocale { #UpdateIvrUserLocale }

Used by AXLClient.update_ivr_user_locale().

| Field | Type |
|-------|------|
| uuid | str |
| userLocale | [UserLocale](#UserLocale) |
| newUserLocale | [UserLocale](#UserLocale) |
| orderIndex | Any |

### UpdateLbmGroup { #UpdateLbmGroup }

Used by AXLClient.update_lbm_group().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| Description | str |
| ProcessnodeActive | str |
| ProcessnodeStandby | str |

### UpdateLbmHubGroup { #UpdateLbmHubGroup }

Used by AXLClient.update_lbm_hub_group().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| member1 | str |
| member2 | str |
| member3 | str |
| removeMembers | Any |
| addMembers | Any |
| members | Any |

### UpdateLdapAuthentication { #UpdateLdapAuthentication }

Used by AXLClient.update_ldap_authentication().

| Field | Type |
|-------|------|
| authenticateEndUsers | bool |
| distinguishedName | str |
| ldapPassword | str |
| userSearchBase | str |
| servers | Any |

### UpdateLdapDirectory { #UpdateLdapDirectory }

Used by AXLClient.update_ldap_directory().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| ldapDn | str |
| ldapPassword | str |
| userSearchBase | str |
| repeatable | bool |
| intervalValue | Any |
| scheduleUnit | [ScheduleUnit](#ScheduleUnit) |
| nextExecTime | Any |
| servers | Any |
| ldapFilter | str |
| synchronize | bool |
| ldapFilterForGroups | str |
| removeAccessControlGroupInfo | Any |
| addAccessControlGroupInfo | Any |
| accessControlGroupInfo | Any |
| featureGroupTemplate | str |
| applyMask | bool |
| mask | str |
| applyPoolList | bool |
| addDns | Any |

### UpdateLdapFilter { #UpdateLdapFilter }

Used by AXLClient.update_ldap_filter().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| filter | str |

### UpdateLdapSearch { #UpdateLdapSearch }

Used by AXLClient.update_ldap_search().

| Field | Type |
|-------|------|
| uuid | str |
| enableDirectorySearch | bool |
| distinguishedName | str |
| password | str |
| userSearchBase1 | str |
| userSearchBase2 | str |
| userSearchBase3 | str |
| ldapFilterForUser | str |
| ldapFilterForGroups | str |
| enableRecursiveSearch | bool |
| primary | str |
| secondary | str |
| tertiary | str |

### UpdateLdapSyncCustomField { #UpdateLdapSyncCustomField }

Used by AXLClient.update_ldap_sync_custom_field().

| Field | Type |
|-------|------|
| uuid | str |
| ldapConfigurationName | str |
| customUserField | str |
| ldapUserField | str |

### UpdateLdapSystem { #UpdateLdapSystem }

Used by AXLClient.update_ldap_system().

| Field | Type |
|-------|------|
| syncEnabled | bool |
| ldapServer | [LdapServer](#LdapServer) |
| userIdAttribute | Any |

### UpdateLine { #UpdateLine }

Used by AXLClient.update_line().

| Field | Type |
|-------|------|
| uuid | str |
| pattern | str |
| routePartitionName | str |
| newPattern | str |
| description | str |
| newRoutePartitionName | str |
| aarNeighborhoodName | str |
| aarDestinationMask | str |
| aarKeepCallHistory | bool |
| aarVoiceMailEnabled | bool |
| callForwardAll | [CallForwardAll](#CallForwardAll) |
| callForwardBusy | [CallForwardBusy](#CallForwardBusy) |
| callForwardBusyInt | [CallForwardBusyInt](#CallForwardBusyInt) |
| callForwardNoAnswer | [CallForwardNoAnswer](#CallForwardNoAnswer) |
| callForwardNoAnswerInt | [CallForwardNoAnswerInt](#CallForwardNoAnswerInt) |
| callForwardNoCoverage | [CallForwardNoCoverage](#CallForwardNoCoverage) |
| callForwardNoCoverageInt | [CallForwardNoCoverageInt](#CallForwardNoCoverageInt) |
| callForwardOnFailure | [CallForwardOnFailure](#CallForwardOnFailure) |
| callForwardAlternateParty | [CallForwardAlternateParty](#CallForwardAlternateParty) |
| callForwardNotRegistered | [CallForwardNotRegistered](#CallForwardNotRegistered) |
| callForwardNotRegisteredInt | [CallForwardNotRegisteredInt](#CallForwardNotRegisteredInt) |
| callPickupGroupName | str |
| autoAnswer | [AutoAnswer](#AutoAnswer) |
| networkHoldMohAudioSourceId | Any |
| userHoldMohAudioSourceId | Any |
| callingIdPresentationWhenDiverted | [PresentationBit](#PresentationBit) |
| alertingName | str |
| asciiAlertingName | Any |
| presenceGroupName | str |
| shareLineAppearanceCssName | str |
| voiceMailProfileName | str |
| patternPrecedence | [PatternPrecedence](#PatternPrecedence) |
| releaseClause | [ReleaseCauseValue](#ReleaseCauseValue) |
| hrDuration | Any |
| hrInterval | Any |
| cfaCssPolicy | [CFACSSActivationPolicy](#CFACSSActivationPolicy) |
| defaultActivatedDeviceName | str |
| parkMonForwardNoRetrieveDn | str |
| parkMonForwardNoRetrieveIntDn | str |
| parkMonForwardNoRetrieveVmEnabled | bool |
| parkMonForwardNoRetrieveIntVmEnabled | bool |
| parkMonForwardNoRetrieveCssName | str |
| parkMonForwardNoRetrieveIntCssName | str |
| parkMonReversionTimer | Any |
| partyEntranceTone | [Status](#Status) |
| directoryURIs | Any |
| allowCtiControlFlag | bool |
| rejectAnonymousCall | bool |
| patternUrgency | bool |
| confidentialAccess | Any |
| externalCallControlProfile | str |
| enterpriseAltNum | Any |
| e164AltNum | Any |
| pstnFailover | str |
| callControlAgentProfile | str |
| useEnterpriseAltNum | bool |
| useE164AltNum | bool |
| active | bool |
| externalPresentationInfo | Any |

### UpdateLineGroup { #UpdateLineGroup }

Used by AXLClient.update_line_group().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| distributionAlgorithm | [DistributeAlgorithm](#DistributeAlgorithm) |
| rnaReversionTimeOut | Any |
| huntAlgorithmNoAnswer | [HuntAlgorithm](#HuntAlgorithm) |
| huntAlgorithmBusy | [HuntAlgorithm](#HuntAlgorithm) |
| huntAlgorithmNotAvailable | [HuntAlgorithm](#HuntAlgorithm) |
| removeMembers | Any |
| addMembers | Any |
| members | Any |
| newName | str |
| autoLogOffHunt | bool |

### UpdateLocalRouteGroup { #UpdateLocalRouteGroup }

Used by AXLClient.update_local_route_group().

| Field | Type |
|-------|------|
| localRouteGroup | Any |

### UpdateLocation { #UpdateLocation }

Used by AXLClient.update_location().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| relatedLocations | Any |
| withinAudioBandwidth | Any |
| withinVideoBandwidth | Any |
| withinImmersiveKbits | Any |
| betweenLocations | Any |

### UpdateMediaResourceGroup { #UpdateMediaResourceGroup }

Used by AXLClient.update_media_resource_group().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| multicast | bool |
| removeMembers | Any |
| addMembers | Any |
| members | Any |

### UpdateMediaResourceList { #UpdateMediaResourceList }

Used by AXLClient.update_media_resource_list().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| removeMembers | Any |
| addMembers | Any |
| members | Any |

### UpdateMeetMe { #UpdateMeetMe }

Used by AXLClient.update_meet_me().

| Field | Type |
|-------|------|
| uuid | str |
| pattern | str |
| routePartitionName | str |
| newPattern | str |
| description | str |
| newRoutePartitionName | str |
| minimumSecurityLevel | [DeviceSecurityMode](#DeviceSecurityMode) |

### UpdateMessageWaiting { #UpdateMessageWaiting }

Used by AXLClient.update_message_waiting().

| Field | Type |
|-------|------|
| uuid | str |
| pattern | str |
| routePartitionName | str |
| newPattern | str |
| newRoutePartitionName | str |
| description | str |
| messageWaitingIndicator | bool |
| callingSearchSpaceName | str |

### UpdateMlppDomain { #UpdateMlppDomain }

Used by AXLClient.update_mlpp_domain().

| Field | Type |
|-------|------|
| uuid | str |
| domainName | str |
| newDomainName | str |
| domainId | str |

### UpdateMobileVoiceAccess { #UpdateMobileVoiceAccess }

Used by AXLClient.update_mobile_voice_access().

| Field | Type |
|-------|------|
| uuid | str |
| pattern | str |
| newPattern | str |
| routePartitionName | str |
| removeLocales | Any |
| addLocales | Any |
| locales | Any |

### UpdateMobility { #UpdateMobility }

Used by AXLClient.update_mobility().

| Field | Type |
|-------|------|
| handoffNumber | str |
| DTMFNumber | str |
| newHandoffNumber | str |
| newHandoffPartitionName | str |
| newDTMFNumber | str |
| newDTMFPartitionName | str |

### UpdateMobilityProfile { #UpdateMobilityProfile }

Used by AXLClient.update_mobility_profile().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| mobileClientCallingOption | [DialViaOffice](#DialViaOffice) |
| dvofServiceAccessNumber | str |
| dirn | [Dirn](#Dirn) |
| dvorCallerId | str |

### UpdateMohAudioSource { #UpdateMohAudioSource }

Used by AXLClient.update_moh_audio_source().

| Field | Type |
|-------|------|
| uuid | str |
| sourceId | Any |
| newName | str |
| sourceFile | str |
| multicast | bool |
| mohFileStatus | Any |
| initialAnnouncement | str |
| periodicAnnouncement | str |
| periodicAnnouncementInterval | Any |
| localeAnnouncement | [UserLocale](#UserLocale) |
| initialAnnouncementPlayed | bool |
| isExternalSource | bool |

### UpdateMohServer { #UpdateMohServer }

Used by AXLClient.update_moh_server().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| devicePoolName | str |
| locationName | str |
| maxUnicastConnections | Any |
| maxMulticastConnections | Any |
| fixedAudioSourceDevice | str |
| runFlag | bool |
| useTrustedRelayPoint | [Status](#Status) |
| isMultiCastEnabled | bool |
| baseMulticastIpaddress | str |
| baseMulticastPort | Any |
| multicastIncrementOnIp | bool |
| audioSources | Any |

### UpdateMraServiceDomain { #UpdateMraServiceDomain }

Used by AXLClient.update_mra_service_domain().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| isDefault | bool |
| serviceDomains | str |

### UpdateMtp { #UpdateMtp }

Used by AXLClient.update_mtp().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| devicePoolName | str |
| trustedRelayPoint | bool |

### UpdateNetworkAccessProfile { #UpdateNetworkAccessProfile }

Used by AXLClient.update_network_access_profile().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| vpnRequired | [Status](#Status) |
| proxySettings | [HTTPProxy](#HTTPProxy) |
| proxyHostname | str |
| proxyPort | Any |
| proxyRequiresAuthentication | bool |
| provideSharedCredentials | bool |
| username | str |
| password | str |

### UpdatePageLayoutPreferences { #UpdatePageLayoutPreferences }

Used by AXLClient.update_page_layout_preferences().

| Field | Type |
|-------|------|
| pageName | str |
| pageSections | Any |

### UpdatePhone { #UpdatePhone }

Used by AXLClient.update_phone().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| callingSearchSpaceName | str |
| devicePoolName | str |
| commonDeviceConfigName | str |
| commonPhoneConfigName | str |
| networkLocation | [NetworkLocation](#NetworkLocation) |
| locationName | str |
| mediaResourceListName | str |
| networkHoldMohAudioSourceId | Any |
| userHoldMohAudioSourceId | Any |
| automatedAlternateRoutingCssName | str |
| aarNeighborhoodName | str |
| loadInformation | [LoadInformation](#LoadInformation) |
| vendorConfig | [VendorConfig](#VendorConfig) |
| versionStamp | str |
| traceFlag | bool |
| mlppDomainId | str |
| mlppIndicationStatus | [Status](#Status) |
| preemption | [Preemption](#Preemption) |
| useTrustedRelayPoint | [Status](#Status) |
| retryVideoCallAsAudio | bool |
| securityProfileName | str |
| sipProfileName | str |
| cgpnTransformationCssName | str |
| useDevicePoolCgpnTransformCss | bool |
| geoLocationName | str |
| geoLocationFilterName | str |
| sendGeoLocation | bool |
| removeLines | Any |
| addLines | Any |
| lines | Any |
| phoneTemplateName | str |
| speeddials | Any |
| busyLampFields | Any |
| primaryPhoneName | str |
| ringSettingIdleBlfAudibleAlert | [Status](#Status) |
| ringSettingBusyBlfAudibleAlert | [Status](#Status) |
| blfDirectedCallParks | Any |
| addOnModules | Any |
| userLocale | [UserLocale](#UserLocale) |
| networkLocale | [Country](#Country) |
| idleTimeout | Any |
| authenticationUrl | str |
| directoryUrl | str |
| idleUrl | str |
| informationUrl | str |
| messagesUrl | str |
| proxyServerUrl | str |
| servicesUrl | str |
| services | Any |
| softkeyTemplateName | str |
| defaultProfileName | str |
| enableExtensionMobility | bool |
| singleButtonBarge | [Barge](#Barge) |
| joinAcrossLines | [Status](#Status) |
| builtInBridgeStatus | [Status](#Status) |
| callInfoPrivacyStatus | [Status](#Status) |
| hlogStatus | [Status](#Status) |
| ownerUserName | str |
| ignorePresentationIndicators | bool |
| packetCaptureMode | [PacketCaptureMode](#PacketCaptureMode) |
| packetCaptureDuration | Any |
| subscribeCallingSearchSpaceName | str |
| rerouteCallingSearchSpaceName | str |
| allowCtiControlFlag | bool |
| presenceGroupName | str |
| unattendedPort | bool |
| requireDtmfReception | bool |
| rfc2833Disabled | bool |
| certificateOperation | [CertificateOperation](#CertificateOperation) |
| authenticationMode | [AuthenticationMode](#AuthenticationMode) |
| keySize | [KeySize](#KeySize) |
| keyOrder | [KeyOrder](#KeyOrder) |
| ecKeySize | [ECKeySize](#ECKeySize) |
| authenticationString | str |
| upgradeFinishTime | str |
| deviceMobilityMode | [Status](#Status) |
| remoteDevice | bool |
| dndOption | [DNDOption](#DNDOption) |
| dndRingSetting | [RingSetting](#RingSetting) |
| dndStatus | bool |
| isActive | bool |
| mobilityUserIdName | str |
| phoneSuite | [PhonePersonalization](#PhonePersonalization) |
| phoneServiceDisplay | [PhoneServiceDisplay](#PhoneServiceDisplay) |
| isProtected | bool |
| mtpRequired | bool |
| mtpPreferedCodec | [SIPCodec](#SIPCodec) |
| dialRulesName | str |
| sshUserId | str |
| sshPwd | str |
| digestUser | str |
| outboundCallRollover | [OutboundCallRollover](#OutboundCallRollover) |
| hotlineDevice | bool |
| secureInformationUrl | str |
| secureDirectoryUrl | str |
| secureMessageUrl | str |
| secureServicesUrl | str |
| secureAuthenticationUrl | str |
| secureIdleUrl | str |
| alwaysUsePrimeLine | [Status](#Status) |
| alwaysUsePrimeLineForVoiceMessage | [Status](#Status) |
| featureControlPolicy | str |
| deviceTrustMode | [DeviceTrustMode](#DeviceTrustMode) |
| earlyOfferSupportForVoiceCall | bool |
| requireThirdPartyRegistration | bool |
| blockIncomingCallsWhenRoaming | bool |
| homeNetworkId | str |
| AllowPresentationSharingUsingBfcp | bool |
| confidentialAccess | Any |
| requireOffPremiseLocation | bool |
| allowiXApplicableMedia | bool |
| cgpnIngressDN | str |
| useDevicePoolCgpnIngressDN | bool |
| msisdn | str |
| enableCallRoutingToRdWhenNoneIsActive | bool |
| wifiHotspotProfile | str |
| wirelessLanProfileGroup | str |
| elinGroup | str |
| enableActivationID | bool |
| mraServiceDomain | str |
| allowMraMode | bool |

### UpdatePhoneButtonTemplate { #UpdatePhoneButtonTemplate }

Used by AXLClient.update_phone_button_template().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| buttons | Any |

### UpdatePhoneNtp { #UpdatePhoneNtp }

Used by AXLClient.update_phone_ntp().

| Field | Type |
|-------|------|
| uuid | str |
| ipAddress | str |
| ipv6Address | str |
| newIpAddress | str |
| newIpv6Address | str |
| description | str |
| mode | [Zzntpmode](#Zzntpmode) |

### UpdatePhoneSecurityProfile { #UpdatePhoneSecurityProfile }

Used by AXLClient.update_phone_security_profile().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| deviceSecurityMode | [DeviceSecurityMode](#DeviceSecurityMode) |
| authenticationMode | [AuthenticationMode](#AuthenticationMode) |
| keySize | [KeySize](#KeySize) |
| keyOrder | [KeyOrder](#KeyOrder) |
| ecKeySize | [ECKeySize](#ECKeySize) |
| tftpEncryptedConfig | bool |
| EnableOAuthAuthentication | bool |
| nonceValidityTime | Any |
| transportType | [Transport](#Transport) |
| sipPhonePort | Any |
| enableDigestAuthentication | bool |
| excludeDigestCredentials | bool |

### UpdatePhysicalLocation { #UpdatePhysicalLocation }

Used by AXLClient.update_physical_location().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |

### UpdatePresenceGroup { #UpdatePresenceGroup }

Used by AXLClient.update_presence_group().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| presenceGroups | Any |

### UpdatePresenceRedundancyGroup { #UpdatePresenceRedundancyGroup }

Used by AXLClient.update_presence_redundancy_group().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| server1 | str |
| server2 | str |
| haEnabled | bool |

### UpdateProcessNode { #UpdateProcessNode }

Used by AXLClient.update_process_node().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| mac | Any |
| ipv6Name | str |
| lbmHubGroup | str |
| cupDomain | str |

### UpdateProcessNodeService { #UpdateProcessNodeService }

Used by AXLClient.update_process_node_service().

| Field | Type |
|-------|------|
| uuid | str |
| processNodeName | str |
| service | [Service](#Service) |
| traceLevel | Any |
| userCategories | Any |
| enable | bool |
| numFiles | Any |
| maxFileSize | Any |

### UpdateRecordingProfile { #UpdateRecordingProfile }

Used by AXLClient.update_recording_profile().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| recordingCssName | str |
| recorderDestination | str |

### UpdateRegion { #UpdateRegion }

Used by AXLClient.update_region().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| relatedRegions | Any |

### UpdateRegionMatrix { #UpdateRegionMatrix }

Used by AXLClient.update_region_matrix().

| Field | Type |
|-------|------|
| uuid | str |
| regionAName | str |
| regionBName | str |
| bandwidth | str |
| videoBandwidth | Any |
| codecPreference | str |

### UpdateRemoteCluster { #UpdateRemoteCluster }

Used by AXLClient.update_remote_cluster().

| Field | Type |
|-------|------|
| uuid | str |
| clusterId | str |
| emcc | [RemoteClusterMember](#RemoteClusterMember) |
| pstnAccess | [RemoteClusterMember](#RemoteClusterMember) |
| rsvpAgent | [RemoteClusterMember](#RemoteClusterMember) |
| tftp | [RemoteClusterMember](#RemoteClusterMember) |
| lbm | [RemoteClusterMember](#RemoteClusterMember) |
| uds | [RemoteClusterMember](#RemoteClusterMember) |

### UpdateRemoteDestination { #UpdateRemoteDestination }

Used by AXLClient.update_remote_destination().

| Field | Type |
|-------|------|
| uuid | str |
| destination | str |
| newName | str |
| newDestination | str |
| answerTooSoonTimer | Any |
| answerTooLateTimer | Any |
| delayBeforeRingingCell | Any |
| ownerUserId | str |
| enableUnifiedMobility | bool |
| remoteDestinationProfileName | str |
| enableExtendAndConnect | bool |
| ctiRemoteDeviceName | str |
| dualModeDeviceName | str |
| isMobilePhone | bool |
| enableMobileConnect | bool |
| lineAssociations | Any |
| timeZone | [TimeZone](#TimeZone) |
| todAccessName | str |
| mobileSmartClientName | str |
| mobilityProfileName | str |
| singleNumberReachVoicemail | [VMAvoidancePolicy](#VMAvoidancePolicy) |
| dialViaOfficeReverseVoicemail | [VMAvoidancePolicy](#VMAvoidancePolicy) |
| removeRingSchedule | Any |
| addRingSchedule | Any |
| ringSchedule | Any |
| accessListName | str |

### UpdateRemoteDestinationProfile { #UpdateRemoteDestinationProfile }

Used by AXLClient.update_remote_destination_profile().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| callingSearchSpaceName | str |
| devicePoolName | str |
| networkHoldMohAudioSourceId | Any |
| userHoldMohAudioSourceId | Any |
| lines | Any |
| callInfoPrivacyStatus | [Status](#Status) |
| userId | str |
| ignorePresentationIndicators | bool |
| rerouteCallingSearchSpaceName | str |
| cgpnTransformationCssName | str |
| automatedAlternateRoutingCssName | str |
| useDevicePoolCgpnTransformCss | bool |
| userLocale | [UserLocale](#UserLocale) |
| networkLocale | [Country](#Country) |
| primaryPhoneName | str |
| dndOption | [DNDOption](#DNDOption) |
| dndStatus | bool |
| mobileSmartClientProfileName | str |

### UpdateResourcePriorityNamespace { #UpdateResourcePriorityNamespace }

Used by AXLClient.update_resource_priority_namespace().

| Field | Type |
|-------|------|
| uuid | str |
| namespace | Any |
| newNamespace | Any |
| description | str |
| isDefault | bool |

### UpdateResourcePriorityNamespaceList { #UpdateResourcePriorityNamespaceList }

Used by AXLClient.update_resource_priority_namespace_list().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| removeMembers | Any |
| addMembers | Any |
| members | Any |

### UpdateRouteFilter { #UpdateRouteFilter }

Used by AXLClient.update_route_filter().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| dialPlanName | str |
| removeMembers | Any |
| addMembers | Any |
| members | Any |

### UpdateRouteGroup { #UpdateRouteGroup }

Used by AXLClient.update_route_group().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| distributionAlgorithm | [DistributeAlgorithm](#DistributeAlgorithm) |
| removeMembers | Any |
| addMembers | Any |
| members | Any |
| newName | str |

### UpdateRouteList { #UpdateRouteList }

Used by AXLClient.update_route_list().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| callManagerGroupName | str |
| routeListEnabled | bool |
| removeMembers | Any |
| addMembers | Any |
| members | Any |
| runOnEveryNode | bool |

### UpdateRoutePartition { #UpdateRoutePartition }

Used by AXLClient.update_route_partition().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| timeScheduleIdName | str |
| useOriginatingDeviceTimeZone | bool |
| timeZone | [TimeZone](#TimeZone) |

### UpdateRoutePartitionsForLearnedPatterns { #UpdateRoutePartitionsForLearnedPatterns }

Used by AXLClient.update_route_partitions_for_learned_patterns().

| Field | Type |
|-------|------|
| partitionForEnterpriseANo | str |
| partitionForE164ANo | str |
| partitionForEnterprisePatterns | str |
| partitionForE164Pattern | str |
| markLearnedEntAltNumbers | bool |
| markLearnedE164AltNumbers | bool |
| markFixedLengthEntPatterns | bool |
| markVariableLengthEntPatterns | bool |
| markFixedLengthE164Patterns | bool |
| markVariableLengthE164Patterns | bool |

### UpdateRoutePattern { #UpdateRoutePattern }

Used by AXLClient.update_route_pattern().

| Field | Type |
|-------|------|
| uuid | str |
| pattern | str |
| routePartitionName | str |
| dialPlanName | str |
| routeFilterName | str |
| newPattern | str |
| description | str |
| newRoutePartitionName | str |
| blockEnable | bool |
| calledPartyTransformationMask | str |
| callingPartyTransformationMask | str |
| useCallingPartyPhoneMask | [Status](#Status) |
| callingPartyPrefixDigits | str |
| newDialPlanName | str |
| digitDiscardInstructionName | str |
| networkLocation | [NetworkLocation](#NetworkLocation) |
| patternUrgency | bool |
| prefixDigitsOut | str |
| newRouteFilterName | str |
| callingLinePresentationBit | [PresentationBit](#PresentationBit) |
| callingNamePresentationBit | [PresentationBit](#PresentationBit) |
| connectedLinePresentationBit | [PresentationBit](#PresentationBit) |
| connectedNamePresentationBit | [PresentationBit](#PresentationBit) |
| supportOverlapSending | bool |
| patternPrecedence | [PatternPrecedence](#PatternPrecedence) |
| releaseClause | [ReleaseCauseValue](#ReleaseCauseValue) |
| allowDeviceOverride | bool |
| provideOutsideDialtone | bool |
| callingPartyNumberingPlan | [NumberingPlan](#NumberingPlan) |
| callingPartyNumberType | [PriOfNumber](#PriOfNumber) |
| calledPartyNumberingPlan | [NumberingPlan](#NumberingPlan) |
| calledPartyNumberType | [PriOfNumber](#PriOfNumber) |
| destination | Any |
| authorizationCodeRequired | bool |
| authorizationLevelRequired | Any |
| clientCodeRequired | bool |
| isdnNsfInfoElement | Any |
| resourcePriorityNamespaceName | str |
| routeClass | [PatternRouteClass](#PatternRouteClass) |
| enableDccEnforcement | bool |
| blockedCallPercentage | str |
| externalCallControl | str |
| isEmergencyServiceNumber | bool |

### UpdateSIPNormalizationScript { #UpdateSIPNormalizationScript }

Used by AXLClient.update_sipnormalization_script().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| content | str |
| scriptExecutionErrorRecoveryAction | [SIPScriptErrorHandling](#SIPScriptErrorHandling) |
| systemResourceErrorRecoveryAction | [SIPScriptErrorHandling](#SIPScriptErrorHandling) |
| maxMemoryThreshold | str |
| maxLuaInstructionsThreshold | str |

### UpdateSNMPCommunityString { #UpdateSNMPCommunityString }

Used by AXLClient.update_snmpcommunity_string().

| Field | Type |
|-------|------|
| communityName | str |
| newValues | [RSNMPCommunityString1](#RSNMPCommunityString1) |

### UpdateSNMPMIB2List { #UpdateSNMPMIB2List }

Used by AXLClient.update_snmpmib2_list().

| Field | Type |
|-------|------|
| sysLocation | str |
| sysContact | str |

### UpdateSNMPUser { #UpdateSNMPUser }

Used by AXLClient.update_snmpuser().

| Field | Type |
|-------|------|
| user | [RSNMPUser](#RSNMPUser) |

### UpdateSafCcdPurgeBlockLearnedRoutes { #UpdateSafCcdPurgeBlockLearnedRoutes }

Used by AXLClient.update_saf_ccd_purge_block_learned_routes().

| Field | Type |
|-------|------|
| uuid | str |
| learnedPattern | str |
| learnedPatternPrefix | str |
| callControlIdentity | str |
| ipAddress | str |
| newLearnedPattern | str |
| newLearnedPatternPrefix | str |
| newCallControlIdentity | str |
| newIpAddress | str |

### UpdateSafForwarder { #UpdateSafForwarder }

Used by AXLClient.update_saf_forwarder().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| clientLabel | str |
| safSecurityProfile | str |
| ipAddress | str |
| port | Any |
| enableTcpKeepAlive | bool |
| safReconnectInterval | Any |
| safNotificationsWindowSize | Any |
| removeAssociatedCucms | Any |
| addAssociatedCucms | Any |
| associatedCucms | Any |

### UpdateSafSecurityProfile { #UpdateSafSecurityProfile }

Used by AXLClient.update_saf_security_profile().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| userid | str |
| password | str |

### UpdateSdpTransparencyProfile { #UpdateSdpTransparencyProfile }

Used by AXLClient.update_sdp_transparency_profile().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |

### UpdateSecureConfig { #UpdateSecureConfig }

Used by AXLClient.update_secure_config().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| value | str |

### UpdateSelfProvisioning { #UpdateSelfProvisioning }

Used by AXLClient.update_self_provisioning().

| Field | Type |
|-------|------|
| requireAuthentication | str |
| allowAuthentication | str |
| authenticationCode | str |
| ctiRoutePoint | str |
| applicationUser | str |
| removeLanguages | Any |
| addLanguages | Any |
| languages | Any |

### UpdateServiceParameter { #UpdateServiceParameter }

Used by AXLClient.update_service_parameter().

| Field | Type |
|-------|------|
| uuid | str |
| processNodeName | str |
| name | str |
| service | [Service](#Service) |
| value | str |

### UpdateServiceProfile { #UpdateServiceProfile }

Used by AXLClient.update_service_profile().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| isDefault | bool |
| serviceProfileInfos | Any |

### UpdateSipDialRules { #UpdateSipDialRules }

Used by AXLClient.update_sip_dial_rules().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| removePatterns | Any |
| addPatterns | Any |
| patterns | Any |
| removePlars | Any |
| addPlars | Any |
| plars | Any |

### UpdateSipProfile { #UpdateSipProfile }

Used by AXLClient.update_sip_profile().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| defaultTelephonyEventPayloadType | Any |
| redirectByApplication | bool |
| ringing180 | bool |
| timerInvite | Any |
| timerRegisterDelta | Any |
| timerRegister | Any |
| timerT1 | Any |
| timerT2 | Any |
| retryInvite | Any |
| retryNotInvite | Any |
| startMediaPort | Any |
| stopMediaPort | Any |
| startVideoPort | Any |
| stopVideoPort | Any |
| dscpForAudioCalls | str |
| dscpForVideoCalls | str |
| dscpForAudioPortionOfVideoCalls | str |
| dscpForTelePresenceCalls | str |
| dscpForAudioPortionOfTelePresenceCalls | str |
| callpickupListUri | str |
| callpickupGroupUri | str |
| meetmeServiceUrl | str |
| userInfo | [ZzuserInfo](#ZzuserInfo) |
| dtmfDbLevel | [ZzdtmfDbLevel](#ZzdtmfDbLevel) |
| callHoldRingback | [Zzpreff](#Zzpreff) |
| anonymousCallBlock | [Zzpreff](#Zzpreff) |
| callerIdBlock | [Zzpreff](#Zzpreff) |
| dndControl | [Zzdndcontrol](#Zzdndcontrol) |
| telnetLevel | [TelnetLevel](#TelnetLevel) |
| timerKeepAlive | Any |
| timerSubscribe | Any |
| timerSubscribeDelta | Any |
| maxRedirects | Any |
| timerOffHookToFirstDigit | Any |
| callForwardUri | str |
| abbreviatedDialUri | str |
| confJointEnable | bool |
| rfc2543Hold | bool |
| semiAttendedTransfer | bool |
| enableVad | bool |
| stutterMsgWaiting | bool |
| callStats | bool |
| t38Invite | bool |
| faxInvite | bool |
| rerouteIncomingRequest | [SIPReroute](#SIPReroute) |
| resourcePriorityNamespaceListName | str |
| enableAnatForEarlyOfferCalls | bool |
| rsvpOverSip | [RSVPOverSIP](#RSVPOverSIP) |
| fallbackToLocalRsvp | bool |
| sipRe11XxEnabled | [SIPRel1XXOptions](#SIPRel1XXOptions) |
| gClear | [GClear](#GClear) |
| sendRecvSDPInMidCallInvite | bool |
| enableOutboundOptionsPing | bool |
| optionsPingIntervalWhenStatusOK | Any |
| optionsPingIntervalWhenStatusNotOK | Any |
| deliverConferenceBridgeIdentifier | bool |
| sipOptionsRetryCount | Any |
| sipOptionsRetryTimer | Any |
| sipBandwidthModifier | [SIPBandwidthModifier](#SIPBandwidthModifier) |
| enableUriOutdialSupport | str |
| userAgentServerHeaderInfo | [UserAgentServerHeaderInfo](#UserAgentServerHeaderInfo) |
| allowPresentationSharingUsingBfcp | bool |
| scriptParameters | str |
| isScriptTraceEnabled | bool |
| sipNormalizationScript | str |
| allowiXApplicationMedia | bool |
| dialStringInterpretation | [URIDisambiguationPolicy](#URIDisambiguationPolicy) |
| acceptAudioCodecPreferences | [Status](#Status) |
| mlppUserAuthorization | bool |
| isAssuredSipServiceEnabled | bool |
| enableExternalQoS | bool |
| resourcePriorityNamespace | str |
| useCallerIdCallerNameinUriOutgoingRequest | bool |
| externalPresentationInfo | Any |
| callingLineIdentification | [CallingLineIdentification](#CallingLineIdentification) |
| rejectAnonymousIncomingCall | bool |
| callpickupUri | str |
| rejectAnonymousOutgoingCall | bool |
| videoCallTrafficClass | [VideoCallTrafficClass](#VideoCallTrafficClass) |
| sdpTransparency | str |
| allowMultipleCodecs | bool |
| sipSessionRefreshMethod | [SipSessionRefreshMethod](#SipSessionRefreshMethod) |
| earlyOfferSuppVoiceCall | [EOSuppVoiceCall](#EOSuppVoiceCall) |
| cucmVersionInSipHeader | [CUCMVersionInSipHeader](#CUCMVersionInSipHeader) |
| confidentialAccessLevelHeaders | [CALHeaders](#CALHeaders) |
| destRouteString | bool |
| inactiveSDPRequired | bool |
| allowRRAndRSBandwidthModifier | bool |
| connectCallBeforePlayingAnnouncement | bool |

### UpdateSipRealm { #UpdateSipRealm }

Used by AXLClient.update_sip_realm().

| Field | Type |
|-------|------|
| uuid | str |
| realm | str |
| newRealm | str |
| userid | str |
| digestCredentials | str |

### UpdateSipRoutePattern { #UpdateSipRoutePattern }

Used by AXLClient.update_sip_route_pattern().

| Field | Type |
|-------|------|
| uuid | str |
| pattern | str |
| routePartitionName | str |
| newPattern | str |
| description | str |
| newRoutePartitionName | str |
| blockEnable | bool |
| callingPartyTransformationMask | str |
| useCallingPartyPhoneMask | [Status](#Status) |
| callingPartyPrefixDigits | str |
| callingLinePresentationBit | [PresentationBit](#PresentationBit) |
| callingNamePresentationBit | [PresentationBit](#PresentationBit) |
| connectedLinePresentationBit | [PresentationBit](#PresentationBit) |
| connectedNamePresentationBit | [PresentationBit](#PresentationBit) |
| sipTrunkName | str |
| dnOrPatternIpv6 | str |
| routeOnUserPart | bool |
| useCallerCss | bool |
| domainRoutingCssName | str |

### UpdateSipTrunk { #UpdateSipTrunk }

Used by AXLClient.update_sip_trunk().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| callingSearchSpaceName | str |
| devicePoolName | str |
| commonDeviceConfigName | str |
| networkLocation | [NetworkLocation](#NetworkLocation) |
| locationName | str |
| mediaResourceListName | str |
| networkHoldMohAudioSourceId | Any |
| userHoldMohAudioSourceId | Any |
| automatedAlternateRoutingCssName | str |
| aarNeighborhoodName | str |
| packetCaptureMode | [PacketCaptureMode](#PacketCaptureMode) |
| packetCaptureDuration | Any |
| mlppDomainId | str |
| mlppIndicationStatus | [Status](#Status) |
| preemption | [Preemption](#Preemption) |
| useTrustedRelayPoint | [Status](#Status) |
| retryVideoCallAsAudio | bool |
| securityProfileName | str |
| sipProfileName | str |
| cgpnTransformationCssName | str |
| useDevicePoolCgpnTransformCss | bool |
| geoLocationName | str |
| geoLocationFilterName | str |
| sendGeoLocation | bool |
| cdpnTransformationCssName | str |
| useDevicePoolCdpnTransformCss | bool |
| unattendedPort | bool |
| transmitUtf8 | bool |
| subscribeCallingSearchSpaceName | str |
| rerouteCallingSearchSpaceName | str |
| referCallingSearchSpaceName | str |
| mtpRequired | bool |
| presenceGroupName | str |
| unknownPrefix | str |
| destAddrIsSrv | bool |
| tkSipCodec | [SIPCodec](#SIPCodec) |
| sigDigits | Any |
| connectedNamePresentation | [PresentationBit](#PresentationBit) |
| connectedPartyIdPresentation | [PresentationBit](#PresentationBit) |
| callingPartySelection | [CallingPartySelection](#CallingPartySelection) |
| callingname | [PresentationBit](#PresentationBit) |
| callingLineIdPresentation | [PresentationBit](#PresentationBit) |
| prefixDn | str |
| externalPresentationInfo | Any |
| acceptInboundRdnis | bool |
| acceptOutboundRdnis | bool |
| srtpAllowed | bool |
| srtpFallbackAllowed | bool |
| isPaiEnabled | bool |
| sipPrivacy | [SipPrivacy](#SipPrivacy) |
| isRpidEnabled | bool |
| sipAssertedType | [SipAssertedType](#SipAssertedType) |
| trustReceivedIdentity | [TrustReceivedIdentity](#TrustReceivedIdentity) |
| dtmfSignalingMethod | [DTMFSignaling](#DTMFSignaling) |
| routeClassSignalling | [Status](#Status) |
| sipTrunkType | [TrunkService](#TrunkService) |
| pstnAccess | bool |
| imeE164TransformationName | str |
| useImePublicIpPort | bool |
| useDevicePoolCntdPnTransformationCss | bool |
| cntdPnTransformationCssName | str |
| useDevicePoolCgpnTransformCssUnkn | bool |
| rdnTransformationCssName | str |
| useDevicePoolRdnTransformCss | bool |
| useOrigCallingPartyPresOnDivert | bool |
| sipNormalizationScriptName | str |
| runOnEveryNode | bool |
| removeDestinations | Any |
| addDestinations | Any |
| destinations | Any |
| unknownStripDigits | Any |
| cgpnTransformationUnknownCssName | str |
| tunneledProtocol | [TunneledProtocol](#TunneledProtocol) |
| asn1RoseOidEncoding | [ASN1RoseOidEncoding](#ASN1RoseOidEncoding) |
| qsigVariant | [QSIGVariant](#QSIGVariant) |
| pathReplacementSupport | bool |
| enableQsigUtf8 | bool |
| scriptParameters | str |
| scriptTraceEnabled | bool |
| trunkTrafficSecure | [SIPTrunkCallLegSecurity](#SIPTrunkCallLegSecurity) |
| callingAndCalledPartyInfoFormat | [SIPIdentityBlend](#SIPIdentityBlend) |
| useCallerIdCallerNameinUriOutgoingRequest | bool |
| service | str |
| parameterLabel | str |
| originatingParameterValue | str |
| terminatingParameterValue | str |
| outboundUriRoutingInstructions | str |
| requestUriDomainName | str |
| enableCiscoRecordingQsigTunneling | bool |
| recordingInformation | str |
| calledPartyUnknownTransformationCssName | str |
| calledPartyUnknownPrefix | str |
| calledPartyUnknownStripDigits | Any |
| useDevicePoolCalledCssUnkn | bool |
| confidentialAccess | Any |

### UpdateSipTrunkSecurityProfile { #UpdateSipTrunkSecurityProfile }

Used by AXLClient.update_sip_trunk_security_profile().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | Any |
| description | str |
| securityMode | [DeviceSecurityMode](#DeviceSecurityMode) |
| incomingTransport | [Transport](#Transport) |
| outgoingTransport | [Transport](#Transport) |
| digestAuthentication | bool |
| noncePolicyTime | Any |
| x509SubjectName | str |
| incomingPort | Any |
| applLevelAuthentication | bool |
| acceptPresenceSubscription | bool |
| acceptOutOfDialogRefer | bool |
| acceptUnsolicitedNotification | bool |
| allowReplaceHeader | bool |
| transmitSecurityStatus | bool |
| sipV150OutboundSdpOfferFiltering | [V150SDPFilter](#V150SDPFilter) |
| allowChargingHeader | bool |

### UpdateSoftKeySet { #UpdateSoftKeySet }

Used by AXLClient.update_soft_key_set().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| removeCallStates | Any |
| addCallStates | Any |
| callStates | Any |

### UpdateSoftKeyTemplate { #UpdateSoftKeyTemplate }

Used by AXLClient.update_soft_key_template().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| isDefault | bool |

### UpdateSrst { #UpdateSrst }

Used by AXLClient.update_srst().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| port | Any |
| ipAddress | str |
| ipv6Address | str |
| SipNetwork | str |
| SipPort | Any |
| isSecure | bool |

### UpdateSyslogConfiguration { #UpdateSyslogConfiguration }

Used by AXLClient.update_syslog_configuration().

| Field | Type |
|-------|------|
| serverName | str |
| serviceGroup | [ServiceGrouping](#ServiceGrouping) |
| service | str |
| alarmConfigs | Any |
| EndPointAlarm | bool |

### UpdateTimePeriod { #UpdateTimePeriod }

Used by AXLClient.update_time_period().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| startTime | [TimeOfDay](#TimeOfDay) |
| endTime | [TimeOfDay](#TimeOfDay) |
| startDay | [DayOfWeek](#DayOfWeek) |
| endDay | [DayOfWeek](#DayOfWeek) |
| monthOfYear | [MonthOfYear](#MonthOfYear) |
| dayOfMonth | Any |
| description | str |
| dayOfMonthEnd | Any |
| monthOfYearEnd | [MonthOfYear](#MonthOfYear) |

### UpdateTimeSchedule { #UpdateTimeSchedule }

Used by AXLClient.update_time_schedule().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| removeMembers | Any |
| addMembers | Any |
| members | Any |
| description | str |
| timeScheduleCategory | [TimeScheduleCategory](#TimeScheduleCategory) |

### UpdateTodAccess { #UpdateTodAccess }

Used by AXLClient.update_tod_access().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| members | Any |

### UpdateTransPattern { #UpdateTransPattern }

Used by AXLClient.update_trans_pattern().

| Field | Type |
|-------|------|
| uuid | str |
| pattern | str |
| routePartitionName | str |
| dialPlanName | str |
| routeFilterName | str |
| newPattern | str |
| description | str |
| newRoutePartitionName | str |
| blockEnable | bool |
| calledPartyTransformationMask | str |
| callingPartyTransformationMask | str |
| useCallingPartyPhoneMask | [Status](#Status) |
| callingPartyPrefixDigits | str |
| newDialPlanName | str |
| digitDiscardInstructionName | str |
| patternUrgency | bool |
| prefixDigitsOut | str |
| newRouteFilterName | str |
| callingLinePresentationBit | [PresentationBit](#PresentationBit) |
| callingNamePresentationBit | [PresentationBit](#PresentationBit) |
| connectedLinePresentationBit | [PresentationBit](#PresentationBit) |
| connectedNamePresentationBit | [PresentationBit](#PresentationBit) |
| patternPrecedence | [PatternPrecedence](#PatternPrecedence) |
| provideOutsideDialtone | bool |
| callingPartyNumberingPlan | [NumberingPlan](#NumberingPlan) |
| callingPartyNumberType | [PriOfNumber](#PriOfNumber) |
| calledPartyNumberingPlan | [NumberingPlan](#NumberingPlan) |
| calledPartyNumberType | [PriOfNumber](#PriOfNumber) |
| callingSearchSpaceName | str |
| resourcePriorityNamespaceName | str |
| routeNextHopByCgpn | bool |
| routeClass | [PatternRouteClass](#PatternRouteClass) |
| callInterceptProfileName | str |
| releaseClause | [ReleaseCauseValue](#ReleaseCauseValue) |
| useOriginatorCss | bool |
| dontWaitForIDTOnSubsequentHops | bool |
| isEmergencyServiceNumber | bool |

### UpdateTranscoder { #UpdateTranscoder }

Used by AXLClient.update_transcoder().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| devicePoolName | str |
| commonDeviceConfigName | str |
| loadInformation | [LoadInformation](#LoadInformation) |
| vendorConfig | [VendorConfig](#VendorConfig) |
| isTrustedRelayPoint | bool |
| maximumCapacity | Any |

### UpdateTransformationProfile { #UpdateTransformationProfile }

Used by AXLClient.update_transformation_profile().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| nationalStripDigits | Any |
| internationalStripDigits | Any |
| unknownStripDigits | Any |
| subscriberStripDigits | Any |
| nationalPrefix | str |
| internationalPrefix | str |
| unknownPrefix | str |
| subscriberPrefix | str |
| nationalCssName | str |
| internationalCssName | str |
| unknownCssName | str |
| subscriberCssName | str |

### UpdateTvsCertificate { #UpdateTvsCertificate }

Used by AXLClient.update_tvs_certificate().

| Field | Type |
|-------|------|
| uuid | str |
| issuerName | str |
| serialNumber | str |
| timeToLive | int |

### UpdateUcService { #UpdateUcService }

Used by AXLClient.update_uc_service().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| hostnameorip | str |
| port | Any |
| protocol | [ConnectProtocol](#ConnectProtocol) |
| ucServiceXml | [VendorConfig](#VendorConfig) |

### UpdateUniversalDeviceTemplate { #UpdateUniversalDeviceTemplate }

Used by AXLClient.update_universal_device_template().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| deviceDescription | str |
| devicePool | str |
| deviceSecurityProfile | str |
| sipProfile | str |
| phoneButtonTemplate | str |
| sipDialRules | str |
| callingSearchSpace | str |
| callingPartyTransformationCSSForInboundCalls | str |
| callingPartyTransformationCSSForOutboundCalls | str |
| reroutingCallingSearchSpace | str |
| subscribeCallingSearchSpaceName | str |
| useDevicePoolCallingPartyTransformationCSSforInboundCalls | bool |
| useDevicePoolCallingPartyTransformationCSSforOutboundCalls | bool |
| commonPhoneProfile | str |
| commonDeviceConfiguration | str |
| softkeyTemplate | str |
| featureControlPolicy | str |
| phonePersonalization | [PhonePersonalization](#PhonePersonalization) |
| mtpPreferredOriginatingCodec | [SIPCodec](#SIPCodec) |
| outboundCallRollover | [OutboundCallRollover](#OutboundCallRollover) |
| mediaTerminationPointRequired | bool |
| unattendedPort | bool |
| requiredDtmfReception | bool |
| rfc2833Disabled | bool |
| speeddials | Any |
| lines | Any |
| blfDirectedCallParks | Any |
| busyLampFields | Any |
| useTrustedRelayPoint | [Status](#Status) |
| protectedDevice | bool |
| certificateOperation | [CertificateOperation](#CertificateOperation) |
| authenticationMode | [AuthenticationMode](#AuthenticationMode) |
| authenticationString | str |
| keySize | [KeySize](#KeySize) |
| keyOrder | [KeyOrder](#KeyOrder) |
| ecKeySize | [ECKeySize](#ECKeySize) |
| servicesProvisioning | [PhoneServiceDisplay](#PhoneServiceDisplay) |
| packetCaptureMode | [PacketCaptureMode](#PacketCaptureMode) |
| packetCaptureDuration | Any |
| secureShellUser | str |
| secureShellPassword | str |
| userLocale | [UserLocale](#UserLocale) |
| networkLocale | [Country](#Country) |
| mlppDomain | str |
| mlppIndication | [Status](#Status) |
| mlppPreemption | [Preemption](#Preemption) |
| doNotDisturb | bool |
| dndOption | [DNDOption](#DNDOption) |
| dndIncomingCallAlert | [RingSetting](#RingSetting) |
| aarGroup | str |
| aarCallingSearchSpace | str |
| blfPresenceGroup | str |
| blfAudibleAlertSettingPhoneBusy | [Status](#Status) |
| blfAudibleAlertSettingPhoneIdle | [Status](#Status) |
| userHoldMohAudioSource | Any |
| networkHoldMohAudioSource | Any |
| location | str |
| geoLocation | str |
| deviceMobilityMode | [Status](#Status) |
| mediaResourceGroupList | str |
| remoteDevice | bool |
| hotlineDevice | bool |
| retryVideoCallAsAudio | bool |
| requireOffPremiseLocation | bool |
| ownerUserId | str |
| mobilityUserId | str |
| joinAcrossLines | [Status](#Status) |
| alwaysUsePrimeLine | [Status](#Status) |
| alwaysUsePrimeLineForVoiceMessage | [Status](#Status) |
| singleButtonBarge | [Barge](#Barge) |
| builtInBridge | [Status](#Status) |
| allowControlOfDeviceFromCti | bool |
| ignorePresentationIndicators | bool |
| enableExtensionMobility | bool |
| privacy | [Status](#Status) |
| loggedIntoHuntGroup | bool |
| proxyServer | str |
| servicesUrl | str |
| idle | str |
| idleTimer | Any |
| secureDirUrl | str |
| messages | str |
| secureIdleUrl | str |
| authenticationServer | str |
| directory | str |
| secureServicesUrl | str |
| information | str |
| secureMessagesUrl | str |
| secureInformationUrl | str |
| secureAuthenticationUrl | str |
| confidentialAccess | Any |
| services | Any |

### UpdateUniversalLineTemplate { #UpdateUniversalLineTemplate }

Used by AXLClient.update_universal_line_template().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| urgentPriority | bool |
| lineDescription | str |
| routePartition | str |
| voiceMailProfile | str |
| callingSearchSpace | str |
| alertingName | str |
| extCallControlProfile | str |
| blfPresenceGroup | str |
| callPickupGroup | str |
| partyEntranceTone | [Status](#Status) |
| autoAnswer | [AutoAnswer](#AutoAnswer) |
| rejectAnonymousCall | bool |
| userHoldMohAudioSource | Any |
| networkHoldMohAudioSource | Any |
| aarDestinationMask | str |
| aarGroup | str |
| retainDestInCallFwdHistory | bool |
| forwardDestAllCalls | str |
| primaryCssForwardingAllCalls | str |
| secondaryCssForwardingAllCalls | str |
| CssActivationPolicy | [CFACSSActivationPolicy](#CFACSSActivationPolicy) |
| fwdDestExtCallsWhenNotRetrieved | str |
| cssFwdExtCallsWhenNotRetrieved | str |
| fwdDestInternalCallsWhenNotRetrieved | str |
| cssFwdInternalCallsWhenNotRetrieved | str |
| parkMonitorReversionTime | Any |
| target | str |
| mlppCss | str |
| mlppNoAnsRingDuration | Any |
| confidentialAccess | Any |
| holdReversionRingDuration | Any |
| holdReversionNotificationInterval | Any |
| busyIntCallsDestination | str |
| busyIntCallsCss | str |
| busyExtCallsDestination | str |
| busyExtCallsCss | str |
| noAnsIntCallsDestination | str |
| noAnsIntCallsCss | str |
| noAnsExtCallsDestination | str |
| noAnsExtCallsCss | str |
| noCoverageIntCallsDestination | str |
| noCoverageIntCallsCss | str |
| noCoverageExtCallsDestination | str |
| noCoverageExtCallsCss | str |
| unregisteredIntCallsDestination | str |
| unregisteredIntCallsCss | str |
| unregisteredExtCallsDestination | str |
| unregisteredExtCallsCss | str |
| ctiFailureDestination | str |
| ctiFailureCss | str |
| callControlAgentProfile | str |
| noAnswerRingDuration | Any |
| enterpriseAltNum | Any |
| e164AltNum | Any |
| advertisedFailoverNumber | str |

### UpdateUser { #UpdateUser }

Used by AXLClient.update_user().

| Field | Type |
|-------|------|
| uuid | str |
| userid | str |
| firstName | str |
| displayName | str |
| middleName | str |
| lastName | str |
| emMaxLoginTime | Any |
| newUserid | str |
| password | str |
| pin | str |
| mailid | str |
| department | str |
| manager | str |
| userLocale | [UserLocale](#UserLocale) |
| associatedDevices | Any |
| primaryExtension | Any |
| associatedPc | str |
| associatedGroups | Any |
| enableCti | bool |
| digestCredentials | str |
| phoneProfiles | Any |
| defaultProfile | str |
| presenceGroupName | str |
| subscribeCallingSearchSpaceName | str |
| enableMobility | bool |
| enableMobileVoiceAccess | bool |
| maxDeskPickupWaitTime | Any |
| remoteDestinationLimit | Any |
| passwordCredentials | Any |
| pinCredentials | Any |
| enableEmcc | bool |
| ctiControlledDeviceProfiles | Any |
| patternPrecedence | [PatternPrecedence](#PatternPrecedence) |
| numericUserId | str |
| mlppPassword | str |
| customUserFields | Any |
| homeCluster | bool |
| imAndPresenceEnable | bool |
| serviceProfile | str |
| lineAppearanceAssociationForPresences | Any |
| directoryUri | str |
| telephoneNumber | str |
| title | str |
| mobileNumber | str |
| homeNumber | str |
| pagerNumber | str |
| removeExtensionsInfo | Any |
| addExtensionsInfo | Any |
| extensionsInfo | Any |
| selfService | str |
| userProfile | str |
| calendarPresence | bool |
| ldapDirectoryName | str |
| userIdentity | str |
| nameDialing | str |
| ipccExtension | str |
| ipccRoutePartition | str |
| convertUserAccount | str |
| enableUserToHostConferenceNow | bool |
| attendeesAccessCode | str |
| zeroHop | bool |
| customerName | str |
| removeAssociatedHeadsets | Any |
| addAssociatedHeadsets | Any |
| associatedHeadsets | Any |

### UpdateUserGroup { #UpdateUserGroup }

Used by AXLClient.update_user_group().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| removeMembers | Any |
| addMembers | Any |
| members | Any |
| removeUserRoles | Any |
| addUserRoles | Any |
| userRoles | Any |
| newName | str |

### UpdateUserProfileProvision { #UpdateUserProfileProvision }

Used by AXLClient.update_user_profile_provision().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| deskPhones | str |
| mobileDevices | str |
| profile | str |
| universalLineTemplate | str |
| allowProvision | bool |
| limitProvision | Any |
| allowPhoneReassign | bool |
| defaultUserProfile | str |
| enableMra | bool |
| mraPolicy_Desktop | [MRAPolicy](#MRAPolicy) |
| mraPolicy_Mobile | [MRAPolicy](#MRAPolicy) |
| allowProvisionEMMaxLoginTime | bool |

### UpdateVg224 { #UpdateVg224 }

Used by AXLClient.update_vg224().

| Field | Type |
|-------|------|
| uuid | str |
| domainName | str |
| newDomainName | str |
| description | str |
| callManagerGroupName | str |
| vendorConfig | [VendorConfig](#VendorConfig) |

### UpdateVohServer { #UpdateVohServer }

Used by AXLClient.update_voh_server().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| sipTrunkName | str |
| defaultVideoStreamId | str |

### UpdateVoiceMailPilot { #UpdateVoiceMailPilot }

Used by AXLClient.update_voice_mail_pilot().

| Field | Type |
|-------|------|
| uuid | str |
| dirn | str |
| cssName | str |
| newDirn | str |
| description | str |
| newCssName | str |
| isDefault | bool |

### UpdateVoiceMailPort { #UpdateVoiceMailPort }

Used by AXLClient.update_voice_mail_port().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| callingSearchSpaceName | str |
| devicePoolName | str |
| commonDeviceConfigName | str |
| locationName | str |
| useTrustedRelayPoint | [Status](#Status) |
| securityProfileName | str |
| geoLocationName | str |
| automatedAlternateRoutingCssName | str |
| dnPattern | str |
| routePartition | str |
| dnCallingSearchSpace | str |
| aarNeighborhoodName | str |
| callerIdDisplay | str |
| callerIdDisplayAscii | str |
| externalMask | str |

### UpdateVoiceMailProfile { #UpdateVoiceMailProfile }

Used by AXLClient.update_voice_mail_profile().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| isDefault | bool |
| voiceMailboxMask | str |
| voiceMailPilot | [VmPilot](#VmPilot) |

### UpdateVpnGateway { #UpdateVpnGateway }

Used by AXLClient.update_vpn_gateway().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| url | str |
| certificates | Any |

### UpdateVpnGroup { #UpdateVpnGroup }

Used by AXLClient.update_vpn_group().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| vpnGateways | Any |

### UpdateVpnProfile { #UpdateVpnProfile }

Used by AXLClient.update_vpn_profile().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| autoNetworkDetection | bool |
| mtu | Any |
| failToConnect | Any |
| clientAuthentication | [VPNClientAuthentication](#VPNClientAuthentication) |
| pwdPersistant | bool |
| enableHostIdCheck | bool |

### UpdateWLANProfile { #UpdateWLANProfile }

Used by AXLClient.update_wlanprofile().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| ssid | str |
| frequencyBand | [WiFiFrequency](#WiFiFrequency) |
| userModifiable | [WLANProfileChanges](#WLANProfileChanges) |
| authMethod | [WiFiAuthenticationMethod](#WiFiAuthenticationMethod) |
| userName | str |
| password | str |
| pskPassphrase | str |
| wepKey | str |
| passwordDescription | str |
| networkAccessProfile | str |

### UpdateWifiHotspot { #UpdateWifiHotspot }

Used by AXLClient.update_wifi_hotspot().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| ssidPrefix | str |
| userModifiable | [WLANProfileChanges](#WLANProfileChanges) |
| frequencyBand | [WiFiFrequency](#WiFiFrequency) |
| authenticationMethod | [HotspotAuthenticationMethod](#HotspotAuthenticationMethod) |
| hostName | Any |
| port | Any |
| sharedSecret | str |
| pskPassPhrase | str |
| wepKey | str |
| passwordDescription | str |

### UpdateWirelessAccessPointControllers { #UpdateWirelessAccessPointControllers }

Used by AXLClient.update_wireless_access_point_controllers().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| snmpVersion | [SNMPVersion](#SNMPVersion) |
| snmpUserIdOrCommunityString | str |
| snmpAuthenticationProtocol | [SNMPAuthenticationProtocol](#SNMPAuthenticationProtocol) |
| snmpAuthenticationPassword | str |
| snmpPrivacyProtocol | [SNMPPrivacyProtocol](#SNMPPrivacyProtocol) |
| snmpPrivacyPassword | str |
| syncNow | bool |
| resyncInterval | Any |
| nextSyncTime | Any |
| scheduleUnit | [ScheduleUnit](#ScheduleUnit) |

### UpdateWlanProfileGroup { #UpdateWlanProfileGroup }

Used by AXLClient.update_wlan_profile_group().

| Field | Type |
|-------|------|
| name | str |
| uuid | str |
| newName | str |
| description | str |
| removeMembers | Any |
| addMembers | Any |
| members | Any |

## Enums

Enum types referenced by the models above.  Values are valid
string literals accepted by the AXL API.

### ASN1RoseOidEncoding { #ASN1RoseOidEncoding }

4 valid values.

??? note "Show values"

    | Value |
    |-------|
    | No Changes |
    | Use Local Value |
    | Use Global Value ISO |
    | Use Global Value ECMA |

### AnnouncementFile { #AnnouncementFile }

109 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Busy Tone |
    | AlertingTone |
    | ReorderTone |
    | RecordingWarning |
    | Tone-on-Hold |
    | MonitoringWarning |
    | Barge-In |
    | WrongPin |
    | UnauthorizedCaller |
    | WrongTargetDN |
    | MobileConnectOn |
    | MobileConnectOff |
    | UnknownCaller |
    | MLPP-PALA |
    | MLPP-ICA |
    | VCA |
    | MLPP-BPA |
    | MLPP-BNEA |
    | MLPP-UPA |
    | CallDisallowed |
    | 900CallsBlocked |
    | IntlCallsBlocked |
    | TollCallsBlocked |
    | DirAsstBlocked |
    | Silence-5sec |
    | OneMoment |
    | ShortTone |
    | Welcome Greeting Sample |
    | Wait In Queue Sample |
    | Mobility_VMA |
    | MLPP-Precedence_RingBack |
    | MLPP-Preemption_tone |
    | Non-secure_Warning |
    | Secure_Warning |
    | Enter_CMC |
    | Enter_FAC |
    | ZipTone |
    | EnterCfbTone |
    | ExitCfbTone |
    | ConferenceNowGreeting |
    | ConferenceNowNumberInvalid |
    | ConferenceNowNumberFailure |
    | ConferenceNowEnterPin |
    | ConferenceNowInvalidPin |
    | ConferenceNowFailedPin |
    | ConferenceNowCFBFailed |
    | ConferenceNowEnterAccessCode |
    | ConferenceNowAccessCodeInvalid |
    | ConferenceNowAccessCodeFailed |
    | Welcome |
    | Press1 |
    | Press2 |
    | Press3 |
    | Press4 |
    | Press5 |
    | Press6 |
    | Press7 |
    | Press8 |
    | Press9 |
    | Language |
    | EnterRemote |
    | ReenterRemoteUnknown |
    | EnterPin |
    | ReenterPinUnrecognized |
    | LoggedOut |
    | PinExpired |
    | AttemptsExceeded |
    | CallPrompt |
    | InvalidKey |
    | Goodbye |
    | EnterNumber |
    | SelectExtension |
    | TurnOnMobility |
    | EnterRemoteOn |
    | OtherRemote |
    | MobilityOnAll |
    | MobilityFailedAll |
    | MobilityOn |
    | MobilityFailed |
    | TurnOffMobility |
    | EnterRemoteOff |
    | OtherRemoteOff |
    | MobilityOffAll |
    | MobilityOffAllFailed |
    | MobilityOff |
    | MobilityOffFailed |
    | One |
    | Two |
    | Three |
    | Four |
    | Five |
    | Six |
    | Seven |
    | Eight |
    | Nine |
    | Zero |
    | ReturnPrevious |
    | ConfigError |
    | NoExtensions |
    | NoDestinations |
    | InternalError |
    | Unavailable |
    | ContactAdmin |
    | ThankYou |
    | Goodbye2 |
    | ResourcesUnavailable |
    | ExtensionInUse |
    | ToggleOn |
    | NotAuthorized |

### AppServer { #AppServer }

8 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Cisco Unity Voice Mail 4.x or later |
    | Cisco Unity Connection |
    | Cisco Unified CM IM and Presence (Obsolete) |
    | CUMA Provisioning Server |
    | CER Location Management |
    | Cisco Web Dialer |
    | Remote Syslog Server |
    | Cisco Webex Hybrid Call Service |

### AppServerContent { #AppServerContent }

3 valid values.

??? note "Show values"

    | Value |
    |-------|
    | UNITY KUBRIK |
    | UNITY PRE KUBRIK |
    | UNITY_CONNECTION |

### AuthenticationMode { #AuthenticationMode }

4 valid values.

??? note "Show values"

    | Value |
    |-------|
    | By Authentication String |
    | By Null String |
    | By Existing Certificate (precedence to LSC) |
    | By Existing Certificate (precedence to MIC) |

### AutoAnswer { #AutoAnswer }

3 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Auto Answer Off |
    | Auto Answer with Headset |
    | Auto Answer with Speakerphone |

### Barge { #Barge }

4 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Off |
    | Barge |
    | CBarge |
    | Default |

### Billingserverprotocol { #Billingserverprotocol }

2 valid values.

??? note "Show values"

    | Value |
    |-------|
    | SFTP |
    | FTP |

### BriProtocol { #BriProtocol }

3 valid values.

??? note "Show values"

    | Value |
    |-------|
    | BRI NET3 |
    | NI |
    | QSIG |

### CALHeaders { #CALHeaders }

3 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Disabled |
    | Preferred |
    | Required |

### CFACSSActivationPolicy { #CFACSSActivationPolicy }

3 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Use System Default |
    | With Configured CSS |
    | With Activating Device/Line CSS |

### CSUParam { #CSUParam }

4 valid values.

??? note "Show values"

    | Value |
    |-------|
    | 0dB |
    | -7.5dB |
    | -15dB |
    | -22.5dB |

### CUCMVersionInSipHeader { #CUCMVersionInSipHeader }

5 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Major And Minor |
    | Major |
    | Major, Minor And Revision |
    | Full Build |
    | None |

### CallTreatmentOnFailure { #CallTreatmentOnFailure }

2 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Allow Calls |
    | Block Calls |

### CallingLineIdentification { #CallingLineIdentification }

3 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Default |
    | Strict From URI presentation Only |
    | Strict Identity Headers presentation Only |

### CallingPartySelection { #CallingPartySelection }

5 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Originator |
    | First Redirect Number |
    | Last Redirect Number |
    | First Redirect Number (External) |
    | Last Redirect Number (External) |

### CertificateOperation { #CertificateOperation }

4 valid values.

??? note "Show values"

    | Value |
    |-------|
    | No Pending Operation |
    | Install/Upgrade |
    | Delete |
    | Troubleshoot |

### Class { #Class }

25 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Phone |
    | Gateway |
    | Conference Bridge |
    | Media Termination Point |
    | Route List |
    | Voice Mail |
    | CTI Route Point |
    | Music On Hold |
    | Simulation |
    | Pilot |
    | GateKeeper |
    | Add-on modules |
    | Hidden Phone |
    | Trunk |
    | Tone Announcement Player |
    | Remote Destination Profile |
    | EMCC Base Phone Template |
    | EMCC Base Phone |
    | Remote Destination Profile Template |
    | Gateway Template |
    | UDP Template |
    | Phone Template |
    | Device Profile |
    | Invalid |
    | Interactive Voice Response |

### ClockReference { #ClockReference }

10 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Network |
    | Internal |
    | Span 1 |
    | Span 2 |
    | Span 3 |
    | Span 4 |
    | Span 5 |
    | Span 6 |
    | Span 7 |
    | Span 8 |

### ConnectProtocol { #ConnectProtocol }

12 valid values.

??? note "Show values"

    | Value |
    |-------|
    | HTTP |
    | HTTPS |
    | TCP |
    | TCP + UDP |
    | UDP |
    | SSL |
    | TLS |
    | SIP |
    | OWA |
    | SOAP |
    | EWS |
    | XMPP |

### Country { #Country }

85 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Argentina |
    | Australia |
    | Austria |
    | Belgium |
    | Brazil |
    | Canada |
    | China |
    | Colombia |
    | Cyprus |
    | Czech Republic |
    | Denmark |
    | Egypt |
    | Finland |
    | France |
    | Germany |
    | Ghana |
    | Greece |
    | Hong Kong |
    | Hungary |
    | Iceland |
    | India |
    | Indonesia |
    | Ireland |
    | Israel |
    | Italy |
    | Japan |
    | Jordan |
    | Kenya |
    | Korea Republic |
    | Lebanon |
    | Luxembourg |
    | Malaysia |
    | Mexico |
    | Nepal |
    | Netherlands |
    | New Zealand |
    | Nigeria |
    | Norway |
    | Pakistan |
    | Panama |
    | Peru |
    | Philippines |
    | Poland |
    | Portugal |
    | Russian Federation |
    | Saudi Arabia |
    | Singapore |
    | Slovakia |
    | Slovenia |
    | South Africa |
    | Spain |
    | Sweden |
    | Switzerland |
    | Taiwan |
    | Thailand |
    | TÃ¼rkiye |
    | United Kingdom |
    | United States |
    | Venezuela |
    | Zimbabwe |
    | Itu |
    | Chile |
    | Bulgaria |
    | Croatia |
    | Romania |
    | Serbia and Montenegro |
    | United Arab Emirates |
    | Oman |
    | Kuwait |
    | Algeria |
    | Bahrain |
    | Iraq |
    | Mauritania |
    | Republic of Montenegro |
    | Morocco |
    | Qatar |
    | Republic of Serbia |
    | Sudan |
    | Tunisia |
    | Vietnam |
    | Yemen |
    | Lithuania |
    | Latvia |
    | Estonia |
    | Ukraine |

### Credential { #Credential }

2 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Password |
    | PIN |

### CredentialUser { #CredentialUser }

2 valid values.

??? note "Show values"

    | Value |
    |-------|
    | End User |
    | Application User |

### DNDOption { #DNDOption }

3 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Ringer Off |
    | Call Reject |
    | Use Common Phone Profile Setting |

### DTMFSignaling { #DTMFSignaling }

4 valid values.

??? note "Show values"

    | Value |
    |-------|
    | No Preference |
    | Out of Band |
    | RFC 2833 |
    | OOB and RFC 2833 |

### DayOfWeek { #DayOfWeek }

8 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Sun |
    | Mon |
    | Tue |
    | Wed |
    | Thu |
    | Fri |
    | Sat |
    | None |

### DeviceProtocol { #DeviceProtocol }

20 valid values.

??? note "Show values"

    | Value |
    |-------|
    | SCCP |
    | Digital Access PRI |
    | H.225 |
    | Analog Access |
    | Digital Access T1 |
    | Route Point |
    | Unicast Bridge |
    | Multicast Point |
    | Inter-Cluster Trunk |
    | RAS |
    | Digital Access BRI |
    | SIP |
    | MGCP |
    | Static SIP Mobile Subscriber |
    | SIP Connector |
    | Remote Destination |
    | Mobile Smart Client |
    | Digital Access E1 R2 |
    | CTI Remote Device |
    | Protocol Not Specified |

### DeviceSecurityMode { #DeviceSecurityMode }

3 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Non Secure |
    | Authenticated |
    | Encrypted |

### DeviceTrustMode { #DeviceTrustMode }

2 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Not Trusted |
    | Trusted |

### DialPattern { #DialPattern }

2 valid values.

??? note "Show values"

    | Value |
    |-------|
    | 7905_7912 |
    | 7940_7960_OTHER |

### DialViaOffice { #DialViaOffice }

2 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Dial via Office Reverse |
    | Dial via Office Forward |

### DigitSending { #DigitSending }

3 valid values.

??? note "Show values"

    | Value |
    |-------|
    | DTMF |
    | MF |
    | PULSE |

### DistributeAlgorithm { #DistributeAlgorithm }

4 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Top Down |
    | Circular |
    | Longest Idle Time |
    | Broadcast |

### ECKeySize { #ECKeySize }

3 valid values.

??? note "Show values"

    | Value |
    |-------|
    | 256 |
    | 384 |
    | 521 |

### EOSuppVoiceCall { #EOSuppVoiceCall }

3 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Disabled (Default value) |
    | Best Effort (no MTP inserted) |
    | Mandatory (insert MTP if needed) |

### Encode { #Encode }

2 valid values.

??? note "Show values"

    | Value |
    |-------|
    | A-law |
    | u-law |

### FDLChannel { #FDLChannel }

4 valid values.

??? note "Show values"

    | Value |
    |-------|
    | AT&T 54016 |
    | ANSI T1.403 NI |
    | ANSI T1.403.CI |
    | None |

### FallBackCSSSelection { #FallBackCSSSelection }

2 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Calling device AAR Calling Search Space |
    | Trunk ReRoute Calling Search Space |

### GClear { #GClear }

5 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Disabled |
    | CLEARMODE |
    | CCD |
    | G.nX64 |
    | X-CCD |

### GlobalNumber { #GlobalNumber }

2 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Enterprise Number |
    | +E.164 Number |

### HTTPProxy { #HTTPProxy }

3 valid values.

??? note "Show values"

    | Value |
    |-------|
    | None |
    | Manual |
    | Auto |

### HostedRoutePatternPSTNRule { #HostedRoutePatternPSTNRule }

3 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Use pattern |
    | Specify |
    | No PSTN |

### HotspotAuthenticationMethod { #HotspotAuthenticationMethod }

7 valid values.

??? note "Show values"

    | Value |
    |-------|
    | None |
    | WEP |
    | WPA-PSK |
    | WPA2-PSK |
    | EAP-FAST |
    | PEAP-MSCHAPv2 |
    | PEAP-GTC |

### HuntAlgorithm { #HuntAlgorithm }

4 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Try next member; then, try next group in Hunt List |
    | Try next member, but do not go to next group |
    | Skip remaining members, and go directly to next group |
    | Stop hunting |

### IPAddressingMode { #IPAddressingMode }

3 valid values.

??? note "Show values"

    | Value |
    |-------|
    | IPv4 Only |
    | IPv6 Only |
    | IPv4 and IPv6 |

### IPAddressingModePrefControl { #IPAddressingModePrefControl }

3 valid values.

??? note "Show values"

    | Value |
    |-------|
    | IPv4 |
    | IPv6 |
    | Use System Default |

### InterClusterService { #InterClusterService }

6 valid values.

??? note "Show values"

    | Value |
    |-------|
    | EMCC |
    | PSTN Access |
    | RSVP Agent |
    | TFTP |
    | LBM |
    | UDS |

### KeepAliveTimeInterval { #KeepAliveTimeInterval }

7 valid values.

??? note "Show values"

    | Value |
    |-------|
    | 0 |
    | 5 |
    | 10 |
    | 15 |
    | 20 |
    | 25 |
    | 30 |

### KeyOrder { #KeyOrder }

3 valid values.

??? note "Show values"

    | Value |
    |-------|
    | RSA Only |
    | EC Only |
    | EC Preferred, RSA Backup |

### KeySize { #KeySize }

5 valid values.

??? note "Show values"

    | Value |
    |-------|
    | 512 |
    | 1024 |
    | 2048 |
    | 3072 |
    | 4096 |

### LDAPDirectoryFunction { #LDAPDirectoryFunction }

4 valid values.

??? note "Show values"

    | Value |
    |-------|
    | DirSync |
    | DN Alias Sync and Lookup |
    | Alias Sync only |
    | Lookup only |

### LdapServer { #LdapServer }

5 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Microsoft Active Directory |
    | Sun or Oracle Directory Server |
    | OpenLDAP |
    | Microsoft ADAM or Lightweight Directory Services |
    | Other LDAPv3 Compliant Directory |

### MRAPolicy { #MRAPolicy }

3 valid values.

??? note "Show values"

    | Value |
    |-------|
    | No Service |
    | IM & Presence only |
    | IM & Presence, Voice and Video calls |

### MediaPayload { #MediaPayload }

7 valid values.

??? note "Show values"

    | Value |
    |-------|
    | G711 a-law 64K |
    | G711 u-law 64K |
    | G723 |
    | G729 |
    | G729AnnexA |
    | G729AnnexB |
    | G729AnnexA-AnnexB |

### Model { #Model }

242 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Cisco 30 SP+ |
    | Cisco 12 SP+ |
    | Cisco 12 SP |
    | Cisco 12 S |
    | Cisco 30 VIP |
    | Cisco 7910 |
    | Cisco 7960 |
    | Cisco 7940 |
    | Cisco 7935 |
    | Cisco VGC Phone |
    | Cisco VGC Virtual Phone |
    | Cisco ATA 186 |
    | EMCC Base Phone |
    | SCCP Phone |
    | Analog Access |
    | Digital Access |
    | Digital Access+ |
    | Digital Access WS-X6608 |
    | Analog Access WS-X6624 |
    | VGC Gateway |
    | Conference Bridge |
    | Conference Bridge WS-X6608 |
    | Cisco IOS Conference Bridge (HDV2) |
    | Cisco Conference Bridge (WS-SVC-CMM) |
    | H.323 Phone |
    | H.323 Gateway |
    | Music On Hold |
    | Device Pilot |
    | CTI Port |
    | CTI Route Point |
    | Voice Mail Port |
    | Cisco IOS Software Media Termination Point (HDV2) |
    | Cisco Media Server (WS-SVC-CMM-MS) |
    | Cisco Video Conference Bridge (IPVC-35xx) |
    | Cisco IOS Heterogeneous Video Conference Bridge |
    | Cisco IOS Guaranteed Audio Video Conference Bridge |
    | Cisco IOS Homogeneous Video Conference Bridge |
    | Route List |
    | Load Simulator |
    | Media Termination Point |
    | Media Termination Point Hardware |
    | Cisco IOS Media Termination Point (HDV2) |
    | Cisco Media Termination Point (WS-SVC-CMM) |
    | Cisco 7941 |
    | Cisco 7971 |
    | MGCP Station |
    | MGCP Trunk |
    | GateKeeper |
    | 7914 14-Button Line Expansion Module |
    | Trunk |
    | Tone Announcement Player |
    | SIP Trunk |
    | SIP Gateway |
    | WSM Trunk |
    | Remote Destination Profile |
    | 7915 12-Button Line Expansion Module |
    | 7915 24-Button Line Expansion Module |
    | 7916 12-Button Line Expansion Module |
    | 7916 24-Button Line Expansion Module |
    | CKEM 36-Button Line Expansion Module |
    | SPA8800 |
    | Unknown MGCP Gateway |
    | Unknown |
    | Cisco 7985 |
    | Cisco 7911 |
    | Cisco 7961G-GE |
    | Cisco 7941G-GE |
    | Motorola CN622 |
    | Third-party SIP Device (Basic) |
    | Cisco 7931 |
    | Cisco Unified Personal Communicator |
    | Cisco 7921 |
    | Cisco 7906 |
    | Third-party SIP Device (Advanced) |
    | Cisco TelePresence |
    | Nokia S60 |
    | Cisco 7962 |
    | Cisco 3951 |
    | Cisco 7937 |
    | Cisco 7942 |
    | Cisco 7945 |
    | Cisco 7965 |
    | Cisco 7975 |
    | Cisco 3911 |
    | Cisco Unified Mobile Communicator |
    | Cisco TelePresence 1000 |
    | Cisco TelePresence 3000 |
    | Cisco TelePresence 3200 |
    | Cisco TelePresence 500-37 |
    | Cisco 7925 |
    | Cisco 9971 |
    | Cisco 6921 |
    | Cisco 6941 |
    | Cisco 6961 |
    | Cisco Unified Client Services Framework |
    | Cisco TelePresence 1300-65 |
    | Cisco TelePresence 1100 |
    | Transnova S3 |
    | BlackBerry MVS VoWifi |
    | Cisco 9951 |
    | Cisco 8961 |
    | Cisco 6901 |
    | Cisco 6911 |
    | Cisco ATA 187 |
    | Cisco TelePresence 200 |
    | Cisco TelePresence 400 |
    | Cisco Dual Mode for iPhone |
    | Cisco 6945 |
    | Cisco Dual Mode for Android |
    | Cisco 7926 |
    | Cisco E20 |
    | Generic Single Screen Room System |
    | Generic Multiple Screen Room System |
    | Cisco TelePresence EX90 |
    | Cisco 8945 |
    | Cisco 8941 |
    | Generic Desktop Video Endpoint |
    | Cisco TelePresence 500-32 |
    | Cisco TelePresence 1300-47 |
    | Cisco 3905 |
    | Cisco Cius |
    | VKEM 36-Button Line Expansion Module |
    | Cisco TelePresence TX1310-65 |
    | Cisco TelePresence MCU |
    | Ascom IP-DECT Device |
    | Cisco TelePresence Exchange System |
    | Cisco TelePresence EX60 |
    | Cisco TelePresence Codec C90 |
    | Cisco TelePresence Codec C60 |
    | Cisco TelePresence Codec C40 |
    | Cisco TelePresence Quick Set C20 |
    | Cisco TelePresence Profile 42 (C20) |
    | Cisco TelePresence Profile 42 (C60) |
    | Cisco TelePresence Profile 52 (C40) |
    | Cisco TelePresence Profile 52 (C60) |
    | Cisco TelePresence Profile 52 Dual (C60) |
    | Cisco TelePresence Profile 65 (C60) |
    | Cisco TelePresence Profile 65 Dual (C90) |
    | Cisco TelePresence MX200 |
    | Cisco TelePresence TX9000 |
    | Cisco TelePresence TX9200 |
    | Cisco 7821 |
    | Cisco 7841 |
    | Cisco 7861 |
    | Cisco TelePresence SX20 |
    | Cisco TelePresence MX300 |
    | IMS-integrated Mobile (Basic) |
    | Third-party AS-SIP Endpoint |
    | Cisco Cius SP |
    | Cisco TelePresence Profile 42 (C40) |
    | Cisco VXC 6215 |
    | CTI Remote Device |
    | Usage Profile |
    | Carrier-integrated Mobile |
    | Universal Device Template |
    | Cisco DX650 |
    | Cisco Unified Communications for RTX |
    | Cisco Jabber for Tablet |
    | Cisco 8831 |
    | Cisco ATA 190 |
    | Cisco TelePresence SX10 |
    | Cisco 8841 |
    | Cisco 8851 |
    | Cisco 8861 |
    | Cisco TelePresence SX80 |
    | Cisco TelePresence MX200 G2 |
    | Cisco TelePresence MX300 G2 |
    | Cisco 7905 |
    | Cisco 7920 |
    | Cisco 7970 |
    | Cisco 7912 |
    | Cisco 7902 |
    | Cisco IP Communicator |
    | Cisco 7961 |
    | Cisco 7936 |
    | Analog Phone |
    | ISDN BRI Phone |
    | SCCP gateway virtual phone |
    | IP-STE |
    | Cisco TelePresence Conductor |
    | Cisco DX80 |
    | Cisco DX70 |
    | BEKEM 36-Button Line Expansion Module |
    | Cisco TelePresence MX700 |
    | Cisco TelePresence MX800 |
    | Cisco TelePresence IX5000 |
    | Cisco 7811 |
    | Cisco 8821 |
    | Cisco 8811 |
    | Interactive Voice Response |
    | Cisco 8845 |
    | Cisco 8865 |
    | Cisco TelePresence MX800 Dual |
    | Cisco 8851NR |
    | Cisco Spark Remote Device |
    | Cisco Webex DX80 |
    | Cisco TelePresence DX70 |
    | Cisco 7832 |
    | Cisco 8865NR |
    | Cisco Meeting Server |
    | Cisco Webex Room Kit |
    | Cisco Webex Room 55 |
    | Cisco Webex Room Kit Plus |
    | CP-8800-Video 28-Button Key Expansion Module |
    | CP-8800-Audio 28-Button Key Expansion Module |
    | Cisco 8832 |
    | Cisco Webex Room 70 Single |
    | Cisco 8832NR |
    | Cisco ATA 191 |
    | Cisco Collaboration Mobile Convergence |
    | Cisco Webex Room 70 Dual |
    | Cisco Webex Room Kit Pro |
    | Cisco Webex Room 55 Dual |
    | Cisco Webex Room 70 Single G2 |
    | Cisco Webex Room 70 Dual G2 |
    | SIP Station |
    | Cisco Webex Room Kit Mini |
    | Cisco Webex VDI Svc Framework |
    | Cisco Webex Board 55 |
    | Cisco Webex Board 70 |
    | Cisco Webex Board 85 |
    | Cisco Webex Desk Pro |
    | Cisco Webex Room Panorama |
    | Cisco Webex Room 70 Panorama |
    | Cisco Webex Room Phone |
    | Cisco 860 |
    | Cisco 840 |
    | Cisco Webex Desk LE |
    | Cisco Webex Desk |
    | Cisco Webex Desk Mini |
    | Cisco Webex Desk Hub |
    | Cisco Webex Board Pro 55 |
    | Cisco Webex Board Pro 75 |
    | Cisco Webex Room Bar |
    | Cisco 8875 |
    | Cisco 8875NR |
    | Cisco 8851NS |
    | Cisco 8811NS |
    | Cisco 8841NS |
    | Cisco Room Kit EQ |
    | Cisco Room Bar Pro |
    | Cisco Room Kit EQX |

### MonthOfYear { #MonthOfYear }

13 valid values.

??? note "Show values"

    | Value |
    |-------|
    | None |
    | Jan |
    | Feb |
    | Mar |
    | Apr |
    | May |
    | Jun |
    | Jul |
    | Aug |
    | Sep |
    | Oct |
    | Nov |
    | Dec |

### NetworkLocation { #NetworkLocation }

3 valid values.

??? note "Show values"

    | Value |
    |-------|
    | OnNet |
    | OffNet |
    | Use System Default |

### NumberingPlan { #NumberingPlan }

5 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Cisco CallManager |
    | ISDN |
    | National Standard |
    | Private |
    | Unknown |

### OutboundCallRollover { #OutboundCallRollover }

3 valid values.

??? note "Show values"

    | Value |
    |-------|
    | No Rollover |
    | Rollover Within Same DN |
    | Rollover to any line |

### PRIChanIE { #PRIChanIE }

4 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Timeslot Number |
    | Slotmap |
    | Use Number when 1B |
    | Continuous Number |

### PacketCaptureMode { #PacketCaptureMode }

2 valid values.

??? note "Show values"

    | Value |
    |-------|
    | None |
    | Batch Processing Mode |

### PartitionUsage { #PartitionUsage }

4 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Intercom |
    | Call Control Discovery Learned Pattern |
    | General |
    | Directory URI |

### PatternPrecedence { #PatternPrecedence }

7 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Flash Override |
    | Flash |
    | Immediate |
    | Priority |
    | Routine |
    | Default |
    | Executive Override |

### PatternRouteClass { #PatternRouteClass }

6 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Default |
    | Voice |
    | Data |
    | Satellite Avoidance |
    | Hotline Voice |
    | Hotline Data |

### PatternUsage { #PatternUsage }

33 valid values.

??? note "Show values"

    | Value |
    |-------|
    | CallPark |
    | Conference |
    | Device |
    | Translation |
    | Call Pick Up Group |
    | Route |
    | Message Waiting |
    | Hunt Pilot |
    | Voice Mail Port |
    | Domain Routing |
    | IPAddress Routing |
    | Device template |
    | Directed Call Park |
    | Device Intercom |
    | Translation Intercom |
    | Translation Calling Party Number |
    | Mobility Handoff |
    | Mobility Enterprise Feature Access |
    | Mobility IVR |
    | Device Intercom Template |
    | Called Party Number Transformation |
    | Call Control Discovery Learned Pattern |
    | Uri Routing |
    | ILS Learned Enterprise Number |
    | ILS Learned E164 Number |
    | ILS Learned Enterprise Numeric Pattern |
    | ILS Learned E164 Numeric Pattern |
    | Alternate Number |
    | ILS Learned URI |
    | ILS Learned PSTN Failover Rule |
    | ILS Imported E164 Number |
    | Centralized Conference Number |
    | Emergency Location ID Number |

### PhonePersonalization { #PhonePersonalization }

4 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Disabled |
    | Enabled |
    | HTTPS Only |
    | Default |

### PhoneService { #PhoneService }

3 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Standard IP Phone Service |
    | Directories |
    | Messages |

### PhoneServiceCategory { #PhoneServiceCategory }

5 valid values.

??? note "Show values"

    | Value |
    |-------|
    | XML Service |
    | Java MIDlet |
    | Web Widget |
    | Web Link |
    | Android APK |

### PhoneServiceDisplay { #PhoneServiceDisplay }

4 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Internal |
    | External URL |
    | Both |
    | Default |

### PickupNotification { #PickupNotification }

4 valid values.

??? note "Show values"

    | Value |
    |-------|
    | No Alert |
    | Audio Alert |
    | Visual Alert |
    | Audio and Visual Alert |

### Preemption { #Preemption }

3 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Disabled |
    | Forceful |
    | Default |

### PresentationBit { #PresentationBit }

3 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Default |
    | Allowed |
    | Restricted |

### PriOfNumber { #PriOfNumber }

5 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Cisco CallManager |
    | Unknown |
    | National |
    | International |
    | Subscriber |

### PriProtocol { #PriProtocol }

15 valid values.

??? note "Show values"

    | Value |
    |-------|
    | PRI 4ESS |
    | PRI 5E8 |
    | PRI 5E8 TELEOS |
    | PRI 5E8 INTECOME |
    | PRI 5E9 |
    | PRI DMS-100 |
    | PRI DMS-250 |
    | PRI EURO |
    | PRI NI2 |
    | PRI AUSTRALIAN |
    | PRI 5E8 CUSTOM |
    | PRI ETSI SC |
    | PRI NTT |
    | PRI ISO QSIG T1 |
    | PRI ISO QSIG E1 |

### ProcessNodeRole { #ProcessNodeRole }

2 valid values.

??? note "Show values"

    | Value |
    |-------|
    | CUCM Voice/Video |
    | CUCM IM and Presence |

### Product { #Product }

324 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Pilot |
    | Cisco Catalyst 6000 T1 VoIP Gateway |
    | Cisco Catalyst 6000 E1 VoIP Gateway |
    | Cisco Catalyst 6000 24 port FXS Gateway |
    | Cisco Catalyst 6000 12 port FXO Gateway |
    | EMCC Base Phone |
    | H.323 Client |
    | H.323 Gateway |
    | Cisco MGCP FXO Port |
    | Cisco MGCP FXS Port |
    | Cisco 12 SP+ |
    | Cisco 12 SP |
    | Cisco 12 S |
    | Cisco 30 SP+ |
    | Cisco 30 VIP |
    | CTI Port |
    | Cisco Voice Mail Port |
    | Cisco Conference Bridge Software |
    | Cisco Conference Bridge Hardware |
    | Cisco Media Termination Point Software |
    | Cisco Media Termination Point Hardware |
    | Cisco 7935 |
    | SCCP Device |
    | Cisco 7910 |
    | Cisco 7960 |
    | Cisco 7940 |
    | Route List |
    | Unknown |
    | Load Simulator |
    | Gatekeeper |
    | NM-1V |
    | NM-2V |
    | Cisco VG200 |
    | Cisco 26XX |
    | Cisco 362X |
    | Cisco 364X |
    | Cisco 366X |
    | CTI Route Point |
    | Music On Hold |
    | Cisco MGCP T1 Port |
    | NM-HDV |
    | VIC_SLOT |
    | Cisco MGCP E1 Port |
    | VWIC_SLOT |
    | FLEX_SLOT |
    | Cisco Catalyst 4224 Voice Gateway Switch |
    | Cisco Catalyst 4000 Access Gateway  Module |
    | Cisco IOS Conference Bridge |
    | Cisco IOS Media Termination Point |
    | Cisco  IAD2400 |
    | IAD2400_ANALOG |
    | IAD2400_DIGITAL |
    | Cisco VGC Phone |
    | Cisco VG248 Gateway |
    | VGC Port |
    | Cisco VGC Virtual Phone |
    | Cisco ATA 186 |
    | H.225 Trunk (Gatekeeper Controlled) |
    | Inter-Cluster Trunk (Gatekeeper Controlled) |
    | Inter-Cluster Trunk (Non-Gatekeeper Controlled) |
    | Communication Media Module |
    | WS-X6600 |
    | AIM-VOICE-30 |
    | NM-HDA |
    | PA-VXA |
    | PA-VXB |
    | PA-VXC |
    | PA-MCX |
    | Annunciator |
    | Cisco MGCP BRI Port |
    | NM-HD-1V |
    | NM-HD-2V |
    | NM-HD-2VE |
    | SIP Trunk |
    | Cisco Conference Bridge (WS-SVC-CMM) |
    | Cisco Media Server (WS-SVC-CMM-MS) |
    | Cisco Media Termination Point (WS-SVC-CMM) |
    | Cisco IOS Enhanced Software Media Termination Point |
    | 7914 14-Button Line Expansion Module |
    | Cisco IOS Enhanced Conference Bridge |
    | Cisco IOS Enhanced Media Termination Point |
    | Cisco Video Conference Bridge(IPVC-35xx) |
    | Cisco IOS Heterogeneous Video Conference Bridge |
    | Cisco IOS Guaranteed Audio Video Conference Bridge |
    | Cisco IOS Homogeneous Video Conference Bridge |
    | Hunt List |
    | SIP WSM Connection |
    | Remote Destination Profile |
    | Cisco 7941 |
    | Cisco 7971 |
    | Cisco 7985 |
    | Cisco 7911 |
    | Cisco 7961G-GE |
    | Cisco 7941G-GE |
    | 7915 12-Button Line Expansion Module |
    | 7915 24-Button Line Expansion Module |
    | 7916 12-Button Line Expansion Module |
    | 7916 24-Button Line Expansion Module |
    | CKEM 36-Button Line Expansion Module |
    | Motorola CN622 |
    | Third-party SIP Device (Basic) |
    | Cisco 7931 |
    | Cisco Unified Personal Communicator |
    | Cisco 7921 |
    | Cisco 7906 |
    | Third-party SIP Device (Advanced) |
    | Cisco TelePresence |
    | Nokia S60 |
    | Cisco 7962 |
    | Cisco 3951 |
    | Cisco 7937 |
    | Cisco 7942 |
    | Cisco 7945 |
    | Cisco 7965 |
    | Cisco 7975 |
    | Cisco 3911 |
    | Cisco Unified Mobile Communicator |
    | Cisco TelePresence 1000 |
    | Cisco TelePresence 3000 |
    | Cisco TelePresence 3200 |
    | Cisco TelePresence 500-37 |
    | Cisco 7925 |
    | Cisco 9971 |
    | Cisco 6921 |
    | Cisco 6941 |
    | Cisco 6961 |
    | Cisco Unified Client Services Framework |
    | Cisco TelePresence 1300-65 |
    | Cisco TelePresence 1100 |
    | Transnova S3 |
    | Cisco 9951 |
    | Cisco 8961 |
    | Cisco 6901 |
    | Cisco 6911 |
    | Cisco ATA 187 |
    | Cisco TelePresence 200 |
    | Cisco TelePresence 400 |
    | Cisco Dual Mode for iPhone |
    | Cisco 6945 |
    | Cisco Dual Mode for Android |
    | Cisco 7926 |
    | Cisco E20 |
    | Generic Single Screen Room System |
    | Generic Multiple Screen Room System |
    | Cisco TelePresence EX90 |
    | Cisco 8945 |
    | Cisco 8941 |
    | Generic Desktop Video Endpoint |
    | Cisco TelePresence 500-32 |
    | Cisco TelePresence 1300-47 |
    | Cisco 3905 |
    | Cisco Cius |
    | VKEM 36-Button Line Expansion Module |
    | Cisco TelePresence TX1310-65 |
    | Cisco TelePresence MCU |
    | Cisco TelePresence Conductor |
    | Cisco TelePresence Exchange System |
    | Cisco TelePresence EX60 |
    | Cisco TelePresence Codec C90 |
    | Cisco TelePresence Codec C60 |
    | Cisco TelePresence Codec C40 |
    | Cisco TelePresence Quick Set C20 |
    | Cisco TelePresence Profile 42 (C20) |
    | Cisco TelePresence Profile 42 (C60) |
    | Cisco TelePresence Profile 52 (C40) |
    | Cisco TelePresence Profile 52 (C60) |
    | Cisco TelePresence Profile 52 Dual (C60) |
    | Cisco TelePresence Profile 65 (C60) |
    | Cisco TelePresence Profile 65 Dual (C90) |
    | Cisco TelePresence MX200 |
    | Cisco TelePresence TX9000 |
    | Cisco TelePresence TX9200 |
    | Cisco 7821 |
    | Cisco 7841 |
    | Cisco 7861 |
    | Cisco TelePresence SX20 |
    | Cisco TelePresence MX300 |
    | IMS-integrated Mobile (Basic) |
    | Third-party AS-SIP Endpoint |
    | Cisco Cius SP |
    | Cisco TelePresence Profile 42 (C40) |
    | Cisco VXC 6215 |
    | CTI Remote Device |
    | Carrier-integrated Mobile |
    | Universal Device Template |
    | Cisco DX650 |
    | Cisco Unified Communications for RTX |
    | Cisco Jabber for Tablet |
    | Cisco 8831 |
    | Cisco ATA 190 |
    | Cisco TelePresence SX10 |
    | Cisco 8841 |
    | Cisco 8851 |
    | Cisco 8861 |
    | Cisco TelePresence SX80 |
    | Cisco TelePresence MX200 G2 |
    | Cisco TelePresence MX300 G2 |
    | WS-SVC-CMM-MS |
    | NM-4VWIC-MBRD |
    | VNM-HDA |
    | NM-HDV2-0PORT |
    | NM-HDV2-1PORT |
    | NM-HDV2-2PORT |
    | Cisco 3745 |
    | Cisco 3725 |
    | Cisco 7905 |
    | Cisco 7920 |
    | Cisco 269X |
    | Cisco 7970 |
    | Cisco 1760 |
    | Cisco 1751 |
    | Cisco 7912 |
    | Cisco 7902 |
    | VG224 |
    | Cisco 2821 |
    | Cisco IP Communicator |
    | Cisco 7961 |
    | Cisco 7936 |
    | Cisco 3825 |
    | Cisco 3845 |
    | Cisco 2811 |
    | Cisco 2851 |
    | Analog Phone |
    | ISDN BRI Phone |
    | SCCP gateway virtual phone |
    | IP-STE |
    | Cisco 2801 |
    | Cisco 1861 |
    | VG204 |
    | Cisco VGD-1T3 |
    | VG202 |
    | Cisco 881 |
    | Cisco 2951 |
    | Cisco 3945 |
    | Cisco 888/887/886 |
    | Cisco 2911 |
    | Cisco 3925 |
    | Cisco 2921 |
    | Cisco 2901 |
    | Cisco 3945E |
    | Cisco 3925E |
    | SPA8800 |
    | C881V |
    | C887VA-V |
    | VG350 |
    | Cisco ISR 4451 |
    | Cisco ISR 4431 |
    | Cisco DX80 |
    | Cisco DX70 |
    | VG310 |
    | VG320 |
    | BEKEM 36-Button Line Expansion Module |
    | Cisco ISR 4351 |
    | Cisco TelePresence MX700 |
    | Cisco TelePresence MX800 |
    | Cisco TelePresence IX5000 |
    | Cisco ISR 4331 |
    | Cisco 7811 |
    | Cisco ISR 4321 |
    | Cisco 8821 |
    | Cisco 8811 |
    | Interactive Voice Response |
    | Cisco 8845 |
    | Cisco 8865 |
    | Cisco TelePresence MX800 Dual |
    | Cisco 8851NR |
    | Cisco Spark Remote Device |
    | Cisco Webex DX80 |
    | Cisco TelePresence DX70 |
    | Cisco 7832 |
    | Cisco 8865NR |
    | Cisco Meeting Server |
    | Cisco Webex Room Kit |
    | Cisco Webex Room 55 |
    | Cisco Webex Room Kit Plus |
    | CP-8800-Audio 28-Button Key Expansion Module |
    | CP-8800-Video 28-Button Key Expansion Module |
    | Cisco 8832 |
    | Cisco Webex Room 70 Single |
    | Cisco 8832NR |
    | Cisco ATA 191 |
    | Cisco Collaboration Mobile Convergence |
    | Cisco Webex Room 70 Dual |
    | VG450 |
    | Cisco ISR 4461 |
    | Cisco ENCS 5400 ISRV |
    | VG400 |
    | Cisco Webex Room Kit Pro |
    | Cisco Webex Room 55 Dual |
    | Cisco Webex Room 70 Single G2 |
    | Cisco Webex Room 70 Dual G2 |
    | Cisco SIP FXS Port |
    | Cisco Webex Room Kit Mini |
    | Cisco C8300-1N1S-4T2X |
    | Cisco C8300-2N2S-4T2X/6T |
    | Cisco C8200/L-1N-4T |
    | Cisco C8300-1N1S-6T |
    | Cisco Webex VDI Svc Framework |
    | Cisco Webex Board 55 |
    | Cisco Webex Board 70 |
    | Cisco Webex Board 85 |
    | Cisco Webex Desk Pro |
    | Cisco Webex Room Panorama |
    | Cisco Webex Room 70 Panorama |
    | Cisco Webex Room Phone |
    | Cisco 860 |
    | Cisco 840 |
    | VG420 |
    | Cisco Webex Desk LE |
    | Cisco Webex Desk |
    | Cisco Webex Desk Mini |
    | Cisco Webex Desk Hub |
    | Cisco Webex Board Pro 55 |
    | Cisco Webex Board Pro 75 |
    | Cisco Webex Room Bar |
    | Cisco 8875 |
    | Cisco 8875NR |
    | Cisco 8851NS |
    | Cisco 8811NS |
    | Cisco 8841NS |
    | Cisco Room Kit EQ |
    | VG410 |
    | Cisco Room Bar Pro |
    | Cisco Room Kit EQX |

### ProtocolSide { #ProtocolSide }

2 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Network |
    | User |

### QSIGVariant { #QSIGVariant }

3 valid values.

??? note "Show values"

    | Value |
    |-------|
    | No Changes |
    | ECMA |
    | ISO |

### RSVPOverSIP { #RSVPOverSIP }

2 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Local RSVP |
    | E2E |

### ReleaseCauseValue { #ReleaseCauseValue }

6 valid values.

??? note "Show values"

    | Value |
    |-------|
    | No Error |
    | Unallocated Number |
    | Call Rejected |
    | Number Changed |
    | Invalid Number Format |
    | Precedence Level Exceeded |

### RevertPriority { #RevertPriority }

2 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Default |
    | Highest |

### RingSetting { #RingSetting }

6 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Use System Default |
    | Disable |
    | Flash Only |
    | Ring Once |
    | Ring |
    | Beep Only |

### SIPBandwidthModifier { #SIPBandwidthModifier }

4 valid values.

??? note "Show values"

    | Value |
    |-------|
    | TIAS and AS |
    | TIAS only |
    | AS only |
    | CT only |

### SIPCodec { #SIPCodec }

4 valid values.

??? note "Show values"

    | Value |
    |-------|
    | 711ulaw |
    | 711alaw |
    | G729/G729a |
    | G729b/G729ab |

### SIPIdentityBlend { #SIPIdentityBlend }

3 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Deliver DN only in connected party |
    | Deliver URI only in connected party, if available |
    | Deliver URI and DN in connected party, if available |

### SIPRel1XXOptions { #SIPRel1XXOptions }

3 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Disabled |
    | Send PRACK if 1xx Contains SDP |
    | Send PRACK for all 1xx Messages |

### SIPReroute { #SIPReroute }

3 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Never |
    | Contact Header |
    | Call-Info Header with purpose=x-cisco-origIP |

### SIPScriptErrorHandling { #SIPScriptErrorHandling }

4 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Message Rollback Only |
    | Disable Script |
    | Reset Script |
    | Reset Trunk / Restart Device |

### SIPTrunkCallLegSecurity { #SIPTrunkCallLegSecurity }

2 valid values.

??? note "Show values"

    | Value |
    |-------|
    | When using both sRTP and TLS |
    | When using sRTP Only |

### SNMPAuthenticationProtocol { #SNMPAuthenticationProtocol }

2 valid values.

??? note "Show values"

    | Value |
    |-------|
    | MD5 |
    | SHA |

### SNMPPrivacyProtocol { #SNMPPrivacyProtocol }

2 valid values.

??? note "Show values"

    | Value |
    |-------|
    | DES |
    | AES-128 |

### SNMPVersion { #SNMPVersion }

3 valid values.

??? note "Show values"

    | Value |
    |-------|
    | 1 |
    | 2C |
    | 3 |

### ScheduleUnit { #ScheduleUnit }

4 valid values.

??? note "Show values"

    | Value |
    |-------|
    | HOUR |
    | DAY |
    | WEEK |
    | MONTH |

### ServerSecurityMode { #ServerSecurityMode }

2 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Authenticated |
    | Encrypted and Authenticated |

### Service { #Service }

108 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Cisco CallManager |
    | Cisco Tftp |
    | Cisco Messaging Interface |
    | Cisco IP Voice Media Streaming App |
    | Cisco CTIManager |
    | Cisco RIS Data Collector |
    | Cisco Extension Mobility |
    | Cisco Database Layer Monitor |
    | Enterprise Wide |
    | Cisco IP Manager Assistant |
    | Cisco Extended Functions |
    | Cisco Serviceability Reporter |
    | Cisco WebDialer Web Service |
    | Cisco Dialed Number Analyzer |
    | Cisco CDR Repository Manager |
    | Cisco Certificate Authority Proxy Function |
    | Cisco CDR Agent |
    | Cisco SOAP - CDRonDemand Service |
    | Cisco CAR Scheduler |
    | Cisco CAR Web Service |
    | Cisco AMC Service |
    | Cisco Log Partition Monitoring Tool |
    | Cisco CallManager SNMP Service |
    | Cisco DirSync |
    | Cisco AXL Web Service |
    | Cisco DRF Master |
    | Cisco DRF Local |
    | Cisco CallManager Cisco IP Phone Services |
    | Cisco CCMAdmin Web Service |
    | Cisco CCMRealm Web Service |
    | Cisco CCMService Web Service |
    | Cisco SOAP Web Service |
    | Cisco RTMT Web Service |
    | Cisco CCM PD Web Service |
    | Cisco CCM DBL Web Library |
    | Cisco CCM NCS Web Library |
    | Cisco Bulk Provisioning Service |
    | Cisco Extension Mobility Application |
    | Cisco License Manager |
    | Cisco Role-based Security |
    | Cisco Trace Collection Service |
    | Cisco Security Agent |
    | Cisco Trust Verification Service |
    | Cisco DHCP Monitor Service |
    | Cisco TAPS Service |
    | Cisco Tomcat |
    | Cisco Unified OS Admin Web Service |
    | Cisco GRT Communication Web Service |
    | Cisco Unified Reporting Web Service |
    | Cisco RisBean Library |
    | Cisco SOAPMessage Service |
    | Platform Administrative Web Service |
    | Cisco Change Credential Application |
    | Cisco CCMUser Web Service |
    | Cisco Audit Event Service |
    | SOAP - Diagnostic Portal Database Service |
    | Cisco SIP Proxy |
    | Cisco UXL Web Service |
    | Cisco Config Agent |
    | Cisco OAM Agent |
    | Cisco Client Profile Agent |
    | Cisco Sync Agent |
    | Cisco SIP Proxy Logger |
    | Cisco Intercluster Sync Agent |
    | Cisco XCP Router |
    | Cisco XCP Text Conference Manager |
    | Cisco XCP Web Connection Manager |
    | Cisco XCP Connection Manager |
    | Cisco XCP SIP Federation Connection Manager |
    | Cisco XCP XMPP Federation Connection Manager |
    | Cisco XCP Message Archiver |
    | Cisco XCP Directory Service |
    | Cisco XCP Authentication Service |
    | Cisco IM and Presence Admin |
    | Cisco Server Recovery Manager |
    | Cisco XCP Config Manager |
    | Cisco IM and Presence Data Monitor |
    | Cisco Presence Datastore |
    | Cisco Login Datastore |
    | Cisco Route Datastore |
    | Cisco SIP Registration Datastore |
    | Cisco Presence Engine |
    | Cisco Common User Interface |
    | Cisco User Data Services |
    | Cisco External Call Control Service |
    | Cisco E911 Service |
    | Cisco Location Bandwidth Manager |
    | Cisco Dialed Number Analyzer Server |
    | Cisco Unified Mobile Voice Access Service |
    | Cisco Intercluster Lookup Service |
    | Cisco Directory Number Alias Sync |
    | Cisco Directory Number Alias Lookup |
    | Self Provisioning IVR |
    | Cisco RCC Device Selection Service |
    | Cisco CtlCli |
    | Cisco XCP File Transfer Manager |
    | Cisco Certificate Change Notification Service |
    | Cisco Wireless Controller Synchronization Service |
    | Cisco Smart License Manager |
    | Cisco Upgrade Agent Service |
    | Cisco Management Agent Service |
    | Cisco Push Notification Service |
    | Cisco Certificate Enrollment Service |
    | Platform Communication Web Service |
    | Cisco Device Activation Service |
    | Cisco Headset Service |
    | Cisco Local Push Notification Service |
    | Cisco Certificate Expiry Monitor |

### ServiceGrouping { #ServiceGrouping }

15 valid values.

??? note "Show values"

    | Value |
    |-------|
    | CM Services |
    | CTI Services |
    | CDR Services |
    | Database and Admin Services |
    | Performance and Monitoring Services |
    | Security Services |
    | Directory Services |
    | Backup and Restore Services |
    | System Services |
    | Soap Services |
    | Voice Quality Reporter Services |
    | Platform Services |
    | IM and Presence Services |
    | Location based Tracking Services |
    | Cloud based Management Services |

### SilenceSuppressionThreshold { #SilenceSuppressionThreshold }

8 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Disable |
    | -48dbm0 |
    | -45dbm0 |
    | -42dbm0 |
    | -39dbm0 |
    | -36dbm0 |
    | -33dbm0 |
    | -30dbm0 |

### SipAssertedType { #SipAssertedType }

3 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Default |
    | PAI |
    | PPI |

### SipPrivacy { #SipPrivacy }

4 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Default |
    | None |
    | ID |
    | ID Critical |

### SipSessionRefreshMethod { #SipSessionRefreshMethod }

2 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Invite |
    | Update |

### StartDialProtocol { #StartDialProtocol }

5 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Not Set |
    | Immediate |
    | Wink Start Feature Group B |
    | Delay Dial |
    | Wink Start Feature Group D |

### Status { #Status }

3 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Off |
    | On |
    | Default |

### TelnetLevel { #TelnetLevel }

3 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Disabled |
    | Limited |
    | Enabled |

### TimeOfDay { #TimeOfDay }

98 valid values.

??? note "Show values"

    | Value |
    |-------|
    | No Office Hours |
    | 00:00 |
    | 00:15 |
    | 00:30 |
    | 00:45 |
    | 01:00 |
    | 01:15 |
    | 01:30 |
    | 01:45 |
    | 02:00 |
    | 02:15 |
    | 02:30 |
    | 02:45 |
    | 03:00 |
    | 03:15 |
    | 03:30 |
    | 03:45 |
    | 04:00 |
    | 04:15 |
    | 04:30 |
    | 04:45 |
    | 05:00 |
    | 05:15 |
    | 05:30 |
    | 05:45 |
    | 06:00 |
    | 06:15 |
    | 06:30 |
    | 06:45 |
    | 07:00 |
    | 07:15 |
    | 07:30 |
    | 07:45 |
    | 08:00 |
    | 08:15 |
    | 08:30 |
    | 08:45 |
    | 09:00 |
    | 09:15 |
    | 09:30 |
    | 09:45 |
    | 10:00 |
    | 10:15 |
    | 10:30 |
    | 10:45 |
    | 11:00 |
    | 11:15 |
    | 11:30 |
    | 11:45 |
    | 12:00 |
    | 12:15 |
    | 12:30 |
    | 12:45 |
    | 13:00 |
    | 13:15 |
    | 13:30 |
    | 13:45 |
    | 14:00 |
    | 14:15 |
    | 14:30 |
    | 14:45 |
    | 15:00 |
    | 15:15 |
    | 15:30 |
    | 15:45 |
    | 16:00 |
    | 16:15 |
    | 16:30 |
    | 16:45 |
    | 17:00 |
    | 17:15 |
    | 17:30 |
    | 17:45 |
    | 18:00 |
    | 18:15 |
    | 18:30 |
    | 18:45 |
    | 19:00 |
    | 19:15 |
    | 19:30 |
    | 19:45 |
    | 20:00 |
    | 20:15 |
    | 20:30 |
    | 20:45 |
    | 21:00 |
    | 21:15 |
    | 21:30 |
    | 21:45 |
    | 22:00 |
    | 22:15 |
    | 22:30 |
    | 22:45 |
    | 23:00 |
    | 23:15 |
    | 23:30 |
    | 23:45 |
    | 24:00 |

### TimeScheduleCategory { #TimeScheduleCategory }

2 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Regular |
    | Holiday or Vacation |

### TimeZone { #TimeZone }

470 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Africa/Abidjan |
    | Africa/Accra |
    | Africa/Addis_Ababa |
    | Africa/Algiers |
    | Africa/Asmara |
    | Africa/Bamako |
    | Africa/Bangui |
    | Africa/Banjul |
    | Africa/Bissau |
    | Africa/Blantyre |
    | Africa/Brazzaville |
    | Africa/Bujumbura |
    | Africa/Cairo |
    | Africa/Casablanca |
    | Africa/Ceuta |
    | Africa/Conakry |
    | Africa/Dakar |
    | Africa/Dar_es_Salaam |
    | Africa/Djibouti |
    | Africa/Douala |
    | Africa/El_Aaiun |
    | Africa/Freetown |
    | Africa/Gaborone |
    | Africa/Harare |
    | Africa/Johannesburg |
    | Africa/Juba |
    | Africa/Kampala |
    | Africa/Khartoum |
    | Africa/Kigali |
    | Africa/Kinshasa |
    | Africa/Lagos |
    | Africa/Libreville |
    | Africa/Lome |
    | Africa/Luanda |
    | Africa/Lubumbashi |
    | Africa/Lusaka |
    | Africa/Malabo |
    | Africa/Maputo |
    | Africa/Maseru |
    | Africa/Mbabane |
    | Africa/Mogadishu |
    | Africa/Monrovia |
    | Africa/Nairobi |
    | Africa/Ndjamena |
    | Africa/Niamey |
    | Africa/Nouakchott |
    | Africa/Ouagadougou |
    | Africa/Porto-Novo |
    | Africa/Sao_Tome |
    | Africa/Tripoli |
    | Africa/Tunis |
    | Africa/Windhoek |
    | America/Adak |
    | America/Anchorage |
    | America/Anguilla |
    | America/Antigua |
    | America/Araguaina |
    | America/Argentina/Buenos_Aires |
    | America/Argentina/Catamarca |
    | America/Argentina/Cordoba |
    | America/Argentina/Jujuy |
    | America/Argentina/La_Rioja |
    | America/Argentina/Mendoza |
    | America/Argentina/Rio_Gallegos |
    | America/Argentina/Salta |
    | America/Argentina/San_Juan |
    | America/Argentina/San_Luis |
    | America/Argentina/Tucuman |
    | America/Argentina/Ushuaia |
    | America/Aruba |
    | America/Asuncion |
    | America/Atikokan |
    | America/Bahia |
    | America/Bahia_Banderas |
    | America/Barbados |
    | America/Belem |
    | America/Belize |
    | America/Blanc-Sablon |
    | America/Boa_Vista |
    | America/Bogota |
    | America/Boise |
    | America/Cambridge_Bay |
    | America/Campo_Grande |
    | America/Cancun |
    | America/Caracas |
    | America/Cayenne |
    | America/Cayman |
    | America/Chicago |
    | America/Chihuahua |
    | America/Costa_Rica |
    | America/Creston |
    | America/Cuiaba |
    | America/Curacao |
    | America/Danmarkshavn |
    | America/Dawson |
    | America/Dawson_Creek |
    | America/Denver |
    | America/Detroit |
    | America/Dominica |
    | America/Edmonton |
    | America/Eirunepe |
    | America/El_Salvador |
    | America/Fortaleza |
    | America/Glace_Bay |
    | America/Godthab |
    | America/Goose_Bay |
    | America/Grand_Turk |
    | America/Grenada |
    | America/Guadeloupe |
    | America/Guatemala |
    | America/Guayaquil |
    | America/Guyana |
    | America/Halifax |
    | America/Havana |
    | America/Hermosillo |
    | America/Indiana/Indianapolis |
    | America/Indiana/Knox |
    | America/Indiana/Marengo |
    | America/Indiana/Petersburg |
    | America/Indiana/Tell_City |
    | America/Indiana/Vevay |
    | America/Indiana/Vincennes |
    | America/Indiana/Winamac |
    | America/Inuvik |
    | America/Iqaluit |
    | America/Jamaica |
    | America/Juneau |
    | America/Kentucky/Louisville |
    | America/Kentucky/Monticello |
    | America/Kralendijk |
    | America/La_Paz |
    | America/Lima |
    | America/Los_Angeles |
    | America/Lower_Princes |
    | America/Maceio |
    | America/Managua |
    | America/Manaus |
    | America/Marigot |
    | America/Martinique |
    | America/Matamoros |
    | America/Mazatlan |
    | America/Menominee |
    | America/Merida |
    | America/Metlakatla |
    | America/Mexico_City |
    | America/Miquelon |
    | America/Moncton |
    | America/Monterrey |
    | America/Montevideo |
    | America/Montreal |
    | America/Montserrat |
    | America/Nassau |
    | America/New_York |
    | America/Nipigon |
    | America/Nome |
    | America/Noronha |
    | America/North_Dakota/Beulah |
    | America/North_Dakota/Center |
    | America/North_Dakota/New_Salem |
    | America/Ojinaga |
    | America/Panama |
    | America/Pangnirtung |
    | America/Paramaribo |
    | America/Phoenix |
    | America/Port-au-Prince |
    | America/Port_of_Spain |
    | America/Porto_Velho |
    | America/Puerto_Rico |
    | America/Rainy_River |
    | America/Rankin_Inlet |
    | America/Recife |
    | America/Regina |
    | America/Resolute |
    | America/Rio_Branco |
    | America/Santa_Isabel |
    | America/Santarem |
    | America/Santiago |
    | America/Santo_Domingo |
    | America/Sao_Paulo |
    | America/Scoresbysund |
    | America/Shiprock |
    | America/Sitka |
    | America/St_Barthelemy |
    | America/St_Johns |
    | America/St_Kitts |
    | America/St_Lucia |
    | America/St_Thomas |
    | America/St_Vincent |
    | America/Swift_Current |
    | America/Tegucigalpa |
    | America/Thule |
    | America/Thunder_Bay |
    | America/Tijuana |
    | America/Toronto |
    | America/Tortola |
    | America/Vancouver |
    | America/Whitehorse |
    | America/Winnipeg |
    | America/Yakutat |
    | America/Yellowknife |
    | Antarctica/Casey |
    | Antarctica/Davis |
    | Antarctica/DumontDUrville |
    | Antarctica/Macquarie |
    | Antarctica/Mawson |
    | Antarctica/McMurdo |
    | Antarctica/Palmer |
    | Antarctica/Rothera |
    | Antarctica/South_Pole |
    | Antarctica/Syowa |
    | Antarctica/Vostok |
    | Arctic/Longyearbyen |
    | Asia/Aden |
    | Asia/Almaty |
    | Asia/Amman |
    | Asia/Anadyr |
    | Asia/Aqtau |
    | Asia/Aqtobe |
    | Asia/Ashgabat |
    | Asia/Baghdad |
    | Asia/Bahrain |
    | Asia/Baku |
    | Asia/Bangkok |
    | Asia/Beirut |
    | Asia/Bishkek |
    | Asia/Brunei |
    | Asia/Choibalsan |
    | Asia/Chongqing |
    | Asia/Colombo |
    | Asia/Damascus |
    | Asia/Dhaka |
    | Asia/Dili |
    | Asia/Dubai |
    | Asia/Dushanbe |
    | Asia/Gaza |
    | Asia/Harbin |
    | Asia/Hebron |
    | Asia/Ho_Chi_Minh |
    | Asia/Hong_Kong |
    | Asia/Hovd |
    | Asia/Irkutsk |
    | Asia/Istanbul |
    | Asia/Jakarta |
    | Asia/Jayapura |
    | Asia/Jerusalem |
    | Asia/Kabul |
    | Asia/Kamchatka |
    | Asia/Karachi |
    | Asia/Kashgar |
    | Asia/Kathmandu |
    | Asia/Kolkata |
    | Asia/Krasnoyarsk |
    | Asia/Kuala_Lumpur |
    | Asia/Kuching |
    | Asia/Kuwait |
    | Asia/Macau |
    | Asia/Magadan |
    | Asia/Makassar |
    | Asia/Manila |
    | Asia/Muscat |
    | Asia/Nicosia |
    | Asia/Novokuznetsk |
    | Asia/Novosibirsk |
    | Asia/Omsk |
    | Asia/Oral |
    | Asia/Phnom_Penh |
    | Asia/Pontianak |
    | Asia/Pyongyang |
    | Asia/Qatar |
    | Asia/Qyzylorda |
    | Asia/Rangoon |
    | Asia/Riyadh |
    | Asia/Riyadh87 |
    | Asia/Riyadh88 |
    | Asia/Riyadh89 |
    | Asia/Sakhalin |
    | Asia/Samarkand |
    | Asia/Seoul |
    | Asia/Shanghai |
    | Asia/Singapore |
    | Asia/Taipei |
    | Asia/Tashkent |
    | Asia/Tbilisi |
    | Asia/Tehran |
    | Asia/Thimphu |
    | Asia/Tokyo |
    | Asia/Ulaanbaatar |
    | Asia/Urumqi |
    | Asia/Vientiane |
    | Asia/Vladivostok |
    | Asia/Yakutsk |
    | Asia/Yekaterinburg |
    | Asia/Yerevan |
    | Atlantic/Azores |
    | Atlantic/Bermuda |
    | Atlantic/Canary |
    | Atlantic/Cape_Verde |
    | Atlantic/Faroe |
    | Atlantic/Madeira |
    | Atlantic/Reykjavik |
    | Atlantic/South_Georgia |
    | Atlantic/St_Helena |
    | Atlantic/Stanley |
    | Australia/Adelaide |
    | Australia/Brisbane |
    | Australia/Broken_Hill |
    | Australia/Currie |
    | Australia/Darwin |
    | Australia/Eucla |
    | Australia/Hobart |
    | Australia/Lindeman |
    | Australia/Lord_Howe |
    | Australia/Melbourne |
    | Australia/Perth |
    | Australia/Sydney |
    | CET |
    | CST6CDT |
    | EET |
    | EST |
    | EST5EDT |
    | Etc/GMT |
    | Etc/GMT+0 |
    | Etc/GMT+1 |
    | Etc/GMT+10 |
    | Etc/GMT+11 |
    | Etc/GMT+12 |
    | Etc/GMT+2 |
    | Etc/GMT+3 |
    | Etc/GMT+4 |
    | Etc/GMT+5 |
    | Etc/GMT+6 |
    | Etc/GMT+7 |
    | Etc/GMT+8 |
    | Etc/GMT+9 |
    | Etc/GMT-0 |
    | Etc/GMT-1 |
    | Etc/GMT-10 |
    | Etc/GMT-11 |
    | Etc/GMT-12 |
    | Etc/GMT-13 |
    | Etc/GMT-14 |
    | Etc/GMT-2 |
    | Etc/GMT-3 |
    | Etc/GMT-4 |
    | Etc/GMT-5 |
    | Etc/GMT-6 |
    | Etc/GMT-7 |
    | Etc/GMT-8 |
    | Etc/GMT-9 |
    | Etc/GMT0 |
    | Etc/Greenwich |
    | Etc/UCT |
    | Etc/UTC |
    | Etc/Universal |
    | Etc/Zulu |
    | Europe/Amsterdam |
    | Europe/Andorra |
    | Europe/Athens |
    | Europe/Belgrade |
    | Europe/Berlin |
    | Europe/Bratislava |
    | Europe/Brussels |
    | Europe/Bucharest |
    | Europe/Budapest |
    | Europe/Chisinau |
    | Europe/Copenhagen |
    | Europe/Dublin |
    | Europe/Gibraltar |
    | Europe/Guernsey |
    | Europe/Helsinki |
    | Europe/Isle_of_Man |
    | Europe/Istanbul |
    | Europe/Jersey |
    | Europe/Kaliningrad |
    | Europe/Kiev |
    | Europe/Lisbon |
    | Europe/Ljubljana |
    | Europe/London |
    | Europe/Luxembourg |
    | Europe/Madrid |
    | Europe/Malta |
    | Europe/Mariehamn |
    | Europe/Minsk |
    | Europe/Monaco |
    | Europe/Moscow |
    | Europe/Nicosia |
    | Europe/Oslo |
    | Europe/Paris |
    | Europe/Podgorica |
    | Europe/Prague |
    | Europe/Riga |
    | Europe/Rome |
    | Europe/Samara |
    | Europe/San_Marino |
    | Europe/Sarajevo |
    | Europe/Simferopol |
    | Europe/Skopje |
    | Europe/Sofia |
    | Europe/Stockholm |
    | Europe/Tallinn |
    | Europe/Tirane |
    | Europe/Uzhgorod |
    | Europe/Vaduz |
    | Europe/Vatican |
    | Europe/Vienna |
    | Europe/Vilnius |
    | Europe/Volgograd |
    | Europe/Warsaw |
    | Europe/Zagreb |
    | Europe/Zaporozhye |
    | Europe/Zurich |
    | HST |
    | Indian/Antananarivo |
    | Indian/Chagos |
    | Indian/Christmas |
    | Indian/Cocos |
    | Indian/Comoro |
    | Indian/Kerguelen |
    | Indian/Mahe |
    | Indian/Maldives |
    | Indian/Mauritius |
    | Indian/Mayotte |
    | Indian/Reunion |
    | MET |
    | MST |
    | MST7MDT |
    | Mideast/Riyadh87 |
    | Mideast/Riyadh88 |
    | Mideast/Riyadh89 |
    | PST8PDT |
    | Pacific/Apia |
    | Pacific/Auckland |
    | Pacific/Chatham |
    | Pacific/Chuuk |
    | Pacific/Easter |
    | Pacific/Efate |
    | Pacific/Enderbury |
    | Pacific/Fakaofo |
    | Pacific/Fiji |
    | Pacific/Funafuti |
    | Pacific/Galapagos |
    | Pacific/Gambier |
    | Pacific/Guadalcanal |
    | Pacific/Guam |
    | Pacific/Honolulu |
    | Pacific/Johnston |
    | Pacific/Kiritimati |
    | Pacific/Kosrae |
    | Pacific/Kwajalein |
    | Pacific/Majuro |
    | Pacific/Marquesas |
    | Pacific/Midway |
    | Pacific/Nauru |
    | Pacific/Niue |
    | Pacific/Norfolk |
    | Pacific/Noumea |
    | Pacific/Pago_Pago |
    | Pacific/Palau |
    | Pacific/Pitcairn |
    | Pacific/Pohnpei |
    | Pacific/Port_Moresby |
    | Pacific/Rarotonga |
    | Pacific/Saipan |
    | Pacific/Tahiti |
    | Pacific/Tarawa |
    | Pacific/Tongatapu |
    | Pacific/Wake |
    | Pacific/Wallis |
    | US/Pacific-New |
    | WET |

### Transport { #Transport }

4 valid values.

??? note "Show values"

    | Value |
    |-------|
    | TCP |
    | UDP |
    | TLS |
    | TCP+UDP |

### Trunk { #Trunk }

5 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Ground Start |
    | Loop Start |
    | DID |
    | POTS |
    | EANDM |

### TrunkDirection { #TrunkDirection }

3 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Inbound |
    | Outbound |
    | Bothways |

### TrunkLevel { #TrunkLevel }

12 valid values.

??? note "Show values"

    | Value |
    |-------|
    | AAL(A) |
    | AAL(D) |
    | A/TT |
    | DAL |
    | ICS |
    | ISD/TT |
    | IST |
    | ONS |
    | OPS |
    | S/ATT |
    | S/DTT |
    | A/TO |

### TrunkPad { #TrunkPad }

65 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Minus32db |
    | Minus31db |
    | Minus30db |
    | Minus29db |
    | Minus28db |
    | Minus27db |
    | Minus26db |
    | Minus25db |
    | Minus24db |
    | Minus23db |
    | Minus22db |
    | Minus21db |
    | Minus20db |
    | Minus19db |
    | Minus18db |
    | Minus17db |
    | Minus16db |
    | Minus15db |
    | Minus14db |
    | Minus13db |
    | Minus12db |
    | Minus11db |
    | Minus10db |
    | Minus9db |
    | Minus8db |
    | Minus7db |
    | Minus6db |
    | Minus5db |
    | Minus4db |
    | Minus3db |
    | Minus2db |
    | Minus1db |
    | NoDbPadding |
    | Plus1db |
    | Plus2db |
    | Plus3db |
    | Plus4db |
    | Plus5db |
    | Plus6db |
    | Plus7db |
    | Plus8db |
    | Plus9db |
    | Plus10db |
    | Plus11db |
    | Plus12db |
    | Plus13db |
    | Plus14db |
    | Plus15db |
    | Plus16db |
    | Plus17db |
    | Plus18db |
    | Plus19db |
    | Plus20db |
    | Plus21db |
    | Plus22db |
    | Plus23db |
    | Plus24db |
    | Plus25db |
    | Plus26db |
    | Plus27db |
    | Plus28db |
    | Plus29db |
    | Plus30db |
    | Plus31db |
    | Plus32db |

### TrunkSelectionOrder { #TrunkSelectionOrder }

2 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Bottom Up |
    | Top Down |

### TrunkService { #TrunkService }

5 valid values.

??? note "Show values"

    | Value |
    |-------|
    | None(Default) |
    | Call Control Discovery |
    | Extension Mobility Cross Cluster |
    | Cisco Intercompany Media Engine |
    | IP Multimedia Subsystem Service Control (ISC) |

### TrustReceivedIdentity { #TrustReceivedIdentity }

3 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Trust All (Default) |
    | Trust PAI Only |
    | Trust None |

### TunneledProtocol { #TunneledProtocol }

2 valid values.

??? note "Show values"

    | Value |
    |-------|
    | None |
    | QSIG |

### UCProduct { #UCProduct }

13 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Unity |
    | Unity Connection |
    | Exchange |
    | MeetingPlace Classic |
    | MeetingPlace Express |
    | WebEx (Conferencing) |
    | Directory |
    | Unified CM (IM and Presence) |
    | WebEx (IM and Presence) |
    | CTI |
    | Enhanced Directory |
    | Telepresence Management System |
    | Jabber |

### UCService { #UCService }

8 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Voicemail |
    | MailStore |
    | Conferencing |
    | Directory |
    | IM and Presence |
    | CTI |
    | Video Conference Scheduling Portal |
    | Jabber Client Configuration (jabber-config.xml) |

### URIDisambiguationPolicy { #URIDisambiguationPolicy }

3 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Always treat all dial strings as URI addresses |
    | Phone number consists of characters 0-9, A-D, *, #, and + (others treated as URI addresses) |
    | Phone number consists of characters 0-9, *, #, and + (others treated as URI addresses) |

### UserAgentServerHeaderInfo { #UserAgentServerHeaderInfo }

3 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Send Unified CM Version Information as User-Agent Header |
    | Pass Through Received Information as Contact Header Parameters |
    | Pass Through Received Information as User-Agent and Server Header |

### UserLocale { #UserLocale }

1 valid values.

??? note "Show values"

    | Value |
    |-------|
    | English United States |

### V150SDPFilter { #V150SDPFilter }

4 valid values.

??? note "Show values"

    | Value |
    |-------|
    | No Filtering |
    | Remove MER V.150 |
    | Remove Pre-MER V.150 |
    | Use Default Filter |

### VMAvoidancePolicy { #VMAvoidancePolicy }

3 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Use System Default |
    | Timer Control |
    | User Control |

### VPNClientAuthentication { #VPNClientAuthentication }

3 valid values.

??? note "Show values"

    | Value |
    |-------|
    | User and Password |
    | Password Only |
    | Certificate |

### VideoCallTrafficClass { #VideoCallTrafficClass }

3 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Immersive |
    | Desktop |
    | Mixed |

### ViprFilterElement { #ViprFilterElement }

2 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Prefix |
    | Domain |

### WLANProfileChanges { #WLANProfileChanges }

3 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Allowed |
    | Disallowed |
    | Restricted |

### WiFiAuthenticationMethod { #WiFiAuthenticationMethod }

7 valid values.

??? note "Show values"

    | Value |
    |-------|
    | None |
    | WEP |
    | PSK |
    | EAP-FAST |
    | PEAP-MSCHAPv2 |
    | PEAP-GTC |
    | EAP-TLS |

### WiFiFrequency { #WiFiFrequency }

3 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Auto |
    | 2.4 GHz |
    | 5 GHz |

### YellowAlarm { #YellowAlarm }

2 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Bit2 |
    | F-Bit |

### ZeroSuppression { #ZeroSuppression }

3 valid values.

??? note "Show values"

    | Value |
    |-------|
    | B8ZS |
    | AMI |
    | HDB3 |

### Zzdndcontrol { #Zzdndcontrol }

2 valid values.

??? note "Show values"

    | Value |
    |-------|
    | User |
    | Admin |

### ZzdtmfDbLevel { #ZzdtmfDbLevel }

5 valid values.

??? note "Show values"

    | Value |
    |-------|
    | 6 dB below nominal |
    | 3 dB below nominal |
    | Nominal |
    | 3 dB above nominal |
    | 6 dB above nominal |

### Zzntpmode { #Zzntpmode }

4 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Unicast |
    | Multicast |
    | Anycast |
    | Directed Broadcast |

### Zzpreff { #Zzpreff }

2 valid values.

??? note "Show values"

    | Value |
    |-------|
    | Off |
    | On |

### ZzuserInfo { #ZzuserInfo }

3 valid values.

??? note "Show values"

    | Value |
    |-------|
    | None |
    | Phone |
    | IP |
