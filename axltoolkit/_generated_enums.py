"""
Auto-generated AXL enum types.

DO NOT EDIT — regenerate with ``python scripts/generate_models.py``.
"""

from __future__ import annotations

from enum import Enum


class _AxlStrEnum(str, Enum):
    """Base class for AXL string enums.

    Overrides ``__str__`` to return the value rather than the
    ``<ClassName>.<MEMBER>`` qualified name that Python 3.11+
    introduced for ``(str, Enum)`` mix-ins. This keeps SOAP
    serialization stable across Python 3.10 → 3.13 (and beyond).
    """

    def __str__(self) -> str:  # noqa: D401 - simple delegation
        """Return the enum's value (the XML wire format)."""
        return str(self.value)


class ASN1RoseOidEncoding(_AxlStrEnum):
    """AXL enum — ``XASN1RoseOidEncoding``.
    """

    NO_CHANGES = 'No Changes'
    USE_LOCAL_VALUE = 'Use Local Value'
    USE_GLOBAL_VALUE_ISO = 'Use Global Value ISO'
    USE_GLOBAL_VALUE_ECMA = 'Use Global Value ECMA'


class AlarmSeverity(_AxlStrEnum):
    """AXL enum — ``XAlarmSeverity``.
    """

    EMERGENCY = 'Emergency'
    ALERT = 'Alert'
    CRITICAL = 'Critical'
    ERROR = 'Error'
    WARNING = 'Warning'
    NOTICE = 'Notice'
    INFORMATIONAL = 'Informational'
    DEBUG = 'Debug'


class AnnouncementFile(_AxlStrEnum):
    """AXL enum — ``XAnnouncementFile``.
    """

    BUSY_TONE = 'Busy Tone'
    ALERTINGTONE = 'AlertingTone'
    REORDERTONE = 'ReorderTone'
    RECORDINGWARNING = 'RecordingWarning'
    TONE_ON_HOLD = 'Tone-on-Hold'
    MONITORINGWARNING = 'MonitoringWarning'
    BARGE_IN = 'Barge-In'
    WRONGPIN = 'WrongPin'
    UNAUTHORIZEDCALLER = 'UnauthorizedCaller'
    WRONGTARGETDN = 'WrongTargetDN'
    MOBILECONNECTON = 'MobileConnectOn'
    MOBILECONNECTOFF = 'MobileConnectOff'
    UNKNOWNCALLER = 'UnknownCaller'
    MLPP_PALA = 'MLPP-PALA'
    MLPP_ICA = 'MLPP-ICA'
    VCA = 'VCA'
    MLPP_BPA = 'MLPP-BPA'
    MLPP_BNEA = 'MLPP-BNEA'
    MLPP_UPA = 'MLPP-UPA'
    CALLDISALLOWED = 'CallDisallowed'
    V_900CALLSBLOCKED = '900CallsBlocked'
    INTLCALLSBLOCKED = 'IntlCallsBlocked'
    TOLLCALLSBLOCKED = 'TollCallsBlocked'
    DIRASSTBLOCKED = 'DirAsstBlocked'
    SILENCE_5SEC = 'Silence-5sec'
    ONEMOMENT = 'OneMoment'
    SHORTTONE = 'ShortTone'
    WELCOME_GREETING_SAMPLE = 'Welcome Greeting Sample'
    WAIT_IN_QUEUE_SAMPLE = 'Wait In Queue Sample'
    MOBILITY_VMA = 'Mobility_VMA'
    MLPP_PRECEDENCE_RINGBACK = 'MLPP-Precedence_RingBack'
    MLPP_PREEMPTION_TONE = 'MLPP-Preemption_tone'
    NON_SECURE_WARNING = 'Non-secure_Warning'
    SECURE_WARNING = 'Secure_Warning'
    ENTER_CMC = 'Enter_CMC'
    ENTER_FAC = 'Enter_FAC'
    ZIPTONE = 'ZipTone'
    ENTERCFBTONE = 'EnterCfbTone'
    EXITCFBTONE = 'ExitCfbTone'
    CONFERENCENOWGREETING = 'ConferenceNowGreeting'
    CONFERENCENOWNUMBERINVALID = 'ConferenceNowNumberInvalid'
    CONFERENCENOWNUMBERFAILURE = 'ConferenceNowNumberFailure'
    CONFERENCENOWENTERPIN = 'ConferenceNowEnterPin'
    CONFERENCENOWINVALIDPIN = 'ConferenceNowInvalidPin'
    CONFERENCENOWFAILEDPIN = 'ConferenceNowFailedPin'
    CONFERENCENOWCFBFAILED = 'ConferenceNowCFBFailed'
    CONFERENCENOWENTERACCESSCODE = 'ConferenceNowEnterAccessCode'
    CONFERENCENOWACCESSCODEINVALID = 'ConferenceNowAccessCodeInvalid'
    CONFERENCENOWACCESSCODEFAILED = 'ConferenceNowAccessCodeFailed'
    WELCOME = 'Welcome'
    PRESS1 = 'Press1'
    PRESS2 = 'Press2'
    PRESS3 = 'Press3'
    PRESS4 = 'Press4'
    PRESS5 = 'Press5'
    PRESS6 = 'Press6'
    PRESS7 = 'Press7'
    PRESS8 = 'Press8'
    PRESS9 = 'Press9'
    LANGUAGE = 'Language'
    ENTERREMOTE = 'EnterRemote'
    REENTERREMOTEUNKNOWN = 'ReenterRemoteUnknown'
    ENTERPIN = 'EnterPin'
    REENTERPINUNRECOGNIZED = 'ReenterPinUnrecognized'
    LOGGEDOUT = 'LoggedOut'
    PINEXPIRED = 'PinExpired'
    ATTEMPTSEXCEEDED = 'AttemptsExceeded'
    CALLPROMPT = 'CallPrompt'
    INVALIDKEY = 'InvalidKey'
    GOODBYE = 'Goodbye'
    ENTERNUMBER = 'EnterNumber'
    SELECTEXTENSION = 'SelectExtension'
    TURNONMOBILITY = 'TurnOnMobility'
    ENTERREMOTEON = 'EnterRemoteOn'
    OTHERREMOTE = 'OtherRemote'
    MOBILITYONALL = 'MobilityOnAll'
    MOBILITYFAILEDALL = 'MobilityFailedAll'
    MOBILITYON = 'MobilityOn'
    MOBILITYFAILED = 'MobilityFailed'
    TURNOFFMOBILITY = 'TurnOffMobility'
    ENTERREMOTEOFF = 'EnterRemoteOff'
    OTHERREMOTEOFF = 'OtherRemoteOff'
    MOBILITYOFFALL = 'MobilityOffAll'
    MOBILITYOFFALLFAILED = 'MobilityOffAllFailed'
    MOBILITYOFF = 'MobilityOff'
    MOBILITYOFFFAILED = 'MobilityOffFailed'
    ONE = 'One'
    TWO = 'Two'
    THREE = 'Three'
    FOUR = 'Four'
    FIVE = 'Five'
    SIX = 'Six'
    SEVEN = 'Seven'
    EIGHT = 'Eight'
    NINE = 'Nine'
    ZERO = 'Zero'
    RETURNPREVIOUS = 'ReturnPrevious'
    CONFIGERROR = 'ConfigError'
    NOEXTENSIONS = 'NoExtensions'
    NODESTINATIONS = 'NoDestinations'
    INTERNALERROR = 'InternalError'
    UNAVAILABLE = 'Unavailable'
    CONTACTADMIN = 'ContactAdmin'
    THANKYOU = 'ThankYou'
    GOODBYE2 = 'Goodbye2'
    RESOURCESUNAVAILABLE = 'ResourcesUnavailable'
    EXTENSIONINUSE = 'ExtensionInUse'
    TOGGLEON = 'ToggleOn'
    NOTAUTHORIZED = 'NotAuthorized'


class AppServer(_AxlStrEnum):
    """AXL enum — ``XAppServer``.
    """

    CISCO_UNITY_VOICE_MAIL_4_X_OR_LATER = 'Cisco Unity Voice Mail 4.x or later'
    CISCO_UNITY_CONNECTION = 'Cisco Unity Connection'
    CISCO_UNIFIED_CM_IM_AND_PRESENCE_OBSOLETE = 'Cisco Unified CM IM and Presence (Obsolete)'
    CUMA_PROVISIONING_SERVER = 'CUMA Provisioning Server'
    CER_LOCATION_MANAGEMENT = 'CER Location Management'
    CISCO_WEB_DIALER = 'Cisco Web Dialer'
    REMOTE_SYSLOG_SERVER = 'Remote Syslog Server'
    CISCO_WEBEX_HYBRID_CALL_SERVICE = 'Cisco Webex Hybrid Call Service'


class AppServerContent(_AxlStrEnum):
    """AXL enum — ``XAppServerContent``.
    """

    UNITY_KUBRIK = 'UNITY KUBRIK'
    UNITY_PRE_KUBRIK = 'UNITY PRE KUBRIK'
    UNITY_CONNECTION = 'UNITY_CONNECTION'


class AuthenticationMode(_AxlStrEnum):
    """AXL enum — ``XAuthenticationMode``.
    """

    BY_AUTHENTICATION_STRING = 'By Authentication String'
    BY_NULL_STRING = 'By Null String'
    BY_EXISTING_CERTIFICATE_PRECEDENCE_TO_LSC = 'By Existing Certificate (precedence to LSC)'
    BY_EXISTING_CERTIFICATE_PRECEDENCE_TO_MIC = 'By Existing Certificate (precedence to MIC)'


class AutoAnswer(_AxlStrEnum):
    """AXL enum — ``XAutoAnswer``.
    """

    AUTO_ANSWER_OFF = 'Auto Answer Off'
    AUTO_ANSWER_WITH_HEADSET = 'Auto Answer with Headset'
    AUTO_ANSWER_WITH_SPEAKERPHONE = 'Auto Answer with Speakerphone'


class BLFSDOption(_AxlStrEnum):
    """AXL enum — ``XBLFSDOption``.
    """

    PICKUP = 'Pickup'


class Barge(_AxlStrEnum):
    """AXL enum — ``XBarge``.
    """

    OFF = 'Off'
    BARGE = 'Barge'
    CBARGE = 'CBarge'
    DEFAULT = 'Default'


class Billingserverprotocol(_AxlStrEnum):
    """AXL enum — ``XBillingserverprotocol``.
    """

    SFTP = 'SFTP'
    FTP = 'FTP'


class BriProtocol(_AxlStrEnum):
    """AXL enum — ``XBriProtocol``.
    """

    BRI_NET3 = 'BRI NET3'
    NI = 'NI'
    QSIG = 'QSIG'


class CALHeaders(_AxlStrEnum):
    """AXL enum — ``XCALHeaders``.
    """

    DISABLED = 'Disabled'
    PREFERRED = 'Preferred'
    REQUIRED = 'Required'


class CALMode(_AxlStrEnum):
    """AXL enum — ``XCALMode``.
    """

    FIXED = 'Fixed'
    VARIABLE = 'Variable'


class CFACSSActivationPolicy(_AxlStrEnum):
    """AXL enum — ``XCFACSSActivationPolicy``.
    """

    USE_SYSTEM_DEFAULT = 'Use System Default'
    WITH_CONFIGURED_CSS = 'With Configured CSS'
    WITH_ACTIVATING_DEVICE_LINE_CSS = 'With Activating Device/Line CSS'


class CSUParam(_AxlStrEnum):
    """AXL enum — ``XCSUParam``.
    """

    V_0DB = '0dB'
    V_7_5DB = '-7.5dB'
    V_15DB = '-15dB'
    V_22_5DB = '-22.5dB'


class CUCMVersionInSipHeader(_AxlStrEnum):
    """AXL enum — ``XCUCMVersionInSipHeader``.
    """

    MAJOR_AND_MINOR = 'Major And Minor'
    MAJOR = 'Major'
    MAJOR_MINOR_AND_REVISION = 'Major, Minor And Revision'
    FULL_BUILD = 'Full Build'
    NONE_ = 'None'


class CallTreatmentOnFailure(_AxlStrEnum):
    """AXL enum — ``XCallTreatmentOnFailure``.
    """

    ALLOW_CALLS = 'Allow Calls'
    BLOCK_CALLS = 'Block Calls'


class CallerFilterMask(_AxlStrEnum):
    """AXL enum — ``XCallerFilterMask``.
    """

    DIRECTORY_NUMBER = 'Directory Number'
    NOT_AVAILABLE = 'Not Available'
    PRIVATE = 'Private'


class CallerID(_AxlStrEnum):
    """AXL enum — ``XCallerID``.
    """

    ANI = 'ANI'
    DNIS = 'DNIS'


class CallingLineIdentification(_AxlStrEnum):
    """AXL enum — ``XCallingLineIdentification``.
    """

    DEFAULT = 'Default'
    STRICT_FROM_URI_PRESENTATION_ONLY = 'Strict From URI presentation Only'
    STRICT_IDENTITY_HEADERS_PRESENTATION_ONLY = 'Strict Identity Headers presentation Only'


class CallingPartySelection(_AxlStrEnum):
    """AXL enum — ``XCallingPartySelection``.
    """

    ORIGINATOR = 'Originator'
    FIRST_REDIRECT_NUMBER = 'First Redirect Number'
    LAST_REDIRECT_NUMBER = 'Last Redirect Number'
    FIRST_REDIRECT_NUMBER_EXTERNAL = 'First Redirect Number (External)'
    LAST_REDIRECT_NUMBER_EXTERNAL = 'Last Redirect Number (External)'


class CertificateOperation(_AxlStrEnum):
    """AXL enum — ``XCertificateOperation``.
    """

    NO_PENDING_OPERATION = 'No Pending Operation'
    INSTALL_UPGRADE = 'Install/Upgrade'
    DELETE = 'Delete'
    TROUBLESHOOT = 'Troubleshoot'


class CertificateService(_AxlStrEnum):
    """AXL enum — ``XCertificateService``.
    """

    PHONE_TRUST = 'Phone-trust'
    PHONE_VPN_TRUST = 'Phone-VPN-trust'
    CALLMANAGER = 'CallManager'
    CALLMANAGER_TRUST = 'CallManager-trust'
    TOMCAT = 'tomcat'
    TOMCAT_TRUST = 'tomcat-trust'
    IPSEC = 'ipsec'
    IPSEC_TRUST = 'ipsec-trust'
    CAPF = 'CAPF'
    CAPF_TRUST = 'CAPF-trust'
    TVS = 'TVS'
    TVS_TRUST = 'TVS-trust'
    DIRECTORY_TRUST = 'directory-trust'
    PHONE_SAST_TRUST = 'Phone-SAST-trust'
    PHONE_CTL_TRUST = 'Phone-CTL-trust'
    USERLICENSING_TRUST = 'userlicensing-trust'
    ITLRECOVERY = 'ITLRecovery'
    CALLMANAGER_ECDSA = 'CallManager-ECDSA'
    TOMCAT_ECDSA = 'tomcat-ECDSA'
    PHONE_CTL_ASA_TRUST = 'Phone-CTL-ASA-trust'
    PHONE_EDGE_TRUST = 'Phone-Edge-trust'


class CertificateStatus(_AxlStrEnum):
    """AXL enum — ``XCertificateStatus``.
    """

    NONE_ = 'None'
    OPERATION_PENDING = 'Operation Pending'
    UPGRADE_SUCCESS = 'Upgrade Success'
    DELETE_SUCCESS = 'Delete Success'
    TROUBLESHOOT_SUCCESS = 'Troubleshoot Success'
    UPGRADE_FAILED = 'Upgrade Failed'
    DELETE_FAILED = 'Delete Failed'
    TROUBLESHOOT_FAILED = 'Troubleshoot Failed'
    UPGRADE_FAILED_INVALID_LSC = 'Upgrade Failed: Invalid LSC'
    UPGRADE_FAILED_INVALID_AUTHENTICATION_STRING = 'Upgrade Failed: Invalid Authentication String'
    UPGRADE_FAILED_INVALID_MIC = 'Upgrade Failed: Invalid MIC'
    UPGRADE_FAILED_INVALID_CREDENTIALS = 'Upgrade Failed: Invalid Credentials'
    UPGRADE_FAILED_PHONE_COMMUNICATION_FAILURE = 'Upgrade Failed: Phone Communication Failure'
    UPGRADE_FAILED_KEY_GENERATION_FAILED_TIMEOUT = 'Upgrade Failed: Key Generation Failed/Timeout'
    UPGRADE_FAILED_CA_COMMUNICATION_FAILURE = 'Upgrade Failed: CA Communication Failure'
    UPGRADE_FAILED_CA_REJECTED_CONNECTION = 'Upgrade Failed: CA Rejected Connection'
    UPGRADE_FAILED_USER_INITIATED_REQUEST_LATE_TIMEDOUT = 'Upgrade Failed: User Initiated Request Late/Timedout'
    DELETE_FAILED_INVALID_LSC = 'Delete Failed: Invalid LSC'
    DELETE_FAILED_INVALID_AUTHENTICATION_STRING = 'Delete Failed: Invalid Authentication String'
    DELETE_FAILED_INVALID_MIC = 'Delete Failed: Invalid MIC'
    DELETE_FAILED_INVALID_CREDENTIALS = 'Delete Failed: Invalid Credentials'
    DELETE_FAILED_PHONE_COMMUNICATION_FAILURE = 'Delete Failed: Phone Communication Failure'
    DELETE_FAILED_KEY_GENERATION_FAILED_TIMEOUT = 'Delete Failed: Key Generation Failed/Timeout'
    DELETE_FAILED_CA_COMMUNICATION_FAILURE = 'Delete Failed: CA Communication Failure'
    DELETE_FAILED_CA_REJECTED_CONNECTION = 'Delete Failed: CA Rejected Connection'
    DELETE_FAILED_USER_INITIATED_REQUEST_LATE_TIMEDOUT = 'Delete Failed: User Initiated Request Late/Timedout'
    TROUBLESHOOT_FAILED_INVALID_LSC = 'Troubleshoot Failed: Invalid LSC'
    TROUBLESHOOT_FAILED_INVALID_AUTHENTICATION_STRING = 'Troubleshoot Failed: Invalid Authentication String'
    TROUBLESHOOT_FAILED_INVALID_MIC = 'Troubleshoot Failed: Invalid MIC'
    TROUBLESHOOT_FAILED_INVALID_CREDENTIALS = 'Troubleshoot Failed: Invalid Credentials'
    TROUBLESHOOT_FAILED_PHONE_COMMUNICATION_FAILURE = 'Troubleshoot Failed: Phone Communication Failure'
    TROUBLESHOOT_FAILED_KEY_GENERATION_FAILED_TIMEOUT = 'Troubleshoot Failed: Key Generation Failed/Timeout'
    TROUBLESHOOT_FAILED_USER_INITIATED_REQUEST_LATE_TIMEDOUT = 'Troubleshoot Failed: User Initiated Request Late/Timedout'
    UPGRADE_FAILED_NO_SUPPORT_FOR_EC_ONLY_IN_CAPF_VERSION_3 = 'Upgrade Failed: No Support for EC only in CAPF version 3'


class CertificateVerificationLevel(_AxlStrEnum):
    """AXL enum — ``XCertificateVerificationLevel``.
    """

    ANY_CERTIFICATE = 'Any Certificate'
    SELF_SIGNED_OR_KEYSTORE = 'Self-signed or Keystore'
    KEYSTORE_ONLY = 'Keystore Only'


class ChangeAction(_AxlStrEnum):
    """AXL enum — ``XChangeAction``.
    """

    A = 'a'
    R = 'r'
    U = 'u'


class ChangeType(_AxlStrEnum):
    """AXL enum — ``XChangeType``.
    """

    AARGROUP = 'AarGroup'
    AARGROUPMATRIX = 'AarGroupMatrix'
    ADVERTISEDPATTERNS = 'AdvertisedPatterns'
    ANNOUNCEMENT = 'Announcement'
    ANNUNCIATOR = 'Annunciator'
    APPSERVERINFO = 'AppServerInfo'
    APPUSER = 'AppUser'
    APPLICATIONDIALRULES = 'ApplicationDialRules'
    APPLICATIONSERVER = 'ApplicationServer'
    APPLICATIONUSERCAPFPROFILE = 'ApplicationUserCapfProfile'
    ASSIGNEDPRESENCESERVERS = 'AssignedPresenceServers'
    ASSIGNEDPRESENCEUSERS = 'AssignedPresenceUsers'
    AUDIOCODECPREFERENCELIST = 'AudioCodecPreferenceList'
    BILLINGSERVER = 'BillingServer'
    BLOCKEDLEARNEDPATTERNS = 'BlockedLearnedPatterns'
    CCAPROFILES = 'CCAProfiles'
    CALLMANAGER = 'CallManager'
    CALLMANAGERGROUP = 'CallManagerGroup'
    CALLPARK = 'CallPark'
    CALLPICKUPGROUP = 'CallPickupGroup'
    CALLEDPARTYTRACING = 'CalledPartyTracing'
    CALLEDPARTYTRANSFORMATIONPATTERN = 'CalledPartyTransformationPattern'
    CALLERFILTERLIST = 'CallerFilterList'
    CALLINGPARTYTRANSFORMATIONPATTERN = 'CallingPartyTransformationPattern'
    CCDADVERTISINGSERVICE = 'CcdAdvertisingService'
    CCDHOSTEDDN = 'CcdHostedDN'
    CCDHOSTEDDNGROUP = 'CcdHostedDNGroup'
    CCDREQUESTINGSERVICE = 'CcdRequestingService'
    CISCOCATALYST600024PORTFXSGATEWAY = 'CiscoCatalyst600024PortFXSGateway'
    CISCOCATALYST6000E1VOIPGATEWAY = 'CiscoCatalyst6000E1VoIPGateway'
    CISCOCATALYST6000T1VOIPGATEWAYPRI = 'CiscoCatalyst6000T1VoIPGatewayPri'
    CISCOCATALYST6000T1VOIPGATEWAYT1 = 'CiscoCatalyst6000T1VoIPGatewayT1'
    CISCOCLOUDONBOARDING = 'CiscoCloudOnboarding'
    CMCINFO = 'CmcInfo'
    COMMONDEVICECONFIG = 'CommonDeviceConfig'
    COMMONPHONECONFIG = 'CommonPhoneConfig'
    CONFERENCEBRIDGE = 'ConferenceBridge'
    CONFERENCENOW = 'ConferenceNow'
    CREDENTIALPOLICY = 'CredentialPolicy'
    CREDENTIALPOLICYDEFAULT = 'CredentialPolicyDefault'
    CSS = 'Css'
    CTIROUTEPOINT = 'CtiRoutePoint'
    CUMASERVERSECURITYPROFILE = 'CumaServerSecurityProfile'
    CUSTOMUSERFIELD = 'CustomUserField'
    CUSTOMER = 'Customer'
    DATETIMEGROUP = 'DateTimeGroup'
    DDI = 'Ddi'
    DEFAULTDEVICEPROFILE = 'DefaultDeviceProfile'
    DEVICEDEFAULTS = 'DeviceDefaults'
    DEVICEMOBILITY = 'DeviceMobility'
    DEVICEMOBILITYGROUP = 'DeviceMobilityGroup'
    DEVICEPOOL = 'DevicePool'
    DEVICEPROFILE = 'DeviceProfile'
    DHCPSERVER = 'DhcpServer'
    DHCPSUBNET = 'DhcpSubnet'
    DIALPLAN = 'DialPlan'
    DIALPLANTAG = 'DialPlanTag'
    DIRNUMBERALIASLOOKUPANDSYNC = 'DirNumberAliasLookupandSync'
    DIRECTEDCALLPARK = 'DirectedCallPark'
    DIRECTORYLOOKUPDIALRULES = 'DirectoryLookupDialRules'
    ELINGROUP = 'ElinGroup'
    EMCCFEATURECONFIG = 'EmccFeatureConfig'
    ENDUSERCAPFPROFILE = 'EndUserCapfProfile'
    ENTERPRISEFEATUREACCESSCONFIGURATION = 'EnterpriseFeatureAccessConfiguration'
    EXPRESSWAYCCONFIGURATION = 'ExpresswayCConfiguration'
    EXTERNALCALLCONTROLPROFILE = 'ExternalCallControlProfile'
    FACINFO = 'FacInfo'
    FALLBACKPROFILE = 'FallbackProfile'
    FEATURECONTROLPOLICY = 'FeatureControlPolicy'
    FEATUREGROUPTEMPLATE = 'FeatureGroupTemplate'
    FIXEDMOHAUDIOSOURCE = 'FixedMohAudioSource'
    GATEKEEPER = 'Gatekeeper'
    GATEWAY = 'Gateway'
    GATEWAYENDPOINTANALOGACCESS = 'GatewayEndpointAnalogAccess'
    GATEWAYENDPOINTDIGITALACCESSBRI = 'GatewayEndpointDigitalAccessBri'
    GATEWAYENDPOINTDIGITALACCESSPRI = 'GatewayEndpointDigitalAccessPri'
    GATEWAYENDPOINTDIGITALACCESST1 = 'GatewayEndpointDigitalAccessT1'
    GATEWAYSCCPENDPOINTS = 'GatewaySccpEndpoints'
    GATEWAYSUBUNITS = 'GatewaySubunits'
    GEOLOCATION = 'GeoLocation'
    GEOLOCATIONFILTER = 'GeoLocationFilter'
    GEOLOCATIONPOLICY = 'GeoLocationPolicy'
    H323GATEWAY = 'H323Gateway'
    H323PHONE = 'H323Phone'
    H323TRUNK = 'H323Trunk'
    HANDOFFCONFIGURATION = 'HandoffConfiguration'
    HTTPPROFILE = 'HttpProfile'
    HUNTLIST = 'HuntList'
    HUNTPILOT = 'HuntPilot'
    IMECLIENT = 'ImeClient'
    IMEE164TRANSFORMATION = 'ImeE164Transformation'
    IMEENROLLEDPATTERN = 'ImeEnrolledPattern'
    IMEENROLLEDPATTERNGROUP = 'ImeEnrolledPatternGroup'
    IMEEXCLUSIONNUMBER = 'ImeExclusionNumber'
    IMEEXCLUSIONNUMBERGROUP = 'ImeExclusionNumberGroup'
    IMEFIREWALL = 'ImeFirewall'
    IMEROUTEFILTERELEMENT = 'ImeRouteFilterElement'
    IMEROUTEFILTERGROUP = 'ImeRouteFilterGroup'
    IMESERVER = 'ImeServer'
    IMPORTEDDIRECTORYURICATALOGS = 'ImportedDirectoryUriCatalogs'
    INFRASTRUCTUREDEVICE = 'InfrastructureDevice'
    INTERCLUSTERSERVICEPROFILE = 'InterClusterServiceProfile'
    INTERACTIVEVOICERESPONSE = 'InteractiveVoiceResponse'
    IPPHONESERVICES = 'IpPhoneServices'
    IVRUSERLOCALE = 'IvrUserLocale'
    LBMGROUP = 'LbmGroup'
    LBMHUBGROUP = 'LbmHubGroup'
    LDAPDIRECTORY = 'LdapDirectory'
    LDAPFILTER = 'LdapFilter'
    LDAPSEARCH = 'LdapSearch'
    LDAPSYNCCUSTOMFIELD = 'LdapSyncCustomField'
    LICENSEDUSER = 'LicensedUser'
    LINE = 'Line'
    LINEGROUP = 'LineGroup'
    LOCALROUTEGROUP = 'LocalRouteGroup'
    LOCATION = 'Location'
    MEDIARESOURCEGROUP = 'MediaResourceGroup'
    MEDIARESOURCELIST = 'MediaResourceList'
    MEETME = 'MeetMe'
    MESSAGEWAITING = 'MessageWaiting'
    MLPPDOMAIN = 'MlppDomain'
    MOBILESMARTCLIENTPROFILE = 'MobileSmartClientProfile'
    MOBILEVOICEACCESS = 'MobileVoiceAccess'
    MOBILITYPROFILE = 'MobilityProfile'
    MOHAUDIOSOURCE = 'MohAudioSource'
    MOHSERVER = 'MohServer'
    MRASERVICEDOMAIN = 'MraServiceDomain'
    MTP = 'Mtp'
    NETWORKACCESSPROFILE = 'NetworkAccessProfile'
    PHONE = 'Phone'
    PHONEACTIVATIONCODE = 'PhoneActivationCode'
    PHONEBUTTONTEMPLATE = 'PhoneButtonTemplate'
    PHONENTP = 'PhoneNtp'
    PHONESECURITYPROFILE = 'PhoneSecurityProfile'
    PHYSICALLOCATION = 'PhysicalLocation'
    PRESENCEGROUP = 'PresenceGroup'
    PRESENCEREDUNDANCYGROUP = 'PresenceRedundancyGroup'
    PROCESSNODE = 'ProcessNode'
    PROCESSNODESERVICE = 'ProcessNodeService'
    RECORDINGPROFILE = 'RecordingProfile'
    REGION = 'Region'
    REGIONMATRIX = 'RegionMatrix'
    REGISTRATIONDYNAMIC = 'RegistrationDynamic'
    REMOTECLUSTER = 'RemoteCluster'
    REMOTEDESTINATION = 'RemoteDestination'
    REMOTEDESTINATIONPROFILE = 'RemoteDestinationProfile'
    RESOURCEPRIORITYNAMESPACE = 'ResourcePriorityNamespace'
    RESOURCEPRIORITYNAMESPACELIST = 'ResourcePriorityNamespaceList'
    ROUTEFILTER = 'RouteFilter'
    ROUTEGROUP = 'RouteGroup'
    ROUTELIST = 'RouteList'
    ROUTEPARTITION = 'RoutePartition'
    ROUTEPATTERN = 'RoutePattern'
    ROUTEPLAN = 'RoutePlan'
    SIPNORMALIZATIONSCRIPT = 'SIPNormalizationScript'
    SAFCCDPURGEBLOCKLEARNEDROUTES = 'SafCcdPurgeBlockLearnedRoutes'
    SAFFORWARDER = 'SafForwarder'
    SAFSECURITYPROFILE = 'SafSecurityProfile'
    SDPTRANSPARENCYPROFILE = 'SdpTransparencyProfile'
    SECURECONFIG = 'SecureConfig'
    SERVICEPARAMETER = 'ServiceParameter'
    SERVICEPROFILE = 'ServiceProfile'
    SIPDIALRULES = 'SipDialRules'
    SIPPROFILE = 'SipProfile'
    SIPREALM = 'SipRealm'
    SIPROUTEPATTERN = 'SipRoutePattern'
    SIPTRUNK = 'SipTrunk'
    SIPTRUNKSECURITYPROFILE = 'SipTrunkSecurityProfile'
    SOFTKEYTEMPLATE = 'SoftKeyTemplate'
    SRST = 'Srst'
    TIMEPERIOD = 'TimePeriod'
    TIMESCHEDULE = 'TimeSchedule'
    TODACCESS = 'TodAccess'
    TRANSPATTERN = 'TransPattern'
    TRANSCODER = 'Transcoder'
    TRANSFORMATIONPROFILE = 'TransformationProfile'
    TVSCERTIFICATE = 'TvsCertificate'
    UCSERVICE = 'UcService'
    UNASSIGNEDDEVICE = 'UnassignedDevice'
    UNASSIGNEDPRESENCESERVERS = 'UnassignedPresenceServers'
    UNASSIGNEDPRESENCEUSERS = 'UnassignedPresenceUsers'
    UNITSTOGATEWAY = 'UnitsToGateway'
    UNIVERSALDEVICETEMPLATE = 'UniversalDeviceTemplate'
    UNIVERSALLINETEMPLATE = 'UniversalLineTemplate'
    USER = 'User'
    USERGROUP = 'UserGroup'
    USERPHONEASSOCIATION = 'UserPhoneAssociation'
    USERPROFILEPROVISION = 'UserProfileProvision'
    VG224 = 'Vg224'
    VOHSERVER = 'VohServer'
    VOICEMAILPILOT = 'VoiceMailPilot'
    VOICEMAILPORT = 'VoiceMailPort'
    VOICEMAILPROFILE = 'VoiceMailProfile'
    VPNGATEWAY = 'VpnGateway'
    VPNGROUP = 'VpnGroup'
    VPNPROFILE = 'VpnProfile'
    WLANPROFILE = 'WLANProfile'
    WIFIHOTSPOT = 'WifiHotspot'
    WIRELESSACCESSPOINTCONTROLLERS = 'WirelessAccessPointControllers'
    WLANPROFILEGROUP = 'WlanProfileGroup'


class Class(_AxlStrEnum):
    """AXL enum — ``XClass``.
    """

    PHONE = 'Phone'
    GATEWAY = 'Gateway'
    CONFERENCE_BRIDGE = 'Conference Bridge'
    MEDIA_TERMINATION_POINT = 'Media Termination Point'
    ROUTE_LIST = 'Route List'
    VOICE_MAIL = 'Voice Mail'
    CTI_ROUTE_POINT = 'CTI Route Point'
    MUSIC_ON_HOLD = 'Music On Hold'
    SIMULATION = 'Simulation'
    PILOT = 'Pilot'
    GATEKEEPER = 'GateKeeper'
    ADD_ON_MODULES = 'Add-on modules'
    HIDDEN_PHONE = 'Hidden Phone'
    TRUNK = 'Trunk'
    TONE_ANNOUNCEMENT_PLAYER = 'Tone Announcement Player'
    REMOTE_DESTINATION_PROFILE = 'Remote Destination Profile'
    EMCC_BASE_PHONE_TEMPLATE = 'EMCC Base Phone Template'
    EMCC_BASE_PHONE = 'EMCC Base Phone'
    REMOTE_DESTINATION_PROFILE_TEMPLATE = 'Remote Destination Profile Template'
    GATEWAY_TEMPLATE = 'Gateway Template'
    UDP_TEMPLATE = 'UDP Template'
    PHONE_TEMPLATE = 'Phone Template'
    DEVICE_PROFILE = 'Device Profile'
    INVALID = 'Invalid'
    INTERACTIVE_VOICE_RESPONSE = 'Interactive Voice Response'


class ClockReference(_AxlStrEnum):
    """AXL enum — ``XClockReference``.
    """

    NETWORK = 'Network'
    INTERNAL = 'Internal'
    SPAN_1 = 'Span 1'
    SPAN_2 = 'Span 2'
    SPAN_3 = 'Span 3'
    SPAN_4 = 'Span 4'
    SPAN_5 = 'Span 5'
    SPAN_6 = 'Span 6'
    SPAN_7 = 'Span 7'
    SPAN_8 = 'Span 8'


class ConnectProtocol(_AxlStrEnum):
    """AXL enum — ``XConnectProtocol``.
    """

    HTTP = 'HTTP'
    HTTPS = 'HTTPS'
    TCP = 'TCP'
    TCP_PLUS_UDP = 'TCP + UDP'
    UDP = 'UDP'
    SSL = 'SSL'
    TLS = 'TLS'
    SIP = 'SIP'
    OWA = 'OWA'
    SOAP = 'SOAP'
    EWS = 'EWS'
    XMPP = 'XMPP'


class Country(_AxlStrEnum):
    """AXL enum — ``XCountry``.
    """

    ARGENTINA = 'Argentina'
    AUSTRALIA = 'Australia'
    AUSTRIA = 'Austria'
    BELGIUM = 'Belgium'
    BRAZIL = 'Brazil'
    CANADA = 'Canada'
    CHINA = 'China'
    COLOMBIA = 'Colombia'
    CYPRUS = 'Cyprus'
    CZECH_REPUBLIC = 'Czech Republic'
    DENMARK = 'Denmark'
    EGYPT = 'Egypt'
    FINLAND = 'Finland'
    FRANCE = 'France'
    GERMANY = 'Germany'
    GHANA = 'Ghana'
    GREECE = 'Greece'
    HONG_KONG = 'Hong Kong'
    HUNGARY = 'Hungary'
    ICELAND = 'Iceland'
    INDIA = 'India'
    INDONESIA = 'Indonesia'
    IRELAND = 'Ireland'
    ISRAEL = 'Israel'
    ITALY = 'Italy'
    JAPAN = 'Japan'
    JORDAN = 'Jordan'
    KENYA = 'Kenya'
    KOREA_REPUBLIC = 'Korea Republic'
    LEBANON = 'Lebanon'
    LUXEMBOURG = 'Luxembourg'
    MALAYSIA = 'Malaysia'
    MEXICO = 'Mexico'
    NEPAL = 'Nepal'
    NETHERLANDS = 'Netherlands'
    NEW_ZEALAND = 'New Zealand'
    NIGERIA = 'Nigeria'
    NORWAY = 'Norway'
    PAKISTAN = 'Pakistan'
    PANAMA = 'Panama'
    PERU = 'Peru'
    PHILIPPINES = 'Philippines'
    POLAND = 'Poland'
    PORTUGAL = 'Portugal'
    RUSSIAN_FEDERATION = 'Russian Federation'
    SAUDI_ARABIA = 'Saudi Arabia'
    SINGAPORE = 'Singapore'
    SLOVAKIA = 'Slovakia'
    SLOVENIA = 'Slovenia'
    SOUTH_AFRICA = 'South Africa'
    SPAIN = 'Spain'
    SWEDEN = 'Sweden'
    SWITZERLAND = 'Switzerland'
    TAIWAN = 'Taiwan'
    THAILAND = 'Thailand'
    TRKIYE = 'TÃ¼rkiye'
    UNITED_KINGDOM = 'United Kingdom'
    UNITED_STATES = 'United States'
    VENEZUELA = 'Venezuela'
    ZIMBABWE = 'Zimbabwe'
    ITU = 'Itu'
    CHILE = 'Chile'
    BULGARIA = 'Bulgaria'
    CROATIA = 'Croatia'
    ROMANIA = 'Romania'
    SERBIA_AND_MONTENEGRO = 'Serbia and Montenegro'
    UNITED_ARAB_EMIRATES = 'United Arab Emirates'
    OMAN = 'Oman'
    KUWAIT = 'Kuwait'
    ALGERIA = 'Algeria'
    BAHRAIN = 'Bahrain'
    IRAQ = 'Iraq'
    MAURITANIA = 'Mauritania'
    REPUBLIC_OF_MONTENEGRO = 'Republic of Montenegro'
    MOROCCO = 'Morocco'
    QATAR = 'Qatar'
    REPUBLIC_OF_SERBIA = 'Republic of Serbia'
    SUDAN = 'Sudan'
    TUNISIA = 'Tunisia'
    VIETNAM = 'Vietnam'
    YEMEN = 'Yemen'
    LITHUANIA = 'Lithuania'
    LATVIA = 'Latvia'
    ESTONIA = 'Estonia'
    UKRAINE = 'Ukraine'


class Credential(_AxlStrEnum):
    """AXL enum — ``XCredential``.
    """

    PASSWORD = 'Password'
    PIN = 'PIN'


class CredentialUser(_AxlStrEnum):
    """AXL enum — ``XCredentialUser``.
    """

    END_USER = 'End User'
    APPLICATION_USER = 'Application User'


class DNDOption(_AxlStrEnum):
    """AXL enum — ``XDNDOption``.
    """

    RINGER_OFF = 'Ringer Off'
    CALL_REJECT = 'Call Reject'
    USE_COMMON_PHONE_PROFILE_SETTING = 'Use Common Phone Profile Setting'


class DTMFSignaling(_AxlStrEnum):
    """AXL enum — ``XDTMFSignaling``.
    """

    NO_PREFERENCE = 'No Preference'
    OUT_OF_BAND = 'Out of Band'
    RFC_2833 = 'RFC 2833'
    OOB_AND_RFC_2833 = 'OOB and RFC 2833'


class DayOfWeek(_AxlStrEnum):
    """AXL enum — ``XDayOfWeek``.
    """

    SUN = 'Sun'
    MON = 'Mon'
    TUE = 'Tue'
    WED = 'Wed'
    THU = 'Thu'
    FRI = 'Fri'
    SAT = 'Sat'
    NONE_ = 'None'


class DeviceProtocol(_AxlStrEnum):
    """AXL enum — ``XDeviceProtocol``.
    """

    SCCP = 'SCCP'
    DIGITAL_ACCESS_PRI = 'Digital Access PRI'
    H_225 = 'H.225'
    ANALOG_ACCESS = 'Analog Access'
    DIGITAL_ACCESS_T1 = 'Digital Access T1'
    ROUTE_POINT = 'Route Point'
    UNICAST_BRIDGE = 'Unicast Bridge'
    MULTICAST_POINT = 'Multicast Point'
    INTER_CLUSTER_TRUNK = 'Inter-Cluster Trunk'
    RAS = 'RAS'
    DIGITAL_ACCESS_BRI = 'Digital Access BRI'
    SIP = 'SIP'
    MGCP = 'MGCP'
    STATIC_SIP_MOBILE_SUBSCRIBER = 'Static SIP Mobile Subscriber'
    SIP_CONNECTOR = 'SIP Connector'
    REMOTE_DESTINATION = 'Remote Destination'
    MOBILE_SMART_CLIENT = 'Mobile Smart Client'
    DIGITAL_ACCESS_E1_R2 = 'Digital Access E1 R2'
    CTI_REMOTE_DEVICE = 'CTI Remote Device'
    PROTOCOL_NOT_SPECIFIED = 'Protocol Not Specified'


class DeviceSecurityMode(_AxlStrEnum):
    """AXL enum — ``XDeviceSecurityMode``.
    """

    NON_SECURE = 'Non Secure'
    AUTHENTICATED = 'Authenticated'
    ENCRYPTED = 'Encrypted'


class DeviceTrustMode(_AxlStrEnum):
    """AXL enum — ``XDeviceTrustMode``.
    """

    NOT_TRUSTED = 'Not Trusted'
    TRUSTED = 'Trusted'


class DialParameter(_AxlStrEnum):
    """AXL enum — ``XDialParameter``.
    """

    PATTERN = 'Pattern'
    BUTTON = 'Button'
    TIMEOUT = 'Timeout'
    USER = 'User'


class DialPattern(_AxlStrEnum):
    """AXL enum — ``XDialPattern``.
    """

    V_7905_7912 = '7905_7912'
    V_7940_7960_OTHER = '7940_7960_OTHER'


class DialViaOffice(_AxlStrEnum):
    """AXL enum — ``XDialViaOffice``.
    """

    DIAL_VIA_OFFICE_REVERSE = 'Dial via Office Reverse'
    DIAL_VIA_OFFICE_FORWARD = 'Dial via Office Forward'


class DigitSending(_AxlStrEnum):
    """AXL enum — ``XDigitSending``.
    """

    DTMF = 'DTMF'
    MF = 'MF'
    PULSE = 'PULSE'


class DistributeAlgorithm(_AxlStrEnum):
    """AXL enum — ``XDistributeAlgorithm``.
    """

    TOP_DOWN = 'Top Down'
    CIRCULAR = 'Circular'
    LONGEST_IDLE_TIME = 'Longest Idle Time'
    BROADCAST = 'Broadcast'


class ECKeySize(_AxlStrEnum):
    """AXL enum — ``XECKeySize``.
    """

    V_256 = '256'
    V_384 = '384'
    V_521 = '521'


class EOSuppVoiceCall(_AxlStrEnum):
    """AXL enum — ``XEOSuppVoiceCall``.
    """

    DISABLED_DEFAULT_VALUE = 'Disabled (Default value)'
    BEST_EFFORT_NO_MTP_INSERTED = 'Best Effort (no MTP inserted)'
    MANDATORY_INSERT_MTP_IF_NEEDED = 'Mandatory (insert MTP if needed)'


class Encode(_AxlStrEnum):
    """AXL enum — ``XEncode``.
    """

    A_LAW = 'A-law'
    U_LAW = 'u-law'


class EndpointConnection(_AxlStrEnum):
    """AXL enum — ``XEndpointConnection``.
    """

    CDP = 'CDP'
    LLDP = 'LLDP'
    SSID = 'SSID'
    SWITCH = 'SWITCH'


class FDLChannel(_AxlStrEnum):
    """AXL enum — ``XFDLChannel``.
    """

    ATANDT_54016 = 'AT&T 54016'
    ANSI_T1_403_NI = 'ANSI T1.403 NI'
    ANSI_T1_403_CI = 'ANSI T1.403.CI'
    NONE_ = 'None'


class FallBackCSSSelection(_AxlStrEnum):
    """AXL enum — ``XFallBackCSSSelection``.
    """

    CALLING_DEVICE_AAR_CALLING_SEARCH_SPACE = 'Calling device AAR Calling Search Space'
    TRUNK_REROUTE_CALLING_SEARCH_SPACE = 'Trunk ReRoute Calling Search Space'


class Feature(_AxlStrEnum):
    """AXL enum — ``XFeature``.
    """

    REDIAL = 'Redial'
    SPEED_DIAL = 'Speed Dial'
    HOLD = 'Hold'
    TRANSFER = 'Transfer'
    FORWARD_ALL = 'Forward All'
    DISPLAY = 'Display'
    LINE = 'Line'
    CHAT = 'Chat'
    WHITEBOARD = 'Whiteboard'
    APPLICATION_SHARING = 'Application Sharing'
    FILE_TRANSFER = 'File Transfer'
    VIDEO = 'Video'
    MESSAGE_WAITING = 'Message Waiting'
    ANSWER_RELEASE = 'Answer/Release'
    AUTO_ANSWER = 'Auto Answer'
    SETTINGS = 'Settings'
    PRIVACY = 'Privacy'
    SERVICE_URL = 'Service URL'
    SPEED_DIAL_BLF = 'Speed Dial BLF'
    CALL_PARK_BLF = 'Call Park BLF'
    INTERCOM = 'Intercom'
    MALICIOUS_CALL_IDENTIFICATION = 'Malicious Call Identification'
    MEET_ME_CONFERENCE = 'Meet Me Conference'
    CONFERENCE = 'Conference'
    CALL_PARK = 'Call Park'
    CALL_PICKUP = 'Call Pickup'
    GROUP_CALL_PICKUP = 'Group Call Pickup'
    MOBILITY = 'Mobility'
    DO_NOT_DISTURB = 'Do Not Disturb'
    CONFERENCE_LIST = 'Conference List'
    REMOVE_LAST_PARTICIPANT = 'Remove Last Participant'
    QUALITY_REPORTING_TOOL = 'Quality Reporting Tool'
    CALLBACK = 'CallBack'
    OTHER_PICKUP = 'Other Pickup'
    VIDEO_MODE = 'Video Mode'
    NEW_CALL = 'New Call'
    END_CALL = 'End Call'
    HUNT_GROUP_LOGOUT = 'Hunt Group Logout'
    ALL_CALLS = 'All Calls'
    ANSWER_OLDEST = 'Answer Oldest'
    ALERTING_CALLS = 'Alerting Calls'
    QUEUE_STATUS = 'Queue Status'
    RECORD = 'Record'
    SERVICES = 'Services'
    MESSAGES = 'Messages'
    DIRECTORIES = 'Directories'
    INFORMATION = 'Information'
    APPLICATION_MENU = 'Application Menu'
    HEADSET = 'Headset'
    AEC = 'AEC'
    NONE_ = 'None'


class GClear(_AxlStrEnum):
    """AXL enum — ``XGClear``.
    """

    DISABLED = 'Disabled'
    CLEARMODE = 'CLEARMODE'
    CCD = 'CCD'
    G_NX64 = 'G.nX64'
    X_CCD = 'X-CCD'


class GeoLocationDevice(_AxlStrEnum):
    """AXL enum — ``XGeoLocationDevice``.
    """

    BORDER = 'Border'
    INTERIOR = 'Interior'


class GlobalNumber(_AxlStrEnum):
    """AXL enum — ``XGlobalNumber``.
    """

    ENTERPRISE_NUMBER = 'Enterprise Number'
    PLUSE_164_NUMBER = '+E.164 Number'


class HTTPProxy(_AxlStrEnum):
    """AXL enum — ``XHTTPProxy``.
    """

    NONE_ = 'None'
    MANUAL = 'Manual'
    AUTO = 'Auto'


class HostedRoutePatternPSTNRule(_AxlStrEnum):
    """AXL enum — ``XHostedRoutePatternPSTNRule``.
    """

    USE_PATTERN = 'Use pattern'
    SPECIFY = 'Specify'
    NO_PSTN = 'No PSTN'


class HotspotAuthenticationMethod(_AxlStrEnum):
    """AXL enum — ``XHotspotAuthenticationMethod``.
    """

    NONE_ = 'None'
    WEP = 'WEP'
    WPA_PSK = 'WPA-PSK'
    WPA2_PSK = 'WPA2-PSK'
    EAP_FAST = 'EAP-FAST'
    PEAP_MSCHAPV2 = 'PEAP-MSCHAPv2'
    PEAP_GTC = 'PEAP-GTC'


class HuntAlgorithm(_AxlStrEnum):
    """AXL enum — ``XHuntAlgorithm``.
    """

    TRY_NEXT_MEMBER_THEN_TRY_NEXT_GROUP_IN_HUNT_LIST = 'Try next member; then, try next group in Hunt List'
    TRY_NEXT_MEMBER_BUT_DO_NOT_GO_TO_NEXT_GROUP = 'Try next member, but do not go to next group'
    SKIP_REMAINING_MEMBERS_AND_GO_DIRECTLY_TO_NEXT_GROUP = 'Skip remaining members, and go directly to next group'
    STOP_HUNTING = 'Stop hunting'


class IPAddressingMode(_AxlStrEnum):
    """AXL enum — ``XIPAddressingMode``.
    """

    IPV4_ONLY = 'IPv4 Only'
    IPV6_ONLY = 'IPv6 Only'
    IPV4_AND_IPV6 = 'IPv4 and IPv6'


class IPAddressingModePrefControl(_AxlStrEnum):
    """AXL enum — ``XIPAddressingModePrefControl``.
    """

    IPV4 = 'IPv4'
    IPV6 = 'IPv6'
    USE_SYSTEM_DEFAULT = 'Use System Default'


class InterClusterService(_AxlStrEnum):
    """AXL enum — ``XInterClusterService``.
    """

    EMCC = 'EMCC'
    PSTN_ACCESS = 'PSTN Access'
    RSVP_AGENT = 'RSVP Agent'
    TFTP = 'TFTP'
    LBM = 'LBM'
    UDS = 'UDS'


class KeepAliveTimeInterval(_AxlStrEnum):
    """AXL enum — ``XKeepAliveTimeInterval``.
    """

    V_0 = '0'
    V_5 = '5'
    V_10 = '10'
    V_15 = '15'
    V_20 = '20'
    V_25 = '25'
    V_30 = '30'


class KeyOrder(_AxlStrEnum):
    """AXL enum — ``XKeyOrder``.
    """

    RSA_ONLY = 'RSA Only'
    EC_ONLY = 'EC Only'
    EC_PREFERRED_RSA_BACKUP = 'EC Preferred, RSA Backup'


class KeySize(_AxlStrEnum):
    """AXL enum — ``XKeySize``.
    """

    V_512 = '512'
    V_1024 = '1024'
    V_2048 = '2048'
    V_3072 = '3072'
    V_4096 = '4096'


class LDAPDirectoryFunction(_AxlStrEnum):
    """AXL enum — ``XLDAPDirectoryFunction``.
    """

    DIRSYNC = 'DirSync'
    DN_ALIAS_SYNC_AND_LOOKUP = 'DN Alias Sync and Lookup'
    ALIAS_SYNC_ONLY = 'Alias Sync only'
    LOOKUP_ONLY = 'Lookup only'


class LdapServer(_AxlStrEnum):
    """AXL enum — ``XLdapServer``.
    """

    MICROSOFT_ACTIVE_DIRECTORY = 'Microsoft Active Directory'
    SUN_OR_ORACLE_DIRECTORY_SERVER = 'Sun or Oracle Directory Server'
    OPENLDAP = 'OpenLDAP'
    MICROSOFT_ADAM_OR_LIGHTWEIGHT_DIRECTORY_SERVICES = 'Microsoft ADAM or Lightweight Directory Services'
    OTHER_LDAPV3_COMPLIANT_DIRECTORY = 'Other LDAPv3 Compliant Directory'


class LogicalPartitionPolicy(_AxlStrEnum):
    """AXL enum — ``XLogicalPartitionPolicy``.
    """

    USE_DEFAULT_POLICY = 'Use Default Policy'
    ALLOW = 'Allow'
    DENY = 'Deny'


class LossyNetwork(_AxlStrEnum):
    """AXL enum — ``XLossyNetwork``.
    """

    KEEP_CURRENT_SETTING = 'Keep Current Setting'
    USE_SYSTEM_DEFAULT = 'Use System Default'
    LOW_LOSS = 'Low Loss'
    LOSSY = 'Lossy'


class MGCPSlotModule(_AxlStrEnum):
    """AXL enum — ``XMGCPSlotModule``.
    """

    NM_1V = 'NM-1V'
    NM_2V = 'NM-2V'
    NM_HDV = 'NM-HDV'
    VIC_SLOT = 'VIC-SLOT'
    NONE_ = 'NONE'
    VWIC_SLOT = 'VWIC-SLOT'
    FLEX_SLOT = 'FLEX-SLOT'
    ANALOG = 'ANALOG'
    DIGITAL = 'DIGITAL'
    VGC_PORT = 'VGC_PORT'
    WS_X6600 = 'WS-X6600'
    AIM_VOICE_30_2_SUBUNITS = 'AIM-VOICE-30 (2 subunits)'
    NM_HDA = 'NM-HDA'
    PA_VXA = 'PA-VXA'
    PA_VXB = 'PA-VXB'
    PA_VXC = 'PA-VXC'
    PA_MCX = 'PA-MCX'
    NM_HD_1V = 'NM-HD-1V'
    NM_HD_2V = 'NM-HD-2V'
    NM_HD_2VE = 'NM-HD-2VE'
    GENERIC_SLOT = 'GENERIC-SLOT'
    NM_4VWIC_MBRD = 'NM-4VWIC-MBRD'
    EVM_HD = 'EVM-HD'
    NM_HDV2_0PORT = 'NM-HDV2-0PORT'
    NM_HDV2_1PORT_T1 = 'NM-HDV2-1PORT-T1'
    NM_HDV2_1PORT_E1 = 'NM-HDV2-1PORT-E1'
    NM_HDV2_2PORT_T1 = 'NM-HDV2-2PORT-T1'
    NM_HDV2_2PORT_E1 = 'NM-HDV2-2PORT-E1'
    AIM_VOICE_30_SLOT_0_3_SUBUNITS_SLOT_0_ONLY = 'AIM-VOICE-30-SLOT-0 (3 subunits- slot 0 only)'
    NM_3VWIC_MBRD = 'NM-3VWIC-MBRD'
    ISR_3NIM_MBRD = 'ISR-3NIM-MBRD'
    VG_2VWIC_MBRD = 'VG-2VWIC-MBRD'
    VG_3VWIC_MBRD = 'VG-3VWIC-MBRD'
    ISR_2NIM_MBRD = 'ISR-2NIM-MBRD'
    SM_X_NIM_ADPTR = 'SM-X-NIM-ADPTR'
    ENCS_1NIM_MBRD = 'ENCS-1NIM-MBRD'
    VG_1NIM_MBRD = 'VG-1NIM-MBRD'
    C_SM_NIM_ADPT = 'C-SM-NIM-ADPT'


class MGCPVic(_AxlStrEnum):
    """AXL enum — ``XMGCPVic``.
    """

    VIC_2FXS = 'VIC-2FXS'
    VIC_2FXO = 'VIC-2FXO'
    VWIC_1MFT_T1 = 'VWIC-1MFT-T1'
    VWIC_2MFT_T1 = 'VWIC-2MFT-T1'
    VIC_NONE = 'VIC_NONE'
    VWIC_1MFT_E1 = 'VWIC-1MFT-E1'
    VWIC_2MFT_E1 = 'VWIC-2MFT-E1'
    WS_U4604_8FXS = 'WS-U4604-8FXS'
    V_8FXS = '8FXS'
    V_16FXS = '16FXS'
    V_1T1 = '1T1'
    V_16FXS8FXO = '16FXS8FXO'
    V_48_PORTS = '48_PORTS'
    VIC_4FXS = 'VIC-4FXS'
    VIC_4FXO = 'VIC-4FXO'
    VIC_8FXS = 'VIC-8FXS'
    VIC_16FXS = 'VIC-16FXS'
    WS_X6600_24FXS = 'WS-X6600-24FXS'
    WS_X6600_6T1 = 'WS-X6600-6T1'
    WS_X6600_6E1 = 'WS-X6600-6E1'
    EM_4FXO_EM0 = 'EM-4FXO-EM0'
    EM_4FXO_EM1 = 'EM-4FXO-EM1'
    EM_8FXS_EM0 = 'EM-8FXS-EM0'
    EM_8FXS_EM1 = 'EM-8FXS-EM1'
    NM_HDA_4FXS = 'NM-HDA-4FXS'
    PA_VXA_1TE1_24_T1 = 'PA-VXA-1TE1-24-T1'
    PA_VXA_1TE1_30_E1 = 'PA-VXA-1TE1-30-E1'
    PA_VXB_2TE1_T1 = 'PA-VXB-2TE1-T1'
    PA_VXB_2TE1_E1 = 'PA-VXB-2TE1-E1'
    PA_VXC_2TE1_T1 = 'PA-VXC-2TE1-T1'
    PA_VXC_2TE1_E1 = 'PA-VXC-2TE1-E1'
    PA_MCX_2TE1_T1 = 'PA-MCX-2TE1-T1'
    PA_MCX_2TE1_E1 = 'PA-MCX-2TE1-E1'
    PA_MCX_4TE1_T1 = 'PA-MCX-4TE1-T1'
    PA_MCX_4TE1_E1 = 'PA-MCX-4TE1-E1'
    PA_MCX_6TE1_T1 = 'PA-MCX-6TE1-T1'
    PA_MCX_6TE1_E1 = 'PA-MCX-6TE1-E1'
    PA_MCX_8TE1_T1 = 'PA-MCX-8TE1-T1'
    PA_MCX_8TE1_E1 = 'PA-MCX-8TE1-E1'
    VIC_8FXO = 'VIC-8FXO'
    WS_U4604_8FXO_2FXS = 'WS-U4604-8FXO-2FXS'
    WS_U4604_16FXS = 'WS-U4604-16FXS'
    VIC_2BRI = 'VIC-2BRI'
    VIC_2FXS_SCCP = 'VIC-2FXS-SCCP'
    VIC_4FXS_SCCP = 'VIC-4FXS-SCCP'
    VIC2_2FXS_SCCP = 'VIC2-2FXS-SCCP'
    VIC2_2BRI_NT_TE_SCCP = 'VIC2-2BRI-NT/TE-SCCP'
    NM_HDA_4FXS_SCCP = 'NM-HDA-4FXS-SCCP'
    EM_8FXS_EM0_SCCP = 'EM-8FXS-EM0-SCCP'
    V_24FXS_SCCP = '24FXS-SCCP'
    EM_8FXS_EM1_SCCP = 'EM-8FXS-EM1-SCCP'
    EVM_HD_8FXS_DID_SCCP = 'EVM-HD-8FXS/DID-SCCP'
    EM_4BRI_NT_TE_SCCP = 'EM-4BRI-NT/TE-SCCP'
    EM_HDA_8FXS_SCCP = 'EM-HDA-8FXS-SCCP'
    EM_HDA_3FXS_4FXO_SCCP = 'EM-HDA-3FXS/4FXO-SCCP'
    VIC3_2FXS_DID = 'VIC3-2FXS/DID'
    VIC3_4FXS_DID = 'VIC3-4FXS/DID'
    EM3_HDA_8FXS_DID = 'EM3-HDA-8FXS/DID'
    VIC3_2FXS_DID_SCCP = 'VIC3-2FXS/DID-SCCP'
    VIC3_4FXS_DID_SCCP = 'VIC3-4FXS/DID-SCCP'
    EM3_HDA_8FXS_DID_SCCP = 'EM3-HDA-8FXS/DID-SCCP'
    V_4FXS_MGCP = '4FXS-MGCP'
    V_4FXS_SCCP = '4FXS-SCCP'
    V_2FXS_MGCP = '2FXS-MGCP'
    V_2FXS_SCCP = '2FXS-SCCP'
    VGD_DFC_CT3 = 'VGD-DFC-CT3'
    VIC3_2FXS_E_DID = 'VIC3-2FXS-E/DID'
    VIC3_2FXS_E_DID_SCCP = 'VIC3-2FXS-E/DID-SCCP'
    VIC2_1FXO = 'VIC2-1FXO'
    VIC2_1BRI = 'VIC2-1BRI'
    HWIC_1CE1T1_PRI_T1 = 'HWIC-1CE1T1-PRI-T1'
    HWIC_1CE1T1_PRI_E1 = 'HWIC-1CE1T1-PRI-E1'
    HWIC_2CE1T1_PRI_T1 = 'HWIC-2CE1T1-PRI-T1'
    HWIC_2CE1T1_PRI_E1 = 'HWIC-2CE1T1-PRI-E1'
    HWIC_4CE1T1_PRI_T1 = 'HWIC-4CE1T1-PRI-T1'
    HWIC_4CE1T1_PRI_E1 = 'HWIC-4CE1T1-PRI-E1'
    VWIC3_1MFT_T1E1_T1 = 'VWIC3-1MFT-T1E1-T1'
    VWIC3_1MFT_T1E1_E1 = 'VWIC3-1MFT-T1E1-E1'
    VWIC3_1MFT_G703_T1 = 'VWIC3-1MFT-G703-T1'
    VWIC3_1MFT_G703_E1 = 'VWIC3-1MFT-G703-E1'
    VWIC3_2MFT_T1E1_T1 = 'VWIC3-2MFT-T1E1-T1'
    VWIC3_2MFT_T1E1_E1 = 'VWIC3-2MFT-T1E1-E1'
    VWIC3_2MFT_G703_T1 = 'VWIC3-2MFT-G703-T1'
    VWIC3_2MFT_G703_E1 = 'VWIC3-2MFT-G703-E1'
    VWIC3_4MFT_T1E1_T1 = 'VWIC3-4MFT-T1E1-T1'
    VWIC3_4MFT_T1E1_E1 = 'VWIC3-4MFT-T1E1-E1'
    SM_D_48FXS_E = 'SM-D-48FXS-E'
    SM_D_72FXS = 'SM-D-72FXS'
    SM_D_48FXS_E_SCCP = 'SM-D-48FXS-E-SCCP'
    SM_D_72FXS_SCCP = 'SM-D-72FXS-SCCP'
    INTELBRAS_80_PORT_FXS = 'Intelbras 80 Port FXS'
    WS_SVC_CMM_MS = 'WS-SVC-CMM-MS'
    VIC2_2FXS = 'VIC2-2FXS'
    VIC2_2FXO = 'VIC2-2FXO'
    VIC2_2BRI = 'VIC2-2BRI'
    VIC_4FXS_DID = 'VIC-4FXS/DID'
    VIC2_4FXO = 'VIC2-4FXO'
    NM_HDV2_ONBOARD_T1 = 'NM-HDV2-ONBOARD-T1'
    NM_HDV2_ONBOARD_E1 = 'NM-HDV2-ONBOARD-E1'
    VWIC2_1MFT_T1E1_T1 = 'VWIC2-1MFT-T1E1-T1'
    VWIC2_1MFT_T1E1_E1 = 'VWIC2-1MFT-T1E1-E1'
    VWIC2_2MFT_T1E1_T1 = 'VWIC2-2MFT-T1E1-T1'
    VWIC2_2MFT_T1E1_E1 = 'VWIC2-2MFT-T1E1-E1'
    VWIC2_1MFT_G703_T1 = 'VWIC2-1MFT-G703-T1'
    VWIC2_1MFT_G703_E1 = 'VWIC2-1MFT-G703-E1'
    VWIC2_2MFT_G703_T1 = 'VWIC2-2MFT-G703-T1'
    VWIC2_2MFT_G703_E1 = 'VWIC2-2MFT-G703-E1'
    EVM_HD_8FXS_DID = 'EVM-HD-8FXS/DID'
    EM_4BRI_NT_TE_EM0 = 'EM-4BRI-NT/TE-EM0'
    EM_4BRI_NT_TE_EM1 = 'EM-4BRI-NT/TE-EM1'
    V_24FXS = '24FXS'
    NM_HDV2_ONBOARD_T1_2PORT = 'NM-HDV2-ONBOARD-T1-2PORT'
    NM_HDV2_ONBOARD_E1_2PORT = 'NM-HDV2-ONBOARD-E1-2PORT'
    EM_HDA_8FXS = 'EM-HDA-8FXS'
    EM_HDA_6FXO = 'EM-HDA-6FXO'
    EM_HDA_3FXS_4FXO = 'EM-HDA-3FXS/4FXO'
    EM_4BRI_NT_TE = 'EM-4BRI-NT/TE'
    VIC2_1MFT_T1E1_T1 = 'VIC2-1MFT-T1E1-T1'
    VIC2_1MFT_T1E1_E1 = 'VIC2-1MFT-T1E1-E1'
    VIC2_2MFT_T1E1_T1 = 'VIC2-2MFT-T1E1-T1'
    VIC2_2MFT_T1E1_E1 = 'VIC2-2MFT-T1E1-E1'
    EM2_4FXO_EM0 = 'EM2-4FXO-EM0'
    EM2_4FXO_EM1 = 'EM2-4FXO-EM1'
    NIM_1MFT_T1E1_T1 = 'NIM-1MFT-T1E1-T1'
    NIM_1CE1T1_PRI_T1 = 'NIM-1CE1T1-PRI-T1'
    NIM_1MFT_T1E1_E1 = 'NIM-1MFT-T1E1-E1'
    NIM_1CE1T1_PRI_E1 = 'NIM-1CE1T1-PRI-E1'
    NIM_2MFT_T1E1_T1 = 'NIM-2MFT-T1E1-T1'
    NIM_2CE1T1_PRI_T1 = 'NIM-2CE1T1-PRI-T1'
    NIM_2MFT_T1E1_E1 = 'NIM-2MFT-T1E1-E1'
    NIM_2CE1T1_PRI_E1 = 'NIM-2CE1T1-PRI-E1'
    NIM_4MFT_T1E1_T1 = 'NIM-4MFT-T1E1-T1'
    NIM_4MFT_T1E1_E1 = 'NIM-4MFT-T1E1-E1'
    NIM_8MFT_T1E1_T1 = 'NIM-8MFT-T1E1-T1'
    NIM_8CE1T1_PRI_T1 = 'NIM-8CE1T1-PRI-T1'
    NIM_8MFT_T1E1_E1 = 'NIM-8MFT-T1E1-E1'
    NIM_8CE1T1_PRI_E1 = 'NIM-8CE1T1-PRI-E1'
    NIM_2FXS = 'NIM-2FXS'
    NIM_2FXO = 'NIM-2FXO'
    NIM_2BRI_NT_TE = 'NIM-2BRI-NT/TE'
    NIM_4FXS = 'NIM-4FXS'
    NIM_4FXO = 'NIM-4FXO'
    NIM_4BRI_NT_TE = 'NIM-4BRI-NT/TE'
    NIM_2FXS_4FXO = 'NIM-2FXS/4FXO'
    NIM_2FXS_SCCP = 'NIM-2FXS-SCCP'
    NIM_2BRI_NT_TE_SCCP = 'NIM-2BRI-NT/TE-SCCP'
    NIM_4FXS_SCCP = 'NIM-4FXS-SCCP'
    NIM_4BRI_NT_TE_SCCP = 'NIM-4BRI-NT/TE-SCCP'
    NIM_2FXS_4FXO_SCCP = 'NIM-2FXS/4FXO-SCCP'
    SM_X_16FXS_2FXO = 'SM-X-16FXS/2FXO'
    SM_X_24FXS_4FXO = 'SM-X-24FXS/4FXO'
    SM_X_8FXS_12FXO = 'SM-X-8FXS/12FXO'
    SM_X_72FXS = 'SM-X-72FXS'
    SM_X_56FXS = 'SM-X-56FXS'
    SM_X_72FXS_SCCP = 'SM-X-72FXS-SCCP'
    SM_X_56FXS_SCCP = 'SM-X-56FXS-SCCP'
    SM_X_16FXS_2FXO_SCCP = 'SM-X-16FXS/2FXO-SCCP'
    SM_X_24FXS_4FXO_SCCP = 'SM-X-24FXS/4FXO-SCCP'
    SM_X_8FXS_12FXO_SCCP = 'SM-X-8FXS/12FXO-SCCP'
    VG_8FXS = 'VG-8FXS'
    VG_2FXS_2FXO = 'VG-2FXS/2FXO'
    VG_4FXS_4FXO = 'VG-4FXS/4FXO'
    VG_6FXS_6FXO = 'VG-6FXS/6FXO'
    VG_8FXS_SCCP = 'VG-8FXS-SCCP'
    VG_2FXS_2FXO_SCCP = 'VG-2FXS/2FXO-SCCP'
    VG_4FXS_4FXO_SCCP = 'VG-4FXS/4FXO-SCCP'
    VG_6FXS_6FXO_SCCP = 'VG-6FXS/6FXO-SCCP'
    SM_X_72FXS_SIP = 'SM-X-72FXS-SIP'
    SM_X_56FXS_SIP = 'SM-X-56FXS-SIP'
    SM_X_16FXS_2FXO_SIP = 'SM-X-16FXS/2FXO-SIP'
    SM_X_24FXS_4FXO_SIP = 'SM-X-24FXS/4FXO-SIP'
    SM_X_8FXS_12FXO_SIP = 'SM-X-8FXS/12FXO-SIP'
    NIM_2FXS_SIP = 'NIM-2FXS-SIP'
    NIM_4FXS_SIP = 'NIM-4FXS-SIP'
    NIM_2FXS_4FXO_SIP = 'NIM-2FXS/4FXO-SIP'
    SM_V_144FXS = 'SM-V-144FXS'
    SM_V_132FXS_6FXO = 'SM-V-132FXS/6FXO'
    SM_V_84FXS_6FXO = 'SM-V-84FXS/6FXO'
    SM_V_144FXS_SCCP = 'SM-V-144FXS-SCCP'
    SM_V_132FXS_6FXO_SCCP = 'SM-V-132FXS/6FXO-SCCP'
    SM_V_84FXS_6FXO_SCCP = 'SM-V-84FXS/6FXO-SCCP'
    SM_V_144FXS_SIP = 'SM-V-144FXS-SIP'
    SM_V_132FXS_6FXO_SIP = 'SM-V-132FXS/6FXO-SIP'
    SM_V_84FXS_6FXO_SIP = 'SM-V-84FXS/6FXO-SIP'
    VG_8FXS_SIP = 'VG-8FXS-SIP'
    VG_2FXS_2FXO_SIP = 'VG-2FXS/2FXO-SIP'
    VG_4FXS_4FXO_SIP = 'VG-4FXS/4FXO-SIP'
    VG_6FXS_6FXO_SIP = 'VG-6FXS/6FXO-SIP'
    VG_24FXS = 'VG-24FXS'
    VG_24FXS_4FXO = 'VG-24FXS/4FXO'
    VG_48FXS = 'VG-48FXS'
    VG_24FXS_SCCP = 'VG-24FXS-SCCP'
    VG_24FXS_4FXO_SCCP = 'VG-24FXS/4FXO-SCCP'
    VG_48FXS_SCCP = 'VG-48FXS-SCCP'
    VG_24FXS_SIP = 'VG-24FXS-SIP'
    VG_24FXS_4FXO_SIP = 'VG-24FXS/4FXO-SIP'
    VG_48FXS_SIP = 'VG-48FXS-SIP'


class MRAPolicy(_AxlStrEnum):
    """AXL enum — ``XMRAPolicy``.
    """

    NO_SERVICE = 'No Service'
    IM_AND_PRESENCE_ONLY = 'IM & Presence only'
    IM_AND_PRESENCE_VOICE_AND_VIDEO_CALLS = 'IM & Presence, Voice and Video calls'


class MWLPolicy(_AxlStrEnum):
    """AXL enum — ``XMWLPolicy``.
    """

    USE_SYSTEM_POLICY = 'Use System Policy'
    LIGHT_AND_PROMPT = 'Light and Prompt'
    PROMPT_ONLY = 'Prompt Only'
    LIGHT_ONLY = 'Light Only'
    NONE_ = 'None'


class MatrixValue(_AxlStrEnum):
    """AXL enum — ``XMatrixValue``.
    """

    USE_SYSTEM_DEFAULT = 'Use System Default'
    NO_RESERVATION = 'No Reservation'
    OPTIONAL_VIDEO_DESIRED = 'Optional(Video Desired)'
    MANDATORY = 'Mandatory'
    MANDATORY_VIDEO_DESIRED = 'Mandatory(Video Desired)'
    ALLOW_SUBSCRIPTION = 'Allow Subscription'
    DISALLOW_SUBSCRIPTION = 'Disallow Subscription'


class MediaPayload(_AxlStrEnum):
    """AXL enum — ``XMediaPayload``.
    """

    G711_A_LAW_64K = 'G711 a-law 64K'
    G711_U_LAW_64K = 'G711 u-law 64K'
    G723 = 'G723'
    G729 = 'G729'
    G729ANNEXA = 'G729AnnexA'
    G729ANNEXB = 'G729AnnexB'
    G729ANNEXA_ANNEXB = 'G729AnnexA-AnnexB'


class MobileSmartClient(_AxlStrEnum):
    """AXL enum — ``XMobileSmartClient``.
    """

    CUMC = 'CUMC'
    STANDARD = 'Standard'


class Model(_AxlStrEnum):
    """AXL enum — ``XModel``.
    """

    CISCO_30_SPPLUS = 'Cisco 30 SP+'
    CISCO_12_SPPLUS = 'Cisco 12 SP+'
    CISCO_12_SP = 'Cisco 12 SP'
    CISCO_12_S = 'Cisco 12 S'
    CISCO_30_VIP = 'Cisco 30 VIP'
    CISCO_7910 = 'Cisco 7910'
    CISCO_7960 = 'Cisco 7960'
    CISCO_7940 = 'Cisco 7940'
    CISCO_7935 = 'Cisco 7935'
    CISCO_VGC_PHONE = 'Cisco VGC Phone'
    CISCO_VGC_VIRTUAL_PHONE = 'Cisco VGC Virtual Phone'
    CISCO_ATA_186 = 'Cisco ATA 186'
    EMCC_BASE_PHONE = 'EMCC Base Phone'
    SCCP_PHONE = 'SCCP Phone'
    ANALOG_ACCESS = 'Analog Access'
    DIGITAL_ACCESS = 'Digital Access'
    DIGITAL_ACCESSPLUS = 'Digital Access+'
    DIGITAL_ACCESS_WS_X6608 = 'Digital Access WS-X6608'
    ANALOG_ACCESS_WS_X6624 = 'Analog Access WS-X6624'
    VGC_GATEWAY = 'VGC Gateway'
    CONFERENCE_BRIDGE = 'Conference Bridge'
    CONFERENCE_BRIDGE_WS_X6608 = 'Conference Bridge WS-X6608'
    CISCO_IOS_CONFERENCE_BRIDGE_HDV2 = 'Cisco IOS Conference Bridge (HDV2)'
    CISCO_CONFERENCE_BRIDGE_WS_SVC_CMM = 'Cisco Conference Bridge (WS-SVC-CMM)'
    H_323_PHONE = 'H.323 Phone'
    H_323_GATEWAY = 'H.323 Gateway'
    MUSIC_ON_HOLD = 'Music On Hold'
    DEVICE_PILOT = 'Device Pilot'
    CTI_PORT = 'CTI Port'
    CTI_ROUTE_POINT = 'CTI Route Point'
    VOICE_MAIL_PORT = 'Voice Mail Port'
    CISCO_IOS_SOFTWARE_MEDIA_TERMINATION_POINT_HDV2 = 'Cisco IOS Software Media Termination Point (HDV2)'
    CISCO_MEDIA_SERVER_WS_SVC_CMM_MS = 'Cisco Media Server (WS-SVC-CMM-MS)'
    CISCO_VIDEO_CONFERENCE_BRIDGE_IPVC_35XX = 'Cisco Video Conference Bridge (IPVC-35xx)'
    CISCO_IOS_HETEROGENEOUS_VIDEO_CONFERENCE_BRIDGE = 'Cisco IOS Heterogeneous Video Conference Bridge'
    CISCO_IOS_GUARANTEED_AUDIO_VIDEO_CONFERENCE_BRIDGE = 'Cisco IOS Guaranteed Audio Video Conference Bridge'
    CISCO_IOS_HOMOGENEOUS_VIDEO_CONFERENCE_BRIDGE = 'Cisco IOS Homogeneous Video Conference Bridge'
    ROUTE_LIST = 'Route List'
    LOAD_SIMULATOR = 'Load Simulator'
    MEDIA_TERMINATION_POINT = 'Media Termination Point'
    MEDIA_TERMINATION_POINT_HARDWARE = 'Media Termination Point Hardware'
    CISCO_IOS_MEDIA_TERMINATION_POINT_HDV2 = 'Cisco IOS Media Termination Point (HDV2)'
    CISCO_MEDIA_TERMINATION_POINT_WS_SVC_CMM = 'Cisco Media Termination Point (WS-SVC-CMM)'
    CISCO_7941 = 'Cisco 7941'
    CISCO_7971 = 'Cisco 7971'
    MGCP_STATION = 'MGCP Station'
    MGCP_TRUNK = 'MGCP Trunk'
    GATEKEEPER = 'GateKeeper'
    V_7914_14_BUTTON_LINE_EXPANSION_MODULE = '7914 14-Button Line Expansion Module'
    TRUNK = 'Trunk'
    TONE_ANNOUNCEMENT_PLAYER = 'Tone Announcement Player'
    SIP_TRUNK = 'SIP Trunk'
    SIP_GATEWAY = 'SIP Gateway'
    WSM_TRUNK = 'WSM Trunk'
    REMOTE_DESTINATION_PROFILE = 'Remote Destination Profile'
    V_7915_12_BUTTON_LINE_EXPANSION_MODULE = '7915 12-Button Line Expansion Module'
    V_7915_24_BUTTON_LINE_EXPANSION_MODULE = '7915 24-Button Line Expansion Module'
    V_7916_12_BUTTON_LINE_EXPANSION_MODULE = '7916 12-Button Line Expansion Module'
    V_7916_24_BUTTON_LINE_EXPANSION_MODULE = '7916 24-Button Line Expansion Module'
    CKEM_36_BUTTON_LINE_EXPANSION_MODULE = 'CKEM 36-Button Line Expansion Module'
    SPA8800 = 'SPA8800'
    UNKNOWN_MGCP_GATEWAY = 'Unknown MGCP Gateway'
    UNKNOWN = 'Unknown'
    CISCO_7985 = 'Cisco 7985'
    CISCO_7911 = 'Cisco 7911'
    CISCO_7961G_GE = 'Cisco 7961G-GE'
    CISCO_7941G_GE = 'Cisco 7941G-GE'
    MOTOROLA_CN622 = 'Motorola CN622'
    THIRD_PARTY_SIP_DEVICE_BASIC = 'Third-party SIP Device (Basic)'
    CISCO_7931 = 'Cisco 7931'
    CISCO_UNIFIED_PERSONAL_COMMUNICATOR = 'Cisco Unified Personal Communicator'
    CISCO_7921 = 'Cisco 7921'
    CISCO_7906 = 'Cisco 7906'
    THIRD_PARTY_SIP_DEVICE_ADVANCED = 'Third-party SIP Device (Advanced)'
    CISCO_TELEPRESENCE = 'Cisco TelePresence'
    NOKIA_S60 = 'Nokia S60'
    CISCO_7962 = 'Cisco 7962'
    CISCO_3951 = 'Cisco 3951'
    CISCO_7937 = 'Cisco 7937'
    CISCO_7942 = 'Cisco 7942'
    CISCO_7945 = 'Cisco 7945'
    CISCO_7965 = 'Cisco 7965'
    CISCO_7975 = 'Cisco 7975'
    CISCO_3911 = 'Cisco 3911'
    CISCO_UNIFIED_MOBILE_COMMUNICATOR = 'Cisco Unified Mobile Communicator'
    CISCO_TELEPRESENCE_1000 = 'Cisco TelePresence 1000'
    CISCO_TELEPRESENCE_3000 = 'Cisco TelePresence 3000'
    CISCO_TELEPRESENCE_3200 = 'Cisco TelePresence 3200'
    CISCO_TELEPRESENCE_500_37 = 'Cisco TelePresence 500-37'
    CISCO_7925 = 'Cisco 7925'
    CISCO_9971 = 'Cisco 9971'
    CISCO_6921 = 'Cisco 6921'
    CISCO_6941 = 'Cisco 6941'
    CISCO_6961 = 'Cisco 6961'
    CISCO_UNIFIED_CLIENT_SERVICES_FRAMEWORK = 'Cisco Unified Client Services Framework'
    CISCO_TELEPRESENCE_1300_65 = 'Cisco TelePresence 1300-65'
    CISCO_TELEPRESENCE_1100 = 'Cisco TelePresence 1100'
    TRANSNOVA_S3 = 'Transnova S3'
    BLACKBERRY_MVS_VOWIFI = 'BlackBerry MVS VoWifi'
    CISCO_9951 = 'Cisco 9951'
    CISCO_8961 = 'Cisco 8961'
    CISCO_6901 = 'Cisco 6901'
    CISCO_6911 = 'Cisco 6911'
    CISCO_ATA_187 = 'Cisco ATA 187'
    CISCO_TELEPRESENCE_200 = 'Cisco TelePresence 200'
    CISCO_TELEPRESENCE_400 = 'Cisco TelePresence 400'
    CISCO_DUAL_MODE_FOR_IPHONE = 'Cisco Dual Mode for iPhone'
    CISCO_6945 = 'Cisco 6945'
    CISCO_DUAL_MODE_FOR_ANDROID = 'Cisco Dual Mode for Android'
    CISCO_7926 = 'Cisco 7926'
    CISCO_E20 = 'Cisco E20'
    GENERIC_SINGLE_SCREEN_ROOM_SYSTEM = 'Generic Single Screen Room System'
    GENERIC_MULTIPLE_SCREEN_ROOM_SYSTEM = 'Generic Multiple Screen Room System'
    CISCO_TELEPRESENCE_EX90 = 'Cisco TelePresence EX90'
    CISCO_8945 = 'Cisco 8945'
    CISCO_8941 = 'Cisco 8941'
    GENERIC_DESKTOP_VIDEO_ENDPOINT = 'Generic Desktop Video Endpoint'
    CISCO_TELEPRESENCE_500_32 = 'Cisco TelePresence 500-32'
    CISCO_TELEPRESENCE_1300_47 = 'Cisco TelePresence 1300-47'
    CISCO_3905 = 'Cisco 3905'
    CISCO_CIUS = 'Cisco Cius'
    VKEM_36_BUTTON_LINE_EXPANSION_MODULE = 'VKEM 36-Button Line Expansion Module'
    CISCO_TELEPRESENCE_TX1310_65 = 'Cisco TelePresence TX1310-65'
    CISCO_TELEPRESENCE_MCU = 'Cisco TelePresence MCU'
    ASCOM_IP_DECT_DEVICE = 'Ascom IP-DECT Device'
    CISCO_TELEPRESENCE_EXCHANGE_SYSTEM = 'Cisco TelePresence Exchange System'
    CISCO_TELEPRESENCE_EX60 = 'Cisco TelePresence EX60'
    CISCO_TELEPRESENCE_CODEC_C90 = 'Cisco TelePresence Codec C90'
    CISCO_TELEPRESENCE_CODEC_C60 = 'Cisco TelePresence Codec C60'
    CISCO_TELEPRESENCE_CODEC_C40 = 'Cisco TelePresence Codec C40'
    CISCO_TELEPRESENCE_QUICK_SET_C20 = 'Cisco TelePresence Quick Set C20'
    CISCO_TELEPRESENCE_PROFILE_42_C20 = 'Cisco TelePresence Profile 42 (C20)'
    CISCO_TELEPRESENCE_PROFILE_42_C60 = 'Cisco TelePresence Profile 42 (C60)'
    CISCO_TELEPRESENCE_PROFILE_52_C40 = 'Cisco TelePresence Profile 52 (C40)'
    CISCO_TELEPRESENCE_PROFILE_52_C60 = 'Cisco TelePresence Profile 52 (C60)'
    CISCO_TELEPRESENCE_PROFILE_52_DUAL_C60 = 'Cisco TelePresence Profile 52 Dual (C60)'
    CISCO_TELEPRESENCE_PROFILE_65_C60 = 'Cisco TelePresence Profile 65 (C60)'
    CISCO_TELEPRESENCE_PROFILE_65_DUAL_C90 = 'Cisco TelePresence Profile 65 Dual (C90)'
    CISCO_TELEPRESENCE_MX200 = 'Cisco TelePresence MX200'
    CISCO_TELEPRESENCE_TX9000 = 'Cisco TelePresence TX9000'
    CISCO_TELEPRESENCE_TX9200 = 'Cisco TelePresence TX9200'
    CISCO_7821 = 'Cisco 7821'
    CISCO_7841 = 'Cisco 7841'
    CISCO_7861 = 'Cisco 7861'
    CISCO_TELEPRESENCE_SX20 = 'Cisco TelePresence SX20'
    CISCO_TELEPRESENCE_MX300 = 'Cisco TelePresence MX300'
    IMS_INTEGRATED_MOBILE_BASIC = 'IMS-integrated Mobile (Basic)'
    THIRD_PARTY_AS_SIP_ENDPOINT = 'Third-party AS-SIP Endpoint'
    CISCO_CIUS_SP = 'Cisco Cius SP'
    CISCO_TELEPRESENCE_PROFILE_42_C40 = 'Cisco TelePresence Profile 42 (C40)'
    CISCO_VXC_6215 = 'Cisco VXC 6215'
    CTI_REMOTE_DEVICE = 'CTI Remote Device'
    USAGE_PROFILE = 'Usage Profile'
    CARRIER_INTEGRATED_MOBILE = 'Carrier-integrated Mobile'
    UNIVERSAL_DEVICE_TEMPLATE = 'Universal Device Template'
    CISCO_DX650 = 'Cisco DX650'
    CISCO_UNIFIED_COMMUNICATIONS_FOR_RTX = 'Cisco Unified Communications for RTX'
    CISCO_JABBER_FOR_TABLET = 'Cisco Jabber for Tablet'
    CISCO_8831 = 'Cisco 8831'
    CISCO_ATA_190 = 'Cisco ATA 190'
    CISCO_TELEPRESENCE_SX10 = 'Cisco TelePresence SX10'
    CISCO_8841 = 'Cisco 8841'
    CISCO_8851 = 'Cisco 8851'
    CISCO_8861 = 'Cisco 8861'
    CISCO_TELEPRESENCE_SX80 = 'Cisco TelePresence SX80'
    CISCO_TELEPRESENCE_MX200_G2 = 'Cisco TelePresence MX200 G2'
    CISCO_TELEPRESENCE_MX300_G2 = 'Cisco TelePresence MX300 G2'
    CISCO_7905 = 'Cisco 7905'
    CISCO_7920 = 'Cisco 7920'
    CISCO_7970 = 'Cisco 7970'
    CISCO_7912 = 'Cisco 7912'
    CISCO_7902 = 'Cisco 7902'
    CISCO_IP_COMMUNICATOR = 'Cisco IP Communicator'
    CISCO_7961 = 'Cisco 7961'
    CISCO_7936 = 'Cisco 7936'
    ANALOG_PHONE = 'Analog Phone'
    ISDN_BRI_PHONE = 'ISDN BRI Phone'
    SCCP_GATEWAY_VIRTUAL_PHONE = 'SCCP gateway virtual phone'
    IP_STE = 'IP-STE'
    CISCO_TELEPRESENCE_CONDUCTOR = 'Cisco TelePresence Conductor'
    CISCO_DX80 = 'Cisco DX80'
    CISCO_DX70 = 'Cisco DX70'
    BEKEM_36_BUTTON_LINE_EXPANSION_MODULE = 'BEKEM 36-Button Line Expansion Module'
    CISCO_TELEPRESENCE_MX700 = 'Cisco TelePresence MX700'
    CISCO_TELEPRESENCE_MX800 = 'Cisco TelePresence MX800'
    CISCO_TELEPRESENCE_IX5000 = 'Cisco TelePresence IX5000'
    CISCO_7811 = 'Cisco 7811'
    CISCO_8821 = 'Cisco 8821'
    CISCO_8811 = 'Cisco 8811'
    INTERACTIVE_VOICE_RESPONSE = 'Interactive Voice Response'
    CISCO_8845 = 'Cisco 8845'
    CISCO_8865 = 'Cisco 8865'
    CISCO_TELEPRESENCE_MX800_DUAL = 'Cisco TelePresence MX800 Dual'
    CISCO_8851NR = 'Cisco 8851NR'
    CISCO_SPARK_REMOTE_DEVICE = 'Cisco Spark Remote Device'
    CISCO_WEBEX_DX80 = 'Cisco Webex DX80'
    CISCO_TELEPRESENCE_DX70 = 'Cisco TelePresence DX70'
    CISCO_7832 = 'Cisco 7832'
    CISCO_8865NR = 'Cisco 8865NR'
    CISCO_MEETING_SERVER = 'Cisco Meeting Server'
    CISCO_WEBEX_ROOM_KIT = 'Cisco Webex Room Kit'
    CISCO_WEBEX_ROOM_55 = 'Cisco Webex Room 55'
    CISCO_WEBEX_ROOM_KIT_PLUS = 'Cisco Webex Room Kit Plus'
    CP_8800_VIDEO_28_BUTTON_KEY_EXPANSION_MODULE = 'CP-8800-Video 28-Button Key Expansion Module'
    CP_8800_AUDIO_28_BUTTON_KEY_EXPANSION_MODULE = 'CP-8800-Audio 28-Button Key Expansion Module'
    CISCO_8832 = 'Cisco 8832'
    CISCO_WEBEX_ROOM_70_SINGLE = 'Cisco Webex Room 70 Single'
    CISCO_8832NR = 'Cisco 8832NR'
    CISCO_ATA_191 = 'Cisco ATA 191'
    CISCO_COLLABORATION_MOBILE_CONVERGENCE = 'Cisco Collaboration Mobile Convergence'
    CISCO_WEBEX_ROOM_70_DUAL = 'Cisco Webex Room 70 Dual'
    CISCO_WEBEX_ROOM_KIT_PRO = 'Cisco Webex Room Kit Pro'
    CISCO_WEBEX_ROOM_55_DUAL = 'Cisco Webex Room 55 Dual'
    CISCO_WEBEX_ROOM_70_SINGLE_G2 = 'Cisco Webex Room 70 Single G2'
    CISCO_WEBEX_ROOM_70_DUAL_G2 = 'Cisco Webex Room 70 Dual G2'
    SIP_STATION = 'SIP Station'
    CISCO_WEBEX_ROOM_KIT_MINI = 'Cisco Webex Room Kit Mini'
    CISCO_WEBEX_VDI_SVC_FRAMEWORK = 'Cisco Webex VDI Svc Framework'
    CISCO_WEBEX_BOARD_55 = 'Cisco Webex Board 55'
    CISCO_WEBEX_BOARD_70 = 'Cisco Webex Board 70'
    CISCO_WEBEX_BOARD_85 = 'Cisco Webex Board 85'
    CISCO_WEBEX_DESK_PRO = 'Cisco Webex Desk Pro'
    CISCO_WEBEX_ROOM_PANORAMA = 'Cisco Webex Room Panorama'
    CISCO_WEBEX_ROOM_70_PANORAMA = 'Cisco Webex Room 70 Panorama'
    CISCO_WEBEX_ROOM_PHONE = 'Cisco Webex Room Phone'
    CISCO_860 = 'Cisco 860'
    CISCO_840 = 'Cisco 840'
    CISCO_WEBEX_DESK_LE = 'Cisco Webex Desk LE'
    CISCO_WEBEX_DESK = 'Cisco Webex Desk'
    CISCO_WEBEX_DESK_MINI = 'Cisco Webex Desk Mini'
    CISCO_WEBEX_DESK_HUB = 'Cisco Webex Desk Hub'
    CISCO_WEBEX_BOARD_PRO_55 = 'Cisco Webex Board Pro 55'
    CISCO_WEBEX_BOARD_PRO_75 = 'Cisco Webex Board Pro 75'
    CISCO_WEBEX_ROOM_BAR = 'Cisco Webex Room Bar'
    CISCO_8875 = 'Cisco 8875'
    CISCO_8875NR = 'Cisco 8875NR'
    CISCO_8851NS = 'Cisco 8851NS'
    CISCO_8811NS = 'Cisco 8811NS'
    CISCO_8841NS = 'Cisco 8841NS'
    CISCO_ROOM_KIT_EQ = 'Cisco Room Kit EQ'
    CISCO_ROOM_BAR_PRO = 'Cisco Room Bar Pro'
    CISCO_ROOM_KIT_EQX = 'Cisco Room Kit EQX'


class MonthOfYear(_AxlStrEnum):
    """AXL enum — ``XMonthOfYear``.
    """

    NONE_ = 'None'
    JAN = 'Jan'
    FEB = 'Feb'
    MAR = 'Mar'
    APR = 'Apr'
    MAY = 'May'
    JUN = 'Jun'
    JUL = 'Jul'
    AUG = 'Aug'
    SEP = 'Sep'
    OCT = 'Oct'
    NOV = 'Nov'
    DEC = 'Dec'


class NSFService(_AxlStrEnum):
    """AXL enum — ``XNSFService``.
    """

    ACCUNET_SWITCHED_DIGITAL_SERVICE = 'ACCUNET Switched Digital Service'
    BILLING_NUMBER_ONLY = 'Billing Number Only'
    BILLING_NUMBER_PREFERRED = 'Billing Number Preferred'
    CALLING_PARTY_NUMBER_ONLY = 'Calling Party Number Only'
    CALLING_PARTY_NUMBER_PREFERRED = 'Calling Party Number Preferred'
    FOREIGN_EXCHANGE = 'Foreign Exchange'
    FOREIGN_EXCHANGE_SELECTION = 'Foreign Exchange Selection'
    INTERNATIONAL_LONG_DISTANCE_SERVICE = 'International Long Distance Service'
    INTERLATAOUTWATS = 'InterLATAOUTWATS'
    INTRALATAOUTWATS = 'IntraLATAOUTWATS'
    LONG_DISTANCE_SERVICE = 'Long Distance Service'
    MEGACOM_TELECOM_SERVICE = 'MEGACOM Telecom Service'
    NATIONAL_ISDN_BANDED_OUTWATS = 'National ISDN Banded OUTWATS'
    NATIONAL_ISDN_UNBANDED_OUTWATS = 'National ISDN Unbanded OUTWATS'
    OUTWATS_SELECTION = 'OUTWATS Selection'
    PRIVATE = 'Private'
    PRIVATE_SELECTION = 'Private Selection'
    SOFTWARE_DEFINED_NETWORK = 'Software Defined Network'
    TIE_TRUNK_CUT_THROUGH = 'Tie Trunk (Cut-through)'
    TIE_TRUNK_SENDERIZED = 'Tie Trunk (Senderized)'
    TIE_TRUNK_SELECTION_CUT_THROUGH = 'Tie Trunk Selection (Cut-through)'
    TIE_TRUNK_SELECTION_SENDERIZED = 'Tie Trunk Selection (Senderized)'
    WATS_BAND_SELECTION = 'WATS Band Selection'
    WATS_MAXIMAL_SUBSCRIBED_BAND = 'WATS Maximal Subscribed Band'


class NetworkLocation(_AxlStrEnum):
    """AXL enum — ``XNetworkLocation``.
    """

    ONNET = 'OnNet'
    OFFNET = 'OffNet'
    USE_SYSTEM_DEFAULT = 'Use System Default'


class NodeUsage(_AxlStrEnum):
    """AXL enum — ``XNodeUsage``.
    """

    PUBLISHER = 'Publisher'
    SUBSCRIBER = 'Subscriber'


class NumberingPlan(_AxlStrEnum):
    """AXL enum — ``XNumberingPlan``.
    """

    CISCO_CALLMANAGER = 'Cisco CallManager'
    ISDN = 'ISDN'
    NATIONAL_STANDARD = 'National Standard'
    PRIVATE = 'Private'
    UNKNOWN = 'Unknown'


class OnboardingRegistrationStatus(_AxlStrEnum):
    """AXL enum — ``XOnboardingRegistrationStatus``.
    """

    ONBOARDING_COMPLETED = 'Onboarding completed'
    ONBOARDING_PENDING = 'Onboarding pending'
    VOUCHER_DETAILS_UNAVAILABLE = 'Voucher Details unavailable'


class Operator(_AxlStrEnum):
    """AXL enum — ``XOperator``.
    """

    NOT_SELECTED = 'NOT-SELECTED'
    EXISTS = 'EXISTS'
    DOES_NOT_EXIST = 'DOES-NOT-EXIST'
    EQEQ = '=='


class OutboundCallRollover(_AxlStrEnum):
    """AXL enum — ``XOutboundCallRollover``.
    """

    NO_ROLLOVER = 'No Rollover'
    ROLLOVER_WITHIN_SAME_DN = 'Rollover Within Same DN'
    ROLLOVER_TO_ANY_LINE = 'Rollover to any line'


class PRIChanIE(_AxlStrEnum):
    """AXL enum — ``XPRIChanIE``.
    """

    TIMESLOT_NUMBER = 'Timeslot Number'
    SLOTMAP = 'Slotmap'
    USE_NUMBER_WHEN_1B = 'Use Number when 1B'
    CONTINUOUS_NUMBER = 'Continuous Number'


class PacketCaptureMode(_AxlStrEnum):
    """AXL enum — ``XPacketCaptureMode``.
    """

    NONE_ = 'None'
    BATCH_PROCESSING_MODE = 'Batch Processing Mode'


class Param(_AxlStrEnum):
    """AXL enum — ``XParam``.
    """

    BOOLEAN = 'boolean'
    DOUBLE = 'double'
    LONG = 'long'
    STRING = 'string'
    DATE_TIME = 'date/time'
    ANY_DIGIT = 'any digit'
    DIGITS = 'digits'
    TIMEOUT = 'timeout'
    TERMINATING = 'terminating'
    MORE_DIGITS = 'more digits'


class PartitionUsage(_AxlStrEnum):
    """AXL enum — ``XPartitionUsage``.
    """

    INTERCOM = 'Intercom'
    CALL_CONTROL_DISCOVERY_LEARNED_PATTERN = 'Call Control Discovery Learned Pattern'
    GENERAL = 'General'
    DIRECTORY_URI = 'Directory URI'


class PatternPrecedence(_AxlStrEnum):
    """AXL enum — ``XPatternPrecedence``.
    """

    FLASH_OVERRIDE = 'Flash Override'
    FLASH = 'Flash'
    IMMEDIATE = 'Immediate'
    PRIORITY = 'Priority'
    ROUTINE = 'Routine'
    DEFAULT = 'Default'
    EXECUTIVE_OVERRIDE = 'Executive Override'


class PatternRouteClass(_AxlStrEnum):
    """AXL enum — ``XPatternRouteClass``.
    """

    DEFAULT = 'Default'
    VOICE = 'Voice'
    DATA = 'Data'
    SATELLITE_AVOIDANCE = 'Satellite Avoidance'
    HOTLINE_VOICE = 'Hotline Voice'
    HOTLINE_DATA = 'Hotline Data'


class PatternUsage(_AxlStrEnum):
    """AXL enum — ``XPatternUsage``.
    """

    CALLPARK = 'CallPark'
    CONFERENCE = 'Conference'
    DEVICE = 'Device'
    TRANSLATION = 'Translation'
    CALL_PICK_UP_GROUP = 'Call Pick Up Group'
    ROUTE = 'Route'
    MESSAGE_WAITING = 'Message Waiting'
    HUNT_PILOT = 'Hunt Pilot'
    VOICE_MAIL_PORT = 'Voice Mail Port'
    DOMAIN_ROUTING = 'Domain Routing'
    IPADDRESS_ROUTING = 'IPAddress Routing'
    DEVICE_TEMPLATE = 'Device template'
    DIRECTED_CALL_PARK = 'Directed Call Park'
    DEVICE_INTERCOM = 'Device Intercom'
    TRANSLATION_INTERCOM = 'Translation Intercom'
    TRANSLATION_CALLING_PARTY_NUMBER = 'Translation Calling Party Number'
    MOBILITY_HANDOFF = 'Mobility Handoff'
    MOBILITY_ENTERPRISE_FEATURE_ACCESS = 'Mobility Enterprise Feature Access'
    MOBILITY_IVR = 'Mobility IVR'
    DEVICE_INTERCOM_TEMPLATE = 'Device Intercom Template'
    CALLED_PARTY_NUMBER_TRANSFORMATION = 'Called Party Number Transformation'
    CALL_CONTROL_DISCOVERY_LEARNED_PATTERN = 'Call Control Discovery Learned Pattern'
    URI_ROUTING = 'Uri Routing'
    ILS_LEARNED_ENTERPRISE_NUMBER = 'ILS Learned Enterprise Number'
    ILS_LEARNED_E164_NUMBER = 'ILS Learned E164 Number'
    ILS_LEARNED_ENTERPRISE_NUMERIC_PATTERN = 'ILS Learned Enterprise Numeric Pattern'
    ILS_LEARNED_E164_NUMERIC_PATTERN = 'ILS Learned E164 Numeric Pattern'
    ALTERNATE_NUMBER = 'Alternate Number'
    ILS_LEARNED_URI = 'ILS Learned URI'
    ILS_LEARNED_PSTN_FAILOVER_RULE = 'ILS Learned PSTN Failover Rule'
    ILS_IMPORTED_E164_NUMBER = 'ILS Imported E164 Number'
    CENTRALIZED_CONFERENCE_NUMBER = 'Centralized Conference Number'
    EMERGENCY_LOCATION_ID_NUMBER = 'Emergency Location ID Number'


class PhonePersonalization(_AxlStrEnum):
    """AXL enum — ``XPhonePersonalization``.
    """

    DISABLED = 'Disabled'
    ENABLED = 'Enabled'
    HTTPS_ONLY = 'HTTPS Only'
    DEFAULT = 'Default'


class PhoneService(_AxlStrEnum):
    """AXL enum — ``XPhoneService``.
    """

    STANDARD_IP_PHONE_SERVICE = 'Standard IP Phone Service'
    DIRECTORIES = 'Directories'
    MESSAGES = 'Messages'


class PhoneServiceCategory(_AxlStrEnum):
    """AXL enum — ``XPhoneServiceCategory``.
    """

    XML_SERVICE = 'XML Service'
    JAVA_MIDLET = 'Java MIDlet'
    WEB_WIDGET = 'Web Widget'
    WEB_LINK = 'Web Link'
    ANDROID_APK = 'Android APK'


class PhoneServiceDisplay(_AxlStrEnum):
    """AXL enum — ``XPhoneServiceDisplay``.
    """

    INTERNAL = 'Internal'
    EXTERNAL_URL = 'External URL'
    BOTH = 'Both'
    DEFAULT = 'Default'


class PickupNotification(_AxlStrEnum):
    """AXL enum — ``XPickupNotification``.
    """

    NO_ALERT = 'No Alert'
    AUDIO_ALERT = 'Audio Alert'
    VISUAL_ALERT = 'Visual Alert'
    AUDIO_AND_VISUAL_ALERT = 'Audio and Visual Alert'


class Preemption(_AxlStrEnum):
    """AXL enum — ``XPreemption``.
    """

    DISABLED = 'Disabled'
    FORCEFUL = 'Forceful'
    DEFAULT = 'Default'


class PreferredMediaSource(_AxlStrEnum):
    """AXL enum — ``XPreferredMediaSource``.
    """

    GATEWAY_PREFERRED = 'Gateway Preferred'
    PHONE_PREFERRED = 'Phone Preferred'


class PresentationBit(_AxlStrEnum):
    """AXL enum — ``XPresentationBit``.
    """

    DEFAULT = 'Default'
    ALLOWED = 'Allowed'
    RESTRICTED = 'Restricted'


class PriOfNumber(_AxlStrEnum):
    """AXL enum — ``XPriOfNumber``.
    """

    CISCO_CALLMANAGER = 'Cisco CallManager'
    UNKNOWN = 'Unknown'
    NATIONAL = 'National'
    INTERNATIONAL = 'International'
    SUBSCRIBER = 'Subscriber'


class PriProtocol(_AxlStrEnum):
    """AXL enum — ``XPriProtocol``.
    """

    PRI_4ESS = 'PRI 4ESS'
    PRI_5E8 = 'PRI 5E8'
    PRI_5E8_TELEOS = 'PRI 5E8 TELEOS'
    PRI_5E8_INTECOME = 'PRI 5E8 INTECOME'
    PRI_5E9 = 'PRI 5E9'
    PRI_DMS_100 = 'PRI DMS-100'
    PRI_DMS_250 = 'PRI DMS-250'
    PRI_EURO = 'PRI EURO'
    PRI_NI2 = 'PRI NI2'
    PRI_AUSTRALIAN = 'PRI AUSTRALIAN'
    PRI_5E8_CUSTOM = 'PRI 5E8 CUSTOM'
    PRI_ETSI_SC = 'PRI ETSI SC'
    PRI_NTT = 'PRI NTT'
    PRI_ISO_QSIG_T1 = 'PRI ISO QSIG T1'
    PRI_ISO_QSIG_E1 = 'PRI ISO QSIG E1'


class ProcessNodeRole(_AxlStrEnum):
    """AXL enum — ``XProcessNodeRole``.
    """

    CUCM_VOICE_VIDEO = 'CUCM Voice/Video'
    CUCM_IM_AND_PRESENCE = 'CUCM IM and Presence'


class Product(_AxlStrEnum):
    """AXL enum — ``XProduct``.
    """

    PILOT = 'Pilot'
    CISCO_CATALYST_6000_T1_VOIP_GATEWAY = 'Cisco Catalyst 6000 T1 VoIP Gateway'
    CISCO_CATALYST_6000_E1_VOIP_GATEWAY = 'Cisco Catalyst 6000 E1 VoIP Gateway'
    CISCO_CATALYST_6000_24_PORT_FXS_GATEWAY = 'Cisco Catalyst 6000 24 port FXS Gateway'
    CISCO_CATALYST_6000_12_PORT_FXO_GATEWAY = 'Cisco Catalyst 6000 12 port FXO Gateway'
    EMCC_BASE_PHONE = 'EMCC Base Phone'
    H_323_CLIENT = 'H.323 Client'
    H_323_GATEWAY = 'H.323 Gateway'
    CISCO_MGCP_FXO_PORT = 'Cisco MGCP FXO Port'
    CISCO_MGCP_FXS_PORT = 'Cisco MGCP FXS Port'
    CISCO_12_SPPLUS = 'Cisco 12 SP+'
    CISCO_12_SP = 'Cisco 12 SP'
    CISCO_12_S = 'Cisco 12 S'
    CISCO_30_SPPLUS = 'Cisco 30 SP+'
    CISCO_30_VIP = 'Cisco 30 VIP'
    CTI_PORT = 'CTI Port'
    CISCO_VOICE_MAIL_PORT = 'Cisco Voice Mail Port'
    CISCO_CONFERENCE_BRIDGE_SOFTWARE = 'Cisco Conference Bridge Software'
    CISCO_CONFERENCE_BRIDGE_HARDWARE = 'Cisco Conference Bridge Hardware'
    CISCO_MEDIA_TERMINATION_POINT_SOFTWARE = 'Cisco Media Termination Point Software'
    CISCO_MEDIA_TERMINATION_POINT_HARDWARE = 'Cisco Media Termination Point Hardware'
    CISCO_7935 = 'Cisco 7935'
    SCCP_DEVICE = 'SCCP Device'
    CISCO_7910 = 'Cisco 7910'
    CISCO_7960 = 'Cisco 7960'
    CISCO_7940 = 'Cisco 7940'
    ROUTE_LIST = 'Route List'
    UNKNOWN = 'Unknown'
    LOAD_SIMULATOR = 'Load Simulator'
    GATEKEEPER = 'Gatekeeper'
    NM_1V = 'NM-1V'
    NM_2V = 'NM-2V'
    CISCO_VG200 = 'Cisco VG200'
    CISCO_26XX = 'Cisco 26XX'
    CISCO_362X = 'Cisco 362X'
    CISCO_364X = 'Cisco 364X'
    CISCO_366X = 'Cisco 366X'
    CTI_ROUTE_POINT = 'CTI Route Point'
    MUSIC_ON_HOLD = 'Music On Hold'
    CISCO_MGCP_T1_PORT = 'Cisco MGCP T1 Port'
    NM_HDV = 'NM-HDV'
    VIC_SLOT = 'VIC_SLOT'
    CISCO_MGCP_E1_PORT = 'Cisco MGCP E1 Port'
    VWIC_SLOT = 'VWIC_SLOT'
    FLEX_SLOT = 'FLEX_SLOT'
    CISCO_CATALYST_4224_VOICE_GATEWAY_SWITCH = 'Cisco Catalyst 4224 Voice Gateway Switch'
    CISCO_CATALYST_4000_ACCESS_GATEWAY_MODULE = 'Cisco Catalyst 4000 Access Gateway  Module'
    CISCO_IOS_CONFERENCE_BRIDGE = 'Cisco IOS Conference Bridge'
    CISCO_IOS_MEDIA_TERMINATION_POINT = 'Cisco IOS Media Termination Point'
    CISCO_IAD2400 = 'Cisco  IAD2400'
    IAD2400_ANALOG = 'IAD2400_ANALOG'
    IAD2400_DIGITAL = 'IAD2400_DIGITAL'
    CISCO_VGC_PHONE = 'Cisco VGC Phone'
    CISCO_VG248_GATEWAY = 'Cisco VG248 Gateway'
    VGC_PORT = 'VGC Port'
    CISCO_VGC_VIRTUAL_PHONE = 'Cisco VGC Virtual Phone'
    CISCO_ATA_186 = 'Cisco ATA 186'
    H_225_TRUNK_GATEKEEPER_CONTROLLED = 'H.225 Trunk (Gatekeeper Controlled)'
    INTER_CLUSTER_TRUNK_GATEKEEPER_CONTROLLED = 'Inter-Cluster Trunk (Gatekeeper Controlled)'
    INTER_CLUSTER_TRUNK_NON_GATEKEEPER_CONTROLLED = 'Inter-Cluster Trunk (Non-Gatekeeper Controlled)'
    COMMUNICATION_MEDIA_MODULE = 'Communication Media Module'
    WS_X6600 = 'WS-X6600'
    AIM_VOICE_30 = 'AIM-VOICE-30'
    NM_HDA = 'NM-HDA'
    PA_VXA = 'PA-VXA'
    PA_VXB = 'PA-VXB'
    PA_VXC = 'PA-VXC'
    PA_MCX = 'PA-MCX'
    ANNUNCIATOR = 'Annunciator'
    CISCO_MGCP_BRI_PORT = 'Cisco MGCP BRI Port'
    NM_HD_1V = 'NM-HD-1V'
    NM_HD_2V = 'NM-HD-2V'
    NM_HD_2VE = 'NM-HD-2VE'
    SIP_TRUNK = 'SIP Trunk'
    CISCO_CONFERENCE_BRIDGE_WS_SVC_CMM = 'Cisco Conference Bridge (WS-SVC-CMM)'
    CISCO_MEDIA_SERVER_WS_SVC_CMM_MS = 'Cisco Media Server (WS-SVC-CMM-MS)'
    CISCO_MEDIA_TERMINATION_POINT_WS_SVC_CMM = 'Cisco Media Termination Point (WS-SVC-CMM)'
    CISCO_IOS_ENHANCED_SOFTWARE_MEDIA_TERMINATION_POINT = 'Cisco IOS Enhanced Software Media Termination Point'
    V_7914_14_BUTTON_LINE_EXPANSION_MODULE = '7914 14-Button Line Expansion Module'
    CISCO_IOS_ENHANCED_CONFERENCE_BRIDGE = 'Cisco IOS Enhanced Conference Bridge'
    CISCO_IOS_ENHANCED_MEDIA_TERMINATION_POINT = 'Cisco IOS Enhanced Media Termination Point'
    CISCO_VIDEO_CONFERENCE_BRIDGE_IPVC_35XX = 'Cisco Video Conference Bridge(IPVC-35xx)'
    CISCO_IOS_HETEROGENEOUS_VIDEO_CONFERENCE_BRIDGE = 'Cisco IOS Heterogeneous Video Conference Bridge'
    CISCO_IOS_GUARANTEED_AUDIO_VIDEO_CONFERENCE_BRIDGE = 'Cisco IOS Guaranteed Audio Video Conference Bridge'
    CISCO_IOS_HOMOGENEOUS_VIDEO_CONFERENCE_BRIDGE = 'Cisco IOS Homogeneous Video Conference Bridge'
    HUNT_LIST = 'Hunt List'
    SIP_WSM_CONNECTION = 'SIP WSM Connection'
    REMOTE_DESTINATION_PROFILE = 'Remote Destination Profile'
    CISCO_7941 = 'Cisco 7941'
    CISCO_7971 = 'Cisco 7971'
    CISCO_7985 = 'Cisco 7985'
    CISCO_7911 = 'Cisco 7911'
    CISCO_7961G_GE = 'Cisco 7961G-GE'
    CISCO_7941G_GE = 'Cisco 7941G-GE'
    V_7915_12_BUTTON_LINE_EXPANSION_MODULE = '7915 12-Button Line Expansion Module'
    V_7915_24_BUTTON_LINE_EXPANSION_MODULE = '7915 24-Button Line Expansion Module'
    V_7916_12_BUTTON_LINE_EXPANSION_MODULE = '7916 12-Button Line Expansion Module'
    V_7916_24_BUTTON_LINE_EXPANSION_MODULE = '7916 24-Button Line Expansion Module'
    CKEM_36_BUTTON_LINE_EXPANSION_MODULE = 'CKEM 36-Button Line Expansion Module'
    MOTOROLA_CN622 = 'Motorola CN622'
    THIRD_PARTY_SIP_DEVICE_BASIC = 'Third-party SIP Device (Basic)'
    CISCO_7931 = 'Cisco 7931'
    CISCO_UNIFIED_PERSONAL_COMMUNICATOR = 'Cisco Unified Personal Communicator'
    CISCO_7921 = 'Cisco 7921'
    CISCO_7906 = 'Cisco 7906'
    THIRD_PARTY_SIP_DEVICE_ADVANCED = 'Third-party SIP Device (Advanced)'
    CISCO_TELEPRESENCE = 'Cisco TelePresence'
    NOKIA_S60 = 'Nokia S60'
    CISCO_7962 = 'Cisco 7962'
    CISCO_3951 = 'Cisco 3951'
    CISCO_7937 = 'Cisco 7937'
    CISCO_7942 = 'Cisco 7942'
    CISCO_7945 = 'Cisco 7945'
    CISCO_7965 = 'Cisco 7965'
    CISCO_7975 = 'Cisco 7975'
    CISCO_3911 = 'Cisco 3911'
    CISCO_UNIFIED_MOBILE_COMMUNICATOR = 'Cisco Unified Mobile Communicator'
    CISCO_TELEPRESENCE_1000 = 'Cisco TelePresence 1000'
    CISCO_TELEPRESENCE_3000 = 'Cisco TelePresence 3000'
    CISCO_TELEPRESENCE_3200 = 'Cisco TelePresence 3200'
    CISCO_TELEPRESENCE_500_37 = 'Cisco TelePresence 500-37'
    CISCO_7925 = 'Cisco 7925'
    CISCO_9971 = 'Cisco 9971'
    CISCO_6921 = 'Cisco 6921'
    CISCO_6941 = 'Cisco 6941'
    CISCO_6961 = 'Cisco 6961'
    CISCO_UNIFIED_CLIENT_SERVICES_FRAMEWORK = 'Cisco Unified Client Services Framework'
    CISCO_TELEPRESENCE_1300_65 = 'Cisco TelePresence 1300-65'
    CISCO_TELEPRESENCE_1100 = 'Cisco TelePresence 1100'
    TRANSNOVA_S3 = 'Transnova S3'
    CISCO_9951 = 'Cisco 9951'
    CISCO_8961 = 'Cisco 8961'
    CISCO_6901 = 'Cisco 6901'
    CISCO_6911 = 'Cisco 6911'
    CISCO_ATA_187 = 'Cisco ATA 187'
    CISCO_TELEPRESENCE_200 = 'Cisco TelePresence 200'
    CISCO_TELEPRESENCE_400 = 'Cisco TelePresence 400'
    CISCO_DUAL_MODE_FOR_IPHONE = 'Cisco Dual Mode for iPhone'
    CISCO_6945 = 'Cisco 6945'
    CISCO_DUAL_MODE_FOR_ANDROID = 'Cisco Dual Mode for Android'
    CISCO_7926 = 'Cisco 7926'
    CISCO_E20 = 'Cisco E20'
    GENERIC_SINGLE_SCREEN_ROOM_SYSTEM = 'Generic Single Screen Room System'
    GENERIC_MULTIPLE_SCREEN_ROOM_SYSTEM = 'Generic Multiple Screen Room System'
    CISCO_TELEPRESENCE_EX90 = 'Cisco TelePresence EX90'
    CISCO_8945 = 'Cisco 8945'
    CISCO_8941 = 'Cisco 8941'
    GENERIC_DESKTOP_VIDEO_ENDPOINT = 'Generic Desktop Video Endpoint'
    CISCO_TELEPRESENCE_500_32 = 'Cisco TelePresence 500-32'
    CISCO_TELEPRESENCE_1300_47 = 'Cisco TelePresence 1300-47'
    CISCO_3905 = 'Cisco 3905'
    CISCO_CIUS = 'Cisco Cius'
    VKEM_36_BUTTON_LINE_EXPANSION_MODULE = 'VKEM 36-Button Line Expansion Module'
    CISCO_TELEPRESENCE_TX1310_65 = 'Cisco TelePresence TX1310-65'
    CISCO_TELEPRESENCE_MCU = 'Cisco TelePresence MCU'
    CISCO_TELEPRESENCE_CONDUCTOR = 'Cisco TelePresence Conductor'
    CISCO_TELEPRESENCE_EXCHANGE_SYSTEM = 'Cisco TelePresence Exchange System'
    CISCO_TELEPRESENCE_EX60 = 'Cisco TelePresence EX60'
    CISCO_TELEPRESENCE_CODEC_C90 = 'Cisco TelePresence Codec C90'
    CISCO_TELEPRESENCE_CODEC_C60 = 'Cisco TelePresence Codec C60'
    CISCO_TELEPRESENCE_CODEC_C40 = 'Cisco TelePresence Codec C40'
    CISCO_TELEPRESENCE_QUICK_SET_C20 = 'Cisco TelePresence Quick Set C20'
    CISCO_TELEPRESENCE_PROFILE_42_C20 = 'Cisco TelePresence Profile 42 (C20)'
    CISCO_TELEPRESENCE_PROFILE_42_C60 = 'Cisco TelePresence Profile 42 (C60)'
    CISCO_TELEPRESENCE_PROFILE_52_C40 = 'Cisco TelePresence Profile 52 (C40)'
    CISCO_TELEPRESENCE_PROFILE_52_C60 = 'Cisco TelePresence Profile 52 (C60)'
    CISCO_TELEPRESENCE_PROFILE_52_DUAL_C60 = 'Cisco TelePresence Profile 52 Dual (C60)'
    CISCO_TELEPRESENCE_PROFILE_65_C60 = 'Cisco TelePresence Profile 65 (C60)'
    CISCO_TELEPRESENCE_PROFILE_65_DUAL_C90 = 'Cisco TelePresence Profile 65 Dual (C90)'
    CISCO_TELEPRESENCE_MX200 = 'Cisco TelePresence MX200'
    CISCO_TELEPRESENCE_TX9000 = 'Cisco TelePresence TX9000'
    CISCO_TELEPRESENCE_TX9200 = 'Cisco TelePresence TX9200'
    CISCO_7821 = 'Cisco 7821'
    CISCO_7841 = 'Cisco 7841'
    CISCO_7861 = 'Cisco 7861'
    CISCO_TELEPRESENCE_SX20 = 'Cisco TelePresence SX20'
    CISCO_TELEPRESENCE_MX300 = 'Cisco TelePresence MX300'
    IMS_INTEGRATED_MOBILE_BASIC = 'IMS-integrated Mobile (Basic)'
    THIRD_PARTY_AS_SIP_ENDPOINT = 'Third-party AS-SIP Endpoint'
    CISCO_CIUS_SP = 'Cisco Cius SP'
    CISCO_TELEPRESENCE_PROFILE_42_C40 = 'Cisco TelePresence Profile 42 (C40)'
    CISCO_VXC_6215 = 'Cisco VXC 6215'
    CTI_REMOTE_DEVICE = 'CTI Remote Device'
    CARRIER_INTEGRATED_MOBILE = 'Carrier-integrated Mobile'
    UNIVERSAL_DEVICE_TEMPLATE = 'Universal Device Template'
    CISCO_DX650 = 'Cisco DX650'
    CISCO_UNIFIED_COMMUNICATIONS_FOR_RTX = 'Cisco Unified Communications for RTX'
    CISCO_JABBER_FOR_TABLET = 'Cisco Jabber for Tablet'
    CISCO_8831 = 'Cisco 8831'
    CISCO_ATA_190 = 'Cisco ATA 190'
    CISCO_TELEPRESENCE_SX10 = 'Cisco TelePresence SX10'
    CISCO_8841 = 'Cisco 8841'
    CISCO_8851 = 'Cisco 8851'
    CISCO_8861 = 'Cisco 8861'
    CISCO_TELEPRESENCE_SX80 = 'Cisco TelePresence SX80'
    CISCO_TELEPRESENCE_MX200_G2 = 'Cisco TelePresence MX200 G2'
    CISCO_TELEPRESENCE_MX300_G2 = 'Cisco TelePresence MX300 G2'
    WS_SVC_CMM_MS = 'WS-SVC-CMM-MS'
    NM_4VWIC_MBRD = 'NM-4VWIC-MBRD'
    VNM_HDA = 'VNM-HDA'
    NM_HDV2_0PORT = 'NM-HDV2-0PORT'
    NM_HDV2_1PORT = 'NM-HDV2-1PORT'
    NM_HDV2_2PORT = 'NM-HDV2-2PORT'
    CISCO_3745 = 'Cisco 3745'
    CISCO_3725 = 'Cisco 3725'
    CISCO_7905 = 'Cisco 7905'
    CISCO_7920 = 'Cisco 7920'
    CISCO_269X = 'Cisco 269X'
    CISCO_7970 = 'Cisco 7970'
    CISCO_1760 = 'Cisco 1760'
    CISCO_1751 = 'Cisco 1751'
    CISCO_7912 = 'Cisco 7912'
    CISCO_7902 = 'Cisco 7902'
    VG224 = 'VG224'
    CISCO_2821 = 'Cisco 2821'
    CISCO_IP_COMMUNICATOR = 'Cisco IP Communicator'
    CISCO_7961 = 'Cisco 7961'
    CISCO_7936 = 'Cisco 7936'
    CISCO_3825 = 'Cisco 3825'
    CISCO_3845 = 'Cisco 3845'
    CISCO_2811 = 'Cisco 2811'
    CISCO_2851 = 'Cisco 2851'
    ANALOG_PHONE = 'Analog Phone'
    ISDN_BRI_PHONE = 'ISDN BRI Phone'
    SCCP_GATEWAY_VIRTUAL_PHONE = 'SCCP gateway virtual phone'
    IP_STE = 'IP-STE'
    CISCO_2801 = 'Cisco 2801'
    CISCO_1861 = 'Cisco 1861'
    VG204 = 'VG204'
    CISCO_VGD_1T3 = 'Cisco VGD-1T3'
    VG202 = 'VG202'
    CISCO_881 = 'Cisco 881'
    CISCO_2951 = 'Cisco 2951'
    CISCO_3945 = 'Cisco 3945'
    CISCO_888_887_886 = 'Cisco 888/887/886'
    CISCO_2911 = 'Cisco 2911'
    CISCO_3925 = 'Cisco 3925'
    CISCO_2921 = 'Cisco 2921'
    CISCO_2901 = 'Cisco 2901'
    CISCO_3945E = 'Cisco 3945E'
    CISCO_3925E = 'Cisco 3925E'
    SPA8800 = 'SPA8800'
    C881V = 'C881V'
    C887VA_V = 'C887VA-V'
    VG350 = 'VG350'
    CISCO_ISR_4451 = 'Cisco ISR 4451'
    CISCO_ISR_4431 = 'Cisco ISR 4431'
    CISCO_DX80 = 'Cisco DX80'
    CISCO_DX70 = 'Cisco DX70'
    VG310 = 'VG310'
    VG320 = 'VG320'
    BEKEM_36_BUTTON_LINE_EXPANSION_MODULE = 'BEKEM 36-Button Line Expansion Module'
    CISCO_ISR_4351 = 'Cisco ISR 4351'
    CISCO_TELEPRESENCE_MX700 = 'Cisco TelePresence MX700'
    CISCO_TELEPRESENCE_MX800 = 'Cisco TelePresence MX800'
    CISCO_TELEPRESENCE_IX5000 = 'Cisco TelePresence IX5000'
    CISCO_ISR_4331 = 'Cisco ISR 4331'
    CISCO_7811 = 'Cisco 7811'
    CISCO_ISR_4321 = 'Cisco ISR 4321'
    CISCO_8821 = 'Cisco 8821'
    CISCO_8811 = 'Cisco 8811'
    INTERACTIVE_VOICE_RESPONSE = 'Interactive Voice Response'
    CISCO_8845 = 'Cisco 8845'
    CISCO_8865 = 'Cisco 8865'
    CISCO_TELEPRESENCE_MX800_DUAL = 'Cisco TelePresence MX800 Dual'
    CISCO_8851NR = 'Cisco 8851NR'
    CISCO_SPARK_REMOTE_DEVICE = 'Cisco Spark Remote Device'
    CISCO_WEBEX_DX80 = 'Cisco Webex DX80'
    CISCO_TELEPRESENCE_DX70 = 'Cisco TelePresence DX70'
    CISCO_7832 = 'Cisco 7832'
    CISCO_8865NR = 'Cisco 8865NR'
    CISCO_MEETING_SERVER = 'Cisco Meeting Server'
    CISCO_WEBEX_ROOM_KIT = 'Cisco Webex Room Kit'
    CISCO_WEBEX_ROOM_55 = 'Cisco Webex Room 55'
    CISCO_WEBEX_ROOM_KIT_PLUS = 'Cisco Webex Room Kit Plus'
    CP_8800_AUDIO_28_BUTTON_KEY_EXPANSION_MODULE = 'CP-8800-Audio 28-Button Key Expansion Module'
    CP_8800_VIDEO_28_BUTTON_KEY_EXPANSION_MODULE = 'CP-8800-Video 28-Button Key Expansion Module'
    CISCO_8832 = 'Cisco 8832'
    CISCO_WEBEX_ROOM_70_SINGLE = 'Cisco Webex Room 70 Single'
    CISCO_8832NR = 'Cisco 8832NR'
    CISCO_ATA_191 = 'Cisco ATA 191'
    CISCO_COLLABORATION_MOBILE_CONVERGENCE = 'Cisco Collaboration Mobile Convergence'
    CISCO_WEBEX_ROOM_70_DUAL = 'Cisco Webex Room 70 Dual'
    VG450 = 'VG450'
    CISCO_ISR_4461 = 'Cisco ISR 4461'
    CISCO_ENCS_5400_ISRV = 'Cisco ENCS 5400 ISRV'
    VG400 = 'VG400'
    CISCO_WEBEX_ROOM_KIT_PRO = 'Cisco Webex Room Kit Pro'
    CISCO_WEBEX_ROOM_55_DUAL = 'Cisco Webex Room 55 Dual'
    CISCO_WEBEX_ROOM_70_SINGLE_G2 = 'Cisco Webex Room 70 Single G2'
    CISCO_WEBEX_ROOM_70_DUAL_G2 = 'Cisco Webex Room 70 Dual G2'
    CISCO_SIP_FXS_PORT = 'Cisco SIP FXS Port'
    CISCO_WEBEX_ROOM_KIT_MINI = 'Cisco Webex Room Kit Mini'
    CISCO_C8300_1N1S_4T2X = 'Cisco C8300-1N1S-4T2X'
    CISCO_C8300_2N2S_4T2X_6T = 'Cisco C8300-2N2S-4T2X/6T'
    CISCO_C8200_L_1N_4T = 'Cisco C8200/L-1N-4T'
    CISCO_C8300_1N1S_6T = 'Cisco C8300-1N1S-6T'
    CISCO_WEBEX_VDI_SVC_FRAMEWORK = 'Cisco Webex VDI Svc Framework'
    CISCO_WEBEX_BOARD_55 = 'Cisco Webex Board 55'
    CISCO_WEBEX_BOARD_70 = 'Cisco Webex Board 70'
    CISCO_WEBEX_BOARD_85 = 'Cisco Webex Board 85'
    CISCO_WEBEX_DESK_PRO = 'Cisco Webex Desk Pro'
    CISCO_WEBEX_ROOM_PANORAMA = 'Cisco Webex Room Panorama'
    CISCO_WEBEX_ROOM_70_PANORAMA = 'Cisco Webex Room 70 Panorama'
    CISCO_WEBEX_ROOM_PHONE = 'Cisco Webex Room Phone'
    CISCO_860 = 'Cisco 860'
    CISCO_840 = 'Cisco 840'
    VG420 = 'VG420'
    CISCO_WEBEX_DESK_LE = 'Cisco Webex Desk LE'
    CISCO_WEBEX_DESK = 'Cisco Webex Desk'
    CISCO_WEBEX_DESK_MINI = 'Cisco Webex Desk Mini'
    CISCO_WEBEX_DESK_HUB = 'Cisco Webex Desk Hub'
    CISCO_WEBEX_BOARD_PRO_55 = 'Cisco Webex Board Pro 55'
    CISCO_WEBEX_BOARD_PRO_75 = 'Cisco Webex Board Pro 75'
    CISCO_WEBEX_ROOM_BAR = 'Cisco Webex Room Bar'
    CISCO_8875 = 'Cisco 8875'
    CISCO_8875NR = 'Cisco 8875NR'
    CISCO_8851NS = 'Cisco 8851NS'
    CISCO_8811NS = 'Cisco 8811NS'
    CISCO_8841NS = 'Cisco 8841NS'
    CISCO_ROOM_KIT_EQ = 'Cisco Room Kit EQ'
    VG410 = 'VG410'
    CISCO_ROOM_BAR_PRO = 'Cisco Room Bar Pro'
    CISCO_ROOM_KIT_EQX = 'Cisco Room Kit EQX'


class ProtocolSide(_AxlStrEnum):
    """AXL enum — ``XProtocolSide``.
    """

    NETWORK = 'Network'
    USER = 'User'


class QSIGVariant(_AxlStrEnum):
    """AXL enum — ``XQSIGVariant``.
    """

    NO_CHANGES = 'No Changes'
    ECMA = 'ECMA'
    ISO = 'ISO'


class RSVPOverSIP(_AxlStrEnum):
    """AXL enum — ``XRSVPOverSIP``.
    """

    LOCAL_RSVP = 'Local RSVP'
    E2E = 'E2E'


class RecordingFlag(_AxlStrEnum):
    """AXL enum — ``XRecordingFlag``.
    """

    CALL_RECORDING_DISABLED = 'Call Recording Disabled'
    AUTOMATIC_CALL_RECORDING_ENABLED = 'Automatic Call Recording Enabled'
    SELECTIVE_CALL_RECORDING_ENABLED = 'Selective Call Recording Enabled'


class ReleaseCauseValue(_AxlStrEnum):
    """AXL enum — ``XReleaseCauseValue``.
    """

    NO_ERROR = 'No Error'
    UNALLOCATED_NUMBER = 'Unallocated Number'
    CALL_REJECTED = 'Call Rejected'
    NUMBER_CHANGED = 'Number Changed'
    INVALID_NUMBER_FORMAT = 'Invalid Number Format'
    PRECEDENCE_LEVEL_EXCEEDED = 'Precedence Level Exceeded'


class Reset(_AxlStrEnum):
    """AXL enum — ``XReset``.
    """

    RESET = 'Reset'
    RESTART = 'Restart'
    APPLY_CONFIGURATION = 'Apply Configuration'
    GENERATE_PRT = 'Generate PRT'
    EXTENDED_CONFIG_PULL = 'Extended Config Pull'


class RevertPriority(_AxlStrEnum):
    """AXL enum — ``XRevertPriority``.
    """

    DEFAULT = 'Default'
    HIGHEST = 'Highest'


class RingSetting(_AxlStrEnum):
    """AXL enum — ``XRingSetting``.
    """

    USE_SYSTEM_DEFAULT = 'Use System Default'
    DISABLE = 'Disable'
    FLASH_ONLY = 'Flash Only'
    RING_ONCE = 'Ring Once'
    RING = 'Ring'
    BEEP_ONLY = 'Beep Only'


class RisStatus(_AxlStrEnum):
    """AXL enum — ``XRisStatus``.
    """

    UNKNOWN = 'Unknown'
    REGISTERED = 'Registered'
    UNREGISTERED = 'Unregistered'
    REJECTED = 'Rejected'
    PARTIAL_REGISTERED = 'Partial Registered'


class SIPBandwidthModifier(_AxlStrEnum):
    """AXL enum — ``XSIPBandwidthModifier``.
    """

    TIAS_AND_AS = 'TIAS and AS'
    TIAS_ONLY = 'TIAS only'
    AS_ONLY = 'AS only'
    CT_ONLY = 'CT only'


class SIPCodec(_AxlStrEnum):
    """AXL enum — ``XSIPCodec``.
    """

    V_711ULAW = '711ulaw'
    V_711ALAW = '711alaw'
    G729_G729A = 'G729/G729a'
    G729B_G729AB = 'G729b/G729ab'


class SIPIdentityBlend(_AxlStrEnum):
    """AXL enum — ``XSIPIdentityBlend``.
    """

    DELIVER_DN_ONLY_IN_CONNECTED_PARTY = 'Deliver DN only in connected party'
    DELIVER_URI_ONLY_IN_CONNECTED_PARTY_IF_AVAILABLE = 'Deliver URI only in connected party, if available'
    DELIVER_URI_AND_DN_IN_CONNECTED_PARTY_IF_AVAILABLE = 'Deliver URI and DN in connected party, if available'


class SIPRel1XXOptions(_AxlStrEnum):
    """AXL enum — ``XSIPRel1XXOptions``.
    """

    DISABLED = 'Disabled'
    SEND_PRACK_IF_1XX_CONTAINS_SDP = 'Send PRACK if 1xx Contains SDP'
    SEND_PRACK_FOR_ALL_1XX_MESSAGES = 'Send PRACK for all 1xx Messages'


class SIPReroute(_AxlStrEnum):
    """AXL enum — ``XSIPReroute``.
    """

    NEVER = 'Never'
    CONTACT_HEADER = 'Contact Header'
    CALL_INFO_HEADER_WITH_PURPOSEEQX_CISCO_ORIGIP = 'Call-Info Header with purpose=x-cisco-origIP'


class SIPScriptErrorHandling(_AxlStrEnum):
    """AXL enum — ``XSIPScriptErrorHandling``.
    """

    MESSAGE_ROLLBACK_ONLY = 'Message Rollback Only'
    DISABLE_SCRIPT = 'Disable Script'
    RESET_SCRIPT = 'Reset Script'
    RESET_TRUNK_RESTART_DEVICE = 'Reset Trunk / Restart Device'


class SIPTrunkCallLegSecurity(_AxlStrEnum):
    """AXL enum — ``XSIPTrunkCallLegSecurity``.
    """

    WHEN_USING_BOTH_SRTP_AND_TLS = 'When using both sRTP and TLS'
    WHEN_USING_SRTP_ONLY = 'When using sRTP Only'


class SNMPAuthenticationProtocol(_AxlStrEnum):
    """AXL enum — ``XSNMPAuthenticationProtocol``.

    .. warning::
       SNMP v3 authentication protocol. ``MD5`` is cryptographically broken and must not be selected for new configurations — choose ``SHA`` instead.
    """

    MD5 = 'MD5'
    SHA = 'SHA'


class SNMPPrivacyProtocol(_AxlStrEnum):
    """AXL enum — ``XSNMPPrivacyProtocol``.

    .. warning::
       SNMP v3 privacy (encryption) protocol. ``DES`` is broken and must not be selected for new configurations — choose ``AES_128`` instead.
    """

    DES = 'DES'
    AES_128 = 'AES-128'


class SNMPVersion(_AxlStrEnum):
    """AXL enum — ``XSNMPVersion``.
    """

    V_1 = '1'
    V_2C = '2C'
    V_3 = '3'


class ScheduleUnit(_AxlStrEnum):
    """AXL enum — ``XScheduleUnit``.
    """

    HOUR = 'HOUR'
    DAY = 'DAY'
    WEEK = 'WEEK'
    MONTH = 'MONTH'


class ServerSecurityMode(_AxlStrEnum):
    """AXL enum — ``XServerSecurityMode``.
    """

    AUTHENTICATED = 'Authenticated'
    ENCRYPTED_AND_AUTHENTICATED = 'Encrypted and Authenticated'


class Service(_AxlStrEnum):
    """AXL enum — ``XService``.
    """

    CISCO_CALLMANAGER = 'Cisco CallManager'
    CISCO_TFTP = 'Cisco Tftp'
    CISCO_MESSAGING_INTERFACE = 'Cisco Messaging Interface'
    CISCO_IP_VOICE_MEDIA_STREAMING_APP = 'Cisco IP Voice Media Streaming App'
    CISCO_CTIMANAGER = 'Cisco CTIManager'
    CISCO_RIS_DATA_COLLECTOR = 'Cisco RIS Data Collector'
    CISCO_EXTENSION_MOBILITY = 'Cisco Extension Mobility'
    CISCO_DATABASE_LAYER_MONITOR = 'Cisco Database Layer Monitor'
    ENTERPRISE_WIDE = 'Enterprise Wide'
    CISCO_IP_MANAGER_ASSISTANT = 'Cisco IP Manager Assistant'
    CISCO_EXTENDED_FUNCTIONS = 'Cisco Extended Functions'
    CISCO_SERVICEABILITY_REPORTER = 'Cisco Serviceability Reporter'
    CISCO_WEBDIALER_WEB_SERVICE = 'Cisco WebDialer Web Service'
    CISCO_DIALED_NUMBER_ANALYZER = 'Cisco Dialed Number Analyzer'
    CISCO_CDR_REPOSITORY_MANAGER = 'Cisco CDR Repository Manager'
    CISCO_CERTIFICATE_AUTHORITY_PROXY_FUNCTION = 'Cisco Certificate Authority Proxy Function'
    CISCO_CDR_AGENT = 'Cisco CDR Agent'
    CISCO_SOAP_CDRONDEMAND_SERVICE = 'Cisco SOAP - CDRonDemand Service'
    CISCO_CAR_SCHEDULER = 'Cisco CAR Scheduler'
    CISCO_CAR_WEB_SERVICE = 'Cisco CAR Web Service'
    CISCO_AMC_SERVICE = 'Cisco AMC Service'
    CISCO_LOG_PARTITION_MONITORING_TOOL = 'Cisco Log Partition Monitoring Tool'
    CISCO_CALLMANAGER_SNMP_SERVICE = 'Cisco CallManager SNMP Service'
    CISCO_DIRSYNC = 'Cisco DirSync'
    CISCO_AXL_WEB_SERVICE = 'Cisco AXL Web Service'
    CISCO_DRF_MASTER = 'Cisco DRF Master'
    CISCO_DRF_LOCAL = 'Cisco DRF Local'
    CISCO_CALLMANAGER_CISCO_IP_PHONE_SERVICES = 'Cisco CallManager Cisco IP Phone Services'
    CISCO_CCMADMIN_WEB_SERVICE = 'Cisco CCMAdmin Web Service'
    CISCO_CCMREALM_WEB_SERVICE = 'Cisco CCMRealm Web Service'
    CISCO_CCMSERVICE_WEB_SERVICE = 'Cisco CCMService Web Service'
    CISCO_SOAP_WEB_SERVICE = 'Cisco SOAP Web Service'
    CISCO_RTMT_WEB_SERVICE = 'Cisco RTMT Web Service'
    CISCO_CCM_PD_WEB_SERVICE = 'Cisco CCM PD Web Service'
    CISCO_CCM_DBL_WEB_LIBRARY = 'Cisco CCM DBL Web Library'
    CISCO_CCM_NCS_WEB_LIBRARY = 'Cisco CCM NCS Web Library'
    CISCO_BULK_PROVISIONING_SERVICE = 'Cisco Bulk Provisioning Service'
    CISCO_EXTENSION_MOBILITY_APPLICATION = 'Cisco Extension Mobility Application'
    CISCO_LICENSE_MANAGER = 'Cisco License Manager'
    CISCO_ROLE_BASED_SECURITY = 'Cisco Role-based Security'
    CISCO_TRACE_COLLECTION_SERVICE = 'Cisco Trace Collection Service'
    CISCO_SECURITY_AGENT = 'Cisco Security Agent'
    CISCO_TRUST_VERIFICATION_SERVICE = 'Cisco Trust Verification Service'
    CISCO_DHCP_MONITOR_SERVICE = 'Cisco DHCP Monitor Service'
    CISCO_TAPS_SERVICE = 'Cisco TAPS Service'
    CISCO_TOMCAT = 'Cisco Tomcat'
    CISCO_UNIFIED_OS_ADMIN_WEB_SERVICE = 'Cisco Unified OS Admin Web Service'
    CISCO_GRT_COMMUNICATION_WEB_SERVICE = 'Cisco GRT Communication Web Service'
    CISCO_UNIFIED_REPORTING_WEB_SERVICE = 'Cisco Unified Reporting Web Service'
    CISCO_RISBEAN_LIBRARY = 'Cisco RisBean Library'
    CISCO_SOAPMESSAGE_SERVICE = 'Cisco SOAPMessage Service'
    PLATFORM_ADMINISTRATIVE_WEB_SERVICE = 'Platform Administrative Web Service'
    CISCO_CHANGE_CREDENTIAL_APPLICATION = 'Cisco Change Credential Application'
    CISCO_CCMUSER_WEB_SERVICE = 'Cisco CCMUser Web Service'
    CISCO_AUDIT_EVENT_SERVICE = 'Cisco Audit Event Service'
    SOAP_DIAGNOSTIC_PORTAL_DATABASE_SERVICE = 'SOAP - Diagnostic Portal Database Service'
    CISCO_SIP_PROXY = 'Cisco SIP Proxy'
    CISCO_UXL_WEB_SERVICE = 'Cisco UXL Web Service'
    CISCO_CONFIG_AGENT = 'Cisco Config Agent'
    CISCO_OAM_AGENT = 'Cisco OAM Agent'
    CISCO_CLIENT_PROFILE_AGENT = 'Cisco Client Profile Agent'
    CISCO_SYNC_AGENT = 'Cisco Sync Agent'
    CISCO_SIP_PROXY_LOGGER = 'Cisco SIP Proxy Logger'
    CISCO_INTERCLUSTER_SYNC_AGENT = 'Cisco Intercluster Sync Agent'
    CISCO_XCP_ROUTER = 'Cisco XCP Router'
    CISCO_XCP_TEXT_CONFERENCE_MANAGER = 'Cisco XCP Text Conference Manager'
    CISCO_XCP_WEB_CONNECTION_MANAGER = 'Cisco XCP Web Connection Manager'
    CISCO_XCP_CONNECTION_MANAGER = 'Cisco XCP Connection Manager'
    CISCO_XCP_SIP_FEDERATION_CONNECTION_MANAGER = 'Cisco XCP SIP Federation Connection Manager'
    CISCO_XCP_XMPP_FEDERATION_CONNECTION_MANAGER = 'Cisco XCP XMPP Federation Connection Manager'
    CISCO_XCP_MESSAGE_ARCHIVER = 'Cisco XCP Message Archiver'
    CISCO_XCP_DIRECTORY_SERVICE = 'Cisco XCP Directory Service'
    CISCO_XCP_AUTHENTICATION_SERVICE = 'Cisco XCP Authentication Service'
    CISCO_IM_AND_PRESENCE_ADMIN = 'Cisco IM and Presence Admin'
    CISCO_SERVER_RECOVERY_MANAGER = 'Cisco Server Recovery Manager'
    CISCO_XCP_CONFIG_MANAGER = 'Cisco XCP Config Manager'
    CISCO_IM_AND_PRESENCE_DATA_MONITOR = 'Cisco IM and Presence Data Monitor'
    CISCO_PRESENCE_DATASTORE = 'Cisco Presence Datastore'
    CISCO_LOGIN_DATASTORE = 'Cisco Login Datastore'
    CISCO_ROUTE_DATASTORE = 'Cisco Route Datastore'
    CISCO_SIP_REGISTRATION_DATASTORE = 'Cisco SIP Registration Datastore'
    CISCO_PRESENCE_ENGINE = 'Cisco Presence Engine'
    CISCO_COMMON_USER_INTERFACE = 'Cisco Common User Interface'
    CISCO_USER_DATA_SERVICES = 'Cisco User Data Services'
    CISCO_EXTERNAL_CALL_CONTROL_SERVICE = 'Cisco External Call Control Service'
    CISCO_E911_SERVICE = 'Cisco E911 Service'
    CISCO_LOCATION_BANDWIDTH_MANAGER = 'Cisco Location Bandwidth Manager'
    CISCO_DIALED_NUMBER_ANALYZER_SERVER = 'Cisco Dialed Number Analyzer Server'
    CISCO_UNIFIED_MOBILE_VOICE_ACCESS_SERVICE = 'Cisco Unified Mobile Voice Access Service'
    CISCO_INTERCLUSTER_LOOKUP_SERVICE = 'Cisco Intercluster Lookup Service'
    CISCO_DIRECTORY_NUMBER_ALIAS_SYNC = 'Cisco Directory Number Alias Sync'
    CISCO_DIRECTORY_NUMBER_ALIAS_LOOKUP = 'Cisco Directory Number Alias Lookup'
    SELF_PROVISIONING_IVR = 'Self Provisioning IVR'
    CISCO_RCC_DEVICE_SELECTION_SERVICE = 'Cisco RCC Device Selection Service'
    CISCO_CTLCLI = 'Cisco CtlCli'
    CISCO_XCP_FILE_TRANSFER_MANAGER = 'Cisco XCP File Transfer Manager'
    CISCO_CERTIFICATE_CHANGE_NOTIFICATION_SERVICE = 'Cisco Certificate Change Notification Service'
    CISCO_WIRELESS_CONTROLLER_SYNCHRONIZATION_SERVICE = 'Cisco Wireless Controller Synchronization Service'
    CISCO_SMART_LICENSE_MANAGER = 'Cisco Smart License Manager'
    CISCO_UPGRADE_AGENT_SERVICE = 'Cisco Upgrade Agent Service'
    CISCO_MANAGEMENT_AGENT_SERVICE = 'Cisco Management Agent Service'
    CISCO_PUSH_NOTIFICATION_SERVICE = 'Cisco Push Notification Service'
    CISCO_CERTIFICATE_ENROLLMENT_SERVICE = 'Cisco Certificate Enrollment Service'
    PLATFORM_COMMUNICATION_WEB_SERVICE = 'Platform Communication Web Service'
    CISCO_DEVICE_ACTIVATION_SERVICE = 'Cisco Device Activation Service'
    CISCO_HEADSET_SERVICE = 'Cisco Headset Service'
    CISCO_LOCAL_PUSH_NOTIFICATION_SERVICE = 'Cisco Local Push Notification Service'
    CISCO_CERTIFICATE_EXPIRY_MONITOR = 'Cisco Certificate Expiry Monitor'


class ServiceGrouping(_AxlStrEnum):
    """AXL enum — ``XServiceGrouping``.
    """

    CM_SERVICES = 'CM Services'
    CTI_SERVICES = 'CTI Services'
    CDR_SERVICES = 'CDR Services'
    DATABASE_AND_ADMIN_SERVICES = 'Database and Admin Services'
    PERFORMANCE_AND_MONITORING_SERVICES = 'Performance and Monitoring Services'
    SECURITY_SERVICES = 'Security Services'
    DIRECTORY_SERVICES = 'Directory Services'
    BACKUP_AND_RESTORE_SERVICES = 'Backup and Restore Services'
    SYSTEM_SERVICES = 'System Services'
    SOAP_SERVICES = 'Soap Services'
    VOICE_QUALITY_REPORTER_SERVICES = 'Voice Quality Reporter Services'
    PLATFORM_SERVICES = 'Platform Services'
    IM_AND_PRESENCE_SERVICES = 'IM and Presence Services'
    LOCATION_BASED_TRACKING_SERVICES = 'Location based Tracking Services'
    CLOUD_BASED_MANAGEMENT_SERVICES = 'Cloud based Management Services'


class SilenceSuppressionThreshold(_AxlStrEnum):
    """AXL enum — ``XSilenceSuppressionThreshold``.
    """

    DISABLE = 'Disable'
    V_48DBM0 = '-48dbm0'
    V_45DBM0 = '-45dbm0'
    V_42DBM0 = '-42dbm0'
    V_39DBM0 = '-39dbm0'
    V_36DBM0 = '-36dbm0'
    V_33DBM0 = '-33dbm0'
    V_30DBM0 = '-30dbm0'


class SipAssertedType(_AxlStrEnum):
    """AXL enum — ``XSipAssertedType``.
    """

    DEFAULT = 'Default'
    PAI = 'PAI'
    PPI = 'PPI'


class SipPrivacy(_AxlStrEnum):
    """AXL enum — ``XSipPrivacy``.
    """

    DEFAULT = 'Default'
    NONE_ = 'None'
    ID = 'ID'
    ID_CRITICAL = 'ID Critical'


class SipSessionRefreshMethod(_AxlStrEnum):
    """AXL enum — ``XSipSessionRefreshMethod``.
    """

    INVITE = 'Invite'
    UPDATE = 'Update'


class StartDialProtocol(_AxlStrEnum):
    """AXL enum — ``XStartDialProtocol``.
    """

    NOT_SET = 'Not Set'
    IMMEDIATE = 'Immediate'
    WINK_START_FEATURE_GROUP_B = 'Wink Start Feature Group B'
    DELAY_DIAL = 'Delay Dial'
    WINK_START_FEATURE_GROUP_D = 'Wink Start Feature Group D'


class Status(_AxlStrEnum):
    """AXL enum — ``XStatus``.
    """

    OFF = 'Off'
    ON = 'On'
    DEFAULT = 'Default'


class SyncStatus(_AxlStrEnum):
    """AXL enum — ``XSyncStatus``.
    """

    NEVER_SYNCED = 'Never Synced'
    PENDING = 'Pending'
    IN_PROCESS = 'In Process'
    FAILURE = 'Failure'
    SUCCESS = 'Success'
    CANCELLED = 'Cancelled'


class TelnetLevel(_AxlStrEnum):
    """AXL enum — ``XTelnetLevel``.
    """

    DISABLED = 'Disabled'
    LIMITED = 'Limited'
    ENABLED = 'Enabled'


class Terminal(_AxlStrEnum):
    """AXL enum — ``XTerminal``.
    """

    NOT_SELECTED = '-- Not Selected --'
    TERMINAL = 'Terminal'
    GATEWAY = 'Gateway'


class TimeOfDay(_AxlStrEnum):
    """AXL enum — ``XTimeOfDay``.
    """

    NO_OFFICE_HOURS = 'No Office Hours'
    V_00_00 = '00:00'
    V_00_15 = '00:15'
    V_00_30 = '00:30'
    V_00_45 = '00:45'
    V_01_00 = '01:00'
    V_01_15 = '01:15'
    V_01_30 = '01:30'
    V_01_45 = '01:45'
    V_02_00 = '02:00'
    V_02_15 = '02:15'
    V_02_30 = '02:30'
    V_02_45 = '02:45'
    V_03_00 = '03:00'
    V_03_15 = '03:15'
    V_03_30 = '03:30'
    V_03_45 = '03:45'
    V_04_00 = '04:00'
    V_04_15 = '04:15'
    V_04_30 = '04:30'
    V_04_45 = '04:45'
    V_05_00 = '05:00'
    V_05_15 = '05:15'
    V_05_30 = '05:30'
    V_05_45 = '05:45'
    V_06_00 = '06:00'
    V_06_15 = '06:15'
    V_06_30 = '06:30'
    V_06_45 = '06:45'
    V_07_00 = '07:00'
    V_07_15 = '07:15'
    V_07_30 = '07:30'
    V_07_45 = '07:45'
    V_08_00 = '08:00'
    V_08_15 = '08:15'
    V_08_30 = '08:30'
    V_08_45 = '08:45'
    V_09_00 = '09:00'
    V_09_15 = '09:15'
    V_09_30 = '09:30'
    V_09_45 = '09:45'
    V_10_00 = '10:00'
    V_10_15 = '10:15'
    V_10_30 = '10:30'
    V_10_45 = '10:45'
    V_11_00 = '11:00'
    V_11_15 = '11:15'
    V_11_30 = '11:30'
    V_11_45 = '11:45'
    V_12_00 = '12:00'
    V_12_15 = '12:15'
    V_12_30 = '12:30'
    V_12_45 = '12:45'
    V_13_00 = '13:00'
    V_13_15 = '13:15'
    V_13_30 = '13:30'
    V_13_45 = '13:45'
    V_14_00 = '14:00'
    V_14_15 = '14:15'
    V_14_30 = '14:30'
    V_14_45 = '14:45'
    V_15_00 = '15:00'
    V_15_15 = '15:15'
    V_15_30 = '15:30'
    V_15_45 = '15:45'
    V_16_00 = '16:00'
    V_16_15 = '16:15'
    V_16_30 = '16:30'
    V_16_45 = '16:45'
    V_17_00 = '17:00'
    V_17_15 = '17:15'
    V_17_30 = '17:30'
    V_17_45 = '17:45'
    V_18_00 = '18:00'
    V_18_15 = '18:15'
    V_18_30 = '18:30'
    V_18_45 = '18:45'
    V_19_00 = '19:00'
    V_19_15 = '19:15'
    V_19_30 = '19:30'
    V_19_45 = '19:45'
    V_20_00 = '20:00'
    V_20_15 = '20:15'
    V_20_30 = '20:30'
    V_20_45 = '20:45'
    V_21_00 = '21:00'
    V_21_15 = '21:15'
    V_21_30 = '21:30'
    V_21_45 = '21:45'
    V_22_00 = '22:00'
    V_22_15 = '22:15'
    V_22_30 = '22:30'
    V_22_45 = '22:45'
    V_23_00 = '23:00'
    V_23_15 = '23:15'
    V_23_30 = '23:30'
    V_23_45 = '23:45'
    V_24_00 = '24:00'


class TimeScheduleCategory(_AxlStrEnum):
    """AXL enum — ``XTimeScheduleCategory``.
    """

    REGULAR = 'Regular'
    HOLIDAY_OR_VACATION = 'Holiday or Vacation'


class TimeZone(_AxlStrEnum):
    """AXL enum — ``XTimeZone``.
    """

    AFRICA_ABIDJAN = 'Africa/Abidjan'
    AFRICA_ACCRA = 'Africa/Accra'
    AFRICA_ADDIS_ABABA = 'Africa/Addis_Ababa'
    AFRICA_ALGIERS = 'Africa/Algiers'
    AFRICA_ASMARA = 'Africa/Asmara'
    AFRICA_BAMAKO = 'Africa/Bamako'
    AFRICA_BANGUI = 'Africa/Bangui'
    AFRICA_BANJUL = 'Africa/Banjul'
    AFRICA_BISSAU = 'Africa/Bissau'
    AFRICA_BLANTYRE = 'Africa/Blantyre'
    AFRICA_BRAZZAVILLE = 'Africa/Brazzaville'
    AFRICA_BUJUMBURA = 'Africa/Bujumbura'
    AFRICA_CAIRO = 'Africa/Cairo'
    AFRICA_CASABLANCA = 'Africa/Casablanca'
    AFRICA_CEUTA = 'Africa/Ceuta'
    AFRICA_CONAKRY = 'Africa/Conakry'
    AFRICA_DAKAR = 'Africa/Dakar'
    AFRICA_DAR_ES_SALAAM = 'Africa/Dar_es_Salaam'
    AFRICA_DJIBOUTI = 'Africa/Djibouti'
    AFRICA_DOUALA = 'Africa/Douala'
    AFRICA_EL_AAIUN = 'Africa/El_Aaiun'
    AFRICA_FREETOWN = 'Africa/Freetown'
    AFRICA_GABORONE = 'Africa/Gaborone'
    AFRICA_HARARE = 'Africa/Harare'
    AFRICA_JOHANNESBURG = 'Africa/Johannesburg'
    AFRICA_JUBA = 'Africa/Juba'
    AFRICA_KAMPALA = 'Africa/Kampala'
    AFRICA_KHARTOUM = 'Africa/Khartoum'
    AFRICA_KIGALI = 'Africa/Kigali'
    AFRICA_KINSHASA = 'Africa/Kinshasa'
    AFRICA_LAGOS = 'Africa/Lagos'
    AFRICA_LIBREVILLE = 'Africa/Libreville'
    AFRICA_LOME = 'Africa/Lome'
    AFRICA_LUANDA = 'Africa/Luanda'
    AFRICA_LUBUMBASHI = 'Africa/Lubumbashi'
    AFRICA_LUSAKA = 'Africa/Lusaka'
    AFRICA_MALABO = 'Africa/Malabo'
    AFRICA_MAPUTO = 'Africa/Maputo'
    AFRICA_MASERU = 'Africa/Maseru'
    AFRICA_MBABANE = 'Africa/Mbabane'
    AFRICA_MOGADISHU = 'Africa/Mogadishu'
    AFRICA_MONROVIA = 'Africa/Monrovia'
    AFRICA_NAIROBI = 'Africa/Nairobi'
    AFRICA_NDJAMENA = 'Africa/Ndjamena'
    AFRICA_NIAMEY = 'Africa/Niamey'
    AFRICA_NOUAKCHOTT = 'Africa/Nouakchott'
    AFRICA_OUAGADOUGOU = 'Africa/Ouagadougou'
    AFRICA_PORTO_NOVO = 'Africa/Porto-Novo'
    AFRICA_SAO_TOME = 'Africa/Sao_Tome'
    AFRICA_TRIPOLI = 'Africa/Tripoli'
    AFRICA_TUNIS = 'Africa/Tunis'
    AFRICA_WINDHOEK = 'Africa/Windhoek'
    AMERICA_ADAK = 'America/Adak'
    AMERICA_ANCHORAGE = 'America/Anchorage'
    AMERICA_ANGUILLA = 'America/Anguilla'
    AMERICA_ANTIGUA = 'America/Antigua'
    AMERICA_ARAGUAINA = 'America/Araguaina'
    AMERICA_ARGENTINA_BUENOS_AIRES = 'America/Argentina/Buenos_Aires'
    AMERICA_ARGENTINA_CATAMARCA = 'America/Argentina/Catamarca'
    AMERICA_ARGENTINA_CORDOBA = 'America/Argentina/Cordoba'
    AMERICA_ARGENTINA_JUJUY = 'America/Argentina/Jujuy'
    AMERICA_ARGENTINA_LA_RIOJA = 'America/Argentina/La_Rioja'
    AMERICA_ARGENTINA_MENDOZA = 'America/Argentina/Mendoza'
    AMERICA_ARGENTINA_RIO_GALLEGOS = 'America/Argentina/Rio_Gallegos'
    AMERICA_ARGENTINA_SALTA = 'America/Argentina/Salta'
    AMERICA_ARGENTINA_SAN_JUAN = 'America/Argentina/San_Juan'
    AMERICA_ARGENTINA_SAN_LUIS = 'America/Argentina/San_Luis'
    AMERICA_ARGENTINA_TUCUMAN = 'America/Argentina/Tucuman'
    AMERICA_ARGENTINA_USHUAIA = 'America/Argentina/Ushuaia'
    AMERICA_ARUBA = 'America/Aruba'
    AMERICA_ASUNCION = 'America/Asuncion'
    AMERICA_ATIKOKAN = 'America/Atikokan'
    AMERICA_BAHIA = 'America/Bahia'
    AMERICA_BAHIA_BANDERAS = 'America/Bahia_Banderas'
    AMERICA_BARBADOS = 'America/Barbados'
    AMERICA_BELEM = 'America/Belem'
    AMERICA_BELIZE = 'America/Belize'
    AMERICA_BLANC_SABLON = 'America/Blanc-Sablon'
    AMERICA_BOA_VISTA = 'America/Boa_Vista'
    AMERICA_BOGOTA = 'America/Bogota'
    AMERICA_BOISE = 'America/Boise'
    AMERICA_CAMBRIDGE_BAY = 'America/Cambridge_Bay'
    AMERICA_CAMPO_GRANDE = 'America/Campo_Grande'
    AMERICA_CANCUN = 'America/Cancun'
    AMERICA_CARACAS = 'America/Caracas'
    AMERICA_CAYENNE = 'America/Cayenne'
    AMERICA_CAYMAN = 'America/Cayman'
    AMERICA_CHICAGO = 'America/Chicago'
    AMERICA_CHIHUAHUA = 'America/Chihuahua'
    AMERICA_COSTA_RICA = 'America/Costa_Rica'
    AMERICA_CRESTON = 'America/Creston'
    AMERICA_CUIABA = 'America/Cuiaba'
    AMERICA_CURACAO = 'America/Curacao'
    AMERICA_DANMARKSHAVN = 'America/Danmarkshavn'
    AMERICA_DAWSON = 'America/Dawson'
    AMERICA_DAWSON_CREEK = 'America/Dawson_Creek'
    AMERICA_DENVER = 'America/Denver'
    AMERICA_DETROIT = 'America/Detroit'
    AMERICA_DOMINICA = 'America/Dominica'
    AMERICA_EDMONTON = 'America/Edmonton'
    AMERICA_EIRUNEPE = 'America/Eirunepe'
    AMERICA_EL_SALVADOR = 'America/El_Salvador'
    AMERICA_FORTALEZA = 'America/Fortaleza'
    AMERICA_GLACE_BAY = 'America/Glace_Bay'
    AMERICA_GODTHAB = 'America/Godthab'
    AMERICA_GOOSE_BAY = 'America/Goose_Bay'
    AMERICA_GRAND_TURK = 'America/Grand_Turk'
    AMERICA_GRENADA = 'America/Grenada'
    AMERICA_GUADELOUPE = 'America/Guadeloupe'
    AMERICA_GUATEMALA = 'America/Guatemala'
    AMERICA_GUAYAQUIL = 'America/Guayaquil'
    AMERICA_GUYANA = 'America/Guyana'
    AMERICA_HALIFAX = 'America/Halifax'
    AMERICA_HAVANA = 'America/Havana'
    AMERICA_HERMOSILLO = 'America/Hermosillo'
    AMERICA_INDIANA_INDIANAPOLIS = 'America/Indiana/Indianapolis'
    AMERICA_INDIANA_KNOX = 'America/Indiana/Knox'
    AMERICA_INDIANA_MARENGO = 'America/Indiana/Marengo'
    AMERICA_INDIANA_PETERSBURG = 'America/Indiana/Petersburg'
    AMERICA_INDIANA_TELL_CITY = 'America/Indiana/Tell_City'
    AMERICA_INDIANA_VEVAY = 'America/Indiana/Vevay'
    AMERICA_INDIANA_VINCENNES = 'America/Indiana/Vincennes'
    AMERICA_INDIANA_WINAMAC = 'America/Indiana/Winamac'
    AMERICA_INUVIK = 'America/Inuvik'
    AMERICA_IQALUIT = 'America/Iqaluit'
    AMERICA_JAMAICA = 'America/Jamaica'
    AMERICA_JUNEAU = 'America/Juneau'
    AMERICA_KENTUCKY_LOUISVILLE = 'America/Kentucky/Louisville'
    AMERICA_KENTUCKY_MONTICELLO = 'America/Kentucky/Monticello'
    AMERICA_KRALENDIJK = 'America/Kralendijk'
    AMERICA_LA_PAZ = 'America/La_Paz'
    AMERICA_LIMA = 'America/Lima'
    AMERICA_LOS_ANGELES = 'America/Los_Angeles'
    AMERICA_LOWER_PRINCES = 'America/Lower_Princes'
    AMERICA_MACEIO = 'America/Maceio'
    AMERICA_MANAGUA = 'America/Managua'
    AMERICA_MANAUS = 'America/Manaus'
    AMERICA_MARIGOT = 'America/Marigot'
    AMERICA_MARTINIQUE = 'America/Martinique'
    AMERICA_MATAMOROS = 'America/Matamoros'
    AMERICA_MAZATLAN = 'America/Mazatlan'
    AMERICA_MENOMINEE = 'America/Menominee'
    AMERICA_MERIDA = 'America/Merida'
    AMERICA_METLAKATLA = 'America/Metlakatla'
    AMERICA_MEXICO_CITY = 'America/Mexico_City'
    AMERICA_MIQUELON = 'America/Miquelon'
    AMERICA_MONCTON = 'America/Moncton'
    AMERICA_MONTERREY = 'America/Monterrey'
    AMERICA_MONTEVIDEO = 'America/Montevideo'
    AMERICA_MONTREAL = 'America/Montreal'
    AMERICA_MONTSERRAT = 'America/Montserrat'
    AMERICA_NASSAU = 'America/Nassau'
    AMERICA_NEW_YORK = 'America/New_York'
    AMERICA_NIPIGON = 'America/Nipigon'
    AMERICA_NOME = 'America/Nome'
    AMERICA_NORONHA = 'America/Noronha'
    AMERICA_NORTH_DAKOTA_BEULAH = 'America/North_Dakota/Beulah'
    AMERICA_NORTH_DAKOTA_CENTER = 'America/North_Dakota/Center'
    AMERICA_NORTH_DAKOTA_NEW_SALEM = 'America/North_Dakota/New_Salem'
    AMERICA_OJINAGA = 'America/Ojinaga'
    AMERICA_PANAMA = 'America/Panama'
    AMERICA_PANGNIRTUNG = 'America/Pangnirtung'
    AMERICA_PARAMARIBO = 'America/Paramaribo'
    AMERICA_PHOENIX = 'America/Phoenix'
    AMERICA_PORT_AU_PRINCE = 'America/Port-au-Prince'
    AMERICA_PORT_OF_SPAIN = 'America/Port_of_Spain'
    AMERICA_PORTO_VELHO = 'America/Porto_Velho'
    AMERICA_PUERTO_RICO = 'America/Puerto_Rico'
    AMERICA_RAINY_RIVER = 'America/Rainy_River'
    AMERICA_RANKIN_INLET = 'America/Rankin_Inlet'
    AMERICA_RECIFE = 'America/Recife'
    AMERICA_REGINA = 'America/Regina'
    AMERICA_RESOLUTE = 'America/Resolute'
    AMERICA_RIO_BRANCO = 'America/Rio_Branco'
    AMERICA_SANTA_ISABEL = 'America/Santa_Isabel'
    AMERICA_SANTAREM = 'America/Santarem'
    AMERICA_SANTIAGO = 'America/Santiago'
    AMERICA_SANTO_DOMINGO = 'America/Santo_Domingo'
    AMERICA_SAO_PAULO = 'America/Sao_Paulo'
    AMERICA_SCORESBYSUND = 'America/Scoresbysund'
    AMERICA_SHIPROCK = 'America/Shiprock'
    AMERICA_SITKA = 'America/Sitka'
    AMERICA_ST_BARTHELEMY = 'America/St_Barthelemy'
    AMERICA_ST_JOHNS = 'America/St_Johns'
    AMERICA_ST_KITTS = 'America/St_Kitts'
    AMERICA_ST_LUCIA = 'America/St_Lucia'
    AMERICA_ST_THOMAS = 'America/St_Thomas'
    AMERICA_ST_VINCENT = 'America/St_Vincent'
    AMERICA_SWIFT_CURRENT = 'America/Swift_Current'
    AMERICA_TEGUCIGALPA = 'America/Tegucigalpa'
    AMERICA_THULE = 'America/Thule'
    AMERICA_THUNDER_BAY = 'America/Thunder_Bay'
    AMERICA_TIJUANA = 'America/Tijuana'
    AMERICA_TORONTO = 'America/Toronto'
    AMERICA_TORTOLA = 'America/Tortola'
    AMERICA_VANCOUVER = 'America/Vancouver'
    AMERICA_WHITEHORSE = 'America/Whitehorse'
    AMERICA_WINNIPEG = 'America/Winnipeg'
    AMERICA_YAKUTAT = 'America/Yakutat'
    AMERICA_YELLOWKNIFE = 'America/Yellowknife'
    ANTARCTICA_CASEY = 'Antarctica/Casey'
    ANTARCTICA_DAVIS = 'Antarctica/Davis'
    ANTARCTICA_DUMONTDURVILLE = 'Antarctica/DumontDUrville'
    ANTARCTICA_MACQUARIE = 'Antarctica/Macquarie'
    ANTARCTICA_MAWSON = 'Antarctica/Mawson'
    ANTARCTICA_MCMURDO = 'Antarctica/McMurdo'
    ANTARCTICA_PALMER = 'Antarctica/Palmer'
    ANTARCTICA_ROTHERA = 'Antarctica/Rothera'
    ANTARCTICA_SOUTH_POLE = 'Antarctica/South_Pole'
    ANTARCTICA_SYOWA = 'Antarctica/Syowa'
    ANTARCTICA_VOSTOK = 'Antarctica/Vostok'
    ARCTIC_LONGYEARBYEN = 'Arctic/Longyearbyen'
    ASIA_ADEN = 'Asia/Aden'
    ASIA_ALMATY = 'Asia/Almaty'
    ASIA_AMMAN = 'Asia/Amman'
    ASIA_ANADYR = 'Asia/Anadyr'
    ASIA_AQTAU = 'Asia/Aqtau'
    ASIA_AQTOBE = 'Asia/Aqtobe'
    ASIA_ASHGABAT = 'Asia/Ashgabat'
    ASIA_BAGHDAD = 'Asia/Baghdad'
    ASIA_BAHRAIN = 'Asia/Bahrain'
    ASIA_BAKU = 'Asia/Baku'
    ASIA_BANGKOK = 'Asia/Bangkok'
    ASIA_BEIRUT = 'Asia/Beirut'
    ASIA_BISHKEK = 'Asia/Bishkek'
    ASIA_BRUNEI = 'Asia/Brunei'
    ASIA_CHOIBALSAN = 'Asia/Choibalsan'
    ASIA_CHONGQING = 'Asia/Chongqing'
    ASIA_COLOMBO = 'Asia/Colombo'
    ASIA_DAMASCUS = 'Asia/Damascus'
    ASIA_DHAKA = 'Asia/Dhaka'
    ASIA_DILI = 'Asia/Dili'
    ASIA_DUBAI = 'Asia/Dubai'
    ASIA_DUSHANBE = 'Asia/Dushanbe'
    ASIA_GAZA = 'Asia/Gaza'
    ASIA_HARBIN = 'Asia/Harbin'
    ASIA_HEBRON = 'Asia/Hebron'
    ASIA_HO_CHI_MINH = 'Asia/Ho_Chi_Minh'
    ASIA_HONG_KONG = 'Asia/Hong_Kong'
    ASIA_HOVD = 'Asia/Hovd'
    ASIA_IRKUTSK = 'Asia/Irkutsk'
    ASIA_ISTANBUL = 'Asia/Istanbul'
    ASIA_JAKARTA = 'Asia/Jakarta'
    ASIA_JAYAPURA = 'Asia/Jayapura'
    ASIA_JERUSALEM = 'Asia/Jerusalem'
    ASIA_KABUL = 'Asia/Kabul'
    ASIA_KAMCHATKA = 'Asia/Kamchatka'
    ASIA_KARACHI = 'Asia/Karachi'
    ASIA_KASHGAR = 'Asia/Kashgar'
    ASIA_KATHMANDU = 'Asia/Kathmandu'
    ASIA_KOLKATA = 'Asia/Kolkata'
    ASIA_KRASNOYARSK = 'Asia/Krasnoyarsk'
    ASIA_KUALA_LUMPUR = 'Asia/Kuala_Lumpur'
    ASIA_KUCHING = 'Asia/Kuching'
    ASIA_KUWAIT = 'Asia/Kuwait'
    ASIA_MACAU = 'Asia/Macau'
    ASIA_MAGADAN = 'Asia/Magadan'
    ASIA_MAKASSAR = 'Asia/Makassar'
    ASIA_MANILA = 'Asia/Manila'
    ASIA_MUSCAT = 'Asia/Muscat'
    ASIA_NICOSIA = 'Asia/Nicosia'
    ASIA_NOVOKUZNETSK = 'Asia/Novokuznetsk'
    ASIA_NOVOSIBIRSK = 'Asia/Novosibirsk'
    ASIA_OMSK = 'Asia/Omsk'
    ASIA_ORAL = 'Asia/Oral'
    ASIA_PHNOM_PENH = 'Asia/Phnom_Penh'
    ASIA_PONTIANAK = 'Asia/Pontianak'
    ASIA_PYONGYANG = 'Asia/Pyongyang'
    ASIA_QATAR = 'Asia/Qatar'
    ASIA_QYZYLORDA = 'Asia/Qyzylorda'
    ASIA_RANGOON = 'Asia/Rangoon'
    ASIA_RIYADH = 'Asia/Riyadh'
    ASIA_RIYADH87 = 'Asia/Riyadh87'
    ASIA_RIYADH88 = 'Asia/Riyadh88'
    ASIA_RIYADH89 = 'Asia/Riyadh89'
    ASIA_SAKHALIN = 'Asia/Sakhalin'
    ASIA_SAMARKAND = 'Asia/Samarkand'
    ASIA_SEOUL = 'Asia/Seoul'
    ASIA_SHANGHAI = 'Asia/Shanghai'
    ASIA_SINGAPORE = 'Asia/Singapore'
    ASIA_TAIPEI = 'Asia/Taipei'
    ASIA_TASHKENT = 'Asia/Tashkent'
    ASIA_TBILISI = 'Asia/Tbilisi'
    ASIA_TEHRAN = 'Asia/Tehran'
    ASIA_THIMPHU = 'Asia/Thimphu'
    ASIA_TOKYO = 'Asia/Tokyo'
    ASIA_ULAANBAATAR = 'Asia/Ulaanbaatar'
    ASIA_URUMQI = 'Asia/Urumqi'
    ASIA_VIENTIANE = 'Asia/Vientiane'
    ASIA_VLADIVOSTOK = 'Asia/Vladivostok'
    ASIA_YAKUTSK = 'Asia/Yakutsk'
    ASIA_YEKATERINBURG = 'Asia/Yekaterinburg'
    ASIA_YEREVAN = 'Asia/Yerevan'
    ATLANTIC_AZORES = 'Atlantic/Azores'
    ATLANTIC_BERMUDA = 'Atlantic/Bermuda'
    ATLANTIC_CANARY = 'Atlantic/Canary'
    ATLANTIC_CAPE_VERDE = 'Atlantic/Cape_Verde'
    ATLANTIC_FAROE = 'Atlantic/Faroe'
    ATLANTIC_MADEIRA = 'Atlantic/Madeira'
    ATLANTIC_REYKJAVIK = 'Atlantic/Reykjavik'
    ATLANTIC_SOUTH_GEORGIA = 'Atlantic/South_Georgia'
    ATLANTIC_ST_HELENA = 'Atlantic/St_Helena'
    ATLANTIC_STANLEY = 'Atlantic/Stanley'
    AUSTRALIA_ADELAIDE = 'Australia/Adelaide'
    AUSTRALIA_BRISBANE = 'Australia/Brisbane'
    AUSTRALIA_BROKEN_HILL = 'Australia/Broken_Hill'
    AUSTRALIA_CURRIE = 'Australia/Currie'
    AUSTRALIA_DARWIN = 'Australia/Darwin'
    AUSTRALIA_EUCLA = 'Australia/Eucla'
    AUSTRALIA_HOBART = 'Australia/Hobart'
    AUSTRALIA_LINDEMAN = 'Australia/Lindeman'
    AUSTRALIA_LORD_HOWE = 'Australia/Lord_Howe'
    AUSTRALIA_MELBOURNE = 'Australia/Melbourne'
    AUSTRALIA_PERTH = 'Australia/Perth'
    AUSTRALIA_SYDNEY = 'Australia/Sydney'
    CET = 'CET'
    CST6CDT = 'CST6CDT'
    EET = 'EET'
    EST = 'EST'
    EST5EDT = 'EST5EDT'
    ETC_GMT = 'Etc/GMT'
    ETC_GMTPLUS0 = 'Etc/GMT+0'
    ETC_GMTPLUS1 = 'Etc/GMT+1'
    ETC_GMTPLUS10 = 'Etc/GMT+10'
    ETC_GMTPLUS11 = 'Etc/GMT+11'
    ETC_GMTPLUS12 = 'Etc/GMT+12'
    ETC_GMTPLUS2 = 'Etc/GMT+2'
    ETC_GMTPLUS3 = 'Etc/GMT+3'
    ETC_GMTPLUS4 = 'Etc/GMT+4'
    ETC_GMTPLUS5 = 'Etc/GMT+5'
    ETC_GMTPLUS6 = 'Etc/GMT+6'
    ETC_GMTPLUS7 = 'Etc/GMT+7'
    ETC_GMTPLUS8 = 'Etc/GMT+8'
    ETC_GMTPLUS9 = 'Etc/GMT+9'
    ETC_GMT_0 = 'Etc/GMT-0'
    ETC_GMT_1 = 'Etc/GMT-1'
    ETC_GMT_10 = 'Etc/GMT-10'
    ETC_GMT_11 = 'Etc/GMT-11'
    ETC_GMT_12 = 'Etc/GMT-12'
    ETC_GMT_13 = 'Etc/GMT-13'
    ETC_GMT_14 = 'Etc/GMT-14'
    ETC_GMT_2 = 'Etc/GMT-2'
    ETC_GMT_3 = 'Etc/GMT-3'
    ETC_GMT_4 = 'Etc/GMT-4'
    ETC_GMT_5 = 'Etc/GMT-5'
    ETC_GMT_6 = 'Etc/GMT-6'
    ETC_GMT_7 = 'Etc/GMT-7'
    ETC_GMT_8 = 'Etc/GMT-8'
    ETC_GMT_9 = 'Etc/GMT-9'
    ETC_GMT0 = 'Etc/GMT0'
    ETC_GREENWICH = 'Etc/Greenwich'
    ETC_UCT = 'Etc/UCT'
    ETC_UTC = 'Etc/UTC'
    ETC_UNIVERSAL = 'Etc/Universal'
    ETC_ZULU = 'Etc/Zulu'
    EUROPE_AMSTERDAM = 'Europe/Amsterdam'
    EUROPE_ANDORRA = 'Europe/Andorra'
    EUROPE_ATHENS = 'Europe/Athens'
    EUROPE_BELGRADE = 'Europe/Belgrade'
    EUROPE_BERLIN = 'Europe/Berlin'
    EUROPE_BRATISLAVA = 'Europe/Bratislava'
    EUROPE_BRUSSELS = 'Europe/Brussels'
    EUROPE_BUCHAREST = 'Europe/Bucharest'
    EUROPE_BUDAPEST = 'Europe/Budapest'
    EUROPE_CHISINAU = 'Europe/Chisinau'
    EUROPE_COPENHAGEN = 'Europe/Copenhagen'
    EUROPE_DUBLIN = 'Europe/Dublin'
    EUROPE_GIBRALTAR = 'Europe/Gibraltar'
    EUROPE_GUERNSEY = 'Europe/Guernsey'
    EUROPE_HELSINKI = 'Europe/Helsinki'
    EUROPE_ISLE_OF_MAN = 'Europe/Isle_of_Man'
    EUROPE_ISTANBUL = 'Europe/Istanbul'
    EUROPE_JERSEY = 'Europe/Jersey'
    EUROPE_KALININGRAD = 'Europe/Kaliningrad'
    EUROPE_KIEV = 'Europe/Kiev'
    EUROPE_LISBON = 'Europe/Lisbon'
    EUROPE_LJUBLJANA = 'Europe/Ljubljana'
    EUROPE_LONDON = 'Europe/London'
    EUROPE_LUXEMBOURG = 'Europe/Luxembourg'
    EUROPE_MADRID = 'Europe/Madrid'
    EUROPE_MALTA = 'Europe/Malta'
    EUROPE_MARIEHAMN = 'Europe/Mariehamn'
    EUROPE_MINSK = 'Europe/Minsk'
    EUROPE_MONACO = 'Europe/Monaco'
    EUROPE_MOSCOW = 'Europe/Moscow'
    EUROPE_NICOSIA = 'Europe/Nicosia'
    EUROPE_OSLO = 'Europe/Oslo'
    EUROPE_PARIS = 'Europe/Paris'
    EUROPE_PODGORICA = 'Europe/Podgorica'
    EUROPE_PRAGUE = 'Europe/Prague'
    EUROPE_RIGA = 'Europe/Riga'
    EUROPE_ROME = 'Europe/Rome'
    EUROPE_SAMARA = 'Europe/Samara'
    EUROPE_SAN_MARINO = 'Europe/San_Marino'
    EUROPE_SARAJEVO = 'Europe/Sarajevo'
    EUROPE_SIMFEROPOL = 'Europe/Simferopol'
    EUROPE_SKOPJE = 'Europe/Skopje'
    EUROPE_SOFIA = 'Europe/Sofia'
    EUROPE_STOCKHOLM = 'Europe/Stockholm'
    EUROPE_TALLINN = 'Europe/Tallinn'
    EUROPE_TIRANE = 'Europe/Tirane'
    EUROPE_UZHGOROD = 'Europe/Uzhgorod'
    EUROPE_VADUZ = 'Europe/Vaduz'
    EUROPE_VATICAN = 'Europe/Vatican'
    EUROPE_VIENNA = 'Europe/Vienna'
    EUROPE_VILNIUS = 'Europe/Vilnius'
    EUROPE_VOLGOGRAD = 'Europe/Volgograd'
    EUROPE_WARSAW = 'Europe/Warsaw'
    EUROPE_ZAGREB = 'Europe/Zagreb'
    EUROPE_ZAPOROZHYE = 'Europe/Zaporozhye'
    EUROPE_ZURICH = 'Europe/Zurich'
    HST = 'HST'
    INDIAN_ANTANANARIVO = 'Indian/Antananarivo'
    INDIAN_CHAGOS = 'Indian/Chagos'
    INDIAN_CHRISTMAS = 'Indian/Christmas'
    INDIAN_COCOS = 'Indian/Cocos'
    INDIAN_COMORO = 'Indian/Comoro'
    INDIAN_KERGUELEN = 'Indian/Kerguelen'
    INDIAN_MAHE = 'Indian/Mahe'
    INDIAN_MALDIVES = 'Indian/Maldives'
    INDIAN_MAURITIUS = 'Indian/Mauritius'
    INDIAN_MAYOTTE = 'Indian/Mayotte'
    INDIAN_REUNION = 'Indian/Reunion'
    MET = 'MET'
    MST = 'MST'
    MST7MDT = 'MST7MDT'
    MIDEAST_RIYADH87 = 'Mideast/Riyadh87'
    MIDEAST_RIYADH88 = 'Mideast/Riyadh88'
    MIDEAST_RIYADH89 = 'Mideast/Riyadh89'
    PST8PDT = 'PST8PDT'
    PACIFIC_APIA = 'Pacific/Apia'
    PACIFIC_AUCKLAND = 'Pacific/Auckland'
    PACIFIC_CHATHAM = 'Pacific/Chatham'
    PACIFIC_CHUUK = 'Pacific/Chuuk'
    PACIFIC_EASTER = 'Pacific/Easter'
    PACIFIC_EFATE = 'Pacific/Efate'
    PACIFIC_ENDERBURY = 'Pacific/Enderbury'
    PACIFIC_FAKAOFO = 'Pacific/Fakaofo'
    PACIFIC_FIJI = 'Pacific/Fiji'
    PACIFIC_FUNAFUTI = 'Pacific/Funafuti'
    PACIFIC_GALAPAGOS = 'Pacific/Galapagos'
    PACIFIC_GAMBIER = 'Pacific/Gambier'
    PACIFIC_GUADALCANAL = 'Pacific/Guadalcanal'
    PACIFIC_GUAM = 'Pacific/Guam'
    PACIFIC_HONOLULU = 'Pacific/Honolulu'
    PACIFIC_JOHNSTON = 'Pacific/Johnston'
    PACIFIC_KIRITIMATI = 'Pacific/Kiritimati'
    PACIFIC_KOSRAE = 'Pacific/Kosrae'
    PACIFIC_KWAJALEIN = 'Pacific/Kwajalein'
    PACIFIC_MAJURO = 'Pacific/Majuro'
    PACIFIC_MARQUESAS = 'Pacific/Marquesas'
    PACIFIC_MIDWAY = 'Pacific/Midway'
    PACIFIC_NAURU = 'Pacific/Nauru'
    PACIFIC_NIUE = 'Pacific/Niue'
    PACIFIC_NORFOLK = 'Pacific/Norfolk'
    PACIFIC_NOUMEA = 'Pacific/Noumea'
    PACIFIC_PAGO_PAGO = 'Pacific/Pago_Pago'
    PACIFIC_PALAU = 'Pacific/Palau'
    PACIFIC_PITCAIRN = 'Pacific/Pitcairn'
    PACIFIC_POHNPEI = 'Pacific/Pohnpei'
    PACIFIC_PORT_MORESBY = 'Pacific/Port_Moresby'
    PACIFIC_RAROTONGA = 'Pacific/Rarotonga'
    PACIFIC_SAIPAN = 'Pacific/Saipan'
    PACIFIC_TAHITI = 'Pacific/Tahiti'
    PACIFIC_TARAWA = 'Pacific/Tarawa'
    PACIFIC_TONGATAPU = 'Pacific/Tongatapu'
    PACIFIC_WAKE = 'Pacific/Wake'
    PACIFIC_WALLIS = 'Pacific/Wallis'
    US_PACIFIC_NEW = 'US/Pacific-New'
    WET = 'WET'


class Transport(_AxlStrEnum):
    """AXL enum — ``XTransport``.
    """

    TCP = 'TCP'
    UDP = 'UDP'
    TLS = 'TLS'
    TCPPLUSUDP = 'TCP+UDP'


class Trunk(_AxlStrEnum):
    """AXL enum — ``XTrunk``.
    """

    GROUND_START = 'Ground Start'
    LOOP_START = 'Loop Start'
    DID = 'DID'
    POTS = 'POTS'
    EANDM = 'EANDM'


class TrunkDirection(_AxlStrEnum):
    """AXL enum — ``XTrunkDirection``.
    """

    INBOUND = 'Inbound'
    OUTBOUND = 'Outbound'
    BOTHWAYS = 'Bothways'


class TrunkLevel(_AxlStrEnum):
    """AXL enum — ``XTrunkLevel``.
    """

    AAL_A = 'AAL(A)'
    AAL_D = 'AAL(D)'
    A_TT = 'A/TT'
    DAL = 'DAL'
    ICS = 'ICS'
    ISD_TT = 'ISD/TT'
    IST = 'IST'
    ONS = 'ONS'
    OPS = 'OPS'
    S_ATT = 'S/ATT'
    S_DTT = 'S/DTT'
    A_TO = 'A/TO'


class TrunkPad(_AxlStrEnum):
    """AXL enum — ``XTrunkPad``.
    """

    MINUS32DB = 'Minus32db'
    MINUS31DB = 'Minus31db'
    MINUS30DB = 'Minus30db'
    MINUS29DB = 'Minus29db'
    MINUS28DB = 'Minus28db'
    MINUS27DB = 'Minus27db'
    MINUS26DB = 'Minus26db'
    MINUS25DB = 'Minus25db'
    MINUS24DB = 'Minus24db'
    MINUS23DB = 'Minus23db'
    MINUS22DB = 'Minus22db'
    MINUS21DB = 'Minus21db'
    MINUS20DB = 'Minus20db'
    MINUS19DB = 'Minus19db'
    MINUS18DB = 'Minus18db'
    MINUS17DB = 'Minus17db'
    MINUS16DB = 'Minus16db'
    MINUS15DB = 'Minus15db'
    MINUS14DB = 'Minus14db'
    MINUS13DB = 'Minus13db'
    MINUS12DB = 'Minus12db'
    MINUS11DB = 'Minus11db'
    MINUS10DB = 'Minus10db'
    MINUS9DB = 'Minus9db'
    MINUS8DB = 'Minus8db'
    MINUS7DB = 'Minus7db'
    MINUS6DB = 'Minus6db'
    MINUS5DB = 'Minus5db'
    MINUS4DB = 'Minus4db'
    MINUS3DB = 'Minus3db'
    MINUS2DB = 'Minus2db'
    MINUS1DB = 'Minus1db'
    NODBPADDING = 'NoDbPadding'
    PLUS1DB = 'Plus1db'
    PLUS2DB = 'Plus2db'
    PLUS3DB = 'Plus3db'
    PLUS4DB = 'Plus4db'
    PLUS5DB = 'Plus5db'
    PLUS6DB = 'Plus6db'
    PLUS7DB = 'Plus7db'
    PLUS8DB = 'Plus8db'
    PLUS9DB = 'Plus9db'
    PLUS10DB = 'Plus10db'
    PLUS11DB = 'Plus11db'
    PLUS12DB = 'Plus12db'
    PLUS13DB = 'Plus13db'
    PLUS14DB = 'Plus14db'
    PLUS15DB = 'Plus15db'
    PLUS16DB = 'Plus16db'
    PLUS17DB = 'Plus17db'
    PLUS18DB = 'Plus18db'
    PLUS19DB = 'Plus19db'
    PLUS20DB = 'Plus20db'
    PLUS21DB = 'Plus21db'
    PLUS22DB = 'Plus22db'
    PLUS23DB = 'Plus23db'
    PLUS24DB = 'Plus24db'
    PLUS25DB = 'Plus25db'
    PLUS26DB = 'Plus26db'
    PLUS27DB = 'Plus27db'
    PLUS28DB = 'Plus28db'
    PLUS29DB = 'Plus29db'
    PLUS30DB = 'Plus30db'
    PLUS31DB = 'Plus31db'
    PLUS32DB = 'Plus32db'


class TrunkSelectionOrder(_AxlStrEnum):
    """AXL enum — ``XTrunkSelectionOrder``.
    """

    BOTTOM_UP = 'Bottom Up'
    TOP_DOWN = 'Top Down'


class TrunkService(_AxlStrEnum):
    """AXL enum — ``XTrunkService``.
    """

    NONE_DEFAULT = 'None(Default)'
    CALL_CONTROL_DISCOVERY = 'Call Control Discovery'
    EXTENSION_MOBILITY_CROSS_CLUSTER = 'Extension Mobility Cross Cluster'
    CISCO_INTERCOMPANY_MEDIA_ENGINE = 'Cisco Intercompany Media Engine'
    IP_MULTIMEDIA_SUBSYSTEM_SERVICE_CONTROL_ISC = 'IP Multimedia Subsystem Service Control (ISC)'


class TrustReceivedIdentity(_AxlStrEnum):
    """AXL enum — ``XTrustReceivedIdentity``.
    """

    TRUST_ALL_DEFAULT = 'Trust All (Default)'
    TRUST_PAI_ONLY = 'Trust PAI Only'
    TRUST_NONE = 'Trust None'


class TrustRole(_AxlStrEnum):
    """AXL enum — ``XTrustRole``.
    """

    SAST = 'SAST'
    CALLMANAGER = 'CallManager'
    CALLMANAGERTFTP = 'CallManagerTFTP'
    TFTP = 'TFTP'
    CAPF = 'CAPF'
    SRST = 'SRST'
    FIREWALL = 'Firewall'
    APPLICATION_SERVER = 'Application Server'
    CERTIFICATE_AUTHORITY = 'Certificate Authority'
    AUTHENTICATION_AND_AUTHORIZATION = 'Authentication and Authorization'
    SIGNALING_AND_CALL_CONTROL = 'Signaling and Call Control'
    PROVISIONING_SERVICE = 'Provisioning Service'
    DATA_SERVICE = 'Data Service'
    NETWORK_ELEMENT = 'Network Element'
    VIRTUAL_PRIVATE_NETWORK = 'Virtual Private Network'
    SERVICEABILITY = 'Serviceability'
    UNKNOWN = 'Unknown'
    CALLMANAGER_ECDSA = 'CallManager-ECDSA'


class TunneledProtocol(_AxlStrEnum):
    """AXL enum — ``XTunneledProtocol``.
    """

    NONE_ = 'None'
    QSIG = 'QSIG'


class UCProduct(_AxlStrEnum):
    """AXL enum — ``XUCProduct``.
    """

    UNITY = 'Unity'
    UNITY_CONNECTION = 'Unity Connection'
    EXCHANGE = 'Exchange'
    MEETINGPLACE_CLASSIC = 'MeetingPlace Classic'
    MEETINGPLACE_EXPRESS = 'MeetingPlace Express'
    WEBEX_CONFERENCING = 'WebEx (Conferencing)'
    DIRECTORY = 'Directory'
    UNIFIED_CM_IM_AND_PRESENCE = 'Unified CM (IM and Presence)'
    WEBEX_IM_AND_PRESENCE = 'WebEx (IM and Presence)'
    CTI = 'CTI'
    ENHANCED_DIRECTORY = 'Enhanced Directory'
    TELEPRESENCE_MANAGEMENT_SYSTEM = 'Telepresence Management System'
    JABBER = 'Jabber'


class UCService(_AxlStrEnum):
    """AXL enum — ``XUCService``.
    """

    VOICEMAIL = 'Voicemail'
    MAILSTORE = 'MailStore'
    CONFERENCING = 'Conferencing'
    DIRECTORY = 'Directory'
    IM_AND_PRESENCE = 'IM and Presence'
    CTI = 'CTI'
    VIDEO_CONFERENCE_SCHEDULING_PORTAL = 'Video Conference Scheduling Portal'
    JABBER_CLIENT_CONFIGURATION_JABBER_CONFIG_XML = 'Jabber Client Configuration (jabber-config.xml)'


class URIDisambiguationPolicy(_AxlStrEnum):
    """AXL enum — ``XURIDisambiguationPolicy``.
    """

    ALWAYS_TREAT_ALL_DIAL_STRINGS_AS_URI_ADDRESSES = 'Always treat all dial strings as URI addresses'
    PHONE_NUMBER_CONSISTS_OF_CHARACTERS_0_9_A_D_STAR_NUM_AND_PLUS_OTHERS_TREATED_AS_URI_ADDRESSES = 'Phone number consists of characters 0-9, A-D, *, #, and + (others treated as URI addresses)'
    PHONE_NUMBER_CONSISTS_OF_CHARACTERS_0_9_STAR_NUM_AND_PLUS_OTHERS_TREATED_AS_URI_ADDRESSES = 'Phone number consists of characters 0-9, *, #, and + (others treated as URI addresses)'


class UserAgentServerHeaderInfo(_AxlStrEnum):
    """AXL enum — ``XUserAgentServerHeaderInfo``.
    """

    SEND_UNIFIED_CM_VERSION_INFORMATION_AS_USER_AGENT_HEADER = 'Send Unified CM Version Information as User-Agent Header'
    PASS_THROUGH_RECEIVED_INFORMATION_AS_CONTACT_HEADER_PARAMETERS = 'Pass Through Received Information as Contact Header Parameters'
    PASS_THROUGH_RECEIVED_INFORMATION_AS_USER_AGENT_AND_SERVER_HEADER = 'Pass Through Received Information as User-Agent and Server Header'


class UserLocale(_AxlStrEnum):
    """AXL enum — ``XUserLocale``.
    """

    ENGLISH_UNITED_STATES = 'English United States'


class V150SDPFilter(_AxlStrEnum):
    """AXL enum — ``XV150SDPFilter``.
    """

    NO_FILTERING = 'No Filtering'
    REMOVE_MER_V_150 = 'Remove MER V.150'
    REMOVE_PRE_MER_V_150 = 'Remove Pre-MER V.150'
    USE_DEFAULT_FILTER = 'Use Default Filter'


class VMAvoidancePolicy(_AxlStrEnum):
    """AXL enum — ``XVMAvoidancePolicy``.
    """

    USE_SYSTEM_DEFAULT = 'Use System Default'
    TIMER_CONTROL = 'Timer Control'
    USER_CONTROL = 'User Control'


class VPNClientAuthentication(_AxlStrEnum):
    """AXL enum — ``XVPNClientAuthentication``.
    """

    USER_AND_PASSWORD = 'User and Password'
    PASSWORD_ONLY = 'Password Only'
    CERTIFICATE = 'Certificate'


class VideoCallTrafficClass(_AxlStrEnum):
    """AXL enum — ``XVideoCallTrafficClass``.
    """

    IMMERSIVE = 'Immersive'
    DESKTOP = 'Desktop'
    MIXED = 'Mixed'


class ViprFilterElement(_AxlStrEnum):
    """AXL enum — ``XViprFilterElement``.
    """

    PREFIX = 'Prefix'
    DOMAIN = 'Domain'


class WLANProfileChanges(_AxlStrEnum):
    """AXL enum — ``XWLANProfileChanges``.
    """

    ALLOWED = 'Allowed'
    DISALLOWED = 'Disallowed'
    RESTRICTED = 'Restricted'


class WebPageDisplay(_AxlStrEnum):
    """AXL enum — ``XWebPageDisplay``.
    """

    EXPANDED = 'Expanded'
    COLLAPSED = 'Collapsed'
    HIDDEN = 'Hidden'


class WebPageSection(_AxlStrEnum):
    """AXL enum — ``XWebPageSection``.
    """

    REQUIRED_AND_FREQUENTLY_ENTERED_SETTINGS = 'Required and Frequently Entered Settings'
    PHONE_BUTTONS_CONFIGURATION = 'Phone Buttons Configuration'
    DEVICE_SETTINGS = 'Device Settings'
    DEVICE_ROUTING_SETTINGS = 'Device Routing Settings'
    PHONE_SETTINGS = 'Phone Settings'
    PROTOCOL_SETTINGS = 'Protocol Settings'
    IP_PHONE_SERVICES_SUBSCRIPTION = 'IP Phone Services Subscription'
    SECURITY_SETTINGS = 'Security Settings'
    SERVICE_CONFIGURATION_SETTINGS = 'Service Configuration Settings'
    TROUBLESHOOTING_SETTINGS = 'Troubleshooting Settings'
    LOCALE_SETTINGS = 'Locale Settings'
    MULTILEVEL_PRECEDENCE_PREEMPTION_MLPP_SETTINGS = 'Multilevel Precedence Preemption (MLPP) Settings'
    DO_NOT_DISTURB_DND_SETTINGS = 'Do Not Disturb (DND) Settings'
    AUTOMATIC_ALTERNATE_ROUTING_AAR_SETTINGS = 'Automatic Alternate Routing (AAR) Settings'
    BUSY_LAMP_FIELD_BLF_SETTINGS = 'Busy Lamp Field (BLF) Settings'
    MUSIC_ON_HOLD_SETTINGS = 'Music on Hold Settings'
    LOCATION_SETTINGS = 'Location Settings'
    DIRECTORY_NUMBER_SETTINGS = 'Directory Number Settings'
    MUSIC_ON_HOLD_MOH_SETTINGS = 'Music On Hold (MOH) Settings'
    CALL_FORWARD_SETTINGS = 'Call Forward Settings'
    PARK_MONITORING_SETTINGS = 'Park Monitoring Settings'
    MULTILEVEL_PRECEDENCE_PREEMPTION_MLPP_ALTERNATE_PARTY_SETTINGS = 'Multilevel Precedence Preemption (MLPP) Alternate Party Settings'
    HOLD_REVERSION_SETTINGS = 'Hold Reversion Settings'
    ENTERPRISE_ALTERNATE_NUMBER = 'Enterprise Alternate Number'
    PLUSE_164_ALTERNATE_NUMBER = '+E.164 Alternate Number'
    PSTN_FAILOVER_FOR_ENTERPRISE_AND_PLUSE_164_ALTERNATE_NUMBER_AND_URI_DIALING = 'PSTN Failover for Enterprise and +E.164 Alternate Number and URI Dialing'


class WiFiAuthenticationMethod(_AxlStrEnum):
    """AXL enum — ``XWiFiAuthenticationMethod``.
    """

    NONE_ = 'None'
    WEP = 'WEP'
    PSK = 'PSK'
    EAP_FAST = 'EAP-FAST'
    PEAP_MSCHAPV2 = 'PEAP-MSCHAPv2'
    PEAP_GTC = 'PEAP-GTC'
    EAP_TLS = 'EAP-TLS'


class WiFiFrequency(_AxlStrEnum):
    """AXL enum — ``XWiFiFrequency``.
    """

    AUTO = 'Auto'
    V_2_4_GHZ = '2.4 GHz'
    V_5_GHZ = '5 GHz'


class YellowAlarm(_AxlStrEnum):
    """AXL enum — ``XYellowAlarm``.
    """

    BIT2 = 'Bit2'
    F_BIT = 'F-Bit'


class ZeroSuppression(_AxlStrEnum):
    """AXL enum — ``XZeroSuppression``.
    """

    B8ZS = 'B8ZS'
    AMI = 'AMI'
    HDB3 = 'HDB3'


class Zzdndcontrol(_AxlStrEnum):
    """AXL enum — ``XZzdndcontrol``.
    """

    USER = 'User'
    ADMIN = 'Admin'


class ZzdtmfDbLevel(_AxlStrEnum):
    """AXL enum — ``XZzdtmfDbLevel``.
    """

    V_6_DB_BELOW_NOMINAL = '6 dB below nominal'
    V_3_DB_BELOW_NOMINAL = '3 dB below nominal'
    NOMINAL = 'Nominal'
    V_3_DB_ABOVE_NOMINAL = '3 dB above nominal'
    V_6_DB_ABOVE_NOMINAL = '6 dB above nominal'


class Zzntpmode(_AxlStrEnum):
    """AXL enum — ``XZzntpmode``.
    """

    UNICAST = 'Unicast'
    MULTICAST = 'Multicast'
    ANYCAST = 'Anycast'
    DIRECTED_BROADCAST = 'Directed Broadcast'


class Zzpreff(_AxlStrEnum):
    """AXL enum — ``XZzpreff``.
    """

    OFF = 'Off'
    ON = 'On'


class ZzuserInfo(_AxlStrEnum):
    """AXL enum — ``XZzuserInfo``.
    """

    NONE_ = 'None'
    PHONE = 'Phone'
    IP = 'IP'

