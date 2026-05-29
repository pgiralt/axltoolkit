"""Verify that all public classes and exceptions are importable."""

import pytest


def test_new_client_imports():
    from axltoolkit import (
        AXLClient,
        DimeGetFileClient,
        LogCollectionClient,
        PAWSClient,
        PerfMonClient,
        RISPortClient,
        ServiceabilityClient,
        WebdialerClient,
    )

    assert AXLClient is not None
    assert RISPortClient is not None
    assert PerfMonClient is not None
    assert ServiceabilityClient is not None
    assert LogCollectionClient is not None
    assert DimeGetFileClient is not None
    assert PAWSClient is not None
    assert WebdialerClient is not None


def test_exception_imports():
    from axltoolkit import (
        AXLAuthenticationError,
        AXLConnectionError,
        AXLDuplicateError,
        AXLError,
        AXLNotFoundError,
        AXLSQLError,
        AXLSQLInjectionError,
        AxlToolkitError,
        AXLValidationError,
        LogCollectionError,
        PAWSError,
        PerfMonError,
        RISPortError,
        ServiceabilityError,
        SXMLError,
        WebdialerError,
    )

    # Verify exception hierarchy
    assert issubclass(AXLError, AxlToolkitError)
    assert issubclass(AXLNotFoundError, AXLError)
    assert issubclass(AXLDuplicateError, AXLError)
    assert issubclass(AXLValidationError, AXLError)
    assert issubclass(AXLSQLError, AXLError)
    assert issubclass(AXLSQLInjectionError, AXLSQLError)
    assert issubclass(AXLAuthenticationError, AxlToolkitError)
    assert issubclass(AXLConnectionError, AxlToolkitError)
    assert issubclass(SXMLError, AxlToolkitError)
    assert issubclass(RISPortError, SXMLError)
    assert issubclass(PerfMonError, SXMLError)
    assert issubclass(ServiceabilityError, SXMLError)
    assert issubclass(LogCollectionError, SXMLError)
    assert issubclass(PAWSError, AxlToolkitError)
    assert issubclass(WebdialerError, AxlToolkitError)


def test_legacy_classes_emit_deprecation_on_instantiation():
    """Legacy classes emit DeprecationWarning when instantiated, not on import."""
    from axltoolkit._compat import AxlToolkit

    # Instantiation triggers the warning (will fail to connect, but that's OK)
    with pytest.warns(DeprecationWarning, match="AxlToolkit is deprecated"):
        try:
            AxlToolkit("u", "p", "127.0.0.1", version="15.0", tls_verify=False, timeout=1)
        except Exception:
            pass  # Connection failure is expected in tests


def test_version():
    import axltoolkit

    assert axltoolkit.__version__ == "2.0.0"


def test_sql_sanitize():
    from axltoolkit.axl import AXLSQLInjectionError, _sanitize_sql_value

    # Normal values pass through with escaped quotes
    assert _sanitize_sql_value("hello") == "hello"
    assert _sanitize_sql_value("it's") == "it''s"

    # Dangerous patterns raise
    with pytest.raises(AXLSQLInjectionError):
        _sanitize_sql_value("'; DROP TABLE device; --")

    with pytest.raises(AXLSQLInjectionError):
        _sanitize_sql_value("x'; -- comment")


def test_axl_error_from_fault():
    from unittest.mock import MagicMock

    from axltoolkit.axl import AXLError, AXLNotFoundError, _axl_error_from_fault

    fault = MagicMock()
    fault.__str__ = lambda self: "Item not valid: The specified Phone was not found"
    fault.code = None
    err = _axl_error_from_fault(fault)
    assert isinstance(err, AXLNotFoundError)

    fault2 = MagicMock()
    fault2.__str__ = lambda self: "Something unexpected happened"
    fault2.code = None
    err2 = _axl_error_from_fault(fault2)
    assert isinstance(err2, AXLError)
    assert not isinstance(err2, AXLNotFoundError)


def test_axl_client_method_count():
    """Verify AXLClient has 1000+ public methods covering the full AXL WSDL."""
    from axltoolkit import AXLClient

    public_methods = [
        m for m in dir(AXLClient) if not m.startswith("_") and callable(getattr(AXLClient, m))
    ]
    assert len(public_methods) >= 1000, (
        f"Expected >=1000 public methods on AXLClient, got {len(public_methods)}"
    )


def test_axl_client_has_key_object_types():
    """Verify commonly-used AXL object type wrappers exist on AXLClient."""
    from axltoolkit import AXLClient

    expected_methods = [
        # Core telephony
        "get_phone",
        "add_phone",
        "update_phone",
        "list_phones",
        "get_line",
        "add_line",
        "update_line",
        "remove_line",
        "get_user",
        "add_user",
        "update_user",
        "remove_user",
        "list_users",
        "get_css",
        "add_css",
        "update_css",
        "remove_css",
        "get_route_partition",
        "add_route_partition",
        "remove_route_partition",
        # Routing
        "get_route_pattern",
        "add_route_pattern",
        "update_route_pattern",
        "remove_route_pattern",
        "get_route_group",
        "add_route_group",
        "update_route_group",
        "remove_route_group",
        "get_route_list",
        "add_route_list",
        "update_route_list",
        "remove_route_list",
        "get_translation_pattern",
        "add_translation_pattern",
        "update_translation_pattern",
        "remove_translation_pattern",
        "get_sip_route_pattern",
        "add_sip_route_pattern",
        "remove_sip_route_pattern",
        # Hunt
        "get_line_group",
        "add_line_group",
        "remove_line_group",
        "get_hunt_list",
        "add_hunt_list",
        "remove_hunt_list",
        "get_hunt_pilot",
        "add_hunt_pilot",
        "remove_hunt_pilot",
        # Trunks / Gateways
        "get_sip_trunk",
        "add_sip_trunk",
        "update_sip_trunk",
        "remove_sip_trunk",
        "get_h323_gateway",
        "add_h323_gateway",
        "remove_h323_gateway",
        "get_h323_trunk",
        "add_h323_trunk",
        "remove_h323_trunk",
        "get_gateway",
        "add_gateway",
        "remove_gateway",
        # Infrastructure
        "get_device_pool",
        "add_device_pool",
        "update_device_pool",
        "remove_device_pool",
        "get_region",
        "add_region",
        "update_region",
        "remove_region",
        "get_location",
        "add_location",
        "update_location",
        "remove_location",
        "get_call_manager_group",
        "add_call_manager_group",
        "remove_call_manager_group",
        "get_date_time_group",
        "add_date_time_group",
        "remove_date_time_group",
        "get_srst",
        "add_srst",
        "remove_srst",
        # Media resources
        "get_conference_bridge",
        "add_conference_bridge",
        "remove_conference_bridge",
        "get_media_resource_group",
        "add_media_resource_group",
        "remove_media_resource_group",
        "get_media_resource_list",
        "add_media_resource_list",
        "remove_media_resource_list",
        "get_transcoder",
        "add_transcoder",
        "remove_transcoder",
        "get_mtp",
        "add_mtp",
        "remove_mtp",
        # Users / security
        "get_app_user",
        "add_app_user",
        "update_app_user",
        "remove_app_user",
        "get_user_group",
        "add_user_group",
        "remove_user_group",
        "get_credential_policy",
        "update_credential_policy",
        # SIP / profiles
        "get_sip_profile",
        "add_sip_profile",
        "remove_sip_profile",
        "get_sip_trunk_security_profile",
        "add_sip_trunk_security_profile",
        "get_phone_security_profile",
        "add_phone_security_profile",
        # Device management
        "get_device_profile",
        "add_device_profile",
        "remove_device_profile",
        "get_cti_route_point",
        "add_cti_route_point",
        "remove_cti_route_point",
        # Call features
        "get_call_park",
        "add_call_park",
        "remove_call_park",
        "get_call_pickup_group",
        "add_call_pickup_group",
        "remove_call_pickup_group",
        # Voicemail
        "get_voicemail_pilot",
        "add_voicemail_pilot",
        "get_voicemail_profile",
        "add_voicemail_profile",
        # Configuration / system
        "get_common_device_config",
        "add_common_device_config",
        "get_common_phone_config",
        "add_common_phone_config",
        "get_service_profile",
        "add_service_profile",
        "get_uc_service",
        "add_uc_service",
        # SQL
        "sql_query",
        "sql_update",
        # Device operations
        "reset_phone",
        "restart_phone",
        "apply_phone",
        "wipe_phone",
        "lock_phone",
        "do_device_login",
        "do_device_logout",
        # System info
        "get_os_version",
        "get_num_devices",
        "get_smart_license_status",
        # List operations (sampling)
        "list_route_plan",
        "list_route_pattern",
        "list_sip_route_pattern",
        "list_hunt_pilot",
        "list_line_group",
        "list_hunt_list",
        "list_region",
        "list_location",
        "list_device_pool",
    ]

    missing = [m for m in expected_methods if not hasattr(AXLClient, m)]
    assert not missing, f"Missing methods on AXLClient: {missing}"


def test_perfmon_decode_counter_name():
    from axltoolkit import PerfMonClient

    result = PerfMonClient.decode_counter_name(r"\\cm-pub\Cisco CallManager\CallsCompleted")
    assert result == {
        "host": "cm-pub",
        "object": "Cisco CallManager",
        "instance": None,
        "counter": "CallsCompleted",
    }

    result2 = PerfMonClient.decode_counter_name(
        r"\\cm-pub\Cisco Locations LBM(Hub_None)\BandwidthAvailable"
    )
    assert result2 == {
        "host": "cm-pub",
        "object": "Cisco Locations LBM",
        "instance": "Hub_None",
        "counter": "BandwidthAvailable",
    }

    # Invalid string
    assert PerfMonClient.decode_counter_name("garbage") is None
