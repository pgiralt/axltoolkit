"""Tests for AXLClient with mocked zeep service.

These tests verify that AXLClient methods:
- Correctly delegate to the underlying zeep service
- Pass the right parameters
- Return the service response
- Raise typed exceptions on faults
- Handle SQL sanitization correctly
"""

import pytest
from unittest.mock import MagicMock, patch, PropertyMock
from zeep.exceptions import Fault

from axltoolkit.axl import AXLClient, _axl_error_from_fault, _sanitize_sql_value
from axltoolkit.exceptions import (
    AXLDuplicateError,
    AXLError,
    AXLNotFoundError,
    AXLSQLError,
    AXLSQLInjectionError,
    AXLValidationError,
)


# ── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture
def axl(tmp_path):
    """Create an AXLClient with a mocked zeep client and service."""
    with patch.object(AXLClient, "__init__", lambda self, *a, **kw: None):
        client = AXLClient.__new__(AXLClient)
        client._service = MagicMock()
        client._server_ip = "10.0.0.1"
        client._version = "15.0"
        client._log = MagicMock()
    return client


def _make_fault(message):
    """Create a mock Fault with a given message."""
    fault = Fault(message)
    return fault


# ── _axl_error_from_fault mapping ─────────────────────────────────────


class TestErrorMapping:
    def test_not_found_by_keyword(self):
        fault = _make_fault("Item not valid: The specified Phone was not found")
        err = _axl_error_from_fault(fault)
        assert isinstance(err, AXLNotFoundError)

    def test_not_found_by_code(self):
        fault = _make_fault("AXL error 5007: object not found")
        err = _axl_error_from_fault(fault)
        assert isinstance(err, AXLNotFoundError)
        assert err.axl_error_code == 5007

    def test_duplicate_by_keyword(self):
        fault = _make_fault("Could not insert new row - duplicate value")
        err = _axl_error_from_fault(fault)
        assert isinstance(err, AXLDuplicateError)

    def test_duplicate_by_code(self):
        fault = _make_fault("Error 11617: duplicate entry")
        err = _axl_error_from_fault(fault)
        assert isinstance(err, AXLDuplicateError)
        assert err.axl_error_code == 11617

    def test_validation_error(self):
        fault = _make_fault("Invalid value for field 'protocol'")
        err = _axl_error_from_fault(fault)
        assert isinstance(err, AXLValidationError)

    def test_generic_error(self):
        fault = _make_fault("Something unexpected happened")
        err = _axl_error_from_fault(fault)
        assert isinstance(err, AXLError)
        assert not isinstance(err, (AXLNotFoundError, AXLDuplicateError, AXLValidationError))

    def test_original_exception_preserved(self):
        fault = _make_fault("not found")
        err = _axl_error_from_fault(fault)
        assert err.original_exception is fault


# ── SQL sanitization ──────────────────────────────────────────────────


class TestSQLSanitization:
    def test_normal_value(self):
        assert _sanitize_sql_value("hello") == "hello"

    def test_single_quotes_escaped(self):
        assert _sanitize_sql_value("it's a test") == "it''s a test"

    def test_multiple_quotes(self):
        assert _sanitize_sql_value("a'b'c") == "a''b''c"

    @pytest.mark.parametrize("dangerous", [
        "'; DROP TABLE device; --",
        "x'; -- comment",
        "1; exec sp_help",
        "1; execute something",
        "foo /* comment */",
        "union select * from enduser",
        "'; insert into device select",
        "xp_cmdshell",
        "'; alter table device",
    ])
    def test_injection_patterns_rejected(self, dangerous):
        with pytest.raises(AXLSQLInjectionError):
            _sanitize_sql_value(dangerous)


# ── Thick AXL: get/add/update/remove ─────────────────────────────────


class TestGetOperations:
    def test_get_user(self, axl):
        axl._service.getUser.return_value = {"return": {"user": {"userid": "jsmith"}}}
        result = axl.get_user(userid="jsmith")
        axl._service.getUser.assert_called_once_with(userid="jsmith")
        assert result["return"]["user"]["userid"] == "jsmith"

    def test_get_phone(self, axl):
        axl._service.getPhone.return_value = {"return": {"phone": {"name": "SEP001122334455"}}}
        result = axl.get_phone(name="SEP001122334455")
        axl._service.getPhone.assert_called_once_with(name="SEP001122334455")
        assert result["return"]["phone"]["name"] == "SEP001122334455"

    def test_get_phone_not_found(self, axl):
        axl._service.getPhone.side_effect = Fault("Item not valid: The specified Phone was not found")
        with pytest.raises(AXLNotFoundError):
            axl.get_phone(name="DOESNOTEXIST")

    def test_get_css(self, axl):
        axl._service.getCss.return_value = {"return": {"css": {"name": "CSS_Internal"}}}
        result = axl.get_css("CSS_Internal")
        assert result["return"]["css"]["name"] == "CSS_Internal"

    def test_get_route_partition(self, axl):
        expected = {"return": {"routePartition": {"name": "PT_Internal"}}}
        axl._service.getRoutePartition.return_value = expected
        result = axl.get_route_partition("PT_Internal")
        axl._service.getRoutePartition.assert_called_once()
        assert result == expected

    def test_get_line(self, axl):
        expected = {"return": {"line": {"pattern": "1000"}}}
        axl._service.getLine.return_value = expected
        result = axl.get_line(pattern="1000", route_partition_name="PT_Internal")
        assert result == expected

    def test_get_device_pool(self, axl):
        axl._service.getDevicePool.return_value = {"return": {"devicePool": {"name": "DP_HQ"}}}
        result = axl.get_device_pool(name="DP_HQ")
        axl._service.getDevicePool.assert_called_once_with(name="DP_HQ")

    def test_get_call_manager_group(self, axl):
        axl._service.getCallManagerGroup.return_value = {"return": {"callManagerGroup": {}}}
        result = axl.get_call_manager_group("CMG_Default")
        axl._service.getCallManagerGroup.assert_called_once_with(name="CMG_Default")

    def test_get_sip_trunk(self, axl):
        axl._service.getSipTrunk.return_value = {"return": {"sipTrunk": {"name": "SIP_CUBE"}}}
        result = axl.get_sip_trunk("SIP_CUBE")
        axl._service.getSipTrunk.assert_called_once_with(name="SIP_CUBE")

    def test_get_conference_bridge(self, axl):
        axl._service.getConferenceBridge.return_value = {"return": {"conferenceBridge": {}}}
        result = axl.get_conference_bridge("CFB_1")
        axl._service.getConferenceBridge.assert_called_once_with(name="CFB_1")


class TestGetNewObjectTypes:
    """Test get methods for object types added in the full API expansion."""

    def test_get_region(self, axl):
        axl._service.getRegion.return_value = {"return": {"region": {"name": "R_HQ"}}}
        result = axl.get_region("R_HQ")
        axl._service.getRegion.assert_called_once_with(name="R_HQ")

    def test_get_location(self, axl):
        axl._service.getLocation.return_value = {"return": {"location": {"name": "LOC_HQ"}}}
        result = axl.get_location("LOC_HQ")
        axl._service.getLocation.assert_called_once_with(name="LOC_HQ")

    def test_get_hunt_pilot(self, axl):
        axl._service.getHuntPilot.return_value = {"return": {"huntPilot": {}}}
        result = axl.get_hunt_pilot("5000", "PT_Internal")
        axl._service.getHuntPilot.assert_called_once_with(pattern="5000", routePartitionName="PT_Internal")

    def test_get_gateway(self, axl):
        axl._service.getGateway.return_value = {"return": {"gateway": {"domainName": "GW1"}}}
        result = axl.get_gateway("GW1")
        axl._service.getGateway.assert_called_once_with(domainName="GW1")

    def test_get_vpn_gateway(self, axl):
        axl._service.getVpnGateway.return_value = {"return": {"vpnGateway": {}}}
        result = axl.get_vpn_gateway("VPN1")
        axl._service.getVpnGateway.assert_called_once_with(name="VPN1")

    def test_get_time_schedule(self, axl):
        axl._service.getTimeSchedule.return_value = {"return": {"timeSchedule": {}}}
        result = axl.get_time_schedule("TS1")
        axl._service.getTimeSchedule.assert_called_once_with(name="TS1")

    def test_get_not_found_raises(self, axl):
        axl._service.getGateway.side_effect = Fault("was not found")
        with pytest.raises(AXLNotFoundError):
            axl.get_gateway("MISSING")


class TestAddOperations:
    def test_add_route_partition(self, axl):
        axl._service.addRoutePartition.return_value = {"return": "uuid-123"}
        result = axl.add_route_partition("PT_Test", "Test partition")
        axl._service.addRoutePartition.assert_called_once()

    def test_add_css(self, axl):
        axl._service.addCss.return_value = {"return": "uuid-css"}
        result = axl.add_css("CSS_Test", "Test CSS", ["PT_Internal", "PT_PSTN"])
        axl._service.addCss.assert_called_once()

    def test_add_call_manager_group(self, axl):
        axl._service.addCallManagerGroup.return_value = {"return": "uuid-cmg"}
        result = axl.add_call_manager_group("CMG_Test", ["cm1", "cm2"])
        call_args = axl._service.addCallManagerGroup.call_args
        group_data = call_args[1]["callManagerGroup"]
        members = group_data["members"]["member"]
        assert members[0]["priority"] == 1
        assert members[0]["callManagerName"] == "cm1"
        assert members[1]["priority"] == 2
        assert members[1]["callManagerName"] == "cm2"

    def test_add_duplicate_raises(self, axl):
        axl._service.addRoutePartition.side_effect = Fault("Error 11617: duplicate value")
        with pytest.raises(AXLDuplicateError):
            axl.add_route_partition("PT_Existing", "Already exists")

    def test_add_line_group(self, axl):
        axl._service.addLineGroup.return_value = {"return": "uuid-lg"}
        data = {"name": "LG_Test", "distributionAlgorithm": "Top Down"}
        result = axl.add_line_group(data)
        axl._service.addLineGroup.assert_called_once()

    def test_add_device_pool(self, axl):
        axl._service.addDevicePool.return_value = {"return": "uuid-dp"}
        data = {"name": "DP_Test", "dateTimeSettingName": "CMLocal"}
        result = axl.add_device_pool(data)
        axl._service.addDevicePool.assert_called_once()

    def test_add_remote_destination(self, axl):
        axl._service.addRemoteDestination.return_value = {"return": "uuid-rd"}
        data = {
            "name": "RD_Mobile",
            "destination": "+15555550100",
            "ownerUserId": "jsmith",
        }
        result = axl.add_remote_destination(data)
        axl._service.addRemoteDestination.assert_called_once_with(
            remoteDestination=data
        )
        assert result == {"return": "uuid-rd"}

    def test_add_remote_destination_duplicate_raises(self, axl):
        axl._service.addRemoteDestination.side_effect = Fault(
            "Error 11617: duplicate value"
        )
        with pytest.raises(AXLDuplicateError):
            axl.add_remote_destination({"name": "RD_Existing"})


class TestUpdateOperations:
    def test_update_user(self, axl):
        axl._service.updateUser.return_value = {"return": "uuid-user"}
        result = axl.update_user(userid="jsmith", firstName="John")
        axl._service.updateUser.assert_called_once_with(userid="jsmith", firstName="John")

    def test_update_css(self, axl):
        axl._service.updateCss.return_value = {"return": "ok"}
        result = axl.update_css("CSS_Test", "Updated", ["PT_New"])
        axl._service.updateCss.assert_called_once()

    def test_update_sip_trunk(self, axl):
        axl._service.updateSipTrunk.return_value = {"return": "ok"}
        result = axl.update_sip_trunk(name="SIP_CUBE", description="Updated desc")
        axl._service.updateSipTrunk.assert_called_once_with(name="SIP_CUBE", description="Updated desc")

    def test_update_not_found_raises(self, axl):
        axl._service.updateUser.side_effect = Fault("was not found")
        with pytest.raises(AXLNotFoundError):
            axl.update_user(userid="nobody", firstName="Ghost")

    def test_update_region(self, axl):
        axl._service.updateRegion.return_value = {"return": "ok"}
        result = axl.update_region(name="R_HQ", relatedRegions={"relatedRegion": []})
        axl._service.updateRegion.assert_called_once()

    def test_update_device_pool(self, axl):
        axl._service.updateDevicePool.return_value = {"return": "ok"}
        result = axl.update_device_pool(name="DP_HQ", description="Updated")
        axl._service.updateDevicePool.assert_called_once_with(name="DP_HQ", description="Updated")


class TestRemoveOperations:
    def test_remove_phone(self, axl):
        axl._service.removePhone.return_value = {"return": "ok"}
        result = axl.remove_phone("SEP001122334455")
        axl._service.removePhone.assert_called_once_with(name="SEP001122334455")

    def test_remove_css(self, axl):
        axl._service.removeCss.return_value = {"return": "ok"}
        result = axl.remove_css("CSS_Old")
        axl._service.removeCss.assert_called_once_with(name="CSS_Old")

    def test_remove_not_found_raises(self, axl):
        axl._service.removePhone.side_effect = Fault("5007 item was not found")
        with pytest.raises(AXLNotFoundError):
            axl.remove_phone("DOESNOTEXIST")

    def test_remove_route_partition(self, axl):
        axl._service.removeRoutePartition.return_value = {"return": "ok"}
        result = axl.remove_route_partition("PT_Old")
        axl._service.removeRoutePartition.assert_called_once_with(name="PT_Old")

    def test_remove_gateway(self, axl):
        axl._service.removeGateway.return_value = {"return": "ok"}
        result = axl.remove_gateway("GW1")
        axl._service.removeGateway.assert_called_once_with(domainName="GW1")


# ── List operations ──────────────────────────────────────────────────


class TestListOperations:
    def test_list_phone(self, axl):
        axl._service.listPhone.return_value = {
            "return": {
                "phone": [
                    {"name": "SEP001122334455", "description": "Phone 1", "uuid": "uuid-1"},
                    {"name": "SEP665544332211", "description": "Phone 2", "uuid": "uuid-2"},
                ]
            }
        }
        result = axl.list_phones(name="SEP%")
        axl._service.listPhone.assert_called_once()
        assert "SEP001122334455" in result

    def test_list_user(self, axl):
        axl._service.listUser.return_value = {
            "return": {
                "user": [
                    {"userid": "jsmith", "uuid": "uuid-u1", "firstName": "John", "lastName": "Smith"},
                ]
            }
        }
        result = axl.list_users(userid="jsmith")
        axl._service.listUser.assert_called_once()
        assert "jsmith" in result

    def test_list_route_plan(self, axl):
        axl._service.listRoutePlan.return_value = {"return": {"routePlan": []}}
        result = axl.list_route_plan()
        axl._service.listRoutePlan.assert_called_once()

    def test_list_device_pool(self, axl):
        axl._service.listDevicePool.return_value = {"return": {"devicePool": []}}
        result = axl.list_device_pool()
        axl._service.listDevicePool.assert_called_once()

    def test_list_region(self, axl):
        axl._service.listRegion.return_value = {"return": {"region": []}}
        result = axl.list_region()
        axl._service.listRegion.assert_called_once()

    def test_list_hunt_pilot(self, axl):
        axl._service.listHuntPilot.return_value = {"return": {"huntPilot": []}}
        result = axl.list_hunt_pilot()
        axl._service.listHuntPilot.assert_called_once()


# ── Thin AXL: SQL ─────────────────────────────────────────────────────


class TestSQLOperations:
    def test_sql_query_with_results(self, axl):
        mock_row1 = MagicMock()
        col1 = MagicMock()
        col1.tag = "name"
        col1.text = "SEP001122334455"
        col2 = MagicMock()
        col2.tag = "description"
        col2.text = "Test Phone"
        mock_row1.__iter__ = lambda self: iter([col1, col2])

        axl._service.executeSQLQuery.return_value = {
            "return": {"row": [mock_row1]}
        }

        result = axl.sql_query("SELECT name, description FROM device")
        assert result["num_rows"] == 1
        assert result["rows"][0]["name"] == "SEP001122334455"
        assert result["rows"][0]["description"] == "Test Phone"

    def test_sql_query_no_results(self, axl):
        axl._service.executeSQLQuery.return_value = {"return": None}
        result = axl.sql_query("SELECT name FROM device WHERE 1=0")
        assert result["num_rows"] == 0
        assert "rows" not in result

    def test_sql_query_fault_raises(self, axl):
        axl._service.executeSQLQuery.side_effect = Fault("SQL syntax error")
        with pytest.raises(AXLSQLError):
            axl.sql_query("INVALID SQL")

    def test_sql_update(self, axl):
        axl._service.executeSQLUpdate.return_value = {
            "return": {"rowsUpdated": 3}
        }
        result = axl.sql_update("UPDATE device SET description='X'")
        assert result["rows_updated"] == 3

    def test_sql_update_no_rows(self, axl):
        axl._service.executeSQLUpdate.return_value = {"return": None}
        result = axl.sql_update("UPDATE device SET description='X' WHERE 1=0")
        assert result["rows_updated"] == 0

    def test_sql_update_fault_raises(self, axl):
        axl._service.executeSQLUpdate.side_effect = Fault("SQL error")
        with pytest.raises(AXLSQLError):
            axl.sql_update("BAD SQL")


# ── Device operations ─────────────────────────────────────────────────


class TestDeviceOperations:
    def test_reset_phone(self, axl):
        axl._service.resetPhone.return_value = {"return": "ok"}
        result = axl.reset_phone("SEP001122334455")
        axl._service.resetPhone.assert_called_once_with(name="SEP001122334455")

    def test_restart_phone(self, axl):
        axl._service.restartPhone.return_value = {"return": "ok"}
        result = axl.restart_phone("SEP001122334455")
        axl._service.restartPhone.assert_called_once_with(name="SEP001122334455")

    def test_apply_phone(self, axl):
        axl._service.applyPhone.return_value = {"return": "ok"}
        result = axl.apply_phone("SEP001122334455")
        axl._service.applyPhone.assert_called_once_with(name="SEP001122334455")

    def test_wipe_phone(self, axl):
        axl._service.wipePhone.return_value = {"return": "ok"}
        result = axl.wipe_phone("SEP001122334455")
        axl._service.wipePhone.assert_called_once_with(name="SEP001122334455")

    def test_lock_phone(self, axl):
        axl._service.lockPhone.return_value = {"return": "ok"}
        result = axl.lock_phone("SEP001122334455")
        axl._service.lockPhone.assert_called_once_with(name="SEP001122334455")

    def test_do_device_login(self, axl):
        axl._service.doDeviceLogin.return_value = {"return": "ok"}
        result = axl.do_device_login(deviceName="SEP001122334455", userId="jsmith",
                                      profileName="DP_jsmith")
        axl._service.doDeviceLogin.assert_called_once()

    def test_do_device_logout(self, axl):
        axl._service.doDeviceLogout.return_value = {"return": "ok"}
        result = axl.do_device_logout(deviceName="SEP001122334455")
        axl._service.doDeviceLogout.assert_called_once()


# ── System / config operations ────────────────────────────────────────


class TestSystemOperations:
    def test_get_os_version(self, axl):
        axl._service.getOSVersion.return_value = {"return": {"osVersion": "15.0.1.10000-1"}}
        result = axl.get_os_version()
        axl._service.getOSVersion.assert_called_once()

    def test_get_num_devices(self, axl):
        axl._service.getNumDevices.return_value = {"return": {"numDevices": 42}}
        result = axl.get_num_devices()
        axl._service.getNumDevices.assert_called_once()

    def test_get_smart_license_status(self, axl):
        axl._service.getSmartLicenseStatus.return_value = {"return": {}}
        result = axl.get_smart_license_status()
        axl._service.getSmartLicenseStatus.assert_called_once()

    def test_get_service_parameter(self, axl):
        axl._service.getServiceParameter.return_value = {"return": {"serviceParameter": {}}}
        result = axl.get_service_parameter("cm-pub", "Cisco CallManager", "ClusterID")
        axl._service.getServiceParameter.assert_called_once_with(
            processNodeName="cm-pub",
            service="Cisco CallManager",
            name="ClusterID",
        )

    def test_update_service_parameter(self, axl):
        axl._service.updateServiceParameter.return_value = {"return": "ok"}
        result = axl.update_service_parameter("cm-pub", "Cisco CallManager", "ClusterID", "CUCM1")
        axl._service.updateServiceParameter.assert_called_once_with(
            processNodeName="cm-pub",
            service="Cisco CallManager",
            name="ClusterID",
            value="CUCM1",
        )

    def test_do_ldap_sync(self, axl):
        axl._service.doLdapSync.return_value = {"return": "ok"}
        result = axl.do_ldap_sync(name="LDAP_Corp")
        axl._service.doLdapSync.assert_called_once()

    def test_get_credential_policy_default(self, axl):
        axl._service.getCredentialPolicyDefault.return_value = {"return": {}}
        result = axl.get_credential_policy_default()
        axl._service.getCredentialPolicyDefault.assert_called_once()


# ── Config-only operations ────────────────────────────────────────────


class TestConfigOperations:
    def test_get_enterprise_phone_config(self, axl):
        axl._service.getEnterprisePhoneConfig.return_value = {"return": {}}
        result = axl.get_enterprise_phone_config()
        axl._service.getEnterprisePhoneConfig.assert_called_once()

    def test_update_enterprise_phone_config(self, axl):
        axl._service.updateEnterprisePhoneConfig.return_value = {"return": "ok"}
        result = axl.update_enterprise_phone_config(enableBLFSpeedDial="true")
        axl._service.updateEnterprisePhoneConfig.assert_called_once()

    def test_get_syslog_configuration(self, axl):
        axl._service.getSyslogConfiguration.return_value = {"return": {}}
        result = axl.get_syslog_configuration()
        axl._service.getSyslogConfiguration.assert_called_once()

    def test_update_syslog_configuration(self, axl):
        axl._service.updateSyslogConfiguration.return_value = {"return": "ok"}
        result = axl.update_syslog_configuration(alarmEnabled="true")
        axl._service.updateSyslogConfiguration.assert_called_once()


# ── Version validation ────────────────────────────────────────────────


class TestVersionValidation:
    def test_supported_versions(self):
        from axltoolkit.axl import SUPPORTED_VERSIONS
        assert "10.0" in SUPPORTED_VERSIONS
        assert "15.0" in SUPPORTED_VERSIONS
