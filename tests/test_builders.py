"""Tests for fluent builder classes."""

import pytest

from axltoolkit.builders import CssBuilder, PhoneBuilder, SipTrunkBuilder


class TestPhoneBuilder:
    def test_minimal_build(self):
        phone = (
            PhoneBuilder("SEP001122334455", product="Cisco 8845")
            .device_pool("Default")
            .build()
        )
        assert phone["name"] == "SEP001122334455"
        assert phone["product"] == "Cisco 8845"
        assert phone["class"] == "Phone"
        assert phone["protocol"] == "SIP"
        assert phone["protocolSide"] == "User"
        assert phone["devicePoolName"] == "Default"
        assert "lines" not in phone

    def test_full_build(self):
        phone = (
            PhoneBuilder("SEP001122334455", product="Cisco 8845")
            .device_pool("Default")
            .sip_profile("Standard SIP Profile")
            .security_profile("Cisco 8845 - Standard SIP Non-Secure Profile")
            .phone_template("Standard 8845 SIP")
            .common_phone_config("Standard Common Phone Profile")
            .location("Hub_None")
            .description("Test Phone")
            .owner("jsmith")
            .calling_search_space("CSS-Internal")
            .user_locale("English United States")
            .network_locale("United States")
            .media_resource_list("MRL-Default")
            .load_information("sip8845.12-5-1-18")
            .add_line(1, "1001", "Internal-PT", display="John Smith")
            .add_line(2, "1002", "Internal-PT", label="Hotline")
            .build()
        )
        assert phone["devicePoolName"] == "Default"
        assert phone["sipProfileName"] == "Standard SIP Profile"
        assert phone["ownerUserName"] == "jsmith"
        assert phone["description"] == "Test Phone"
        assert phone["callingSearchSpaceName"] == "CSS-Internal"
        assert phone["loadInformation"] == "sip8845.12-5-1-18"
        lines = phone["lines"]["line"]
        assert len(lines) == 2
        assert lines[0]["index"] == 1
        assert lines[0]["dirn"]["pattern"] == "1001"
        assert lines[0]["dirn"]["routePartitionName"] == "Internal-PT"
        assert lines[0]["display"] == "John Smith"
        assert lines[1]["index"] == 2
        assert lines[1]["label"] == "Hotline"

    def test_sccp_protocol(self):
        phone = (
            PhoneBuilder("SEP001122334455", product="Cisco 7960", protocol="SCCP")
            .device_pool("Default")
            .build()
        )
        assert phone["protocol"] == "SCCP"

    def test_missing_device_pool_raises(self):
        with pytest.raises(ValueError, match="devicePoolName"):
            PhoneBuilder("SEP001122334455").build()

    def test_set_arbitrary_field(self):
        phone = (
            PhoneBuilder("SEP001122334455")
            .device_pool("Default")
            .set("enableExtensionMobility", True)
            .build()
        )
        assert phone["enableExtensionMobility"] is True

    def test_line_defaults(self):
        phone = (
            PhoneBuilder("SEP001122334455")
            .device_pool("Default")
            .add_line(1, "1001")
            .build()
        )
        line = phone["lines"]["line"][0]
        assert line["maxNumCalls"] == 4
        assert line["busyTrigger"] == 2
        assert line["dirn"]["routePartitionName"] == ""
        assert "display" not in line

    def test_line_e164_mask(self):
        phone = (
            PhoneBuilder("SEP001122334455")
            .device_pool("Default")
            .add_line(1, "1001", e164_mask="+15551001")
            .build()
        )
        line = phone["lines"]["line"][0]
        assert line["e164Mask"] == "+15551001"


class TestSipTrunkBuilder:
    def test_minimal_build(self):
        trunk = (
            SipTrunkBuilder("SIP-Trunk-ITSP")
            .device_pool("Default")
            .security_profile("Non Secure SIP Trunk Profile")
            .sip_profile("Standard SIP Profile")
            .build()
        )
        assert trunk["name"] == "SIP-Trunk-ITSP"
        assert trunk["product"] == "SIP Trunk"
        assert trunk["class"] == "Trunk"
        assert trunk["protocol"] == "SIP"
        assert trunk["protocolSide"] == "Network"
        assert trunk["devicePoolName"] == "Default"
        assert "destinations" not in trunk

    def test_full_build(self):
        trunk = (
            SipTrunkBuilder("SIP-Trunk-ITSP")
            .device_pool("Default")
            .security_profile("Non Secure SIP Trunk Profile")
            .sip_profile("Standard SIP Profile")
            .description("ITSP trunk")
            .calling_search_space("CSS-Trunk")
            .location("Hub_None")
            .media_resource_list("MRL-Default")
            .run_on_every_node(True)
            .trunk_type("None(Default)")
            .add_destination("10.0.0.100", 5060)
            .add_destination("10.0.0.101", 5061)
            .build()
        )
        assert trunk["description"] == "ITSP trunk"
        assert trunk["runOnEveryNode"] is True
        dests = trunk["destinations"]["destination"]
        assert len(dests) == 2
        assert dests[0]["addressIpv4"] == "10.0.0.100"
        assert dests[0]["port"] == 5060
        assert dests[0]["sortOrder"] == 1
        assert dests[1]["addressIpv4"] == "10.0.0.101"
        assert dests[1]["sortOrder"] == 2

    def test_ipv6_destination(self):
        trunk = (
            SipTrunkBuilder("SIP-Trunk-v6")
            .device_pool("Default")
            .security_profile("Non Secure SIP Trunk Profile")
            .sip_profile("Standard SIP Profile")
            .add_destination("2001:db8::1", 5060, ipv6=True)
            .build()
        )
        dest = trunk["destinations"]["destination"][0]
        assert dest["addressIpv6"] == "2001:db8::1"
        assert "addressIpv4" not in dest

    def test_custom_sort_order(self):
        trunk = (
            SipTrunkBuilder("SIP-Trunk")
            .device_pool("Default")
            .security_profile("Non Secure SIP Trunk Profile")
            .sip_profile("Standard SIP Profile")
            .add_destination("10.0.0.100", sort_order=5)
            .build()
        )
        assert trunk["destinations"]["destination"][0]["sortOrder"] == 5

    def test_missing_required_raises(self):
        with pytest.raises(ValueError, match="devicePoolName"):
            SipTrunkBuilder("SIP-Trunk").build()

    def test_set_arbitrary_field(self):
        trunk = (
            SipTrunkBuilder("SIP-Trunk")
            .device_pool("Default")
            .security_profile("Non Secure SIP Trunk Profile")
            .sip_profile("Standard SIP Profile")
            .set("normalizationScript", "DefaultScript")
            .build()
        )
        assert trunk["normalizationScript"] == "DefaultScript"


class TestCssBuilder:
    def test_empty_css(self):
        css = CssBuilder("CSS-Empty").build()
        assert css["name"] == "CSS-Empty"
        assert css["description"] == ""
        assert css["members"]["member"] == []

    def test_with_partitions(self):
        css = (
            CssBuilder("CSS-Internal")
            .description("Internal dialing")
            .add_partition("PT-Internal")
            .add_partition("PT-Local")
            .add_partition("PT-LD")
            .build()
        )
        assert css["name"] == "CSS-Internal"
        assert css["description"] == "Internal dialing"
        members = css["members"]["member"]
        assert len(members) == 3
        assert members[0] == {"routePartitionName": "PT-Internal", "index": 1}
        assert members[1] == {"routePartitionName": "PT-Local", "index": 2}
        assert members[2] == {"routePartitionName": "PT-LD", "index": 3}

    def test_ordering_preserved(self):
        css = (
            CssBuilder("CSS-Test")
            .add_partition("Z-Partition")
            .add_partition("A-Partition")
            .build()
        )
        members = css["members"]["member"]
        assert members[0]["routePartitionName"] == "Z-Partition"
        assert members[0]["index"] == 1
        assert members[1]["routePartitionName"] == "A-Partition"
        assert members[1]["index"] == 2
