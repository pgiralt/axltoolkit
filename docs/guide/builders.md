# Fluent Builders

Builders help you construct the deeply nested dict structures required by
AXL `add*` operations without worrying about exact key names or nesting.

## PhoneBuilder

Build phone device payloads for
[`add_phone()`][axltoolkit.axl.AXLClient.add_phone]:

```python
from axltoolkit import PhoneBuilder

phone = (
    PhoneBuilder("SEP001122334455", product="Cisco 8845")
    .device_pool("Default")
    .calling_search_space("CSS_Internal")
    .sip_profile("Standard SIP Profile")
    .security_profile("Cisco 8845 - Standard SIP Non-Secure Profile")
    .phone_template("Standard 8845 SIP")
    .common_phone_config("Standard Common Phone Profile")
    .location("Hub_None")
    .description("John Smith's desk phone")
    .owner("jsmith")
    .add_line(1, "1001", "PT_Internal", display="John Smith", e164_mask="+15551001")
    .add_line(2, "1002", "PT_Internal", label="Shared Line")
    .build()
)

client.add_phone(phone)
```

### Available Methods

| Method | Sets |
|--------|------|
| `.device_pool(name)` | `devicePoolName` |
| `.calling_search_space(name)` | `callingSearchSpaceName` |
| `.common_device_config(name)` | `commonDeviceConfigName` |
| `.common_phone_config(name)` | `commonPhoneConfigName` |
| `.phone_template(name)` | `phoneTemplateName` |
| `.location(name)` | `locationName` |
| `.security_profile(name)` | `securityProfileName` |
| `.sip_profile(name)` | `sipProfileName` |
| `.softkey_template(name)` | `softkeyTemplateName` |
| `.description(desc)` | `description` |
| `.owner(userid)` | `ownerUserName` |
| `.user_locale(locale)` | `userLocale` |
| `.network_locale(locale)` | `networkLocale` |
| `.media_resource_list(name)` | `mediaResourceListName` |
| `.load_information(firmware)` | `loadInformation` |
| `.set(key, value)` | Any arbitrary key |
| `.add_line(...)` | Appends a line association |

### Adding Lines

```python
builder.add_line(
    index=1,                          # Line button position (1-based)
    pattern="1001",                   # Directory number
    route_partition_name="PT_Internal",
    display="John Smith",             # Display name (optional)
    display_ascii="John Smith",       # ASCII display (optional)
    label="Line 1",                   # Line text label (optional)
    e164_mask="+15551001",            # E.164 mask (optional)
    max_num_calls=4,                  # Max simultaneous calls (default: 4)
    busy_trigger=2,                   # Busy trigger threshold (default: 2)
)
```

### Validation

`build()` raises `ValueError` if required fields (`name`, `product`,
`devicePoolName`) are missing.

## SipTrunkBuilder

Build SIP trunk payloads for
[`add_sip_trunk()`][axltoolkit.axl.AXLClient.add_sip_trunk]:

```python
from axltoolkit import SipTrunkBuilder

trunk = (
    SipTrunkBuilder("SIP-Trunk-ITSP")
    .device_pool("Default")
    .security_profile("Non Secure SIP Trunk Profile")
    .sip_profile("Standard SIP Profile")
    .calling_search_space("CSS_Trunk")
    .description("ITSP trunk")
    .add_destination("sbc.example.com", 5060)
    .add_destination("sbc-backup.example.com", 5060)
    .run_on_every_node(True)
    .build()
)

client.add_sip_trunk(trunk)
```

### Available Methods

| Method | Sets |
|--------|------|
| `.device_pool(name)` | `devicePoolName` |
| `.calling_search_space(name)` | `callingSearchSpaceName` |
| `.security_profile(name)` | `securityProfileName` |
| `.sip_profile(name)` | `sipProfileName` |
| `.description(desc)` | `description` |
| `.media_resource_list(name)` | `mediaResourceListName` |
| `.location(name)` | `locationName` |
| `.run_on_every_node(bool)` | `runOnEveryNode` |
| `.trunk_type(type)` | `sipTrunkType` |
| `.set(key, value)` | Any arbitrary key |
| `.add_destination(...)` | Appends a SIP peer destination |

### Validation

`build()` raises `ValueError` if required fields (`name`,
`devicePoolName`, `securityProfileName`, `sipProfileName`) are missing.

## CssBuilder

Build Calling Search Space payloads for
[`add_css()`][axltoolkit.axl.AXLClient.add_css]:

```python
from axltoolkit import CssBuilder

css = (
    CssBuilder("CSS-Internal-LD")
    .description("Internal + Long Distance")
    .add_partition("PT_Internal")
    .add_partition("PT_Local")
    .add_partition("PT_LongDistance")
    .build()
)

client.add_css(css)
```

Partitions are added in order — the first partition has the highest priority
(index 1).

## The `.set()` Escape Hatch

All builders expose a `.set(key, value)` method for setting AXL fields
that don't have a dedicated builder method:

```python
phone = (
    PhoneBuilder("SEP001122334455", product="Cisco 8845")
    .device_pool("Default")
    .set("enableExtensionMobility", True)
    .set("builtInBridgeStatus", "On")
    .build()
)
```

## API Reference

See the full builder API documentation:

- [`PhoneBuilder`](../api/builders.md)
- [`SipTrunkBuilder`](../api/builders.md)
- [`CssBuilder`](../api/builders.md)
