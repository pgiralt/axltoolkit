# Migration Guide (v1 to v2)

## Overview

axltoolkit v2 replaces the monolithic `AxlToolkit` class with focused,
modular clients.  The old class names still work but emit
`DeprecationWarning` and will be removed in a future major release.

## Class Name Changes

| v1 (deprecated) | v2 |
|---|---|
| `AxlToolkit` | [`AXLClient`](api/axl.md) |
| `UcmRisPortToolkit` | [`RISPortClient`](api/risport.md) |
| `UcmPerfMonToolkit` | [`PerfMonClient`](api/perfmon.md) |
| `UcmServiceabilityToolkit` | [`ServiceabilityClient`](api/serviceability.md) |
| `UcmLogCollectionToolkit` | [`LogCollectionClient`](api/log_collection.md) |
| `UcmDimeGetFileToolkit` | [`DimeGetFileClient`](api/log_collection.md) |
| `PawsToolkit` | [`PAWSClient`](api/paws.md) |
| `WebdialerToolkit` | [`WebdialerClient`](api/webdialer.md) |

## Constructor Changes

The constructor signature is identical, but we recommend using FQDNs (not IP
addresses) and keeping TLS verification enabled:

=== "v1 (deprecated)"

    ```python
    from axltoolkit import AxlToolkit
    client = AxlToolkit("admin", "pass", "ucm-pub.example.com",
                         version="15.0", tls_verify=True, timeout=10)
    ```

=== "v2 (recommended)"

    ```python
    from axltoolkit import AXLClient
    client = AXLClient("admin", "pass", "ucm-pub.example.com",
                        version="15.0", tls_verify=True, timeout=10)
    ```

## Method Name Changes

| v1 | v2 |
|---|---|
| `run_sql_query(sql)` | `sql_query(query)` |
| `run_sql_update(sql)` | `sql_update(query)` |
| `list_phone(...)` | `list_phones(...)` |
| `get_cfb(name)` | `get_conference_bridge(name)` |
| `get_mrg(name)` | `get_media_resource_group(name)` |
| `add_partition(...)` | `add_route_partition(...)` |
| `add_user_phone_association(userid, devices)` | `associate_user_devices(userid, devices)` |
| `get_cisco_cloud_onboarding()` | *removed* — use `list_cisco_cloud_onboarding()` |
| `get_service()` | `.service` property |

## Exception Hierarchy

v2 introduces [typed exceptions](api/exceptions.md) instead of generic
`Exception`:

```python
from axltoolkit import AXLNotFoundError, AXLDuplicateError, AXLError

try:
    client.get_phone(name="MISSING")
except AXLNotFoundError:
    print("Not found")
except AXLDuplicateError:
    print("Already exists")
except AXLError as e:
    print(f"AXL error {e.axl_error_code}: {e}")
```

## Security Improvements in v2

- **TLS verification** enabled by default (`tls_verify=True`)
- **WSDL cache** moved to `~/.cache/axltoolkit/` with restricted
  permissions
- **SQL injection protection** with pattern detection and value escaping
- **Credential redaction** in `last_request_debug()` output
- **Server IP validation** at construction time

See the [TLS & Security guide](guide/security.md) for details.

## Type-Hint Support (new in v2)

All `add_*` methods now accept typed `TypedDict` parameters, and all
`update_*` methods use typed `**kwargs` via `Unpack`:

```python
from axltoolkit import AXLClient
from axltoolkit._generated_models import Phone, UpdatePhone

client = AXLClient("admin", "pass", "ucm-pub.example.com", version="15.0")

# add_phone now expects a Phone TypedDict — IDE shows all valid fields
phone_data: Phone = {
    "name": "SEP001122334455",
    "product": "Cisco 8845",
    "protocol": "SIP",
    "protocolSide": "User",
    "devicePoolName": "Default",
    "class": "Phone",
}
client.add_phone(phone_data)

# update_phone kwargs are typed — IDE autocompletes field names
client.update_phone(name="SEP001122334455", description="Lab Phone")
```

170 enum classes are also available for constrained fields:

```python
from axltoolkit._generated_enums import ProtocolSide

phone_data["protocolSide"] = ProtocolSide.USER
```

See the [Models reference](api/models.md) for the full list of generated
types.

## Backward Compatibility

The old class names still work.  They emit `DeprecationWarning` on
instantiation but delegate to the new clients:

```python
from axltoolkit import AxlToolkit  # emits DeprecationWarning
client = AxlToolkit("admin", "pass", "ucm-pub.example.com")
client.run_sql_query("SELECT 1")  # still works
```

!!! warning
    The backward-compatibility shims will be removed in a future major
    release.  Migrate to the new class names at your earliest convenience.
