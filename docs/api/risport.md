# RISPort Client

The `RISPortClient` provides real-time device registration status and CTI
manager information from the UCM cluster via the **RISPort70** SXML API.

## Quick Example

```python
from axltoolkit import RISPortClient

ris = RISPortClient(
    username="admin",
    password="secret",
    server_ip="ucm-pub.example.com",
    tls_verify=True,
)

# Convenience method — flat list of registered phones
for phone in ris.get_registered_phones("SEP*"):
    print(f"{phone['name']}: {phone['ip_address']}")

# Full selectCmDevice query
result = ris.select_cm_device(device_class="Phone", status="Registered")
```

## Class Reference

::: axltoolkit.risport.RISPortClient
    options:
      show_root_heading: true
      members_order: source
      filters:
        - "!^_"
