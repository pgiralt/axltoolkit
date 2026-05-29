# Serviceability Client

The `ServiceabilityClient` manages UCM services (start, stop, restart,
status, deploy/undeploy) via the **ControlCenter** SXML API.

> [!NOTE]
> This client requires **platform/OS admin credentials**, not AXL
> application user credentials.

## Quick Example

```python
from axltoolkit import ServiceabilityClient

svc = ServiceabilityClient(
    username="platformadmin",
    password="secret",
    server_ip="ucm-pub.example.com",
    tls_verify=True,
)

status = svc.get_service_status(["Cisco CallManager"])
svc.restart_service("Cisco CallManager")
```

## Class Reference

::: axltoolkit.serviceability.ServiceabilityClient
    options:
      show_root_heading: true
      members_order: source
      filters:
        - "!^_"
