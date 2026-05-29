# PAWS Client

The `PAWSClient` provides access to **Platform Administrative Web Services**
for hardware details, software versions, cluster topology, installed options,
deployment mode, and upgrade/restart/switch-version operations.

Unlike the other SXML clients which use a single WSDL, PAWS consists of
multiple independent SOAP services.  The client **lazily initializes** each
service on first use, so only the services you call will have their WSDLs
fetched.

!!! note
    PAWS requires **platform/OS admin credentials**.

## Quick Example

```python
from axltoolkit import PAWSClient

paws = PAWSClient(
    username="platformadmin",
    password="secret",
    server_ip="ucm-pub.example.com",
    tls_verify=True,
)

# Platform information
version = paws.get_active_version()
nodes = paws.get_cluster_nodes()
hw = paws.get_hardware_information()
model = paws.get_hardware_model()
mode = paws.get_deployment_mode()

# Upgrade operations
stage = paws.get_upgrade_stage()
valid = paws.is_upgrade_valid("UCSInstall_UCOS_14.0.1.zip")
```

## Class Reference

::: axltoolkit.paws_client.PAWSClient
    options:
      show_root_heading: true
      members_order: source
      filters:
        - "!^_"
