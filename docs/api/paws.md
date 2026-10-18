# PAWS Client

The `PAWSClient` provides access to **Platform Administrative Web Services**
for hardware details, software versions, cluster topology, installed options,
deployment mode, and upgrade/restart/switch-version operations.

Unlike the other SXML clients which use a single WSDL, PAWS consists of
multiple independent SOAP services.  The client **lazily initializes** each
service on first use, so only the services you call will have their WSDLs
fetched.

> [!NOTE]
> PAWS requires **platform/OS admin credentials**.

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
nodes = paws.get_cluster_status()
cluster_replication = paws.is_cluster_replication_ok()
node_replication = paws.is_node_replication_ok("ucm-pub.example.com")
hw = paws.get_hardware_information()
model = paws.get_hardware_model()
mode = paws.get_deployment_mode()

# Upgrade operations
stage = paws.get_upgrade_stage()
valid = paws.is_upgrade_valid("UCSInstall_UCOS_14.0.1.zip")
```

Use `get_cluster_status()` for current cluster node status. The existing
`get_cluster_nodes()` and `get_my_cluster_node()` methods remain available.
All five cluster methods use the same lazily initialized `ClusterNodesService`
proxy. `is_node_replication_ok(node_name)` forwards the selected cluster node
hostname as the native `args0` string required by the installed WSDL. The other
four cluster methods call their native operations without arguments.

The replication methods return the native response, including
`clusterReplicationStatusOK` or `nodeReplicationStatusOK`. Inspect that boolean
field explicitly: a response containing `False` still represents a successful
query. SOAP faults raise `PAWSError` with the original exception preserved.

## Class Reference

::: axltoolkit.paws_client.PAWSClient
    options:
      show_root_heading: true
      members_order: source
      filters:
        - "!^_"
