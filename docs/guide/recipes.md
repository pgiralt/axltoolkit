# Configuration Recipes

Common provisioning workflows using axltoolkit.

## Provision a New User with a Phone

```python
from axltoolkit import AXLClient, PhoneBuilder

client = AXLClient(
    username="admin",
    password="secret",
    server_ip="ucm-pub.example.com",
    version="15.0",
    tls_verify=True,
)

# 1. Add a directory number (line)
client.add_line(line={
    "pattern": "1001",
    "routePartitionName": "PT_Internal",
    "description": "John Smith",
    "alertingName": "John Smith",
    "asciiAlertingName": "John Smith",
})

# 2. Add the phone using the builder
phone = (
    PhoneBuilder("SEP001122334455", product="Cisco 8845")
    .device_pool("Default")
    .sip_profile("Standard SIP Profile")
    .security_profile("Cisco 8845 - Standard SIP Non-Secure Profile")
    .phone_template("Standard 8845 SIP")
    .description("John Smith - 1001")
    .owner("jsmith")
    .add_line(1, "1001", "PT_Internal", display="John Smith")
    .build()
)
client.add_phone(phone)

# 3. Create the end user
client.add_user(user={
    "userid": "jsmith",
    "firstName": "John",
    "lastName": "Smith",
    "password": "changeme123",
    "pin": "12345",
    "associatedDevices": {"device": ["SEP001122334455"]},
    "primaryExtension": {
        "pattern": "1001",
        "routePartitionName": "PT_Internal",
    },
    "enableCti": True,
})

# 4. Apply the phone to push config
client.apply_phone(name="SEP001122334455")
```

## Bulk Update Phone Descriptions

```python
# Get all SEP phones via SQL
result = client.sql_query("SELECT name FROM device WHERE name LIKE 'SEP%'")

for row in result.get("rows", []):
    phone_name = row["name"]
    try:
        client.update_phone(name=phone_name, description=f"Auto-labeled: {phone_name}")
        print(f"Updated {phone_name}")
    except Exception as e:
        print(f"Failed to update {phone_name}: {e}")
```

## Export Registered Phones to CSV

```python
import csv
from axltoolkit import RISPortClient

ris = RISPortClient("admin", "password", "ucm-pub.example.com", tls_verify=True)

phones = ris.get_registered_phones("SEP*")

with open("registered_phones.csv", "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=["name", "ip_address", "status", "model", "node"])
    writer.writeheader()
    writer.writerows(phones)

print(f"Exported {len(phones)} phones")
```

## Monitor Call Volume with PerfMon

```python
import time
from axltoolkit import PerfMonClient

pm = PerfMonClient("admin", "password", "ucm-pub.example.com", tls_verify=True)

session = pm.open_session()
pm.add_counters(session, [
    r"\\cm-pub\Cisco CallManager\CallsActive",
    r"\\cm-pub\Cisco CallManager\CallsCompleted",
])

try:
    for _ in range(10):
        data = pm.collect_session_data(session)
        if data:
            for host, objects in data.items():
                for obj_name, obj_data in objects.items():
                    counters = obj_data.get("counters", {})
                    print(f"[{host}] {obj_name}: {counters}")
        time.sleep(5)
finally:
    pm.close_session(session)
```

## Check UCM Version and Cluster Topology

```python
from axltoolkit import PAWSClient

paws = PAWSClient("platformadmin", "secret", "ucm-pub.example.com", tls_verify=True)

version = paws.get_active_version()
print(f"UCM Version: {version}")

nodes = paws.get_cluster_nodes()
print(f"Cluster Nodes: {nodes}")

hw = paws.get_hardware_information()
print(f"Hardware: {hw}")
```

## Restart a Service

```python
from axltoolkit import ServiceabilityClient

svc = ServiceabilityClient("platformadmin", "secret", "ucm-pub.example.com", tls_verify=True)

# Check current status
status = svc.get_service_status(["Cisco CallManager"])
print(status)

# Restart the service
svc.restart_service("Cisco CallManager")
```

## Add a SIP Trunk with Multiple Destinations

```python
from axltoolkit import AXLClient, SipTrunkBuilder

client = AXLClient("admin", "password", "ucm-pub.example.com", version="15.0")

trunk = (
    SipTrunkBuilder("SIP-Trunk-ITSP")
    .device_pool("Default")
    .security_profile("Non Secure SIP Trunk Profile")
    .sip_profile("Standard SIP Profile")
    .calling_search_space("CSS_Trunk_Outbound")
    .description("ITSP SIP trunk with failover")
    .add_destination("sbc-primary.example.com", 5060)
    .add_destination("sbc-secondary.example.com", 5060)
    .run_on_every_node(True)
    .build()
)

client.add_sip_trunk(trunk)
```

## Build a Calling Search Space

```python
from axltoolkit import AXLClient, CssBuilder

client = AXLClient("admin", "password", "ucm-pub.example.com", version="15.0")

# Create partitions first
for pt_name in ["PT_Internal", "PT_Local", "PT_LongDistance"]:
    client.add_route_partition(routePartition={"name": pt_name})

# Build and add the CSS
css = (
    CssBuilder("CSS-Full-Access")
    .description("Internal + Local + Long Distance")
    .add_partition("PT_Internal")
    .add_partition("PT_Local")
    .add_partition("PT_LongDistance")
    .build()
)

client.add_css(css)
```

## Using the Direct Service Proxy

For AXL operations not yet wrapped by a dedicated method, use the
`.service` property to access the raw zeep service proxy:

```python
# Direct zeep call for an uncommon operation
result = client.service.doLdapSync(name="LDAP_Directory_1", sync=True)
```

## Debugging Requests

Enable request/response logging for troubleshooting:

```python
import logging

# Turn on axltoolkit debug logging
logging.basicConfig(level=logging.DEBUG)
logging.getLogger("axltoolkit").setLevel(logging.DEBUG)

# Or inspect the last request/response
client.get_phone(name="SEP001122334455")
debug = client.last_request_debug()
print(debug["request"]["envelope"])   # SOAP XML sent
print(debug["response"]["envelope"])  # SOAP XML received
```
