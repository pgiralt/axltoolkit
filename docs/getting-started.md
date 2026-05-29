# Getting Started

## Prerequisites

- **Python 3.10** or later
- Network access to a Cisco UCM server (port 8443)
- An **AXL-enabled application user** for AXL, RISPort, and PerfMon operations
- A **platform/OS admin user** for PAWS, Serviceability, and Log Collection

> [!TIP]
> **Enabling the AXL API** — in UCM Administration, go to
> **User Management > Application User** and ensure your user has the
> **Standard AXL API Access** role.  The AXL SOAP service must be
> activated under
> **Cisco Unified Serviceability > Tools > Service Activation**.

## Installation

Install from the repository:

```bash
pip install .
```

For development (tests, linting):

```bash
pip install -e ".[dev]"
```

## Credentials

You can pass UCM credentials directly as constructor arguments, but for
anything beyond a one-off script we strongly recommend reading them
from the environment. The repository ships a `.env.example` template
you can copy:

```bash
cp .env.example .env
# edit .env with your UCM publisher, AXL user, and password
```

`.env` is `.gitignore`d, so secrets stay out of version control.
`python-dotenv` is part of the `dev` extras; the
[Local Development guide](guide/local-development.md) walks through the
full workflow, including how the samples and integration tests pick
the values up automatically.

```python
import os
from axltoolkit import AXLClient
from dotenv import load_dotenv

load_dotenv()      # loads .env into os.environ

client = AXLClient(
    username=os.environ["UCM_USERNAME"],
    password=os.environ["UCM_PASSWORD"],
    server_ip=os.environ["UCM_ADDRESS"],
    version=os.environ.get("UCM_AXL_VERSION", "15.0"),
    tls_verify=True,
)
```

## Connecting to UCM

### AXL Client

The [`AXLClient`](api/axl.md) is the main entry point for UCM configuration:

```python
from axltoolkit import AXLClient

client = AXLClient(
    username="axladmin",
    password="secret",
    server_ip="ucm-pub.example.com",
    version="15.0",
    tls_verify=True,
)
```

> [!NOTE]
> **AXL Schema Versions** — the `version` parameter must match an AXL
> schema bundled with the library. Supported versions: `10.0`, `10.5`,
> `11.0`, `11.5`, `12.0`, `12.5`, `14.0`, `15.0`. Use the version that
> matches (or is closest to) your UCM release.

### SXML Clients

The SXML clients (RISPort, PerfMon, Serviceability, Log Collection, PAWS,
Webdialer) share the same constructor pattern:

```python
from axltoolkit import RISPortClient, PerfMonClient, PAWSClient

ris = RISPortClient(
    username="axladmin",
    password="secret",
    server_ip="ucm-pub.example.com",
    tls_verify=True,
)

paws = PAWSClient(
    username="platformadmin",       # PAWS uses platform credentials
    password="platformsecret",
    server_ip="ucm-pub.example.com",
    tls_verify=True,
)
```

### TLS Verification

By default, `tls_verify=True` validates the server's TLS certificate.  If
your UCM uses a self-signed certificate, you have three options:

```python
# Option 1 — Provide a custom CA bundle
client = AXLClient(..., tls_verify="/path/to/ucm-ca-bundle.pem")

# Option 2 — Disable verification (development only!)
client = AXLClient(..., tls_verify=False)

# Option 3 — Install the UCM CA in your system trust store (recommended)
client = AXLClient(..., tls_verify=True)
```

> [!WARNING]
> Setting `tls_verify=False` disables certificate validation entirely.
> **Never** use this in production — it makes connections vulnerable to
> man-in-the-middle attacks.

See the [TLS & Security guide](guide/security.md) for more details.

## Basic Operations

### Thick AXL — CRUD Operations

```python
# Get a user
user = client.get_user(userid="jsmith")
print(user["return"]["user"]["firstName"])

# List phones matching a pattern
phones = client.list_phones(name="SEP%")

# Update a user
client.update_user(userid="jsmith", firstName="John")

# Add a route partition
client.add_route_partition(routePartition={"name": "PT_Internal", "description": "Internal"})

# Remove a CSS
client.remove_css(name="CSS_Old")
```

### Thin AXL — SQL Queries

```python
# Read-only query
result = client.sql_query("SELECT name, description FROM device WHERE name LIKE 'SEP%'")
for row in result.get("rows", []):
    print(row["name"], row["description"])

# DML update
update = client.sql_update("UPDATE device SET description='Lab' WHERE name='SEP001122334455'")
print(f"Updated {update['rows_updated']} rows")
```

See the [SQL Queries guide](guide/sql.md) for security considerations and
helper methods.

### Fluent Builders

For complex objects like phones and SIP trunks, use the
[fluent builders](guide/builders.md):

```python
from axltoolkit import AXLClient, PhoneBuilder

client = AXLClient("admin", "password", "ucm-pub.example.com", version="15.0")

phone = (
    PhoneBuilder("SEP001122334455", product="Cisco 8845")
    .device_pool("Default")
    .sip_profile("Standard SIP Profile")
    .security_profile("Cisco 8845 - Standard SIP Non-Secure Profile")
    .phone_template("Standard 8845 SIP")
    .add_line(1, "1001", "Internal-PT", display="John Smith")
    .owner("jsmith")
    .build()
)

client.add_phone(phone)
```

### RISPort — Real-time Registration

```python
from axltoolkit import RISPortClient

ris = RISPortClient("admin", "password", "ucm-pub.example.com", tls_verify=True)

# Convenience method — flat list of registered phones
phones = ris.get_registered_phones("SEP*")
for phone in phones:
    print(f"{phone['name']}: {phone['ip_address']}")

# Full selectCmDevice for advanced queries
result = ris.select_cm_device(
    device_class="Phone",
    select_items=["CSF*"],
    status="Registered",
)
```

### PerfMon — Performance Counters

```python
from axltoolkit import PerfMonClient

pm = PerfMonClient("admin", "password", "ucm-pub.example.com", tls_verify=True)

session = pm.open_session()
pm.add_counters(session, [r"\\cm-pub\Cisco CallManager\CallsCompleted"])
data = pm.collect_session_data(session)
pm.close_session(session)
print(data)
```

### PAWS — Platform Information & Upgrades

```python
from axltoolkit import PAWSClient

paws = PAWSClient("platformadmin", "secret", "ucm-pub.example.com", tls_verify=True)

# Platform queries
version = paws.get_active_version()
nodes = paws.get_cluster_nodes()
hw = paws.get_hardware_information()
model = paws.get_hardware_model()
mode = paws.get_deployment_mode()

# Upgrade status
stage = paws.get_upgrade_stage()
valid = paws.is_upgrade_valid("UCSInstall_UCOS_14.0.1.zip")
```

## Error Handling

All library exceptions inherit from
[`AxlToolkitError`](api/exceptions.md), so you can catch everything with a
single clause, or handle specific error types:

```python
from axltoolkit import AXLClient, AXLNotFoundError, AXLDuplicateError, AXLError

client = AXLClient("admin", "password", "ucm-pub.example.com", version="15.0")

try:
    phone = client.get_phone(name="DOESNOTEXIST")
except AXLNotFoundError:
    print("Phone not found")
except AXLDuplicateError:
    print("Duplicate entry")
except AXLError as e:
    print(f"AXL error {e.axl_error_code}: {e}")
```

AXL errors include structured attributes:

- `e.fault_code` — The SOAP fault code string
- `e.fault_message` — Human-readable detail message
- `e.axl_error_code` — Numeric AXL error code (e.g. `5007` = Not Found)
- `e.original_exception` — The underlying `zeep.exceptions.Fault`

## Type Hints & Models

The library ships two layers of `TypedDict` models for IDE auto-completion
and static type checking.

### Generated Models (from AXL XSD)

Auto-generated from the AXL schema, covering **every** `add_*` and
`update_*` operation:

```python
from axltoolkit._generated_models import Phone, SipTrunk, Line
from axltoolkit._generated_models import UpdatePhone, UpdateSipTrunk
```

Add-method signatures use the generated TypedDict directly:

```python
phone_data: Phone = {
    "name": "SEP001122334455",
    "product": "Cisco 8845",
    "class": "Phone",
    "protocol": "SIP",
    "protocolSide": "User",
    "devicePoolName": "Default",
}
client.add_phone(phone_data)
```

Update methods accept typed keyword arguments via `Unpack`:

```python
client.update_phone(name="SEP001122334455", description="Lab Phone")
```

### Generated Enums

Enum types for constrained AXL fields:

```python
from axltoolkit._generated_enums import ProtocolSide, ClockReference

phone_data["protocolSide"] = ProtocolSide.USER  # passes as plain string
```

### Hand-Curated Models

For the most common objects, there are also hand-curated models with
curated field documentation:

```python
from axltoolkit.models import PhoneData, UserData, SQLQueryResult
```

See the full list in the [Models reference](api/models.md).

## Next Steps

- [TLS & Security](guide/security.md) — Certificate management, SQL
  injection protection, credential handling, production checklist
- [SQL Queries](guide/sql.md) — Thin AXL deep-dive with helper methods
- [Fluent Builders](guide/builders.md) — PhoneBuilder, SipTrunkBuilder,
  CssBuilder
- [Configuration Recipes](guide/recipes.md) — Common provisioning workflows
- [Local Development](guide/local-development.md) — `.env` setup, integration
  tests against a live UCM, and the coverage scripts
- [API Reference](api/axl.md) — Complete method documentation
- [Migration Guide](migration.md) — Upgrading from v1
