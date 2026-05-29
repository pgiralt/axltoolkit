# axltoolkit

**A complete Python SDK for Cisco Unified Communications Manager (UCM).**

---

axltoolkit gives you Pythonic, fully-typed access to **every** Cisco UCM
administration and serviceability API from a single package:

| Client | API | What it does |
|--------|-----|--------------|
| [`AXLClient`](api/axl.md) | AXL (Thick + Thin) | CRUD for 1,000+ configuration objects — phones, users, partitions, CSS, route patterns, SIP trunks, and more |
| [`RISPortClient`](api/risport.md) | RISPort70 | Real-time device registration status and CTI information |
| [`PerfMonClient`](api/perfmon.md) | PerfMon | Session-based and one-shot performance counter collection |
| [`ServiceabilityClient`](api/serviceability.md) | ControlCenter | UCM service management — start, stop, restart, status |
| [`LogCollectionClient`](api/log_collection.md) | LogCollection | Log file listing and retrieval |
| [`DimeGetFileClient`](api/log_collection.md) | DimeGetFile | Direct file download from UCM servers |
| [`PAWSClient`](api/paws.md) | PAWS | Platform hardware, software versions, cluster topology |
| [`WebdialerClient`](api/webdialer.md) | Webdialer | Click-to-call functionality |

## Quick Start

```python
from axltoolkit import AXLClient

client = AXLClient(
    username="axladmin",
    password="secret",
    server_ip="ucm-pub.example.com",
    version="15.0",
    tls_verify=True,
)

# Thick AXL — get a user
user = client.get_user(userid="jsmith")
print(user["return"]["user"]["firstName"])

# Thick AXL — list phones
phones = client.list_phones(name="SEP%")

# Thin AXL — direct SQL query
result = client.sql_query("SELECT name FROM device WHERE name LIKE 'SEP%'")
for row in result.get("rows", []):
    print(row["name"])
```

## Installation

Install from source:

```bash
pip install .
```

For development (tests + linting):

```bash
pip install -e ".[dev]"
```

For building the docs locally:

```bash
pip install -e ".[docs]"
mkdocs serve
```

## Key Features

- **Full AXL coverage** — All 1,068 AXL WSDL operations wrapped as
  snake_case methods
- **Seven SXML clients** — RISPort, PerfMon, Serviceability, Log Collection,
  PAWS, and Webdialer
- **Fluent builders** — [`PhoneBuilder`](guide/builders.md),
  `SipTrunkBuilder`, `CssBuilder` for complex payloads
- **Typed models** — Auto-generated `TypedDict` classes for every `add_*`
  and `update_*` payload, plus 170 `Enum` types for constrained fields —
  full IDE auto-completion and static type checking
- **Security first** — TLS verification by default, SQL injection protection,
  credential redaction in debug output
- **Session caching** — JSESSIONID reuse for better performance
- **Retry logic** — Automatic exponential back-off on transient errors
- **Backward compatible** — Legacy `AxlToolkit` class names still work
  (with `DeprecationWarning`)

## Requirements

- **Python 3.9+**
- Access to a Cisco UCM server with AXL and/or SXML APIs enabled
- An **AXL-enabled application user** (for AXL operations)
- A **platform admin user** (for PAWS, Serviceability, Log Collection)

## License

Cisco Sample Code License — see the [LICENSE section](https://github.com/pgiralt/axltoolkit#license) in the repository.
