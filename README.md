# axltoolkit

A Python toolkit for Cisco Unified Communications Manager (UCM) AXL and SXML APIs.

## Documentation

Full user guide and API reference live in the [`docs/`](docs/) folder
and are designed to be served via MkDocs Material.

### Read the docs locally

The fastest path — clone, install the `docs` extra, and serve:

```bash
pip install -e ".[docs]"
mkdocs serve              # live-reload at http://127.0.0.1:8000
# or, to build a static site:
mkdocs build              # outputs to ./site/
```

### Hosted versions

Two hosting targets are configured but require a one-time setup before
the URLs go live:

- **GitHub Pages — https://pgiralt.github.io/axltoolkit/**
  Built and deployed by [`.github/workflows/docs.yml`](.github/workflows/docs.yml)
  on every push to `master`. Requires a one-time repo settings change:
  *Settings → Pages → Source = "GitHub Actions"*. Each PR also runs a
  build-only sanity check so doc breakage is caught at review time.
- **Read the Docs — https://axltoolkit.readthedocs.io/**
  Configured by [`.readthedocs.yaml`](.readthedocs.yaml). Requires a
  one-time import at [readthedocs.org/dashboard/import](https://readthedocs.org/dashboard/import/)
  — pick this repo from the list and RTD will build on every push.

What's in the docs:

| Section | What you'll find |
|---|---|
| **[Getting Started](docs/getting-started.md)** | Install, first connection, AXL/SXML basics, error handling, type hints |
| **[TLS & Security](docs/guide/security.md)** | TLS verification, CA bundles, envelope redaction, SQL-injection defenses, production checklist |
| **[SQL Queries](docs/guide/sql.md)** | Thin-AXL deep dive, sanitization, built-in helpers, common UCM tables |
| **[Fluent Builders](docs/guide/builders.md)** | `PhoneBuilder`, `SipTrunkBuilder`, `CssBuilder` recipes |
| **[Configuration Recipes](docs/guide/recipes.md)** | End-to-end provisioning workflows (new user + phone, bulk updates, monitoring) |
| **[Local Development](docs/guide/local-development.md)** | `.env` setup, running integration tests against a real UCM, coverage scripts, **publishing to PyPI** |
| **[API Reference](docs/api/axl.md)** | Auto-generated reference for every client class, exception, builder, and TypedDict model |
| **[Migration Guide](docs/migration.md)** | v1 → v2 class/method renames, exception hierarchy, type hints |
| **[Changelog](docs/changelog.md)** | Per-release notes |

## Installation

```bash
pip install .
```

Or for development:

```bash
pip install -e ".[dev]"
```

## Quick Start

```python
from axltoolkit import AXLClient

# Connect to UCM
client = AXLClient(
    username="axladmin",
    password="secret",
    server_ip="ucm-pub.example.com",
    version="15.0",
    tls_verify=True,
)

# Thick AXL — get a user
user = client.get_user(userid="jsmith")
print(user['return']['user']['firstName'])

# Thin AXL — SQL query
result = client.sql_query("SELECT name FROM device WHERE name LIKE 'SEP%'")
for row in result.get('rows', []):
    print(row['name'])

# List phones
phones = client.list_phones(name="SEP%")
for name, info in phones.items():
    print(name, info['description'])
```

## Available Clients

| Client | API | Description |
|--------|-----|-------------|
| `AXLClient` | AXL (Thick + Thin) | Configuration CRUD for phones, users, partitions, CSS, route patterns, SIP trunks, LDAP, and more |
| `RISPortClient` | RISPort70 | Real-time device registration status and CTI information |
| `PerfMonClient` | PerfMon | Performance counter collection (session-based and one-shot) |
| `ServiceabilityClient` | ControlCenter | UCM service management (start, stop, restart, status) |
| `LogCollectionClient` | LogCollection | Log file listing and retrieval |
| `DimeGetFileClient` | DimeGetFile | Direct file retrieval from UCM servers |
| `PAWSClient` | PAWS | Platform info (hardware, version, cluster nodes, options) |
| `WebdialerClient` | Webdialer | Click-to-call functionality |

## AXL Client — Full API Coverage

The `AXLClient` wraps **all 1,068 AXL WSDL operations** with 1,000+ documented, snake_case methods. Every `get`, `add`, `update`, `remove`, `list`, `apply`, `reset`, and `restart` operation in the 15.0 schema is covered.

### Highlights

- **Core Telephony** — Phones, Lines, Users, CSS, Route Partitions
- **Routing** — Route Patterns, Translation Patterns, SIP Route Patterns, Route Groups, Route Lists, Route Filters, Transformation Patterns, Route Plan
- **Hunt** — Line Groups, Hunt Lists, Hunt Pilots
- **Trunks & Gateways** — SIP Trunks, H.323 Gateways/Trunks, Gateways, Gatekeepers, VG224, Cisco Catalyst gateways
- **Infrastructure** — Device Pools, Regions, Locations, Date/Time Groups, SRST, Call Manager Groups, Common Device/Phone Config
- **Media** — Conference Bridges, MRGs, MRGLs, Transcoders, MTPs, MOH Audio Sources, Annunciators, Announcements
- **Profiles & Templates** — SIP Profiles, Phone/Trunk Security Profiles, Device Profiles, Phone Button Templates, Soft Key Templates, Service Profiles, UC Services, Feature Group Templates, Universal Device/Line Templates
- **Users & Security** — End Users, Application Users, User Groups, Credential Policies, LDAP (filters, directories, sync, authentication), CAPF Profiles, Presence Groups
- **Voicemail** — Voicemail Pilots, Profiles, Ports
- **Call Features** — Call Park, Directed Call Park, Call Pickup Groups, Meet Me, CTI Route Points, IVR
- **Mobility** — Remote Destinations, Remote Destination Profiles, Device Mobility, Mobility Profiles
- **VPN / Wireless** — VPN Gateways, Groups, Profiles, WLAN Profiles, WiFi Hotspots
- **System** — Enterprise Parameters, Service Parameters, Process Nodes, SNMP, Smart License, OS Version, Syslog Configuration
- **Device Operations** — `reset_phone()`, `restart_phone()`, `apply_phone()`, `wipe_phone()`, `lock_phone()`, `do_device_login()`, `do_device_logout()`
- **SQL Helpers** — `sql_query()`, `sql_update()`, `sql_get_device_pkid()`, `sql_associate_user_to_group()`, etc.

### Method Naming Convention

All methods follow the pattern `{operation}_{snake_case_object}`:

```python
client.get_phone("SEP001122334455")
client.add_route_partition({"name": "PT_Internal"})
client.update_sip_trunk(name="MySipTrunk", description="Updated")
client.remove_css(name="CSS_Default")
client.list_device_pool(search_criteria={"name": "%"})
client.apply_phone(name="SEP001122334455")
client.reset_sip_trunk(name="MySipTrunk")
client.restart_conference_bridge(name="CFB_1")
```

## Error Handling

All operations raise typed exceptions instead of returning `None`:

```python
from axltoolkit import AXLClient, AXLNotFoundError, AXLError

client = AXLClient(...)

try:
    phone = client.get_phone("SEP001122334455")
except AXLNotFoundError:
    print("Phone not found")
except AXLError as e:
    print(f"AXL error: {e}")
```

## SXML Examples

### RISPort — Registered Phones

```python
from axltoolkit import RISPortClient

ris = RISPortClient(username="admin", password="pw", server_ip="ucm-pub.example.com", tls_verify=True)

# Convenience method
phones = ris.get_registered_phones("SEP*")
for phone in phones:
    print(f"{phone['name']}: {phone['ip_address']}")
```

### PerfMon — Counter Collection

```python
from axltoolkit import PerfMonClient

pm = PerfMonClient(username="admin", password="pw", server_ip="ucm-pub.example.com", tls_verify=True)

session = pm.open_session()
pm.add_counters(session, [r"\\cm-pub\Cisco CallManager\CallsCompleted"])
data = pm.collect_session_data(session)
pm.close_session(session)
print(data)
```

### PAWS — Platform Information

```python
from axltoolkit import PAWSClient

paws = PAWSClient(username="admin", password="pw", server_ip="ucm-pub.example.com", tls_verify=True)
version = paws.get_active_version()
nodes = paws.get_cluster_nodes()
```

## Backward Compatibility

The legacy class names (`AxlToolkit`, `UcmRisPortToolkit`, etc.) are still importable and work with the old constructor signatures. They emit `DeprecationWarning` on instantiation.

```python
# Still works, but deprecated
from axltoolkit import AxlToolkit
axl = AxlToolkit(username="admin", password="pw", server_ip="ucm-pub.example.com",
                 version="12.5", tls_verify=True)
```

## Samples

The `samples/` folder contains example scripts:

- **sample1_axl** — Thick and Thin AXL usage
- **sample2_ris** — RISPort device registration query
- **sample3_perfmon** — PerfMon counter collection
- **sample4_paws** — PAWS version information
- **sample5_certs** — Certificate retrieval and decoding via Thin AXL
  *(requires `pip install asn1crypto`)*
- **sample6_ris_cti** — RISPort CTI item query
- **sample7_axl_registration_dynamic** — Registration dynamic data
- **sample8_webdialer** — Webdialer click-to-call

All samples read UCM credentials from a `.env` file at the repo root
(see [`.env.example`](.env.example) and the
[Local Development guide](docs/guide/local-development.md)).


## License

These terms govern this Cisco Systems, Inc. (“Cisco”), example or demo source code and its associated documentation (together, the “Sample Code”). By downloading, copying, modifying, compiling, or redistributing the Sample Code, you accept and agree to be bound by the following terms and conditions (the “License”). If you are accepting the License on behalf of an entity, you represent that you have the authority to do so (either you or the entity, “you”). Sample Code is not supported by Cisco TAC and is not tested for quality or performance. This is your only license to the Sample Code and all rights not expressly granted are reserved.

1. LICENSE GRANT: Subject to the terms and conditions of this License, Cisco hereby grants to you a perpetual, worldwide, non-exclusive, non-transferable, non-sublicensable, royalty-free license to copy and modify the Sample Code in source code form, and compile and redistribute the Sample Code in binary/object code or other executable forms, in whole or in part, solely for use with Cisco products and services. For interpreted languages like Java and Python, the executable form of the software may include source code and compilation is not required.

2. CONDITIONS: You shall not use the Sample Code independent of, or to replicate or compete with, a Cisco product or service. Cisco products and services are licensed under their own separate terms and you shall not use the Sample Code in any way that violates or is inconsistent with those terms (for more information, please visit: www.cisco.com/go/terms ).

3. OWNERSHIP: Cisco retains sole and exclusive ownership of the Sample Code, including all intellectual property rights therein, except with respect to any third-party material that may be used in or by the Sample Code. Any such third-party material is licensed under its own separate terms (such as an open source license) and all use must be in full accordance with the applicable license. This License does not grant you permission to use any trade names, trademarks, service marks, or product names of Cisco. If you provide any feedback to Cisco regarding the Sample Code, you agree that Cisco, its partners, and its customers shall be free to use and incorporate such feedback into the Sample Code, and Cisco products and services, for any purpose, and without restriction, payment, or additional consideration of any kind. If you initiate or participate in any litigation against Cisco, its partners, or its customers (including cross-claims and counter-claims) alleging that the Sample Code and/or its use infringe any patent, copyright, or other intellectual property right, then all rights granted to you under this License shall terminate immediately without notice.

4. LIMITATION OF LIABILITY: CISCO SHALL HAVE NO LIABILITY IN CONNECTION WITH OR RELATING TO THIS LICENSE OR USE OF THE SAMPLE CODE, FOR DAMAGES OF ANY KIND, INCLUDING BUT NOT LIMITED TO DIRECT, INCIDENTAL, AND CONSEQUENTIAL DAMAGES, OR FOR ANY LOSS OF USE, DATA, INFORMATION, PROFITS, BUSINESS, OR GOODWILL, HOWEVER CAUSED, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.

5. DISCLAIMER OF WARRANTY: SAMPLE CODE IS INTENDED FOR EXAMPLE PURPOSES ONLY AND IS PROVIDED BY CISCO “AS IS” WITH ALL FAULTS AND WITHOUT WARRANTY OR SUPPORT OF ANY KIND. TO THE MAXIMUM EXTENT PERMITTED BY LAW, ALL EXPRESS AND IMPLIED CONDITIONS, REPRESENTATIONS, AND WARRANTIES INCLUDING, WITHOUT LIMITATION, ANY IMPLIED WARRANTY OR CONDITION OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT, SATISFACTORY QUALITY, NON-INTERFERENCE, AND ACCURACY, ARE HEREBY EXCLUDED AND EXPRESSLY DISCLAIMED BY CISCO. CISCO DOES NOT WARRANT THAT THE SAMPLE CODE IS SUITABLE FOR PRODUCTION OR COMMERCIAL USE, WILL OPERATE PROPERLY, IS ACCURATE OR COMPLETE, OR IS WITHOUT ERROR OR DEFECT.

6. GENERAL: This License shall be governed by and interpreted in accordance with the laws of the State of California, excluding its conflict of laws provisions. You agree to comply with all applicable United States export laws, rules, and regulations. If any provision of this License is judged illegal, invalid, or otherwise unenforceable, that provision shall be severed and the rest of the License shall remain in full force and effect. No failure by Cisco to enforce any of its rights related to the Sample Code or to a breach of this License in a particular situation will act as a waiver of such rights. In the event of any inconsistencies with any other terms, this License shall take precedence.

