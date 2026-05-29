# AXL Client

The `AXLClient` wraps **all 1,068 AXL WSDL operations** for Cisco UCM
configuration management.  It supports both **Thick AXL** (SOAP-based CRUD)
and **Thin AXL** (direct SQL queries against the UCM Informix database).

Every `get_*`, `add_*`, `update_*`, `remove_*`, `list_*`, `apply_*`,
`reset_*`, and `restart_*` operation in the AXL 15.0 schema has a
corresponding snake_case method.

## Quick Example

```python
from axltoolkit import AXLClient

client = AXLClient(
    username="admin",
    password="secret",
    server_ip="ucm-pub.example.com",
    version="15.0",
    tls_verify=True,
)

# CRUD operations
phone = client.get_phone(name="SEP001122334455")
client.update_phone(name="SEP001122334455", description="Lab Phone")

# SQL query
result = client.sql_query("SELECT name FROM device WHERE name LIKE 'SEP%'")
```

## Class Reference

::: axltoolkit.axl.AXLClient
    options:
      show_root_heading: true
      members_order: source
      filters:
        - "!^_"

## SQL Sanitization

::: axltoolkit.axl._sanitize_sql_value
