# SQL Queries (Thin AXL)

Cisco UCM exposes a subset of its Informix database through the **Thin AXL**
interface.  axltoolkit provides two raw methods and several safe helper
methods for common operations.

## Raw SQL Methods

### Read-Only Queries

```python
result = client.sql_query(
    "SELECT name, description FROM device WHERE name LIKE 'SEP%'"
)

print(f"Found {result['num_rows']} devices")
for row in result.get("rows", []):
    print(row["name"], row["description"])
```

The return dict has the following structure:

| Key | Type | Description |
|-----|------|-------------|
| `num_rows` | `int` | Number of rows returned |
| `query` | `str` | The original SQL string |
| `rows` | `list[dict]` | List of `{column: value}` dicts (only if `num_rows > 0`) |

### DML Statements

```python
result = client.sql_update(
    "UPDATE device SET description='Lab Phone' WHERE name='SEP001122334455'"
)
print(f"Updated {result['rows_updated']} rows")
```

> [!WARNING]
> **SQL Injection Risk** — `sql_query()` and `sql_update()` send the SQL
> string **as-is** to the UCM database.  Never interpolate user-supplied
> values directly into the query string.  Use the sanitization function
> or the helper methods shown below.

## Sanitizing User Input

When building queries from dynamic values, use `_sanitize_sql_value()`:

```python
from axltoolkit.axl import _sanitize_sql_value

device_name = user_input  # untrusted input
safe_name = _sanitize_sql_value(device_name)
result = client.sql_query(f"SELECT pkid FROM device WHERE name='{safe_name}'")
```

This function:

1. **Detects** common SQL injection patterns (`--`, `UNION SELECT`,
   `DROP TABLE`, etc.) and raises `AXLSQLInjectionError`
2. **Escapes** single quotes by doubling them (`'` → `''`)

## Built-in SQL Helpers

These methods handle sanitization automatically, so they are safe to call
with user-supplied values:

### PKID Lookups

```python
# Get a device's PKID
device_pkid = client.sql_get_device_pkid("SEP001122334455")

# Get an end user's PKID
user_pkid = client.sql_get_enduser_pkid("jsmith")

# Get a user group's PKID
group_pkid = client.sql_get_user_group_pkid("Standard CCM End Users")
```

### User-Group Associations

```python
# Associate a user with a group
client.sql_associate_user_to_group("jsmith", "Standard CCM End Users")

# Remove a user from a group
client.sql_remove_user_from_group("jsmith", "Standard CCM End Users")
```

### Device-User Associations

```python
client.sql_associate_device_to_user("jsmith", "SEP001122334455")
```

### Service Parameters

```python
# Read a service parameter
value = client.sql_get_service_parameter(
    "ucm-pub.example.com",
    "Cisco CallManager",
    "ClusterID",
)

# Update a service parameter
client.sql_update_service_parameter(
    "ucm-pub.example.com",
    "Cisco CallManager",
    "ClusterID",
    "StandAloneCluster",
)
```

## Common UCM Tables

Here are some frequently queried tables:

| Table | Description |
|-------|-------------|
| `device` | All devices (phones, trunks, gateways, CTI route points) |
| `numplan` | Directory numbers (lines) |
| `enduser` | End user accounts |
| `applicationuser` | Application user accounts |
| `devicenumplanmap` | Device-to-line associations |
| `enduserdevicemap` | User-to-device associations |
| `routepartition` | Route partitions |
| `callingsearchspace` | Calling search spaces |
| `devicepool` | Device pools |
| `processnode` | Cluster nodes |
| `typemodel` | Device model lookup table |

> [!TIP]
> Use `sql_query("SELECT * FROM device WHERE name='...' ")` to explore
> the column names available for a given table.  The UCM Data Dictionary
> in the Cisco Developer documentation has the full schema reference.
