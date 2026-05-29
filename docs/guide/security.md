# TLS & Security

This guide covers the security features built into axltoolkit and best
practices for production deployments. The library is designed to be
**secure by default** — TLS verification on, DTDs forbidden, SQL
injection sanitization, plaintext-secret redaction in debug output, and
HTTPS-only retries.

## TLS Certificate Verification

All axltoolkit clients communicate over **HTTPS** (port 8443) and
verify the server's TLS certificate by default.

### Using the System Trust Store

If your UCM certificate is signed by a CA already in your OS trust
store, no extra configuration is needed:

```python
client = AXLClient(
    username="admin",
    password="secret",
    server_ip="ucm-pub.example.com",
    tls_verify=True,          # this is the default
)
```

### Custom CA Bundle

If UCM uses a private CA (common in enterprise deployments), export
the CA certificate chain to a PEM file and pass the path:

```python
client = AXLClient(
    username="admin",
    password="secret",
    server_ip="ucm-pub.example.com",
    tls_verify="/etc/ssl/certs/ucm-ca-chain.pem",
)
```

> [!TIP]
> **Exporting the UCM CA Certificate** — in
> **Cisco Unified OS Administration**, navigate to
> **Security > Certificate Management** and download the
> `tomcat-trust` certificate chain. Save it as a PEM file.

### Disabling Verification (Development Only)

```python
client = AXLClient(..., tls_verify=False)
```

> [!CAUTION]
> Disabling TLS verification makes the connection vulnerable to
> man-in-the-middle attacks. Credentials are sent as HTTP Basic Auth,
> so an attacker could intercept usernames and passwords. **Never**
> use `tls_verify=False` in production.

### Using FQDNs Instead of IP Addresses

Certificate validation checks that the server's certificate matches the
hostname you connect to. Most UCM certificates are issued for the
server's **FQDN**, not its IP address. Always use the FQDN:

```python
# Good — FQDN matches the certificate's CN/SAN
client = AXLClient(..., server_ip="ucm-pub.example.com")

# May fail — IP address won't match the certificate
client = AXLClient(..., server_ip="10.0.0.1")
```

## Credential Management

### Never Hard-code Credentials

Use environment variables, a secrets manager, or a `.env` file
(excluded from version control). The repository ships an `.env.example`
template — see the [Local Development guide](local-development.md) for
the full workflow:

```python
import os
from axltoolkit import AXLClient

client = AXLClient(
    username=os.environ["UCM_USERNAME"],
    password=os.environ["UCM_PASSWORD"],
    server_ip=os.environ["UCM_ADDRESS"],
    tls_verify=True,
)
```

### Debug Output Redaction

`last_request_debug()` returns the headers and SOAP envelopes of the
most recent request/response. The library redacts secrets at **two
layers** before returning them:

1. **HTTP header redaction** — `Authorization`, `Cookie`, and
   `Set-Cookie` headers are replaced with `[REDACTED]`.
2. **XML envelope redaction** — every element whose local name matches
   a known-secret keyword (`<password>`, `<token>`, `<apiKey>`,
   `<ldapPassword>`, `<snmpPassword>`, `<authProtocolPassword>`,
   `<privProtocolPassword>`, etc.) has its text content replaced with
   `[REDACTED]`. The match is case-insensitive on the local name only,
   so namespace prefixes don't matter.

```python
debug = client.last_request_debug()
print(debug["request"]["headers"])
# {'Authorization': '[REDACTED]', 'Content-Type': 'text/xml', ...}

print(debug["request"]["envelope"].decode())
# ... <ns0:password>[REDACTED]</ns0:password> ...
```

> [!WARNING]
> Redaction is **best-effort** based on a known list of element local
> names (see `axltoolkit._base._REDACT_LOCAL_NAMES`). If you add new
> AXL operations whose payloads carry secrets under unfamiliar
> element names, extend the set or treat any logged envelope as
> sensitive.

## SQL Injection Protection

The Thin AXL methods `sql_query()` and `sql_update()` pass SQL directly
to the UCM Informix database. The library provides two layers of
defense:

### 1. Pattern Detection

A regex pattern detects common SQL injection fragments (`--`, `;`,
`/*`, `xp_`, `EXEC`, `DROP TABLE`, `ALTER TABLE`, `INSERT INTO ...
SELECT`, `UNION SELECT`, etc.) and raises `AXLSQLInjectionError`
**before** the query is ever sent to the database:

```python
from axltoolkit.axl import _sanitize_sql_value

_sanitize_sql_value("admin'; DROP TABLE device --")
# Raises: AXLSQLInjectionError
```

### 2. Single-Quote Escaping

Once the value passes the pattern check, single quotes are escaped by
doubling them (`'` → `''`), which is the standard escaping mechanism
for the Informix SQL dialect used by UCM.

### Safe Helpers

The built-in SQL helper methods handle sanitization automatically, so
they are safe to call with user-supplied values:

```python
pkid = client.sql_get_device_pkid("SEP001122334455")
client.sql_associate_device_to_user("jsmith", "SEP001122334455")
client.sql_associate_user_to_group("jsmith", "Standard CCM End Users")
```

> [!WARNING]
> **Defense-in-depth, not a silver bullet** — `_sanitize_sql_value()` is
> a **denylist** of common injection patterns plus quote-doubling — it
> is not a parameterized prepared statement (the AXL `executeSQLQuery`
> operation doesn't support those). When you build raw SQL for
> `sql_query()` or `sql_update()`, you are still responsible for:
>
> 1. Passing every dynamic value through `_sanitize_sql_value()`.
> 2. Authorizing the caller at the application layer (a user with
>    AXL access can already read or modify any column).

## XML Hardening

`zeep` is configured with `forbid_dtd=True` and `strict=False`, which
disables Document Type Declaration processing entirely. Combined with
the defaults in modern `lxml`, this blocks:

- **XXE (XML eXternal Entity) injection** — external entity references
  cannot be resolved.
- **Billion Laughs / entity expansion DoS** — DTD-defined entities are
  rejected outright.
- **DTD-based parameter entity attacks** — incoming responses that
  declare a DOCTYPE are rejected.

```python
from zeep import Settings
# In axltoolkit/_base.py:
settings = Settings(strict=False, forbid_dtd=True)
```

You don't need to configure anything — these settings are applied to
every client automatically.

## Server IP Validation

The `server_ip` parameter is validated at construction time. Only
valid hostnames, FQDNs, and IPv4/IPv6 addresses are accepted, which
prevents URL-injection style attacks (SSRF, path traversal, query-
string smuggling) on the constructed endpoint URL:

```python
# Valid
AXLClient(..., server_ip="ucm-pub.example.com")
AXLClient(..., server_ip="10.0.0.1")
AXLClient(..., server_ip="2001:db8::1")

# Raises ValueError
AXLClient(..., server_ip="evil.com/foo#bar")
AXLClient(..., server_ip="ucm.example.com:8443/admin")
```

## Retry Logic

All clients use automatic retry with exponential back-off for transient
HTTP errors (502, 503, 504):

```python
client = AXLClient(
    ...,
    max_retries=3,     # default: 3 retries
    timeout=30,        # default: 30 seconds
)
```

Retries are mounted **only** for the `https://` prefix — there is no
HTTP fallback adapter, so an accidental `http://` URL fails fast
instead of silently downgrading to plaintext.

## Session Recovery (RISPort)

`RISPortClient` automatically recovers from session staleness. When
UCM returns `Error Code = 7` (*"Cisco RISDC needs SOAP clients to
start a new session"*), the client:

1. Clears the cached `JSESSIONID` cookie.
2. Re-binds the zeep service proxy.
3. Retries the operation **once**.

This is transparent to callers. If the retry also fails, the original
fault is raised as `RISPortError`. It is especially relevant in
long-running scripts or test suites where the RIS session may expire
between calls.

## SNMP Algorithm Selection

The generated enums `SNMPAuthenticationProtocol` and
`SNMPPrivacyProtocol` include warning docstrings advising against
legacy values:

| Enum | Avoid | Prefer |
|------|-------|--------|
| `SNMPAuthenticationProtocol` | `MD5` (broken) | `SHA` |
| `SNMPPrivacyProtocol` | `DES` (broken) | `AES128`, `AES192`, `AES256` |

```python
from axltoolkit._generated_enums import (
    SNMPAuthenticationProtocol,
    SNMPPrivacyProtocol,
)

# Recommended
auth = SNMPAuthenticationProtocol.SHA
priv = SNMPPrivacyProtocol.AES256
```

## WSDL Cache

Zeep caches parsed WSDL files in an SQLite database under
`~/.cache/axltoolkit/` with **owner-only** permissions (`0700`). This
prevents other local users from tampering with cached WSDLs.

## Dependency Vulnerability Scanning

The CI workflow runs `pip-audit --strict --desc` on every push. It
fails the build if any installed dependency carries a known CVE. To
reproduce the scan locally:

```bash
pip install pip-audit
pip-audit --strict --desc
```

## Production Checklist

Before shipping any code that uses axltoolkit to production, verify:

- [ ] **`tls_verify=True`** (or a path to a private CA bundle) — never
      `False`.
- [ ] **`server_ip`** is the UCM **FQDN**, not an IP — required for
      certificate validation to match.
- [ ] **Credentials** come from a secrets manager / environment / vault
      — not from source code, config files in Git, or shell history.
- [ ] The application user has only the **AXL roles it needs** — not
      Standard CCM Super Users.
- [ ] **`last_request_debug()`** output is only logged to a destination
      you treat as sensitive — even with redaction, response payloads
      can carry PII (extensions, names, MAC addresses).
- [ ] **Raw SQL** built from external input is run through
      `_sanitize_sql_value()` (or use a `sql_*` helper that does it for
      you).
- [ ] **SNMP profiles** use `SHA` + AES, never `MD5` or `DES`.
- [ ] **Dependencies** were installed from `pyproject.toml` (which pins
      modern `zeep>=4.2.1`, `lxml>=4.9.0`, `urllib3>=2`), not from any
      legacy `requirements.txt`.
- [ ] **`pip-audit --strict`** passes against your final lockfile.
