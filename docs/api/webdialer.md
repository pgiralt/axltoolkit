# Webdialer Client

The `WebdialerClient` provides **click-to-call** functionality via the
UCM Webdialer SOAP API — initiate calls, end calls, and query device lines.

## Quick Example

```python
from axltoolkit import WebdialerClient

wd = WebdialerClient(
    username="webdialer_user",
    password="secret",
    server_ip="ucm-pub.example.com",
    tls_verify=True,
)

# Make a call
result = wd.make_call(
    user="jsmith",
    device="SEPAC7E8AB697E8",
    line="1001",
    destination="1002",
)

# End the call
wd.end_call(user="jsmith", device="SEPAC7E8AB697E8", line="1001")
```

## Class Reference

::: axltoolkit.webdialer.WebdialerClient
    options:
      show_root_heading: true
      members_order: source
      filters:
        - "!^_"
