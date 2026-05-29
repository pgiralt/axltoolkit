# PerfMon Client

The `PerfMonClient` provides performance counter collection from UCM
servers via the **PerfMon** SXML API.  Counters can be collected in
**session-based** mode (open → add → collect → close) or via **one-shot**
queries.

## Quick Example

```python
from axltoolkit import PerfMonClient

pm = PerfMonClient(
    username="admin",
    password="secret",
    server_ip="ucm-pub.example.com",
    tls_verify=True,
)

session = pm.open_session()
pm.add_counters(session, [r"\\cm-pub\Cisco CallManager\CallsCompleted"])
data = pm.collect_session_data(session)
pm.close_session(session)
```

## Class Reference

::: axltoolkit.perfmon.PerfMonClient
    options:
      show_root_heading: true
      members_order: source
      filters:
        - "!^_"
