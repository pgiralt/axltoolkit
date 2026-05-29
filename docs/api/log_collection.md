# Log Collection

Two clients for retrieving log files and traces from UCM servers.

- **`LogCollectionClient`** — List and select log files via the
  LogCollection SXML API
- **`DimeGetFileClient`** — Download individual files via the
  DimeGetFile SXML API

> [!NOTE]
> Both clients require **platform/OS admin credentials**.

## LogCollectionClient

::: axltoolkit.log_collection.LogCollectionClient
    options:
      show_root_heading: true
      members_order: source
      filters:
        - "!^_"

::: axltoolkit.log_collection.DimeGetFileClient
    options:
      show_root_heading: true
      members_order: source
      filters:
        - "!^_"
