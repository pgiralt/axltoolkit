# Exceptions

All library exceptions inherit from `AxlToolkitError`, making it easy to
catch any library error with a single `except` clause.

## Hierarchy

```
AxlToolkitError
├── AXLAuthenticationError
├── AXLConnectionError
├── AXLError
│   ├── AXLNotFoundError
│   ├── AXLDuplicateError
│   ├── AXLValidationError
│   └── AXLSQLError
│       └── AXLSQLInjectionError
├── SXMLError
│   ├── RISPortError
│   ├── PerfMonError
│   ├── ServiceabilityError
│   └── LogCollectionError
├── PAWSError
└── WebdialerError
```

## Reference

::: axltoolkit.exceptions
    options:
      show_root_heading: false
      members_order: source
      show_if_no_docstring: true
