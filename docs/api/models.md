# Typed Models

## AXL Models

`TypedDict` classes for **every** `add_*` and `update_*`
operation, providing complete field coverage.

- **Add models** (e.g. `Phone`, `SipTrunk`, `Line`) — used as the data
  parameter type for `add_*` methods.  Fields are annotated with
  `Required` or `NotRequired`.
- **Update models** (e.g. `UpdatePhone`, `UpdateSipTrunk`) — used with
  `Unpack` for `update_*` method `**kwargs`.  All fields are optional
  since you only send the fields you want to change.

```python
from axltoolkit._generated_models import Phone, UpdatePhone, SipTrunk
```

👉 **[Models Reference](models-reference.md)** — full field-level
documentation for all Add and Update models.

## Enums

`str`/`Enum` classes for constrained AXL fields.  Since they inherit
`str`, enum members serialize naturally into SOAP dicts.

```python
from axltoolkit._generated_enums import ProtocolSide, ClockReference
```

::: axltoolkit._generated_enums
    options:
      show_root_heading: false
      members_order: source
      show_if_no_docstring: true

## Hand-Curated Models

`TypedDict` definitions for common AXL objects.  These provide **IDE
autocompletion** and document expected fields for the most commonly used
AXL object types.

> [!IMPORTANT]
> These types are for annotation and documentation only — they are not
> enforced at runtime.  AXL responses may include additional fields not
> listed here.

::: axltoolkit.models
    options:
      show_root_heading: false
      members_order: source
      show_if_no_docstring: true
