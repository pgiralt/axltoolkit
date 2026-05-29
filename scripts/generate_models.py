#!/usr/bin/env python3
"""Generate Python enums and TypedDict models from AXL XSD schema files.

This script parses the AXL XSD schema (AXLEnums.xsd and AXLSoap.xsd) and
generates two Python modules:

  - ``axltoolkit/_generated_enums.py``  — ``str, Enum`` classes for every
    named enum simpleType.
  - ``axltoolkit/_generated_models.py`` — ``TypedDict`` classes for every
    ``X*`` complexType that appears as a direct child of an ``Add*Req``
    type, plus any nested complex types they reference.

Usage::

    python scripts/generate_models.py [--version 15.0] [--schema-dir axltoolkit/schema]

The generated files are checked into the repository so that users get
autocompletion and type-checking without running the script themselves.
Re-run the script whenever the bundled XSD files are updated.
"""

from __future__ import annotations

import argparse
import keyword
import re
import textwrap
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from lxml import etree

XSD_NS = "{http://www.w3.org/2001/XMLSchema}"
AXL_PREFIX = "axlapi:"


# ── Helpers ─────────────────────────────────────────────────────────


def _strip_axl(type_str: str) -> str:
    """Strip the ``axlapi:`` prefix from a type string."""
    return type_str.replace(AXL_PREFIX, "").replace("xsd:", "")


def _safe_enum_member(value: str) -> str:
    """Convert an enum value string to a valid Python identifier.

    Examples:
        "0dB"            -> "DB_0"
        "-7.5dB"         -> "DB_MINUS_7_5"
        "A-law"          -> "A_LAW"
        "AT&T 54016"     -> "ATT_54016"
        "PRI 5E9"        -> "PRI_5E9"
        "None(Default)"  -> "NONE_DEFAULT"
        ""               -> "EMPTY"
    """
    if not value:
        return "EMPTY"

    s = value
    s = s.replace("&amp;", "AND").replace("&", "AND")
    s = s.replace("µ", "MU").replace("μ", "MU")
    # Strip any remaining non-ASCII characters
    s = s.encode("ascii", "ignore").decode("ascii")
    s = s.replace("(", "_").replace(")", "")
    s = s.replace("/", "_").replace("\\", "_")
    s = s.replace("-", "_").replace(".", "_")
    s = s.replace(" ", "_").replace(",", "_")
    s = s.replace("+", "PLUS").replace("*", "STAR")
    s = s.replace(":", "_").replace(";", "_").replace("'", "").replace('"', "")
    s = s.replace("=", "EQ").replace("<", "LT").replace(">", "GT")
    s = s.replace("@", "AT").replace("#", "NUM")

    # Collapse repeated underscores and strip edges
    s = re.sub(r"_+", "_", s).strip("_")

    # If it starts with a digit, prefix
    if s and s[0].isdigit():
        s = f"V_{s}"

    s = s.upper()

    if not s:
        s = "UNNAMED"

    # Avoid Python keywords
    if keyword.iskeyword(s.lower()) or s.lower() in ("none", "true", "false"):
        s = f"{s}_"

    return s


def _safe_class_name(xsd_name: str) -> str:
    """Convert an XSD type name to a Python class name.

    ``XPhone`` -> ``Phone``,  ``XSipTrunk`` -> ``SipTrunk``.
    Leaves names without leading ``X`` unchanged.
    """
    if xsd_name.startswith("X") and len(xsd_name) > 1 and xsd_name[1].isupper():
        return xsd_name[1:]
    return xsd_name


# ── XSD type → Python type mapping ─────────────────────────────────


# Primitive XSD → Python type strings
_XSD_PRIMITIVES = {
    "string": "str",
    "boolean": "bool",
    "integer": "int",
    "int": "int",
    "long": "int",
    "unsignedLong": "int",
    "unsignedInt": "int",
    "nonNegativeInteger": "int",
    "positiveInteger": "int",
    "short": "int",
    "byte": "int",
    "decimal": "float",
    "float": "float",
    "double": "float",
    "dateTime": "str",
    "date": "str",
    "time": "str",
    "anyType": "Any",
    "anySimpleType": "Any",
}

# axlapi: simple types that are just strings with length constraints
_AXL_STRING_TYPES = {
    "String2", "String16", "String50", "String100", "String128",
    "String255", "String1024", "String2048", "String4096",
    "UniqueString50", "UniqueString128", "UniqueString255",
    "XUUID",
}


# ── Parse enums from AXLEnums.xsd ──────────────────────────────────


def parse_enums(enums_xsd_path: Path) -> Dict[str, List[str]]:
    """Return ``{TypeName: [value1, value2, ...]}`` for each named enum."""
    tree = etree.parse(str(enums_xsd_path))
    root = tree.getroot()
    result: Dict[str, List[str]] = {}
    for st in root.iter(f"{XSD_NS}simpleType"):
        name = st.get("name", "")
        if not name:
            continue
        restriction = st.find(f"{XSD_NS}restriction")
        if restriction is None:
            continue
        enums = restriction.findall(f"{XSD_NS}enumeration")
        if enums:
            result[name] = [e.get("value", "") for e in enums]
    return result


# ── Parse complex types from AXLSoap.xsd ───────────────────────────


class FieldInfo:
    """Metadata for a single element inside a complexType."""

    __slots__ = ("name", "xsd_type", "min_occurs", "max_occurs", "is_choice")

    def __init__(
        self,
        name: str,
        xsd_type: str,
        min_occurs: str = "1",
        max_occurs: str = "1",
        is_choice: bool = False,
    ):
        self.name = name
        self.xsd_type = _strip_axl(xsd_type)
        self.min_occurs = min_occurs
        self.max_occurs = max_occurs
        self.is_choice = is_choice

    @property
    def required(self) -> bool:
        return self.min_occurs == "1" and not self.is_choice

    @property
    def is_list(self) -> bool:
        return self.max_occurs == "unbounded" or (
            self.max_occurs.isdigit() and int(self.max_occurs) > 1
        )


class ComplexTypeInfo:
    """Parsed metadata for an XSD complexType."""

    __slots__ = ("name", "fields", "base_type")

    def __init__(self, name: str, fields: List[FieldInfo], base_type: str = ""):
        self.name = name
        self.fields = fields
        self.base_type = base_type


def _collect_elements(
    container, in_choice: bool = False, parent_optional: bool = False
) -> List[FieldInfo]:
    """Recursively collect element declarations from a sequence/choice/all.

    Args:
        container: The XSD element to collect from.
        in_choice: ``True`` when inside a ``<choice>`` group.
        parent_optional: ``True`` when the enclosing ``<sequence>``/``<all>``
            has ``minOccurs="0"``, meaning *all* children are effectively
            optional even if they individually declare ``minOccurs="1"``.
    """
    fields: List[FieldInfo] = []
    for child in container:
        tag = etree.QName(child.tag).localname if isinstance(child.tag, str) else ""
        if tag == "element":
            name = child.get("name", "")
            xsd_type = child.get("type", "")
            min_occ = child.get("minOccurs", "1" if not in_choice else "0")
            max_occ = child.get("maxOccurs", "1")
            if parent_optional:
                min_occ = "0"
            if name:
                fields.append(
                    FieldInfo(name, xsd_type, min_occ, max_occ, is_choice=in_choice)
                )
            # Inline anonymous complex types — skip for now (rare)
        elif tag == "choice":
            fields.extend(
                _collect_elements(child, in_choice=True, parent_optional=parent_optional)
            )
        elif tag in ("sequence", "all"):
            seq_optional = parent_optional or child.get("minOccurs", "1") == "0"
            fields.extend(
                _collect_elements(child, in_choice=in_choice, parent_optional=seq_optional)
            )
    return fields


def parse_complex_types(soap_xsd_path: Path) -> Dict[str, ComplexTypeInfo]:
    """Return ``{TypeName: ComplexTypeInfo}`` for every complexType."""
    tree = etree.parse(str(soap_xsd_path))
    root = tree.getroot()
    result: Dict[str, ComplexTypeInfo] = {}
    for ct in root.iter(f"{XSD_NS}complexType"):
        name = ct.get("name", "")
        if not name:
            continue
        # Check for direct complexContent/extension (inheritance)
        cc = ct.find(f"{XSD_NS}complexContent")
        ext = cc.find(f"{XSD_NS}extension") if cc is not None else None
        base_type = ""
        if ext is not None:
            base_type = _strip_axl(ext.get("base", ""))
            fields = _collect_elements(ext)
        else:
            fields = _collect_elements(ct)
        result[name] = ComplexTypeInfo(name, fields, base_type)
    return result


def discover_add_req_models(
    complex_types: Dict[str, ComplexTypeInfo],
) -> Dict[str, str]:
    """Return ``{XTypeName: AddMethodDescription}`` for types used in Add*Req.

    For example ``AddPhoneReq`` wraps ``XPhone``, so we return
    ``{"XPhone": "add_phone"}``.
    """
    mapping: Dict[str, str] = {}
    for ct_name, ct_info in complex_types.items():
        if ct_name.startswith("Add") and ct_name.endswith("Req"):
            # The Add*Req type typically has one element whose type is X* or R*
            for field in ct_info.fields:
                if (field.xsd_type.startswith("X") or field.xsd_type.startswith("R")) and field.xsd_type in complex_types:
                    # Derive method name: AddPhoneReq -> add_phone
                    mid = ct_name[3:-3]  # strip "Add" and "Req"
                    method = "add_" + re.sub(r"(?<=[a-z])(?=[A-Z])", "_", mid).lower()
                    mapping[field.xsd_type] = method
    return mapping


def discover_update_req_models(
    complex_types: Dict[str, ComplexTypeInfo],
) -> Dict[str, Tuple[str, List[FieldInfo]]]:
    """Return ``{UpdateClassName: (method_name, fields)}`` for ``Update*Req`` types.

    Fields include inherited identification fields (``name``/``uuid``) from
    ``NameAndGUIDRequest`` when applicable.
    """
    mapping: Dict[str, Tuple[str, List[FieldInfo]]] = {}
    for ct_name, ct_info in complex_types.items():
        if not (ct_name.startswith("Update") and ct_name.endswith("Req")):
            continue
        class_name = ct_name[:-3]  # UpdatePhoneReq -> UpdatePhone
        mid = ct_name[6:-3]       # Phone
        method = "update_" + re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", mid).lower()

        fields: List[FieldInfo] = []
        # Prepend inherited name/uuid for NameAndGUIDRequest-based types
        if ct_info.base_type == "NameAndGUIDRequest":
            fields.append(FieldInfo("name", "string", min_occurs="0", is_choice=True))
            fields.append(FieldInfo("uuid", "string", min_occurs="0", is_choice=True))

        fields.extend(ct_info.fields)
        mapping[class_name] = (method, fields)

    return mapping


# ── Code generation ─────────────────────────────────────────────────


def generate_enums_module(enums: Dict[str, List[str]]) -> str:
    """Generate the full Python source for the enums module."""
    lines: List[str] = []
    lines.append('"""')
    lines.append("Auto-generated AXL enum types.")
    lines.append("")
    lines.append("DO NOT EDIT — regenerate with ``python scripts/generate_models.py``.")
    lines.append('"""')
    lines.append("")
    lines.append("from __future__ import annotations")
    lines.append("")
    lines.append("from enum import Enum")
    lines.append("")
    lines.append("")
    # Emit a private base class that preserves the pre-Python-3.11
    # str-mixin behavior. Without this override, ``str(MyEnum.X)``
    # returns ``"MyEnum.X"`` on Python 3.11+, which corrupts SOAP
    # serialization (zeep stringifies enum values when emitting XML
    # element text). The override forces serialization to the raw value
    # string on every supported Python version.
    lines.append("class _AxlStrEnum(str, Enum):")
    lines.append('    """Base class for AXL string enums.')
    lines.append("")
    lines.append("    Overrides ``__str__`` to return the value rather than the")
    lines.append("    ``<ClassName>.<MEMBER>`` qualified name that Python 3.11+")
    lines.append("    introduced for ``(str, Enum)`` mix-ins. This keeps SOAP")
    lines.append("    serialization stable across Python 3.10 → 3.13 (and beyond).")
    lines.append('    """')
    lines.append("")
    lines.append("    def __str__(self) -> str:  # noqa: D401 - simple delegation")
    lines.append('        """Return the enum\'s value (the XML wire format)."""')
    lines.append("        return str(self.value)")
    lines.append("")
    lines.append("")

    # Enum classes that expose UCM configuration options selecting
    # cryptographically weak algorithms. We surface them (UCM exposes
    # them in the schema, so users must be able to *read* existing
    # configurations) but call out the insecure values in the class
    # docstring so anyone selecting a new value sees the guidance.
    _INSECURE_ALGO_NOTES = {
        "XSNMPAuthenticationProtocol": (
            "SNMP v3 authentication protocol. ``MD5`` is cryptographically"
            " broken and must not be selected for new configurations —"
            " choose ``SHA`` instead."
        ),
        "XSNMPPrivacyProtocol": (
            "SNMP v3 privacy (encryption) protocol. ``DES`` is broken and"
            " must not be selected for new configurations — choose"
            " ``AES_128`` instead."
        ),
    }

    for type_name in sorted(enums):
        values = enums[type_name]
        class_name = _safe_class_name(type_name)
        lines.append(f"class {class_name}(_AxlStrEnum):")
        lines.append(f'    """AXL enum — ``{type_name}``.')
        note = _INSECURE_ALGO_NOTES.get(type_name)
        if note:
            lines.append("")
            lines.append(f"    .. warning::")
            lines.append(f"       {note}")
        lines.append('    """')
        lines.append("")

        # Track used member names to avoid duplicates
        used: Set[str] = set()
        for val in values:
            member = _safe_enum_member(val)
            orig = member
            counter = 2
            while member in used:
                member = f"{orig}_{counter}"
                counter += 1
            used.add(member)
            # Use repr for the value string to handle special chars
            lines.append(f"    {member} = {val!r}")
        lines.append("")
        lines.append("")

    return "\n".join(lines)


def _python_type_for_field(
    field: FieldInfo,
    enums: Dict[str, List[str]],
    complex_types: Dict[str, ComplexTypeInfo],
    models_to_emit: Set[str],
) -> str:
    """Resolve an XSD type to a Python type annotation string."""
    xsd_type = field.xsd_type

    # xsd primitives
    if xsd_type in _XSD_PRIMITIVES:
        py = _XSD_PRIMITIVES[xsd_type]
    # AXL string types
    elif xsd_type in _AXL_STRING_TYPES:
        py = "str"
    # AXL boolean type
    elif xsd_type == "boolean":
        py = "bool"
    # Enum reference
    elif xsd_type in enums:
        py = f'"{_safe_class_name(xsd_type)}"'
    # Foreign key reference (XFkType) — these are name strings or UUIDs
    elif xsd_type in ("XFkType",):
        py = "str"
    # Nested complex type
    elif xsd_type in complex_types:
        models_to_emit.add(xsd_type)
        py = f'"{_safe_class_name(xsd_type)}"'
    # Fallback
    else:
        py = "Any"

    if field.is_list:
        py = f"List[{py}]"

    return py


def generate_models_module(
    enums: Dict[str, List[str]],
    complex_types: Dict[str, ComplexTypeInfo],
    add_req_map: Dict[str, str],
    update_req_map: Optional[Dict[str, Tuple[str, List[FieldInfo]]]] = None,
) -> str:
    """Generate the full Python source for the TypedDict models module."""
    if update_req_map is None:
        update_req_map = {}

    # Determine which complex types to emit: those in add_req_map + their deps
    models_to_emit: Set[str] = set(add_req_map.keys())

    # Also include complex types referenced by update model fields
    for _class_name, (_method, fields) in update_req_map.items():
        for field in fields:
            if field.xsd_type in complex_types:
                models_to_emit.add(field.xsd_type)

    # Iteratively resolve nested dependencies
    resolved: Set[str] = set()
    while models_to_emit - resolved:
        for ct_name in list(models_to_emit - resolved):
            resolved.add(ct_name)
            if ct_name not in complex_types:
                continue
            ct = complex_types[ct_name]
            for field in ct.fields:
                if field.xsd_type in complex_types and field.xsd_type not in resolved:
                    models_to_emit.add(field.xsd_type)

    # Build dependency graph for emission order (simple topological sort)
    emitted: Set[str] = set()
    ordered: List[str] = []

    def _visit(name: str) -> None:
        if name in emitted or name not in complex_types:
            return
        ct = complex_types[name]
        for field in ct.fields:
            if field.xsd_type in models_to_emit and field.xsd_type != name:
                _visit(field.xsd_type)
        emitted.add(name)
        ordered.append(name)

    for name in sorted(models_to_emit):
        _visit(name)

    # Generate code
    lines: List[str] = []
    lines.append('"""')
    lines.append("Auto-generated AXL TypedDict models for ``add_*`` and ``update_*`` method payloads.")
    lines.append("")
    lines.append("DO NOT EDIT — regenerate with ``python scripts/generate_models.py``.")
    lines.append("")
    lines.append("These TypedDict classes document the fields accepted by each")
    lines.append("``add_*`` and ``update_*`` method. Required fields are annotated")
    lines.append("explicitly. Enum-typed fields accept both the enum member and a")
    lines.append("plain string.")
    lines.append('"""')
    lines.append("")
    lines.append("import sys")
    lines.append("from typing import Any, Dict, List, Optional, Sequence, Union")
    lines.append("")
    lines.append("if sys.version_info >= (3, 11):")
    lines.append("    from typing import NotRequired, Required, TypedDict")
    lines.append("else:")
    lines.append("    from typing_extensions import NotRequired, Required, TypedDict")
    lines.append("")
    lines.append("")

    # Track deps that need forward ref
    dummy_set: Set[str] = set()

    _PYTHON_RESERVED = set(keyword.kwlist) | {"match", "case", "type"}

    for ct_name in ordered:
        if ct_name not in complex_types:
            continue
        ct = complex_types[ct_name]
        class_name = _safe_class_name(ct_name)
        method_name = add_req_map.get(ct_name, "")
        docstring_extra = f"  Used by ``AXLClient.{method_name}()``." if method_name else ""

        # Check if any field names are Python reserved words
        has_reserved = any(f.name in _PYTHON_RESERVED for f in ct.fields)

        if has_reserved:
            # Use functional TypedDict form which supports arbitrary string keys
            field_entries: List[str] = []
            for field in ct.fields:
                py_type = _python_type_for_field(field, enums, complex_types, dummy_set)
                if field.required:
                    annotation = f"Required[{py_type}]"
                else:
                    annotation = f"NotRequired[{py_type}]"
                field_entries.append(f'    "{field.name}": {annotation},')

            docstring = f'"""AXL model — ``{ct_name}``.'
            if docstring_extra:
                docstring += f"\n\n   {docstring_extra}"
            docstring += '"""'

            lines.append(f"{class_name} = TypedDict(\"{class_name}\", {{")
            for entry in field_entries:
                lines.append(entry)
            lines.append("}, total=False)")
            lines.append(f"{class_name}.__doc__ = {docstring!r}")
        else:
            lines.append(f"class {class_name}(TypedDict, total=False):")
            lines.append(f'    """AXL model — ``{ct_name}``.')
            if docstring_extra:
                lines.append("")
                lines.append(f"   {docstring_extra}")
            lines.append('    """')
            lines.append("")

            if not ct.fields:
                lines.append("    pass")
                lines.append("")
                lines.append("")
                continue

            for field in ct.fields:
                py_type = _python_type_for_field(field, enums, complex_types, dummy_set)

                if field.required:
                    annotation = f"Required[{py_type}]"
                else:
                    annotation = f"NotRequired[{py_type}]"

                lines.append(f"    {field.name}: {annotation}")

        lines.append("")
        lines.append("")

    # ── Update models ────────────────────────────────────────────────
    if update_req_map:
        lines.append("")
        lines.append("# ═══════════════════════════════════════════════════════════════════")
        lines.append("#  Update models — used with Unpack for update_* method kwargs")
        lines.append("# ═══════════════════════════════════════════════════════════════════")
        lines.append("")
        lines.append("")

        for class_name in sorted(update_req_map):
            method, fields = update_req_map[class_name]
            xsd_name = class_name + "Req"

            has_reserved = any(f.name in _PYTHON_RESERVED for f in fields)

            if has_reserved:
                field_entries_u: List[str] = []
                for field in fields:
                    py_type = _python_type_for_field(
                        field, enums, complex_types, dummy_set
                    )
                    field_entries_u.append(f'    "{field.name}": {py_type},')

                docstring_u = f'"""AXL update model — ``{xsd_name}``.\n\n   Used by ``AXLClient.{method}()``."""'
                lines.append(f'{class_name} = TypedDict("{class_name}", {{')
                for entry in field_entries_u:
                    lines.append(entry)
                lines.append("}, total=False)")
                lines.append(f"{class_name}.__doc__ = {docstring_u!r}")
            else:
                lines.append(f"class {class_name}(TypedDict, total=False):")
                lines.append(f'    """AXL update model — ``{xsd_name}``.')
                lines.append(f"")
                lines.append(f'     Used by ``AXLClient.{method}()``.')
                lines.append('    """')
                lines.append("")

                if not fields:
                    lines.append("    pass")
                else:
                    for field in fields:
                        py_type = _python_type_for_field(
                            field, enums, complex_types, dummy_set
                        )
                        lines.append(f"    {field.name}: {py_type}")

            lines.append("")
            lines.append("")

    return "\n".join(lines)


# ── Markdown docs generation ────────────────────────────────────────


def _linked_type(
    field: FieldInfo,
    enums: Dict[str, List[str]],
    complex_types: Dict[str, ComplexTypeInfo],
    models_to_emit: Set[str],
    referenced_enums: Set[str],
) -> str:
    """Return a Markdown string for the field type with in-page anchor links.

    Enum types link to ``#enum-ClassName``, model types link to
    ``#ClassName``.  Primitives are rendered as plain code.
    """
    xsd_type = field.xsd_type
    if xsd_type in _XSD_PRIMITIVES:
        py = _XSD_PRIMITIVES[xsd_type]
    elif xsd_type in _AXL_STRING_TYPES:
        py = "str"
    elif xsd_type == "boolean":
        py = "bool"
    elif xsd_type in enums:
        cls = _safe_class_name(xsd_type)
        referenced_enums.add(xsd_type)
        py = f"[{cls}](#{cls})"
    elif xsd_type in ("XFkType",):
        py = "str"
    elif xsd_type in complex_types and xsd_type in models_to_emit:
        cls = _safe_class_name(xsd_type)
        py = f"[{cls}](#{cls})"
    elif xsd_type in complex_types:
        py = _safe_class_name(xsd_type)
    else:
        py = "Any"
    if field.is_list:
        py = f"List[{py}]"
    return py


def generate_models_markdown(
    enums: Dict[str, List[str]],
    complex_types: Dict[str, ComplexTypeInfo],
    add_req_map: Dict[str, str],
    update_req_map: Dict[str, Tuple[str, List[FieldInfo]]],
    ordered_add: List[str],
    models_to_emit: Set[str],
) -> str:
    """Generate a Markdown reference page documenting every generated model."""
    referenced_enums: Set[str] = set()

    md: List[str] = []
    md.append("# Models Reference")
    md.append("")

    # ── Add models ───────────────────────────────────────────────────
    md.append("## Add Models")
    md.append("")
    md.append("Types used as the data parameter for `add_*` methods.")
    md.append("Fields marked **Required** must be present; others are optional.")
    md.append("")

    for ct_name in ordered_add:
        if ct_name not in complex_types:
            continue
        ct = complex_types[ct_name]
        class_name = _safe_class_name(ct_name)
        method_name = add_req_map.get(ct_name, "")

        md.append(f"### {class_name} {{ #{class_name} }}")
        md.append("")
        if method_name:
            md.append(f"Used by AXLClient.{method_name}().")
            md.append("")

        if not ct.fields:
            md.append("*No fields.*")
            md.append("")
            continue

        md.append("| Field | Type | Required |")
        md.append("|-------|------|:--------:|")
        for field in ct.fields:
            ftype = _linked_type(field, enums, complex_types, models_to_emit, referenced_enums)
            req = "✅" if field.required else ""
            md.append(f"| {field.name} | {ftype} | {req} |")
        md.append("")

    # ── Dependency models (not top-level add models) ─────────────────
    dep_models = sorted(
        models_to_emit - set(add_req_map.keys()),
        key=lambda k: _safe_class_name(k),
    )
    if dep_models:
        md.append("## Supporting Models")
        md.append("")
        md.append("Nested types referenced by the Add and Update models above.")
        md.append("")

        for ct_name in dep_models:
            if ct_name not in complex_types:
                continue
            ct = complex_types[ct_name]
            class_name = _safe_class_name(ct_name)

            md.append(f"### {class_name} {{ #{class_name} }}")
            md.append("")

            if not ct.fields:
                md.append("*No fields.*")
                md.append("")
                continue

            md.append("| Field | Type | Required |")
            md.append("|-------|------|:--------:|")
            for field in ct.fields:
                ftype = _linked_type(field, enums, complex_types, models_to_emit, referenced_enums)
                req = "✅" if field.required else ""
                md.append(f"| {field.name} | {ftype} | {req} |")
            md.append("")

    # ── Update models ────────────────────────────────────────────────
    md.append("## Update Models")
    md.append("")
    md.append("Types used with `Unpack` for `update_*` method `**kwargs`.")
    md.append("All fields are optional — only send the fields you want to change.")
    md.append("")

    for class_name in sorted(update_req_map):
        method, fields = update_req_map[class_name]

        md.append(f"### {class_name} {{ #{class_name} }}")
        md.append("")
        md.append(f"Used by AXLClient.{method}().")
        md.append("")

        if not fields:
            md.append("*No fields.*")
            md.append("")
            continue

        md.append("| Field | Type |")
        md.append("|-------|------|")
        for field in fields:
            ftype = _linked_type(field, enums, complex_types, models_to_emit, referenced_enums)
            md.append(f"| {field.name} | {ftype} |")
        md.append("")

    # ── Referenced enums ─────────────────────────────────────────────
    if referenced_enums:
        md.append("## Enums")
        md.append("")
        md.append("Enum types referenced by the models above.  Values are valid")
        md.append("string literals accepted by the AXL API.")
        md.append("")

        for xsd_name in sorted(referenced_enums, key=lambda k: _safe_class_name(k)):
            cls = _safe_class_name(xsd_name)
            values = enums[xsd_name]
            md.append(f"### {cls} {{ #{cls} }}")
            md.append("")
            md.append(f"{len(values)} valid values.")
            md.append("")
            md.append("??? note \"Show values\"")
            md.append("")
            md.append("    | Value |")
            md.append("    |-------|")
            for v in values:
                md.append(f"    | {v} |")
            md.append("")

    return "\n".join(md)


# ── Main ────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--version", default="15.0",
        help="AXL schema version directory name (default: 15.0)",
    )
    parser.add_argument(
        "--schema-dir", default="axltoolkit/schema",
        help="Path to the schema directory (default: axltoolkit/schema)",
    )
    parser.add_argument(
        "--output-dir", default="axltoolkit",
        help="Output directory for generated modules (default: axltoolkit)",
    )
    args = parser.parse_args()

    schema_base = Path(args.schema_dir) / args.version
    enums_xsd = schema_base / "AXLEnums.xsd"
    soap_xsd = schema_base / "AXLSoap.xsd"

    if not enums_xsd.exists():
        raise FileNotFoundError(f"Enum XSD not found: {enums_xsd}")
    if not soap_xsd.exists():
        raise FileNotFoundError(f"SOAP XSD not found: {soap_xsd}")

    print(f"Parsing enums from {enums_xsd} …")
    enums = parse_enums(enums_xsd)
    print(f"  Found {len(enums)} enum types")

    print(f"Parsing complex types from {soap_xsd} …")
    complex_types = parse_complex_types(soap_xsd)
    print(f"  Found {len(complex_types)} complex types")

    add_req_map = discover_add_req_models(complex_types)
    print(f"  Matched {len(add_req_map)} Add*Req → X* model pairs")

    update_req_map = discover_update_req_models(complex_types)
    print(f"  Matched {len(update_req_map)} Update*Req model pairs")

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Generate enums
    enums_code = generate_enums_module(enums)
    enums_path = output_dir / "_generated_enums.py"
    enums_path.write_text(enums_code, encoding="utf-8")
    print(f"  Wrote {enums_path} ({len(enums)} enum classes)")

    # Generate models
    models_code = generate_models_module(enums, complex_types, add_req_map, update_req_map)
    models_path = output_dir / "_generated_models.py"
    models_path.write_text(models_code, encoding="utf-8")
    print(f"  Wrote {models_path}")

    # Compute the full set of model types that were emitted (for linking)
    models_to_emit: Set[str] = set(add_req_map.keys())
    for _cn, (_m, fields) in update_req_map.items():
        for field in fields:
            if field.xsd_type in complex_types:
                models_to_emit.add(field.xsd_type)
    resolved: Set[str] = set()
    while models_to_emit - resolved:
        for ct_name in list(models_to_emit - resolved):
            resolved.add(ct_name)
            if ct_name not in complex_types:
                continue
            for field in complex_types[ct_name].fields:
                if field.xsd_type in complex_types and field.xsd_type not in resolved:
                    models_to_emit.add(field.xsd_type)

    # Generate markdown reference docs
    ordered_add = sorted(add_req_map.keys(), key=lambda k: _safe_class_name(k))
    docs_md = generate_models_markdown(
        enums, complex_types, add_req_map, update_req_map, ordered_add,
        models_to_emit,
    )
    docs_path = Path("docs/api/models-reference.md")
    docs_path.parent.mkdir(parents=True, exist_ok=True)
    docs_path.write_text(docs_md, encoding="utf-8")
    print(f"  Wrote {docs_path}")

    print("\nDone. You can now import from:")
    print(f"  from axltoolkit._generated_enums import ClockReference, PriProtocol, ...")
    print(f"  from axltoolkit._generated_models import Phone, SipTrunk, ...")


if __name__ == "__main__":
    main()
