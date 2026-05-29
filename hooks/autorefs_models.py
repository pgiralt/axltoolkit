"""MkDocs hook — register autorefs anchors for generated model headings.

When mkdocstrings renders a method signature like
``add_phone(phone_data: Phone, ...)``, it creates an autorefs link for
``axltoolkit._generated_models.Phone``.  This hook scans the Generated
Models Reference page for heading anchors and registers them so that those
cross-page links resolve to the correct visible headings instead of
requiring a hidden mkdocstrings rendering pass.
"""

from __future__ import annotations

import re
from typing import Any

# Heading IDs are set via attr_list:  ### `Phone` { #Phone }
# After markdown→HTML they become:  <h3 id="Phone">...</h3>
_HEADING_ID_RE = re.compile(r'<h[23][^>]*\bid="([^"]+)"')

# The generated-models page src_path
_TARGET_PAGE = "api/models-reference.md"

# Modules whose identifiers should be registered
_MODULES = (
    "axltoolkit._generated_models",
    "axltoolkit._generated_enums",
)


def on_page_content(html: str, page: Any, config: Any, files: Any) -> str:
    """After markdown rendering, register heading anchors with autorefs."""
    if page.file.src_path != _TARGET_PAGE:
        return html

    autorefs = config["plugins"].get("autorefs")
    if autorefs is None:
        return html

    for match in _HEADING_ID_RE.finditer(html):
        anchor_id = match.group(1)
        # Skip generic section anchors (e.g. "add-models", "update-models")
        if "-" in anchor_id or anchor_id[0].islower():
            continue
        for module in _MODULES:
            identifier = f"{module}.{anchor_id}"
            autorefs.register_anchor(page.url, identifier, anchor_id)

    return html
