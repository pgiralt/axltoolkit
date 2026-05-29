"""
axltoolkit — Python toolkit for Cisco UCM AXL and SXML APIs.

New-style clients (recommended)::

    from axltoolkit import AXLClient, RISPortClient, PerfMonClient

Legacy class names are still available for backward compatibility::

    from axltoolkit import AxlToolkit, UcmRisPortToolkit  # deprecated
"""

from __future__ import annotations

# ── New public API ─────────────────────────────────────────────────────
from .axl import AXLClient
from .risport import RISPortClient
from .perfmon import PerfMonClient
from .serviceability import ServiceabilityClient
from .log_collection import DimeGetFileClient, LogCollectionClient
from .paws_client import PAWSClient
from .webdialer import WebdialerClient

# ── Builders ──────────────────────────────────────────────────────────
from .builders import CssBuilder, PhoneBuilder, SipTrunkBuilder

# ── Generated enums & models (from AXL XSD) ─────────────────────────
from . import _generated_enums as axl_enums     # noqa: F401 — submodule access
from . import _generated_models as axl_models   # noqa: F401 — submodule access

# ── Typed models (hand-curated) ──────────────────────────────────────
from .models import (
    CssData,
    CssMember,
    DevicePoolData,
    GatewayData,
    H323TrunkData,
    HuntListData,
    HuntPilotData,
    LineAssociation,
    LineData,
    LineGroupData,
    LocationData,
    PhoneData,
    RegionData,
    RegisteredPhone,
    RoutePartitionData,
    RoutePatternData,
    SipTrunkData,
    SipTrunkDestination,
    SQLQueryResult,
    SQLUpdateResult,
    TranslationPatternData,
    UserData,
)

# ── Exception hierarchy ────────────────────────────────────────────────
from .exceptions import (
    AxlToolkitError,
    AXLAuthenticationError,
    AXLConnectionError,
    AXLDuplicateError,
    AXLError,
    AXLNotFoundError,
    AXLSQLError,
    AXLSQLInjectionError,
    AXLValidationError,
    LogCollectionError,
    PAWSError,
    PerfMonError,
    RISPortError,
    SXMLError,
    ServiceabilityError,
    WebdialerError,
)

# ── Backward-compatible aliases (deprecated) ──────────────────────────
from ._compat import (
    AxlToolkit,
    PawsToolkit,
    UcmDimeGetFileToolkit,
    UcmLogCollectionToolkit,
    UcmPerfMonToolkit,
    UcmRisPortToolkit,
    UcmServiceabilityToolkit,
    WebdialerToolkit,
)

__all__ = [
    # New clients
    "AXLClient",
    "RISPortClient",
    "PerfMonClient",
    "ServiceabilityClient",
    "LogCollectionClient",
    "DimeGetFileClient",
    "PAWSClient",
    "WebdialerClient",
    # Generated enums & models
    "axl_enums",
    "axl_models",
    # Builders
    "CssBuilder",
    "PhoneBuilder",
    "SipTrunkBuilder",
    # Typed models
    "CssData",
    "CssMember",
    "DevicePoolData",
    "GatewayData",
    "H323TrunkData",
    "HuntListData",
    "HuntPilotData",
    "LineAssociation",
    "LineData",
    "LineGroupData",
    "LocationData",
    "PhoneData",
    "RegionData",
    "RegisteredPhone",
    "RoutePartitionData",
    "RoutePatternData",
    "SipTrunkData",
    "SipTrunkDestination",
    "SQLQueryResult",
    "SQLUpdateResult",
    "TranslationPatternData",
    "UserData",
    # Exceptions
    "AxlToolkitError",
    "AXLAuthenticationError",
    "AXLConnectionError",
    "AXLDuplicateError",
    "AXLError",
    "AXLNotFoundError",
    "AXLSQLError",
    "AXLSQLInjectionError",
    "AXLValidationError",
    "SXMLError",
    "RISPortError",
    "PerfMonError",
    "ServiceabilityError",
    "LogCollectionError",
    "PAWSError",
    "WebdialerError",
    # Legacy aliases (deprecated)
    "AxlToolkit",
    "UcmServiceabilityToolkit",
    "UcmRisPortToolkit",
    "UcmPerfMonToolkit",
    "UcmLogCollectionToolkit",
    "UcmDimeGetFileToolkit",
    "PawsToolkit",
    "WebdialerToolkit",
]

__version__ = "2.0.0"
