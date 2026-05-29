"""Shared environment loader for the ``samples/`` scripts.

Reads the ``.env`` file at the repository root (gitignored — see
``.env.example`` for the template) and exposes its values as
module-level constants so each sample can simply do::

    from _env import UCM_ADDRESS, UCM_USERNAME, UCM_PASSWORD

``python-dotenv`` is an *optional* dependency: if it isn't installed,
this module silently falls back to reading whatever values are already
set in ``os.environ``. That way the samples still work in a CI / shell
environment where credentials are injected directly without a ``.env``
file.

The variable names mirror the convention already used by
``tests/integration/conftest.py``.
"""

from __future__ import annotations

import os
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - optional dependency
    def load_dotenv(*_args, **_kwargs) -> bool:
        """No-op fallback when python-dotenv is not installed."""
        return False


_REPO_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(_REPO_ROOT / ".env")

# ── Required ──────────────────────────────────────────────────────────

UCM_ADDRESS: str = os.environ.get("UCM_ADDRESS", "")
UCM_USERNAME: str = os.environ.get("UCM_USERNAME", "")
UCM_PASSWORD: str = os.environ.get("UCM_PASSWORD", "")

# ── Optional (fall back to AXL creds for backwards compatibility) ────

UCM_PLATFORM_USERNAME: str = os.environ.get("UCM_PLATFORM_USERNAME", UCM_USERNAME)
UCM_PLATFORM_PASSWORD: str = os.environ.get("UCM_PLATFORM_PASSWORD", UCM_PASSWORD)

# ── Connection knobs ─────────────────────────────────────────────────

UCM_AXL_VERSION: str = os.environ.get("UCM_AXL_VERSION", "15.0")
UCM_TIMEOUT: int = int(os.environ.get("UCM_TIMEOUT", "30"))
UCM_LOG_TIMEOUT: int = int(os.environ.get("UCM_LOG_TIMEOUT", "120"))


def _parse_tls_verify(raw: str):
    """Translate the UCM_TLS_VERIFY string into the value expected by clients."""
    val = (raw or "").strip().lower()
    if val in ("", "true", "1", "yes", "y"):
        return True
    if val in ("false", "0", "no", "n"):
        return False
    # Anything else is treated as a path to a CA bundle
    return raw


# Default to verifying TLS. Users must explicitly set UCM_TLS_VERIFY=false
# in their .env to opt into the lab-only insecure mode.
UCM_TLS_VERIFY = _parse_tls_verify(os.environ.get("UCM_TLS_VERIFY", "true"))


__all__ = [
    "UCM_ADDRESS",
    "UCM_USERNAME",
    "UCM_PASSWORD",
    "UCM_PLATFORM_USERNAME",
    "UCM_PLATFORM_PASSWORD",
    "UCM_AXL_VERSION",
    "UCM_TLS_VERIFY",
    "UCM_TIMEOUT",
    "UCM_LOG_TIMEOUT",
]
