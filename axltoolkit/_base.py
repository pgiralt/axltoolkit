"""
Base client providing shared session management, cookie caching, retry logic,
TLS configuration, and logging for all axltoolkit service clients.
"""

from __future__ import annotations

import copy
import logging
import os
import re
import stat
from pathlib import Path
from typing import Optional, Union

from lxml import etree
from lxml.etree import tostring
from requests import Session
from requests.adapters import HTTPAdapter
from requests.auth import HTTPBasicAuth
from urllib3.util.retry import Retry
from zeep import Client, Settings
from zeep.cache import SqliteCache
from zeep.plugins import HistoryPlugin
from zeep.transports import Transport

from .exceptions import AXLAuthenticationError, AXLConnectionError

logger = logging.getLogger("axltoolkit")

# Local-element names (lowercased, namespace stripped) whose text content
# carries secrets and must be redacted before envelopes are surfaced to
# callers via ``last_request_debug``. Match on the XSD element's local
# name so namespace prefixes don't matter.
_REDACT_LOCAL_NAMES = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "secret",
        "secretcode",
        "secrettoken",
        "apikey",
        "apipassword",
        "token",
        "accesstoken",
        "refreshtoken",
        "ldappassword",
        "trustpassword",
        "snmppassword",
        "authprotocolpassword",
        "privprotocolpassword",
    }
)
_REDACTED_TEXT = "[REDACTED]"


class BaseClient:
    """Base class for all axltoolkit service clients.

    Provides:
    - HTTP session with cookie caching (JSESSIONID reuse across requests)
    - Configurable retry logic with exponential back-off
    - TLS certificate verification (custom CA bundle support)
    - Request/response history for debugging
    - Structured logging via the ``axltoolkit`` logger hierarchy

    Args:
        username: UCM application or platform user name.
        password: Password for the user.
        server_ip: IP address or FQDN of the UCM server.
        tls_verify: ``True`` to verify server TLS certificate (default),
            ``False`` to skip verification, or a *str* path to a CA bundle file.
        timeout: Request timeout in seconds.  Applied to both the connection
            timeout and the read (operation) timeout.
        max_retries: Maximum number of automatic retries on transient failures
            (HTTP 502/503/504 and connection errors).  Set to ``0`` to disable.
        history_enabled: When ``True`` (the default), records the last SOAP
            request/response for debugging via :meth:`last_request_debug`.
    """

    def __init__(
        self,
        username: str,
        password: str,
        server_ip: str,
        *,
        tls_verify: Union[bool, str] = True,
        timeout: int = 30,
        max_retries: int = 3,
        history_enabled: bool = True,
    ):
        # ── Validate server_ip ──────────────────────────────────────
        if not re.match(r"^[A-Za-z0-9._-]+(:\d{1,5})?$", server_ip):
            raise ValueError(
                f"Invalid server_ip: {server_ip!r}. Must be a valid hostname, FQDN, or IP address."
            )

        self._server_ip = server_ip
        self._username = username
        self._timeout = timeout
        if not hasattr(self, "_cache_key_suffix"):
            self._cache_key_suffix: str = ""

        # ── Logger ─────────────────────────────────────────────────────
        self._log = logging.getLogger(f"axltoolkit.{self.__class__.__name__}")

        # ── HTTP Session with cookie jar (JSESSIONID caching) ─────────
        self._session = Session()
        self._session.auth = HTTPBasicAuth(username, password)

        # TLS verification: True, False, or path to CA bundle
        if isinstance(tls_verify, str):
            if not os.path.isfile(tls_verify):
                raise FileNotFoundError(f"CA bundle not found: {tls_verify}")
        self._session.verify = tls_verify

        # ── Retry adapter ─────────────────────────────────────────────
        if max_retries > 0:
            retry_strategy = Retry(
                total=max_retries,
                backoff_factor=0.5,
                status_forcelist=[502, 503, 504],
                allowed_methods=["POST"],  # SOAP is POST-only
                raise_on_status=False,
            )
            adapter = HTTPAdapter(max_retries=retry_strategy)
            self._session.mount("https://", adapter)

        # ── Zeep WSDL cache (user-scoped, restricted permissions) ────
        cache_dir = Path.home() / ".cache" / "axltoolkit"
        cache_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(cache_dir, stat.S_IRWXU)  # 700 — owner only
        cache_name = self.__class__.__name__.lower()
        suffix = f"_{self._cache_key_suffix}" if self._cache_key_suffix else ""
        cache_path = cache_dir / f"{cache_name}_{server_ip}{suffix}.db"
        self._cache = SqliteCache(path=str(cache_path), timeout=3600)

        # ── History plugin (instance-level, not class-level) ──────────
        self._history_enabled = history_enabled
        self._history = HistoryPlugin() if history_enabled else None
        self._plugins = [self._history] if self._history else []

    # ── Factory helper for creating a zeep Client ──────────────────────

    def _create_zeep_client(self, wsdl: str) -> Client:
        """Create a zeep ``Client`` with the shared session and plugins.

        Args:
            wsdl: Path to a local WSDL file or an ``https://`` URL.

        Returns:
            A configured :class:`zeep.Client`.
        """
        transport = Transport(
            timeout=self._timeout,
            operation_timeout=self._timeout,
            cache=self._cache,
            session=self._session,
        )
        # XML hardening: zeep 4.x already disables external entities and
        # external DTD references by default (resolve_entities=False,
        # forbid_entities=True, forbid_external=True, xml_huge_tree=False).
        # We additionally forbid inline DOCTYPE declarations entirely —
        # Cisco's AXL/SXML schemas use XSD, not DTD, so legitimate
        # responses never include one. ``strict=False`` is kept so that
        # UCM's occasional non-strict response framing (extra whitespace,
        # unexpected ordering) is tolerated.
        settings = Settings(strict=False, forbid_dtd=True)
        return Client(
            wsdl=wsdl,
            plugins=self._plugins,
            transport=transport,
            settings=settings,
        )

    # ── Debug helpers ──────────────────────────────────────────────────

    @staticmethod
    def _redact_envelope(envelope) -> bytes:
        """Serialize a SOAP envelope with sensitive element text redacted.

        UCM SOAP requests and responses can carry plaintext credentials
        in element bodies (``<password>``, ``<secretCode>``, LDAP/SNMP
        passwords on configuration operations, etc.). This helper walks
        a deep copy of the envelope tree, replaces the text content of
        any element whose XSD local name matches the redaction allow-
        list, and serializes the result. The original envelope object
        on the history plugin is left untouched so it can be re-emitted
        on the wire if needed.

        Args:
            envelope: An ``lxml.etree._Element`` representing the SOAP
                envelope (as zeep stores it in ``HistoryPlugin``).

        Returns:
            The serialized envelope as bytes, with redactions applied.
        """
        if envelope is None:
            return b""
        try:
            cloned = copy.deepcopy(envelope)
            for el in cloned.iter():
                if not isinstance(el.tag, str):
                    # Skip comments / processing instructions
                    continue
                local = etree.QName(el.tag).localname.lower()
                if local in _REDACT_LOCAL_NAMES and el.text:
                    el.text = _REDACTED_TEXT
            return tostring(cloned)
        except Exception:
            # If anything in the redaction pass fails, fall back to a
            # placeholder rather than leaking the un-redacted envelope.
            return b"<!-- envelope redacted: serialization failed -->"

    def last_request_debug(self) -> Optional[dict]:
        """Return the last SOAP request and response for debugging.

        Returns:
            A dict with ``request`` and ``response`` keys, each containing
            ``raw``, ``headers``, and ``envelope`` (as bytes).
            Returns ``None`` if history tracking is disabled or no requests
            have been made yet.

        .. note::
            Sensitive element text (``<password>``, ``<secretCode>``,
            etc.) is redacted in the returned ``envelope`` bytes, and
            ``Authorization`` / ``Cookie`` / ``Set-Cookie`` headers are
            also redacted. The ``raw`` history dicts are returned
            untouched for callers that genuinely need the unredacted
            data; treat them with care.
        """
        if not self._history:
            return None

        try:
            last_sent = self._history.last_sent
            last_received = self._history.last_received
            if not last_sent:
                return None
            request_env = self._redact_envelope(last_sent.get("envelope"))
            request_headers = last_sent["http_headers"]
            response_env = self._redact_envelope(last_received.get("envelope"))
            response_headers = last_received["http_headers"]
        except (KeyError, TypeError, IndexError):
            return None

        # Redact sensitive headers to avoid credential leakage
        _SENSITIVE = {"authorization", "cookie", "set-cookie"}
        safe_req_headers = {
            k: ("[REDACTED]" if k.lower() in _SENSITIVE else v)
            for k, v in (request_headers or {}).items()
        }
        safe_resp_headers = {
            k: ("[REDACTED]" if k.lower() in _SENSITIVE else v)
            for k, v in (response_headers or {}).items()
        }

        return {
            "request": {
                "raw": self._history.last_sent,
                "headers": safe_req_headers,
                "envelope": request_env,
            },
            "response": {
                "raw": self._history.last_received,
                "headers": safe_resp_headers,
                "envelope": response_env,
            },
        }

    # ── Connection validation ──────────────────────────────────────────

    def check_connectivity(self) -> bool:
        """Test basic HTTPS connectivity to the UCM server.

        Returns:
            ``True`` if the server is reachable.

        Raises:
            AXLConnectionError: If the server cannot be reached.
            AXLAuthenticationError: If credentials are rejected (HTTP 401).
        """
        import requests

        url = f"https://{self._server_ip}:8443"
        try:
            resp = self._session.get(url, timeout=self._timeout)
            if resp.status_code == 401:
                raise AXLAuthenticationError(
                    f"Authentication failed for user '{self._username}' "
                    f"on {self._server_ip} (HTTP 401)"
                )
            return True
        except requests.ConnectionError as exc:
            raise AXLConnectionError(
                f"Cannot reach UCM server at {self._server_ip}: {exc}"
            ) from exc

    @property
    def server_ip(self) -> str:
        """The IP address or FQDN of the connected UCM server."""
        return self._server_ip
