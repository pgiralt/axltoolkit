"""
Exception hierarchy for axltoolkit.

All exceptions raised by the library inherit from :class:`AxlToolkitError`,
making it easy to catch any library error with a single except clause::

    try:
        result = client.get_phone(name="SEP001122334455")
    except AxlToolkitError as e:
        print(f"AXL operation failed: {e}")
"""

from __future__ import annotations


class AxlToolkitError(Exception):
    """Base exception for all axltoolkit errors."""


# ── Authentication / Connectivity ──────────────────────────────────────────

class AXLAuthenticationError(AxlToolkitError):
    """Raised when authentication with the UCM server fails (HTTP 401)."""


class AXLConnectionError(AxlToolkitError):
    """Raised when the connection to the UCM server cannot be established."""


# ── AXL API Errors ─────────────────────────────────────────────────────────

class AXLError(AxlToolkitError):
    """Raised when an AXL SOAP operation returns a fault.

    Attributes:
        fault_code: The AXL fault code string (e.g. ``"Item not valid"``).
        fault_message: The human-readable fault detail message.
        axl_error_code: Numeric AXL error code, if available.
        original_exception: The underlying ``zeep.exceptions.Fault`` or other
            exception that triggered this error.
    """

    def __init__(
        self,
        message: str,
        *,
        fault_code: str | None = None,
        fault_message: str | None = None,
        axl_error_code: int | None = None,
        original_exception: Exception | None = None,
    ):
        super().__init__(message)
        self.fault_code = fault_code
        self.fault_message = fault_message
        self.axl_error_code = axl_error_code
        self.original_exception = original_exception


class AXLNotFoundError(AXLError):
    """Raised when a requested object is not found in UCM (error 5007)."""


class AXLDuplicateError(AXLError):
    """Raised when attempting to add an object that already exists."""


class AXLValidationError(AXLError):
    """Raised when an AXL request contains invalid data."""


# ── SQL Errors ─────────────────────────────────────────────────────────────

class AXLSQLError(AXLError):
    """Raised when a Thin AXL SQL query or update fails."""


class AXLSQLInjectionError(AXLSQLError):
    """Raised when a potential SQL injection attempt is detected in input."""


# ── SXML / Serviceability Errors ───────────────────────────────────────────

class SXMLError(AxlToolkitError):
    """Base exception for SXML (Serviceability XML) API errors."""

    def __init__(
        self,
        message: str,
        *,
        original_exception: Exception | None = None,
    ):
        super().__init__(message)
        self.original_exception = original_exception


class RISPortError(SXMLError):
    """Raised when a RISPort70 API operation fails."""


class PerfMonError(SXMLError):
    """Raised when a PerfMon API operation fails."""


class ServiceabilityError(SXMLError):
    """Raised when a ControlCenter / Serviceability API operation fails."""


class LogCollectionError(SXMLError):
    """Raised when a Log Collection API operation fails."""


# ── PAWS Errors ────────────────────────────────────────────────────────────

class PAWSError(AxlToolkitError):
    """Raised when a Platform Administrative Web Service (PAWS) operation fails."""

    def __init__(
        self,
        message: str,
        *,
        original_exception: Exception | None = None,
    ):
        super().__init__(message)
        self.original_exception = original_exception


# ── Webdialer Errors ───────────────────────────────────────────────────────

class WebdialerError(AxlToolkitError):
    """Raised when a Webdialer API operation fails."""

    def __init__(
        self,
        message: str,
        *,
        original_exception: Exception | None = None,
    ):
        super().__init__(message)
        self.original_exception = original_exception
