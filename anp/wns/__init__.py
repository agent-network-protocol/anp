"""WNS (WBA Name Space) — Handle resolution and binding verification.

Public API surface for the ``anp.wns`` package.
"""

# Exceptions
from .exceptions import (
    HandleBindingError,
    HandleGoneError,
    HandleMovedError,
    HandleNotFoundError,
    HandleResolutionError,
    HandleValidationError,
    WbaUriParseError,
    WnsError,
)

# Data models
from .models import (
    HandleResolutionDocument,
    HandleServiceEntry,
    HandleStatus,
    ParsedWbaUri,
)

# Validation (pure functions, no I/O)
from .validator import (
    build_resolution_url,
    build_wba_uri,
    normalize_handle,
    parse_wba_uri,
    validate_handle,
    validate_local_part,
)

# Resolution (async + sync)
from .resolver import (
    resolve_handle,
    resolve_handle_from_uri,
    resolve_handle_sync,
)

# Binding verification
from .binding import (
    BindingVerificationResult,
    build_handle_service_entry,
    extract_handle_service_from_did_document,
    verify_handle_binding,
)

__all__ = [
    # Exceptions
    "WnsError",
    "HandleValidationError",
    "HandleNotFoundError",
    "HandleGoneError",
    "HandleMovedError",
    "HandleResolutionError",
    "HandleBindingError",
    "WbaUriParseError",
    # Models
    "HandleStatus",
    "HandleResolutionDocument",
    "HandleServiceEntry",
    "ParsedWbaUri",
    # Validation
    "validate_local_part",
    "validate_handle",
    "normalize_handle",
    "parse_wba_uri",
    "build_resolution_url",
    "build_wba_uri",
    # Resolution
    "resolve_handle",
    "resolve_handle_sync",
    "resolve_handle_from_uri",
    # Binding
    "BindingVerificationResult",
    "verify_handle_binding",
    "build_handle_service_entry",
    "extract_handle_service_from_did_document",
]
