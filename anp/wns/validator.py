"""Handle format validation — pure functions, no network I/O.

Implements the Handle syntax rules from WNS spec section 3.
"""

import re
from typing import Tuple

from .exceptions import HandleValidationError, WbaUriParseError
from .models import ParsedWbaUri

# local-part: 1-63 chars, a-z0-9 and hyphen, must start/end with alnum,
# no consecutive hyphens.
_LOCAL_PART_RE = re.compile(r"^[a-z0-9](?:[a-z0-9]|(?:-(?!-))){0,61}[a-z0-9]$|^[a-z0-9]$")

# Simplified FQDN check: at least two labels separated by dots,
# each label 1-63 chars of alnum/hyphen, starting/ending with alnum.
_DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _is_valid_domain(domain: str) -> bool:
    """Check whether *domain* looks like a valid FQDN (case-insensitive)."""
    labels = domain.lower().split(".")
    if len(labels) < 2:
        return False
    return all(_DOMAIN_LABEL_RE.match(label) for label in labels)


def validate_local_part(local_part: str) -> bool:
    """Return True if *local_part* is a valid Handle local-part.

    Rules (spec section 3.1):
    - Only ASCII lowercase letters, digits and hyphens.
    - Must start and end with a letter or digit.
    - No consecutive hyphens.
    - Length 1–63.
    """
    return bool(_LOCAL_PART_RE.match(local_part.lower()))


def validate_handle(handle: str) -> Tuple[str, str]:
    """Validate *handle* and return ``(local_part, domain)``.

    The input is normalised to lowercase before validation.

    Raises:
        HandleValidationError: If the handle format is invalid.
    """
    normalized = handle.lower().strip()
    if not normalized:
        raise HandleValidationError("Handle must not be empty")

    # Split on the first dot to separate local-part from domain.
    dot_index = normalized.find(".")
    if dot_index < 0:
        raise HandleValidationError(
            f"Handle must contain at least one dot: '{handle}'"
        )

    local_part = normalized[:dot_index]
    domain = normalized[dot_index + 1 :]

    if not local_part:
        raise HandleValidationError(f"Handle local-part is empty: '{handle}'")
    if not domain:
        raise HandleValidationError(f"Handle domain is empty: '{handle}'")

    if not validate_local_part(local_part):
        raise HandleValidationError(
            f"Invalid local-part '{local_part}': must be 1-63 chars of a-z, "
            "0-9, hyphen; must start/end with alnum; no consecutive hyphens"
        )

    if not _is_valid_domain(domain):
        raise HandleValidationError(f"Invalid domain '{domain}'")

    return local_part, domain


def normalize_handle(handle: str) -> str:
    """Normalise *handle* to lowercase."""
    local_part, domain = validate_handle(handle)
    return f"{local_part}.{domain}"


def parse_wba_uri(uri: str) -> ParsedWbaUri:
    """Parse a ``wba://`` URI and return its components.

    Raises:
        WbaUriParseError: If the URI does not start with ``wba://`` or the
            embedded handle is invalid.
    """
    if not uri.startswith("wba://"):
        raise WbaUriParseError(f"URI must start with 'wba://': '{uri}'")

    handle_part = uri[len("wba://") :]
    if not handle_part:
        raise WbaUriParseError(f"URI contains no handle after 'wba://': '{uri}'")

    try:
        local_part, domain = validate_handle(handle_part)
    except HandleValidationError as exc:
        raise WbaUriParseError(f"Invalid handle in URI '{uri}': {exc}") from exc

    return ParsedWbaUri(
        local_part=local_part,
        domain=domain,
        handle=f"{local_part}.{domain}",
        original_uri=uri,
    )


def build_resolution_url(local_part: str, domain: str) -> str:
    """Build the HTTPS resolution URL for a handle.

    Returns ``https://{domain}/.well-known/handle/{local-part}``.
    """
    return f"https://{domain}/.well-known/handle/{local_part}"


def build_wba_uri(local_part: str, domain: str) -> str:
    """Build a ``wba://`` URI from handle components.

    Returns ``wba://{local-part}.{domain}``.
    """
    return f"wba://{local_part}.{domain}"
