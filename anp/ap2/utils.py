"""AP2 Protocol Utility Functions.

This module provides common utilities for AP2 protocol implementation,
including JCS canonicalization and hash computation.
"""

import base64
import hashlib
import json
from typing import Any, Dict


def jcs_canonicalize(obj: Dict[str, Any]) -> str:
    """Canonicalize a JSON object using JCS (RFC 8785).

    Args:
        obj: The JSON object to canonicalize

    Returns:
        Canonicalized JSON string

    References:
        RFC 8785: https://datatracker.ietf.org/doc/rfc8785/
    """
    return json.dumps(
        obj,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True
    )


def b64url_no_pad(data: bytes) -> str:
    """Base64URL encode without padding.

    Args:
        data: Bytes to encode

    Returns:
        Base64URL encoded string without padding
    """
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def compute_hash(obj: Dict[str, Any]) -> str:
    """Compute hash for a JSON object using SHA-256 and JCS.

    The hash is computed as:
        hash = Base64URL( SHA-256( JCS(obj) ) )

    Args:
        obj: The JSON object to hash

    Returns:
        Base64URL encoded hash string

    Example:
        >>> obj = {"id": "123", "amount": 100}
        >>> hash_value = compute_hash(obj)
    """
    canonical = jcs_canonicalize(obj)
    digest = hashlib.sha256(canonical.encode("utf-8")).digest()
    return b64url_no_pad(digest)


def compute_cart_hash(cart_contents: Dict[str, Any]) -> str:
    """Compute cart_hash for CartMandate.contents.

    Args:
        cart_contents: CartMandate.contents dictionary

    Returns:
        Base64URL encoded cart_hash

    Example:
        >>> contents = {"id": "cart_123", "payment_request": {...}}
        >>> cart_hash = compute_cart_hash(contents)
    """
    return compute_hash(cart_contents)


def compute_pmt_hash(payment_mandate_contents: Dict[str, Any]) -> str:
    """Compute pmt_hash for PaymentMandate.payment_mandate_contents.

    Args:
        payment_mandate_contents: PaymentMandate.payment_mandate_contents dictionary
            (without user_authorization field)

    Returns:
        Base64URL encoded pmt_hash

    Example:
        >>> contents = {"payment_mandate_id": "pm_123", ...}
        >>> pmt_hash = compute_pmt_hash(contents)
    """
    return compute_hash(payment_mandate_contents)
