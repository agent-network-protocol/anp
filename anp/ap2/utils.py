"""AP2 Protocol Utility Functions.

This module provides common utilities for AP2 protocol implementation,
including JCS canonicalization and hash computation.
"""

import base64
import hashlib
import json
from typing import Any, Dict, Optional

import jwt


def jcs_canonicalize(obj: Dict[str, Any]) -> str:
    """Canonicalize a JSON object using JCS (RFC 8785).

    Args:
        obj: The JSON object to canonicalize

    Returns:
        Canonicalized JSON string

    References:
        RFC 8785: https://datatracker.ietf.org/doc/rfc8785/
    """
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


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
    """
    canonical = jcs_canonicalize(obj)
    digest = hashlib.sha256(canonical.encode("utf-8")).digest()
    return b64url_no_pad(digest)


def verify_jws_payload(
    token: str,
    public_key: str,
    algorithm: str = "RS256",
    expected_audience: Optional[str] = None,
    verify_time: bool = True,
) -> Dict[str, Any]:
    """Verify JWS token and return decoded payload.

    Args:
        token: JWS token string.
        public_key: Public key for signature verification.
        algorithm: Expected JWT algorithm (default: RS256).
        expected_audience: Expected audience ('aud') claim.
        verify_time: Whether to verify time validity (exp, iat, nbf).

    Returns:
        Decoded JWT payload.

    Raises:
        jwt.InvalidTokenError: If token is invalid.
    """
    options = {"verify_exp": verify_time}
    decode_kwargs: Dict[str, Any] = {"algorithms": [algorithm], "options": options}

    if expected_audience:
        decode_kwargs["audience"] = expected_audience
    else:
        options["verify_aud"] = False

    return jwt.decode(token, public_key, **decode_kwargs)


__all__ = [
    "jcs_canonicalize",
    "b64url_no_pad",
    "compute_hash",
    "verify_jws_payload",
]
