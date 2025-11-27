"""Functional API for Mandate Protocol.

This module provides a minimal, orthogonal API for building and validating
mandates using pure functions. Follows Unix philosophy: do one thing well,
accept and return plain dicts, compose naturally.

Design Principles:
- Pure functions operating on plain dicts
- Minimal API surface (2 core functions)
- Developer controls all contents structure
- JWT-based signing with standard claims (iss, sub, aud, iat, exp, jti)
- Content hash verification for integrity

Example:
    >>> # Build a mandate
    >>> cart = build_mandate(
    ...     contents={"id": "cart-123", "items": [...]},
    ...     private_key=merchant_key,
    ...     headers={"alg": "ES256K", "kid": "key-1", "typ": "JWT"},
    ...     iss="did:wba:merchant",
    ...     sub="did:wba:merchant",
    ...     aud="did:wba:shopper",
    ...     ttl_seconds=900
    ... )
    >>> # Validate
    >>> assert validate_mandate(cart, merchant_public_key, expected_audience="did:wba:shopper")
"""

import base64
import hashlib
import json
import time
import uuid
from typing import Any, Dict, Optional

import jwt


def jcs_canonicalize(obj: Dict[str, Any]) -> str:
    """Canonicalize a JSON object using RFC 8785 (JCS)."""

    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def b64url_no_pad(data: bytes) -> str:
    """Encode bytes as Base64URL without padding."""

    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def compute_hash(contents: dict) -> str:
    """Hash a JSON object using SHA-256 over JCS canonicalization."""

    canonical = jcs_canonicalize(contents)
    digest = hashlib.sha256(canonical.encode("utf-8")).digest()
    return b64url_no_pad(digest)


def build_mandate(
    contents: dict,
    headers: Dict[str, Any],
    iss: str,
    sub: str,
    aud: str,
    private_key: str,
    algorithm: str = "ES256K",
    ttl_seconds: int = 900,
    hash_field_name: str = "content_hash",
) -> dict:
    """Build mandate with JWT-based signature.

    Pure function that computes content hash, creates JWT payload with
    standard claims, and returns signed mandate. This is the core building
    block used by higher-level functions like build_cart_mandate.

    Args:
        contents: Developer-assembled dict with any structure.
        private_key: JWS signing key in PEM format.
        headers: JWT headers dict (must include alg, kid, typ).
        iss: Issuer claim (typically DID of the signer).
        sub: Subject claim (typically DID of the entity being signed).
        aud: Audience claim (typically DID of the intended recipient).
        ttl_seconds: Time-to-live in seconds (default: 900 = 15 minutes).
        algorithm: JWT algorithm for signing (default: ES256K).
        hash_field_name: Name of hash field in JWT payload (default: "content_hash").
                        Can be "cart_hash", "pmt_hash", etc. for semantic clarity.
        extra_payload: Optional mapping of additional claims to merge into the payload.

    Returns:
        Dict with structure: {"contents": {...}, "auth": "JWS..."}
        The auth field contains JWT with payload:
        {
            "iss": ..., "sub": ..., "aud": ...,
            "iat": ..., "exp": ..., "jti": ...,
            "<hash_field_name>": "..."  # e.g., cart_hash, pmt_hash
        }

    Example:
        >>> mandate = build_mandate(
        ...     contents={"id": "order-1", "amount": 100},
        ...     private_key=my_key,
        ...     headers={"alg": "ES256K", "kid": "key-1", "typ": "JWT"},
        ...     iss="did:wba:merchant",
        ...     sub="did:wba:merchant",
        ...     aud="did:wba:shopper",
        ...     ttl_seconds=900,
        ...     hash_field_name="cart_hash"
        ... )
    """
    # Compute content hash
    content_hash = compute_hash(contents)

    # Create JWT payload with standard claims
    now = int(time.time())
    payload = {
        "iss": iss,
        "sub": sub,
        "iat": now,
        "exp": now + ttl_seconds,
        "jti": str(uuid.uuid4()),
        hash_field_name: content_hash,  # Flexible field name
    }
    if aud is not None:
        payload["aud"] = aud

    # Sign payload
    auth_token = jwt.encode(
        payload=payload,
        key=private_key,
        algorithm=algorithm,
        headers=headers,
    )

    return {
        "contents": contents,
        "auth": auth_token,
    }


def validate_mandate(
    mandate: dict,
    public_key: str,
    algorithm: str = "ES256K",
    expected_audience: Optional[str] = None,
    verify_time: bool = True,
    hash_field_name: str = "content_hash",
) -> bool:
    """Validate mandate signature and content hash.

    Pure function that verifies the cryptographic signature on a mandate
    and ensures the hash in the JWT payload matches the actual contents hash.

    Args:
        mandate: Dict with structure {"contents": dict, "auth": str}.
        public_key: JWS verification key in PEM format.
        algorithm: Expected JWT algorithm (default: ES256K).
        expected_audience: Expected audience ('aud') claim for verification.
        verify_time: Whether to verify JWT time claims (exp, iat, nbf).
                     Default True for security.
        hash_field_name: Name of hash field in JWT payload (default: "content_hash").
                        Must match the field name used in build_mandate.

    Returns:
        True if signature and content hash are valid, False otherwise.

    Example:
        >>> is_valid = validate_mandate(
        ...     mandate,
        ...     public_key,
        ...     expected_audience="did:wba:shopper",
        ...     hash_field_name="cart_hash"
        ... )
        >>> if is_valid:
        ...     # Process mandate
        ...     process(mandate["contents"])
    """
    try:
        # Extract components
        contents = mandate.get("contents")
        auth_token = mandate.get("auth")

        if contents is None or auth_token is None:
            return False

        # Prepare decode options
        options = {"verify_exp": verify_time}
        if not verify_time:
            options.update(
                {
                    "verify_iat": False,
                    "verify_nbf": False,
                }
            )

        decode_kwargs = {"algorithms": [algorithm], "options": options}

        # Add audience verification if provided
        if expected_audience:
            decode_kwargs["audience"] = expected_audience
        else:
            options["verify_aud"] = False

        # Verify JWT signature
        decoded = jwt.decode(auth_token, public_key, **decode_kwargs)

        # Verify content hash (flexible field name)
        if hash_field_name not in decoded:
            return False

        expected_hash = compute_hash(contents)
        return decoded[hash_field_name] == expected_hash

    except (jwt.InvalidTokenError, jwt.DecodeError, Exception):
        return False


__all__ = [
    "jcs_canonicalize",
    "b64url_no_pad",
    "compute_hash",
    "build_mandate",
    "validate_mandate",
]
