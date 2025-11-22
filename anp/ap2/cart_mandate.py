"""CartMandate utilities.

This module provides signing helpers for CartMandate contents plus
helper validation utilities for merchants and shoppers.
"""

import time
import uuid

import jwt

from anp.ap2.models import (
    CartContents,
    CartMandate,
)
from anp.ap2.utils import compute_hash, verify_jws_payload


def build_cart_mandate(
    contents: CartContents,
    merchant_private_key: str,
    merchant_did: str,
    merchant_kid: str,
    shopper_did: str,
    algorithm: str = "RS256",
    ttl_seconds: int = 900,
) -> CartMandate:
    """Sign CartMandate contents with merchant authorization."""

    contents_dict = contents.model_dump(exclude_none=True)
    cart_hash = compute_hash(contents_dict)

    now = int(time.time())
    payload = {
        "iss": merchant_did,
        "sub": merchant_did,
        "aud": shopper_did,
        "iat": now,
        "exp": now + ttl_seconds,
        "jti": str(uuid.uuid4()),
        "cart_hash": cart_hash,
    }

    headers = {
        "alg": algorithm,
        "kid": merchant_kid,
        "typ": "JWT",
    }

    merchant_authorization = jwt.encode(
        payload,
        merchant_private_key,
        algorithm=algorithm,
        headers=headers,
    )

    return CartMandate(
        contents=contents,
        merchant_authorization=merchant_authorization,
    )


def validate_cart_mandate(
    cart_mandate: CartMandate,
    merchant_public_key: str,
    merchant_algorithm: str,
    expected_shopper_did: str,
) -> dict:
    """Validate CartMandate and return decoded payload.

    Args:
        cart_mandate: CartMandate to validate.
        merchant_public_key: Merchant's public key for verification.
        merchant_algorithm: JWT algorithm (e.g., RS256).
        expected_shopper_did: DID of the shopper (expected audience).

    Returns:
        Decoded JWT payload from merchant_authorization.

    Raises:
        ValueError: If cart_hash does not match content.
        jwt.InvalidTokenError: If JWT is invalid.
    """
    payload = verify_jws_payload(
        token=cart_mandate.merchant_authorization,
        public_key=merchant_public_key,
        algorithm=merchant_algorithm,
        expected_audience=expected_shopper_did,
    )

    contents_dict = cart_mandate.contents.model_dump(exclude_none=True)
    computed_cart_hash = compute_hash(contents_dict)

    cart_hash_in_token = payload.get("cart_hash")
    if cart_hash_in_token != computed_cart_hash:
        raise ValueError(
            f"cart_hash mismatch: expected {computed_cart_hash}, "
            f"got {cart_hash_in_token}"
        )

    return payload


__all__ = [
    "build_cart_mandate",
    "validate_cart_mandate",
]
