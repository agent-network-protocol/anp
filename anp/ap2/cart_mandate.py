"""CartMandate utilities.

This module provides signing helpers for CartMandate contents plus
helper validation utilities for merchants and shoppers.
"""

from anp.ap2.mandate import build_mandate, validate_mandate
from anp.ap2.models import CartMandate


def build_cart_mandate(
    contents: dict,
    shopper_did: str,
    merchant_private_key: str,
    merchant_did: str,
    merchant_kid: str,
    algorithm: str = "ES256K",
    ttl_seconds: int = 900,
) -> CartMandate:
    """Sign CartMandate contents with merchant authorization.

    Wraps the core build_mandate with CartMandate-specific configuration
    and returns a typed CartMandate model.

    Args:
        contents: Cart contents as plain dict (developer-controlled structure).
        shopper_did: Shopper's DID (audience).
        merchant_private_key: Merchant's private key in PEM format.
        merchant_did: Merchant's DID (issuer and subject).
        merchant_kid: Merchant's key ID for JWT header.
        algorithm: JWT algorithm (default: ES256K).
        ttl_seconds: Time-to-live in seconds (default: 900).

    Returns:
        CartMandate instance with contents and merchant_authorization.
        JWT payload contains "cart_hash" field.

    Example:
        >>> cart = build_cart_mandate(
        ...     contents={"id": "cart-123", "items": [...]},
        ...     shopper_did="did:wba:shopper",
        ...     merchant_private_key=key,
        ...     merchant_did="did:wba:merchant",
        ...     merchant_kid="key-1",
        ... )
        >>> cart.contents  # dict
        >>> cart.merchant_authorization  # str (JWS)
    """
    # Prepare headers
    headers = {
        "alg": algorithm,
        "kid": merchant_kid,
        "typ": "JWT",
    }

    # Use core build_mandate function with CartMandate-specific hash field name
    mandate_dict = build_mandate(
        contents=contents,
        private_key=merchant_private_key,
        headers=headers,
        iss=merchant_did,
        sub=merchant_did,
        aud=shopper_did,
        ttl_seconds=ttl_seconds,
        algorithm=algorithm,
        hash_field_name="cart_hash",  # CartMandate uses "cart_hash"
    )

    # Convert to CartMandate model using Pydantic helper
    return CartMandate.model_validate(
        {
            "contents": mandate_dict["contents"],
            "merchant_authorization": mandate_dict["auth"],
        }
    )


def validate_cart_mandate(
    cart_mandate: CartMandate,
    merchant_public_key: str,
    merchant_algorithm: str,
    expected_shopper_did: str,
) -> bool:
    """Validate CartMandate signature and content hash.

    Wraps the core validate_mandate with CartMandate-specific configuration
    and accepts typed CartMandate model.

    Args:
        cart_mandate: CartMandate instance to validate.
        merchant_public_key: Merchant's public key for verification.
        merchant_algorithm: JWT algorithm (e.g., ES256K).
        expected_shopper_did: DID of the shopper (expected audience).

    Returns:
        True if the mandate signature and content hash are valid, False otherwise.
    """

    # Support both Pydantic model and dict
    if isinstance(cart_mandate, dict):
        mandate_dict = {
            "contents": cart_mandate["contents"],
            "auth": cart_mandate["merchant_authorization"],
        }
    else:
        mandate_dict = {
            "contents": cart_mandate.contents,
            "auth": cart_mandate.merchant_authorization,
        }

    return validate_mandate(
        mandate=mandate_dict,
        public_key=merchant_public_key,
        algorithm=merchant_algorithm,
        expected_audience=expected_shopper_did,
        verify_time=True,
        hash_field_name="cart_hash",
    )


__all__ = [
    "build_cart_mandate",
    "validate_cart_mandate",
]
