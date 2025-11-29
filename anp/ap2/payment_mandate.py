"""PaymentMandate utilities."""

from anp.ap2.mandate import build_mandate, validate_mandate
from anp.ap2.models import PaymentMandate


def build_payment_mandate(
    contents: dict,
    merchant_did: str,
    shopper_did: str,
    shopper_kid: str,
    shopper_private_key: str,
    algorithm: str = "ES256K",
    ttl_seconds: int = 15552000,
) -> PaymentMandate:
    """Sign PaymentMandate contents with the shopper's authorization.

    Pure function that wraps the core build_mandate with PaymentMandate-specific
    configuration (uses "pmt_hash" field name).

    Args:
        contents: Payment mandate contents as plain dict. Must include "cart_hash"
                  field to maintain hash chain integrity.
        merchant_did: Merchant's DID (issuer and subject).
        shopper_did: Shopper's DID (audience).
        shopper_kid: Shopper's key ID for JWT header.
        shopper_private_key: Shopper's private key in PEM format.
        merchant_did: Merchant's DID (audience).
        algorithm: JWT algorithm (default: ES256K).
        ttl_seconds: Time-to-live in seconds (default: 15552000 = 180 days).

    Returns:
        PaymentMandate instance linking the contents dict with the user authorization.
        JWT payload contains "pmt_hash" field.

    Raises:
        ValueError: If cart_hash is missing from contents.

    Example:
        >>> payment = build_payment_mandate(
        ...     contents={
        ...         "payment_mandate_id": "pmt-456",
        ...         "cart_hash": cart_hash,
        ...         ...
        ...     },
        ...     shopper_private_key=key,
        ...     shopper_did="did:wba:shopper",
        ...     shopper_kid="key-1",
        ...     merchant_did="did:wba:merchant"
        ... )
    """
    if not contents.get("cart_hash"):
        raise ValueError("contents['cart_hash'] must be set to maintain the hash chain")

    # Prepare headers
    headers = {
        "alg": algorithm,
        "kid": shopper_kid,
        "typ": "JWT",
    }

    # Use core build_mandate function with PaymentMandate-specific hash field name
    mandate_dict = build_mandate(
        contents=contents,
        headers=headers,
        iss=shopper_did,
        sub=shopper_did,
        aud=merchant_did,
        private_key=shopper_private_key,
        algorithm=algorithm,
        ttl_seconds=ttl_seconds,
        hash_field_name="pmt_hash",  # PaymentMandate uses "pmt_hash"
    )

    # Convert to PaymentMandate model using Pydantic helper
    return PaymentMandate.model_validate(
        {
            "payment_mandate_contents": mandate_dict["contents"],
            "user_authorization": mandate_dict["auth"],
        }
    )


def validate_payment_mandate(
    payment_mandate: PaymentMandate,
    shopper_public_key: str,
    shopper_algorithm: str,
    expected_merchant_did: str,
    expected_cart_hash: str,
) -> bool:
    """Validate PaymentMandate and verify hash chain.

    Pure function that wraps the core validate_mandate with PaymentMandate-specific
    configuration (expects "pmt_hash" field name) and verifies hash chain integrity.

    Args:
        payment_mandate: PaymentMandate instance to validate.
        shopper_public_key: Shopper's public key for verification.
        shopper_algorithm: JWT algorithm (e.g., ES256K).
        expected_merchant_did: DID of the merchant (expected audience).
        expected_cart_hash: Expected cart_hash from validated CartMandate.

    Returns:
        True if the PaymentMandate is valid, False otherwise.
    """

    # Support both Pydantic model and dict
    if isinstance(payment_mandate, dict):
        mandate_dict = {
            "contents": payment_mandate["payment_mandate_contents"],
            "auth": payment_mandate["user_authorization"],
        }
        cart_hash_in_pmt = payment_mandate["payment_mandate_contents"].get("cart_hash")
    else:
        mandate_dict = {
            "contents": payment_mandate.payment_mandate_contents,
            "auth": payment_mandate.user_authorization,
        }
        cart_hash_in_pmt = payment_mandate.payment_mandate_contents.get("cart_hash")

    if not validate_mandate(
        mandate=mandate_dict,
        public_key=shopper_public_key,
        algorithm=shopper_algorithm,
        expected_audience=expected_merchant_did,
        verify_time=True,
        hash_field_name="pmt_hash",
    ):
        return False

    return cart_hash_in_pmt == expected_cart_hash


__all__ = [
    "build_payment_mandate",
    "validate_payment_mandate",
]
