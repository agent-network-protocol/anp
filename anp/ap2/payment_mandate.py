"""PaymentMandate utilities."""

import time
import uuid

import jwt

from anp.ap2.models import (
    PaymentMandate,
    PaymentMandateContents,
)
from anp.ap2.utils import compute_hash, verify_jws_payload


def build_payment_mandate(
    contents: PaymentMandateContents,
    user_private_key: str,
    user_did: str,
    user_kid: str,
    merchant_did: str,
    algorithm: str = "RS256",
    ttl_seconds: int = 15552000,
) -> PaymentMandate:
    """Sign PaymentMandate contents with the shopper's authorization."""

    if not contents.cart_hash:
        raise ValueError("contents.cart_hash must be set to maintain the hash chain")

    contents_dict = contents.model_dump(exclude_none=True)
    pmt_hash = compute_hash(contents_dict)

    now = int(time.time())
    payload = {
        "iss": user_did,
        "sub": user_did,
        "aud": merchant_did,
        "iat": now,
        "exp": now + ttl_seconds,
        "jti": str(uuid.uuid4()),
        "pmt_hash": pmt_hash,
    }

    # Build JWT header
    headers = {
        "alg": algorithm,
        "kid": user_kid,
        "typ": "JWT",
    }

    # Generate signature
    user_authorization = jwt.encode(
        payload,
        user_private_key,
        algorithm=algorithm,
        headers=headers,
    )

    # Build payment mandate
    return PaymentMandate(
        payment_mandate_contents=contents,
        user_authorization=user_authorization,
    )


def validate_payment_mandate(
    payment_mandate: PaymentMandate,
    shopper_public_key: str,
    shopper_algorithm: str,
    expected_merchant_did: str,
    expected_cart_hash: str,
) -> dict:
    """Validate PaymentMandate and return decoded payload.

    Args:
        payment_mandate: PaymentMandate to validate.
        shopper_public_key: Shopper's public key for verification.
        shopper_algorithm: JWT algorithm (e.g., RS256).
        expected_merchant_did: DID of the merchant (expected audience).
        expected_cart_hash: Expected cart_hash from validated CartMandate.

    Returns:
        Decoded JWT payload from user_authorization.

    Raises:
        ValueError: If content hash or chain hash is invalid.
        jwt.InvalidTokenError: If JWT is invalid.
    """
    # 1. Verify the shopper's JWS
    payload = verify_jws_payload(
        token=payment_mandate.user_authorization,
        public_key=shopper_public_key,
        algorithm=shopper_algorithm,
        expected_audience=expected_merchant_did,
    )

    # 2. Verify the content hash (pmt_hash)
    contents_dict = payment_mandate.payment_mandate_contents.model_dump(
        exclude_none=True
    )
    computed_pmt_hash = compute_hash(contents_dict)

    pmt_hash_in_token = payload.get("pmt_hash")
    if pmt_hash_in_token != computed_pmt_hash:
        raise ValueError(
            f"pmt_hash mismatch: expected {computed_pmt_hash}, got {pmt_hash_in_token}"
        )

    # 3. Verify the hash chain link
    cart_hash_in_pmt = payment_mandate.payment_mandate_contents.cart_hash
    if cart_hash_in_pmt != expected_cart_hash:
        raise ValueError(
            f"cart_hash mismatch: expected {expected_cart_hash}, got {cart_hash_in_pmt}"
        )

    return payload


__all__ = [
    "build_payment_mandate",
    "validate_payment_mandate",
]
