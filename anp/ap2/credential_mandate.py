"""Credential convenience functions.

This module provides high-level functions for building and verifying
PaymentReceipt and FulfillmentReceipt credentials.
"""

import time
from typing import Optional

import jwt

from anp.ap2.models import (
    FulfillmentReceipt,
    FulfillmentReceiptContents,
    PaymentReceipt,
    PaymentReceiptContents,
)
from anp.ap2.utils import compute_hash, verify_jws_payload


def build_payment_receipt(
    contents: PaymentReceiptContents,
    pmt_hash: str,
    merchant_private_key: str,
    merchant_did: str,
    merchant_kid: str,
    algorithm: str = "RS256",
    shopper_did: Optional[str] = None,
    ttl_seconds: int = 15552000,
) -> PaymentReceipt:
    """Build a PaymentReceipt with merchant authorization.

    This is a convenience function that builds and signs a PaymentReceipt.

    Args:
        contents: Payment receipt contents
        pmt_hash: Hash of the preceding PaymentMandate in the chain
        merchant_private_key: Merchant private key
        merchant_did: Merchant DID
        merchant_kid: Merchant key identifier
        algorithm: JWT signing algorithm
        shopper_did: Shopper DID (optional)
        ttl_seconds: Time to live in seconds

    Returns:
        Built PaymentReceipt object
    """
    if not isinstance(contents, PaymentReceiptContents):
        raise TypeError("contents must be a PaymentReceiptContents instance")

    # Ensure contents include pmt_hash
    contents_with_chain = contents.model_copy(update={"pmt_hash": pmt_hash})

    # Calculate credential hash
    contents_dict = contents_with_chain.model_dump(exclude_none=True)
    cred_hash = compute_hash(contents_dict)

    # Build JWT payload
    now = int(time.time())
    payload = {
        "iss": merchant_did,
        "sub": merchant_did,
        "aud": shopper_did,
        "iat": now,
        "exp": now + ttl_seconds,
        "jti": contents_with_chain.id,
        "credential_type": "PaymentReceipt",
        "cred_hash": cred_hash,
    }

    # Build JWT header
    headers = {
        "alg": algorithm,
        "kid": merchant_kid,
        "typ": "JWT",
    }

    # Generate signature
    merchant_authorization = jwt.encode(
        payload,
        merchant_private_key,
        algorithm=algorithm,
        headers=headers,
    )

    # Build PaymentReceipt
    return PaymentReceipt(
        contents=contents_with_chain,
        merchant_authorization=merchant_authorization,
    )


def build_fulfillment_receipt(
    contents: FulfillmentReceiptContents,
    pmt_hash: str,
    merchant_private_key: str,
    merchant_did: str,
    merchant_kid: str,
    algorithm: str = "RS256",
    shopper_did: Optional[str] = None,
    ttl_seconds: int = 15552000,
) -> FulfillmentReceipt:
    """Build a FulfillmentReceipt with merchant authorization.

    This is a convenience function that builds and signs a FulfillmentReceipt.

    Args:
        contents: Fulfillment receipt contents
        pmt_hash: Hash of the preceding PaymentMandate in the chain
        merchant_private_key: Merchant private key
        merchant_did: Merchant DID
        merchant_kid: Merchant key identifier
        algorithm: JWT signing algorithm
        shopper_did: Shopper DID (optional)
        ttl_seconds: Time to live in seconds

    Returns:
        Built FulfillmentReceipt object
    """
    if not isinstance(contents, FulfillmentReceiptContents):
        raise TypeError("contents must be a FulfillmentReceiptContents instance")

    # Ensure contents include pmt_hash
    contents_with_chain = contents.model_copy(update={"pmt_hash": pmt_hash})

    # Calculate credential hash
    contents_dict = contents_with_chain.model_dump(exclude_none=True)
    cred_hash = compute_hash(contents_dict)

    # Build JWT payload
    now = int(time.time())
    payload = {
        "iss": merchant_did,
        "sub": merchant_did,
        "aud": shopper_did,
        "iat": now,
        "exp": now + ttl_seconds,
        "jti": contents_with_chain.id,
        "credential_type": "FulfillmentReceipt",
        "cred_hash": cred_hash,
    }

    # Build JWT header
    headers = {
        "alg": algorithm,
        "kid": merchant_kid,
        "typ": "JWT",
    }

    # Generate signature
    merchant_authorization = jwt.encode(
        payload,
        merchant_private_key,
        algorithm=algorithm,
        headers=headers,
    )

    # Build FulfillmentReceipt
    return FulfillmentReceipt(
        contents=contents_with_chain,
        merchant_authorization=merchant_authorization,
    )


def validate_credential(
    credential: PaymentReceipt | FulfillmentReceipt,
    merchant_public_key: str,
    merchant_algorithm: str,
    expected_shopper_did: str,
    expected_pmt_hash: str,
) -> dict:
    """Validate a Credential (PaymentReceipt or FulfillmentReceipt) and return the payload.

    Args:
        credential: PaymentReceipt or FulfillmentReceipt to validate.
        merchant_public_key: Merchant's public key for verification.
        merchant_algorithm: JWT algorithm (e.g., RS256).
        expected_shopper_did: DID of the shopper (expected audience).
        expected_pmt_hash: Hash of the preceding PaymentMandate in the chain.

    Returns:
        Decoded JWT payload from merchant_authorization.

    Raises:
        ValueError: If content hash or chain hash is invalid.
        jwt.InvalidTokenError: If JWT is invalid.
    """
    # 1. Determine expected credential type
    if isinstance(credential, PaymentReceipt):
        expected_cred_type = "PaymentReceipt"
    elif isinstance(credential, FulfillmentReceipt):
        expected_cred_type = "FulfillmentReceipt"
    else:
        raise TypeError(f"Unsupported credential type: {type(credential).__name__}")

    # 2. Verify the merchant's JWS
    payload = verify_jws_payload(
        token=credential.merchant_authorization,
        public_key=merchant_public_key,
        algorithm=merchant_algorithm,
        expected_audience=expected_shopper_did,
    )

    # 3. Verify the credential type from the payload
    cred_type_in_token = payload.get("credential_type")
    if cred_type_in_token != expected_cred_type:
        raise ValueError(
            f"credential_type mismatch: expected {expected_cred_type}, "
            f"got {cred_type_in_token}"
        )

    # 4. Verify the hash chain link
    contents_pmt_hash = credential.contents.pmt_hash
    if contents_pmt_hash != expected_pmt_hash:
        raise ValueError(
            f"pmt_hash mismatch: expected {expected_pmt_hash}, got {contents_pmt_hash}"
        )

    # 5. Compute and return the hash for this credential
    contents_dict = credential.contents.model_dump(exclude_none=True)
    computed_cred_hash = compute_hash(contents_dict)

    # 6. Verify cred_hash in JWT payload
    cred_hash_in_token = payload.get("cred_hash")
    if cred_hash_in_token != computed_cred_hash:
        raise ValueError(
            f"cred_hash mismatch: expected {computed_cred_hash}, "
            f"got {cred_hash_in_token}"
        )

    # Return payload only; caller may recompute cred_hash if needed
    return payload


__all__ = [
    # Building functions
    "build_payment_receipt",
    "build_fulfillment_receipt",
    # Verification
    "validate_credential",
]
