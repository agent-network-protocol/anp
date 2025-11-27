"""Credential convenience functions.

This module provides high-level functions for building and verifying
PaymentReceipt and FulfillmentReceipt credentials.
"""

import jwt

from anp.ap2.mandate import build_mandate, validate_mandate
from anp.ap2.models import (
    FulfillmentReceipt,
    FulfillmentReceiptContents,
    PaymentReceipt,
    PaymentReceiptContents,
)


def build_payment_receipt(
    contents: PaymentReceiptContents,
    pmt_hash: str,
    shopper_did: str,
    merchant_did: str,
    merchant_kid: str,
    merchant_private_key: str,
    algorithm: str = "ES256K",
    ttl_seconds: int = 15552000,
) -> PaymentReceipt:
    """Build a PaymentReceipt with merchant authorization.

    This is a convenience function that builds and signs a PaymentReceipt.

    Args:
        contents: Payment receipt contents
        pmt_hash: Hash of the preceding PaymentMandate in the chain
        shopper_did: Shopper DID
        merchant_did: Merchant DID
        merchant_kid: Merchant key identifier
        merchant_private_key: Merchant private key
        algorithm: JWT signing algorithm
        ttl_seconds: Time to live in seconds

    Returns:
        Built PaymentReceipt object
    """
    if not isinstance(contents, PaymentReceiptContents):
        raise TypeError("contents must be a PaymentReceiptContents instance")

    # Ensure contents include pmt_hash
    contents_with_chain = contents.model_copy(update={"pmt_hash": pmt_hash})
    contents_dict = contents_with_chain.model_dump(exclude_none=True)

    headers = {
        "alg": algorithm,
        "kid": merchant_kid,
        "typ": "JWT",
    }

    mandate = build_mandate(
        contents=contents_dict,
        private_key=merchant_private_key,
        headers=headers,
        iss=merchant_did,
        sub=merchant_did,
        aud=shopper_did,
        ttl_seconds=ttl_seconds,
        algorithm=algorithm,
        hash_field_name="cred_hash",
    )

    return PaymentReceipt.model_validate(
        {"contents": contents_dict, "merchant_authorization": mandate["auth"]}
    )


def build_fulfillment_receipt(
    contents: FulfillmentReceiptContents,
    pmt_hash: str,
    shopper_did: str,
    merchant_did: str,
    merchant_kid: str,
    merchant_private_key: str,
    algorithm: str = "ES256K",
    ttl_seconds: int = 15552000,
) -> FulfillmentReceipt:
    """Build a FulfillmentReceipt with merchant authorization.

    This is a convenience function that builds and signs a FulfillmentReceipt.

    Args:
        contents: Fulfillment receipt contents
        pmt_hash: Hash of the preceding PaymentMandate in the chain
        shopper_did: Shopper DID
        merchant_did: Merchant DID
        merchant_kid: Merchant key identifier
        merchant_private_key: Merchant private key
        algorithm: JWT signing algorithm
        ttl_seconds: Time to live in seconds

    Returns:
        Built FulfillmentReceipt object
    """
    if not isinstance(contents, FulfillmentReceiptContents):
        raise TypeError("contents must be a FulfillmentReceiptContents instance")

    contents_with_chain = contents.model_copy(update={"pmt_hash": pmt_hash})
    contents_dict = contents_with_chain.model_dump(exclude_none=True)

    headers = {
        "alg": algorithm,
        "kid": merchant_kid,
        "typ": "JWT",
    }

    mandate = build_mandate(
        contents=contents_dict,
        private_key=merchant_private_key,
        headers=headers,
        iss=merchant_did,
        sub=merchant_did,
        aud=shopper_did,
        ttl_seconds=ttl_seconds,
        algorithm=algorithm,
        hash_field_name="cred_hash",
    )

    return FulfillmentReceipt.model_validate(
        {"contents": contents_dict, "merchant_authorization": mandate["auth"]}
    )


def validate_credential(
    credential: PaymentReceipt | FulfillmentReceipt,
    expected_shopper_did: str,
    merchant_public_key: str,
    merchant_algorithm: str,
    expected_pmt_hash: str,
) -> bool:
    """Validate a Credential (PaymentReceipt or FulfillmentReceipt) and return the payload.

    Args:
        credential: PaymentReceipt or FulfillmentReceipt to validate.
        expected_shopper_did: DID of the shopper (expected audience).
        merchant_public_key: Merchant's public key for verification.
        merchant_algorithm: JWT algorithm (e.g., ES256K).
        expected_pmt_hash: Hash of the preceding PaymentMandate in the chain.

    Returns:
        True if the credential passes verification, False otherwise.

    Raises:
        TypeError: If the credential type is unsupported.
        jwt.InvalidTokenError: If JWT decoding fails (allowing caller to inspect failure reason).
    """
    if isinstance(credential, PaymentReceipt):
        expected_cred_type = "PaymentReceipt"
    elif isinstance(credential, FulfillmentReceipt):
        expected_cred_type = "FulfillmentReceipt"
    else:
        raise TypeError(f"Unsupported credential type: {type(credential).__name__}")

    credential_dict = {
        "contents": credential.contents,
        "auth": credential.merchant_authorization,
    }

    if not validate_mandate(
        mandate=credential_dict,
        public_key=merchant_public_key,
        algorithm=merchant_algorithm,
        expected_audience=expected_shopper_did,
        hash_field_name="cred_hash",
    ):
        return False

    payload = jwt.decode(
        credential.merchant_authorization,
        merchant_public_key,
        algorithms=[merchant_algorithm],
        audience=expected_shopper_did,
    )

    if payload.get("credential_type") != expected_cred_type:
        return False

    return credential.contents.get("pmt_hash") == expected_pmt_hash


__all__ = [
    # Building functions
    "build_payment_receipt",
    "build_fulfillment_receipt",
    # Verification
    "validate_credential",
]
