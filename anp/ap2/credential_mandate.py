"""Credential convenience functions.

This module provides high-level functions for building and verifying
PaymentReceipt and FulfillmentReceipt credentials.
"""

import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

import jwt

from anp.ap2.models import (
    FulfillmentReceipt,
    FulfillmentReceiptContents,
    PaymentReceipt,
    PaymentReceiptContents,
)
from anp.ap2.utils import JWTVerifier, compute_hash, verify_jws_payload


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
        pmt_hash: Payment mandate hash from PaymentMandate
        merchant_private_key: Merchant private key
        merchant_did: Merchant DID
        merchant_kid: Merchant key identifier
        algorithm: JWT signing algorithm
        shopper_did: Shopper DID (optional)
        ttl_seconds: Time to live in seconds

    Returns:
        Built PaymentReceipt object

    Example:
        >>> from anp.ap2.credential_mandate import build_payment_receipt
        >>> from anp.ap2.models import PaymentReceiptContents, PaymentProvider, PaymentStatus, MoneyAmount
        >>> contents = PaymentReceiptContents(
        ...     payment_mandate_id="pm_123",
        ...     provider=PaymentProvider.ALIPAY,
        ...     status=PaymentStatus.SUCCEEDED,
        ...     transaction_id="alipay_txn_123",
        ...     out_trade_no="trade_001",
        ...     paid_at="2025-01-17T08:00:00Z",
        ...     amount=MoneyAmount(currency="CNY", value=120.0)
        ... )
        >>> receipt = build_payment_receipt(
        ...     contents=contents,
        ...     pmt_hash="def456...",
        ...     merchant_private_key=key,
        ...     merchant_did="did:wba:merchant.example.com:merchant",
        ...     merchant_kid="merchant-key-001"
        ... )
    """
    if not isinstance(contents, PaymentReceiptContents):
        raise TypeError("contents must be a PaymentReceiptContents instance")

    # Generate credential ID and timestamp
    credential_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()

    # Ensure contents include timestamp and chaining info
    contents_with_chain = contents.model_copy(
        update={"timestamp": timestamp, "prev_hash": pmt_hash}
    )

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
        "jti": credential_id,
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
        id=credential_id,
        timestamp=timestamp,
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
        pmt_hash: Payment mandate hash from PaymentMandate
        merchant_private_key: Merchant private key
        merchant_did: Merchant DID
        merchant_kid: Merchant key identifier
        algorithm: JWT signing algorithm
        shopper_did: Shopper DID (optional)
        ttl_seconds: Time to live in seconds

    Returns:
        Built FulfillmentReceipt object

    Example:
        >>> from anp.ap2.credential_mandate import build_fulfillment_receipt
        >>> from anp.ap2.models import FulfillmentReceiptContents, FulfillmentItem
        >>> contents = FulfillmentReceiptContents(
        ...     order_id="order_123",
        ...     items=[FulfillmentItem(id="sku-001", quantity=1)],
        ...     fulfilled_at="2025-01-17T10:00:00Z"
        ... )
        >>> receipt = build_fulfillment_receipt(
        ...     contents=contents,
        ...     pmt_hash="def456...",
        ...     merchant_private_key=key,
        ...     merchant_did="did:wba:merchant.example.com:merchant",
        ...     merchant_kid="merchant-key-001"
        ... )
    """
    if not isinstance(contents, FulfillmentReceiptContents):
        raise TypeError("contents must be a FulfillmentReceiptContents instance")

    # Generate credential ID and timestamp
    credential_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()

    # Ensure contents include timestamp and chaining info
    contents_with_chain = contents.model_copy(
        update={"timestamp": timestamp, "prev_hash": pmt_hash}
    )

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
        "jti": credential_id,
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
        id=credential_id,
        timestamp=timestamp,
        contents=contents_with_chain,
        merchant_authorization=merchant_authorization,
    )


# =============================================================================
# Verification
# =============================================================================


class CredentialValidator:
    """Validator for Credential objects (PaymentReceipt, FulfillmentReceipt).

    This stateless validator is composed with a JWTVerifier to check
    the signature, content integrity, and hash chain link of a Credential.
    """

    def __init__(self, merchant_jwt_verifier: JWTVerifier):
        """Initialize the validator.

        Args:
            merchant_jwt_verifier: A JWTVerifier configured with the merchant's public key.
        """
        self.jwt_verifier = merchant_jwt_verifier

    def validate(
        self,
        credential: PaymentReceipt | FulfillmentReceipt,
        expected_shopper_did: str,
        expected_pmt_hash: str,
    ) -> Tuple[Dict[str, Any], str]:
        """Validate a Credential.

        Args:
            credential: The PaymentReceipt or FulfillmentReceipt to validate.
            expected_shopper_did: The DID of the shopper (expected audience).
            expected_pmt_hash: The hash of the preceding PaymentMandate in the chain.

        Returns:
            A tuple containing the decoded JWT payload and the computed credential_hash.

        Raises:
            ValueError: If the credential type or chain hash is invalid.
            jwt.InvalidTokenError: If the JWT is invalid.
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
            public_key=self.jwt_verifier.public_key,
            algorithm=self.jwt_verifier.algorithm,
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
        prev_hash = credential.contents.prev_hash
        if prev_hash != expected_pmt_hash:
            raise ValueError(
                f"prev_hash mismatch: expected {expected_pmt_hash}, got {prev_hash}"
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

        return payload, computed_cred_hash


__all__ = [
    # Building functions
    "build_payment_receipt",
    "build_fulfillment_receipt",
    # Verification
    "CredentialValidator",
]
