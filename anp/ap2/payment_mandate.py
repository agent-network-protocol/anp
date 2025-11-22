"""PaymentMandate utilities.

This module provides tools for building and verifying payment mandates.
"""

import time
import uuid
from typing import Any, Dict, Optional, Tuple

import jwt

from anp.ap2.models import (
    MoneyAmount,
    PaymentDetails,
    PaymentDetailsTotal,
    PaymentMandate,
    PaymentMandateContents,
    PaymentResponse,
    PaymentResponseDetails,
    ShippingAddress,
)
from anp.ap2.utils import JWTVerifier, compute_hash, verify_jws_payload


def build_payment_mandate_contents(
    payment_mandate_id: str,
    payment_details_id: str,
    total_amount: MoneyAmount,
    payment_details: PaymentResponseDetails,
    merchant_agent: str,
    prev_hash: str,
    method_name: str = "QR_CODE",
    refund_period: int = 30,
    shipping_address: Optional[ShippingAddress] = None,
) -> PaymentMandateContents:
    """Build PaymentMandateContents from business data."""

    payment_response = PaymentResponse(
        request_id=payment_details_id,
        method_name=method_name,
        details=payment_details,
        shipping_address=shipping_address,
    )

    return PaymentMandateContents(
        payment_mandate_id=payment_mandate_id,
        payment_details_id=payment_details_id,
        payment_details_total=PaymentDetailsTotal(
            label="Total",
            amount=total_amount,
            refund_period=refund_period,
        ),
        payment_response=payment_response,
        merchant_agent=merchant_agent,
        prev_hash=prev_hash,
    )


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

    if not contents.prev_hash:
        raise ValueError("contents.prev_hash must be set to maintain the hash chain")

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


class PaymentMandateValidator:
    """Validator for PaymentMandate objects.

    This stateless validator is composed with a JWTVerifier to check
    the signature, content integrity, and hash chain link of a PaymentMandate.
    """

    def __init__(self, shopper_jwt_verifier: JWTVerifier):
        """Initialize the validator.

        Args:
            shopper_jwt_verifier: A JWTVerifier configured with the shopper's public key.
        """
        self.jwt_verifier = shopper_jwt_verifier

    def validate(
        self,
        payment_mandate: PaymentMandate,
        expected_merchant_did: str,
        expected_cart_hash: str,
    ) -> Tuple[Dict[str, Any], str]:
        """Validate a PaymentMandate.

        Args:
            payment_mandate: The PaymentMandate object to validate.
            expected_merchant_did: The DID of the merchant (expected audience).
            expected_cart_hash: The hash of the preceding CartMandate in the chain.

        Returns:
            A tuple containing the decoded JWT payload and the computed pmt_hash.

        Raises:
            ValueError: If the content hash or chain hash is invalid.
            jwt.InvalidTokenError: If the JWT is invalid.
        """
        # 1. Verify the shopper's JWS
        payload = verify_jws_payload(
            token=payment_mandate.user_authorization,
            public_key=self.jwt_verifier.public_key,
            algorithm=self.jwt_verifier.algorithm,
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
                f"pmt_hash mismatch: expected {computed_pmt_hash}, "
                f"got {pmt_hash_in_token}"
            )

        # 3. Verify the hash chain link
        prev_hash = payment_mandate.payment_mandate_contents.prev_hash
        if prev_hash != expected_cart_hash:
            raise ValueError(
                f"prev_hash mismatch: expected {expected_cart_hash}, got {prev_hash}"
            )

        return payload, computed_pmt_hash


__all__ = [
    "build_payment_mandate_contents",
    "build_payment_mandate",
    "PaymentMandateValidator",
]
