"""PaymentMandate Request/Response utilities.

This module provides tools for payment authorization protocol.
"""

from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timezone
import time
import uuid

import jwt

from anp.ap2.models import (
    PaymentMandate,
    PaymentMandateContents,
    PaymentMandateRequest,
    PaymentDetailsTotal,
    PaymentResponse,
    MoneyAmount,
    ShippingAddress,
)
from anp.ap2.utils import compute_hash, JWTVerifier


# =============================================================================
# Request Builders (Client Side - TA)
# =============================================================================

def build_payment_mandate_response(
    payment_mandate_id: str,
    order_id: str,
    total_amount: Dict[str, Any],
    payment_details: Dict[str, Any],
    cart_hash: str,
    user_private_key: str,
    user_did: str,
    user_kid: str,
    merchant_did: str,
    merchant_agent: str = "MerchantAgent",
    refund_period: int = 30,
    shipping_address: Optional[Dict[str, str]] = None,
    algorithm: str = "RS256",
) -> PaymentMandate:
    """Create a payment mandate response with shopper authorization.

    This is for Client (TA) to authorize payment after cart creation and
    return a signed PaymentMandate that can be embedded in a request message.

    Args:
        payment_mandate_id: Unique payment ID
        order_id: Order ID from CartMandate
        total_amount: Total amount dict {"currency": "CNY", "value": 120.0}
        payment_details: Payment method details (channel, out_trade_no, etc.)
        cart_hash: Cart hash from verified CartMandate
        user_private_key: User's private key
        user_did: User's DID
        user_kid: User's key identifier
        merchant_did: Merchant's DID
        merchant_agent: Merchant agent identifier
        refund_period: Refund period in days
        shipping_address: Shipping address (optional)
        algorithm: JWT algorithm

    Returns:
        Signed PaymentMandate

    Example:
        >>> from anp.ap2.payment_mandate import build_payment_mandate_response
        >>> mandate = create_payment_response(
        ...     payment_mandate_id="pm_123",
        ...     order_id="order_123",
        ...     total_amount={"currency": "CNY", "value": 120.0},
        ...     payment_details={"channel": "ALIPAY", "out_trade_no": "trade_001"},
        ...     cart_hash="abc123...",
        ...     user_private_key=key,
        ...     user_did="did:wba:didhost.cc:shopper",
        ...     user_kid="shopper-key-001",
        ...     merchant_did="did:wba:merchant.example.com:merchant"
        ... )
    """
    # Build payment mandate contents
    pmt_contents = PaymentMandateContents(
        payment_mandate_id=payment_mandate_id,
        payment_details_id=order_id,
        payment_details_total=PaymentDetailsTotal(
            label="Total",
            amount=MoneyAmount(**total_amount),
            refund_period=refund_period,
        ),
        payment_response=PaymentResponse(
            request_id=order_id,
            method_name=payment_details.get("method_name", "QR_CODE"),
            details=payment_details,
            shipping_address=ShippingAddress(**shipping_address) if shipping_address else None,
        ),
        merchant_agent=merchant_agent,
        timestamp=datetime.now(timezone.utc).isoformat(),
        prev_hash=cart_hash,  # Set prev_hash directly
    )

    # Calculate pmt_hash
    contents_dict = pmt_contents.model_dump(exclude_none=True)
    pmt_hash = compute_hash(contents_dict)

    # Build JWT payload (chain via contents.prev_hash, not transaction_data)
    now = int(time.time())
    payload = {
        "iss": user_did,
        "sub": user_did,
        "aud": merchant_did,
        "iat": now,
        "exp": now + 15552000,  # 180 days
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
    payment_mandate = PaymentMandate(
        payment_mandate_contents=pmt_contents,
        user_authorization=user_authorization,
    )

    return payment_mandate


def build_payment_mandate_request(
    payment_mandate_id: str,
    order_id: str,
    total_amount: Dict[str, Any],
    payment_details: Dict[str, Any],
    cart_hash: str,
    user_private_key: str,
    user_did: str,
    user_kid: str,
    merchant_did: str,
    merchant_agent: str = "MerchantAgent",
    refund_period: int = 30,
    shipping_address: Optional[Dict[str, str]] = None,
    algorithm: str = "RS256",
) -> PaymentMandateRequest:
    """Wrap a signed PaymentMandate into an ANP request message."""

    payment_mandate = build_payment_mandate_response(
        payment_mandate_id=payment_mandate_id,
        order_id=order_id,
        total_amount=total_amount,
        payment_details=payment_details,
        cart_hash=cart_hash,
        user_private_key=user_private_key,
        user_did=user_did,
        user_kid=user_kid,
        merchant_did=merchant_did,
        merchant_agent=merchant_agent,
        refund_period=refund_period,
        shipping_address=shipping_address,
        algorithm=algorithm,
    )

    return PaymentMandateRequest(
        messageId=f"msg-{payment_mandate_id}",
        from_=user_did,
        to=merchant_did,
        data=payment_mandate,
    )


# =============================================================================
# Verification
# =============================================================================

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
        payload = self.jwt_verifier.verify(
            payment_mandate.user_authorization,
            expected_audience=expected_merchant_did
        )

        # 2. Verify the content hash (pmt_hash)
        contents_dict = payment_mandate.payment_mandate_contents.model_dump(exclude_none=True)
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
    # Request builders (Client side)
    "build_payment_mandate_response",
    "build_payment_mandate_request",
    
    # Verification
    "PaymentMandateValidator",
]
