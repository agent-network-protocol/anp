"""CartMandate utilities.

This module provides builders for CartMandate contents and signatures plus
helper validation utilities for merchants and shoppers.
"""

import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Sequence, Tuple

import jwt

from anp.ap2.models import (
    CartContents,
    CartMandate,
    DisplayItem,
    MoneyAmount,
    PaymentDetails,
    PaymentDetailsTotal,
    PaymentMethodData,
    PaymentRequest,
    PaymentRequestOptions,
    QRCodePaymentData,
    ShippingAddress,
)
from anp.ap2.utils import JWTVerifier, compute_hash, verify_jws_payload


def build_cart_mandate_contents(
    order_id: str,
    items: Sequence[DisplayItem],
    total_amount: MoneyAmount,
    shipping_address: Optional[ShippingAddress] = None,
    payment_method: str = "QR_CODE",
    payment_channel: str = "ALIPAY",
    qr_url: str = "",
    out_trade_no: str = "",
) -> CartContents:
    """Build CartMandate contents from business models."""

    payment_request = PaymentRequest(
        method_data=[
            PaymentMethodData(
                supported_methods=payment_method,
                data=QRCodePaymentData(
                    channel=payment_channel,
                    qr_url=qr_url,
                    out_trade_no=out_trade_no,
                ),
            )
        ],
        details=PaymentDetails(
            id=order_id,
            displayItems=list(items),
            total=PaymentDetailsTotal(label="Total", amount=total_amount),
            shipping_address=shipping_address,
        ),
        options=PaymentRequestOptions(requestShipping=shipping_address is not None),
    )

    return CartContents(
        id=f"cart_{order_id}",
        user_signature_required=False,
        timestamp=datetime.now(timezone.utc).isoformat(),
        payment_request=payment_request,
    )


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


class CartMandateValidator:
    """Validator for CartMandate objects.

    This stateless validator is composed with a JWTVerifier to check
    the signature and content integrity of a CartMandate.
    """

    def __init__(self, merchant_jwt_verifier: JWTVerifier):
        """Initialize the validator.

        Args:
            merchant_jwt_verifier: A JWTVerifier configured with the merchant's public key.
        """
        self.jwt_verifier = merchant_jwt_verifier

    def validate(
        self,
        cart_mandate: CartMandate,
        expected_shopper_did: str,
    ) -> Tuple[Dict[str, Any], str]:
        """Validate a CartMandate.

        Args:
            cart_mandate: The CartMandate object to validate.
            expected_shopper_did: The DID of the shopper (expected audience).

        Returns:
            A tuple containing the decoded JWT payload and the computed cart_hash.

        Raises:
            ValueError: If the cart_hash does not match the content.
            jwt.InvalidTokenError: If the JWT is invalid.
        """
        payload = verify_jws_payload(
            token=cart_mandate.merchant_authorization,
            public_key=self.jwt_verifier.public_key,
            algorithm=self.jwt_verifier.algorithm,
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

        return payload, computed_cart_hash


def extract_cart_hash(cart_mandate: CartMandate) -> str:
    """Extract cart_hash from CartMandate without verification.

    WARNING: This does not verify the signature! Use only when you trust the source.

    Args:
        cart_mandate: CartMandate object

    Returns:
        cart_hash string
    """
    contents_dict = cart_mandate.contents.model_dump(exclude_none=True)
    return compute_hash(contents_dict)


__all__ = [
    "build_cart_mandate_contents",
    "build_cart_mandate",
    "CartMandateValidator",
    "extract_cart_hash",
]
