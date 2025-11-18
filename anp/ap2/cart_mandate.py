"""CartMandate Request/Response utilities.

This module provides fast composition tools for CartMandate protocol,
serving both Client (TA) and Server (MA) developers.
"""

import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import jwt

from anp.ap2.models import (
    CartContents,
    CartMandate,
    CartMandateRequest,
    CartMandateRequestData,
    CartRequestItem,
    DisplayItem,
    MoneyAmount,
    PaymentDetails,
    PaymentDetailsTotal,
    PaymentMandateContents,
    PaymentMethodData,
    PaymentRequest,
    PaymentRequestOptions,
    PaymentResponse,
    QRCodePaymentData,
    ShippingAddress,
)
from anp.ap2.utils import JWTVerifier, compute_hash

# =============================================================================
# Request Builders (Client Side - TA)
# =============================================================================


def build_cart_mandate_request(
    cart_mandate_id: str,
    items: List[Dict[str, Any]],
    shipping_address: Dict[str, str],
    client_did: str,
    merchant_did: str,
    credential_webhook_url: Optional[str] = None,
    remark: Optional[str] = None,
) -> CartMandateRequest:
    """Create a cart mandate request from business data.

    This is for Client (TA) to initiate an order.

    Args:
        cart_mandate_id: Unique cart ID
        items: List of items [{"id": "sku-001", "quantity": 1, "amount": {...}, ...}]
        shipping_address: Shipping address dict
        client_did: Client's DID
        merchant_did: Merchant's DID
        credential_webhook_url: URL to receive credentials
        remark: Optional remark

    Returns:
        CartMandateRequest ready to send

    Example:
        >>> from anp.ap2.cart_mandate import build_cart_mandate_request
        >>> request = create_order_request(
        ...     cart_mandate_id="cart_123",
        ...     items=[{
        ...         "id": "sku-001",
        ...         "quantity": 1,
        ...         "amount": {"currency": "CNY", "value": 120.0},
        ...         "label": "Product Name"
        ...     }],
        ...     shipping_address={
        ...         "recipient_name": "张三",
        ...         "phone": "13800138000",
        ...         "region": "北京市",
        ...         "city": "北京市",
        ...         "address_line": "朝阳区某某街道123号",
        ...         "postal_code": "100000"
        ...     },
        ...     client_did="did:wba:didhost.cc:shopper",
        ...     merchant_did="did:wba:merchant.example.com:merchant"
        ... )
    """
    # Convert items to CartRequestItem
    cart_items = [
        CartRequestItem(
            id=item["id"],
            quantity=item["quantity"],
            amount=MoneyAmount(**item["amount"]),
            label=item.get("label"),
        )
        for item in items
    ]

    # Build request data
    request_data = CartMandateRequestData(
        cart_mandate_id=cart_mandate_id,
        items=cart_items,
        shipping_address=ShippingAddress(**shipping_address)
        if shipping_address
        else None,
    )

    # Build request message
    return CartMandateRequest(
        messageId=f"msg-{cart_mandate_id}",
        from_=client_did,
        to=merchant_did,
        credential_webhook_url=credential_webhook_url,
        data=request_data,
    )


# =============================================================================
# Response Builders (Server Side - MA)
# =============================================================================


def build_cart_mandate_response(
    order_id: str,
    items: List[Dict[str, Any]],
    total_amount: Dict[str, Any],
    merchant_private_key: str,
    merchant_did: str,
    merchant_kid: str,
    shopper_did: str,
    payment_method: str = "QR_CODE",
    payment_channel: str = "ALIPAY",
    qr_url: str = "",
    out_trade_no: str = "",
    shipping_address: Optional[Dict[str, str]] = None,
    algorithm: str = "RS256",
    ttl_seconds: int = 900,
) -> CartMandate:
    """Create a cart mandate response with merchant authorization.

    This is for Server (MA) to respond to order creation request.
    Auto-generates CartContents and signs with merchant key.

    Args:
        order_id: Order unique identifier
        items: List of items with full details
        total_amount: Total amount {"currency": "CNY", "value": 120.0}
        merchant_private_key: Merchant private key
        merchant_did: Merchant DID
        merchant_kid: Merchant key identifier
        shopper_did: Shopper DID
        payment_method: Payment method (default: QR_CODE)
        payment_channel: Payment channel (default: ALIPAY)
        qr_url: QR code URL for payment
        out_trade_no: External trade number
        shipping_address: Shipping address (optional)
        algorithm: JWT algorithm
        ttl_seconds: Time to live

    Returns:
        CartMandate with merchant authorization

    Example:
        >>> from anp.ap2.cart_mandate import build_cart_mandate_response
        >>> cart_mandate = create_order_response(
        ...     order_id="order_123",
        ...     items=[{
        ...         "id": "sku-001",
        ...         "sku": "Product-SKU",
        ...         "label": "Product Name",
        ...         "quantity": 1,
        ...         "amount": {"currency": "CNY", "value": 120.0}
        ...     }],
        ...     total_amount={"currency": "CNY", "value": 120.0},
        ...     merchant_private_key=key,
        ...     merchant_did="did:wba:merchant.example.com:merchant",
        ...     merchant_kid="merchant-key-001",
        ...     shopper_did="did:wba:didhost.cc:shopper",
        ...     qr_url="https://qr.alipay.com/...",
        ...     out_trade_no="trade_20250117_001"
        ... )
    """
    # Build display items
    display_items = [
        DisplayItem(
            id=item["id"],
            sku=item.get("sku", item["id"]),
            label=item.get("label", item["id"]),
            quantity=item["quantity"],
            amount=MoneyAmount(**item["amount"]),
            options=item.get("options"),
            remark=item.get("remark"),
        )
        for item in items
    ]

    # Build payment request
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
            displayItems=display_items,
            total=PaymentDetailsTotal(
                label="Total", amount=MoneyAmount(**total_amount)
            ),
            shipping_address=ShippingAddress(**shipping_address)
            if shipping_address
            else None,
        ),
        options=PaymentRequestOptions(requestShipping=shipping_address is not None),
    )

    # Build cart contents
    cart_contents = CartContents(
        id=f"cart_{order_id}",
        user_signature_required=False,
        timestamp=datetime.now(timezone.utc).isoformat(),
        payment_request=payment_request,
    )

    # Build and sign CartMandate directly
    contents_dict = cart_contents.model_dump(exclude_none=True)
    cart_hash = compute_hash(contents_dict)

    # Build JWT payload
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

    return CartMandate(
        contents=cart_contents,
        merchant_authorization=merchant_authorization,
    )


# =============================================================================
# Verification
# =============================================================================


def verify_cart_mandate_request(
    request: CartMandateRequest,
    expected_merchant_did: str,
) -> Dict[str, Any]:
    """Verify an incoming order request from Client (TA).

    Validates the request structure and extracts business data.

    Args:
        request: CartMandateRequest from client
        expected_merchant_did: This server's DID

    Returns:
        Extracted business data dict

    Raises:
        ValueError: If request is invalid

    Example:
        >>> from anp.ap2.cart_mandate import verify_cart_mandate_request
        >>> order_data = verify_order_request(request, merchant_did)
        >>> # Process order_data in your business logic
    """
    # Verify recipient
    if request.to != expected_merchant_did:
        raise ValueError(f"Request not for this merchant: {request.to}")

    # Extract and return business data
    return {
        "cart_mandate_id": request.data.cart_mandate_id,
        "items": [item.model_dump() for item in request.data.items],
        "shipping_address": request.data.shipping_address.model_dump()
        if request.data.shipping_address
        else None,
        "client_did": request.from_,
        "webhook_url": request.credential_webhook_url,
    }


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
        # 1. Verify the merchant's JWS
        payload = self.jwt_verifier.verify(
            cart_mandate.merchant_authorization, expected_audience=expected_shopper_did
        )

        # 2. Verify the content hash
        contents_dict = cart_mandate.contents.model_dump(exclude_none=True)
        computed_cart_hash = compute_hash(contents_dict)

        cart_hash_in_token = payload.get("cart_hash")
        if cart_hash_in_token != computed_cart_hash:
            raise ValueError(
                f"cart_hash mismatch: expected {computed_cart_hash}, "
                f"got {cart_hash_in_token}"
            )

        return payload, computed_cart_hash


# =============================================================================
# Utility Functions
# =============================================================================


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
    # Request builders (Client side)
    "build_cart_mandate_request",
    # Response builders (Server side)
    "build_cart_mandate_response",
    # Verification
    "verify_cart_mandate_request",
    "CartMandateValidator",
]
