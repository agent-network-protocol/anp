"""AP2 Merchant Agent - Stateless Protocol Implementation.

This module provides a stateless Merchant Agent for the AP2 protocol.
The agent DOES NOT manage business state - that's your responsibility.

Design Philosophy:
- Stateless: No session management, no database
- Protocol-focused: Only handles signing and verification
- Pure functions: Predictable, testable, composable
"""

import logging
from typing import Any, Optional, Sequence

from anp.ap2 import (
    ANPMessage,
    CartContents,
    CartMandate,
    CartMandateRequestData,
    DisplayItem,
    FulfillmentReceipt,
    MoneyAmount,
    PaymentDetails,
    PaymentDetailsTotal,
    PaymentMandate,
    PaymentReceipt,
    PaymentRequest,
    PaymentRequestOptions,
    PaymentMethodData,
    QRCodePaymentData,
    ShippingAddress,
)
from anp.ap2.cart_mandate import build_cart_mandate
from anp.ap2.credential_mandate import (
    build_fulfillment_receipt,
    build_payment_receipt,
)
from anp.ap2.payment_mandate import validate_payment_mandate
from anp.ap2.utils import compute_hash

logger = logging.getLogger(__name__)


class MerchantAgent:
    """Stateless AP2 Merchant Agent.

    This agent provides protocol-level operations for building and verifying
    AP2 mandates. It does NOT manage business state (sessions, hashes, etc.).

    Design:
    - Stateless: No instance variables for business data
    - Pure methods: Same input -> same output
    - Your responsibility: State management, database, cache

    Example Usage:
        ```python
        # Initialize once with credentials
        agent = MerchantAgent(
            merchant_private_key=load_key("merchant.pem"),
            merchant_did="did:wba:merchant.example.com:shop",
            merchant_kid="key-1",
        )

        # Build CartMandate (stateless)
        cart_response = agent.build_cart_mandate_response(
            message_id="cart-response-order-123",
            request_from="did:wba:shopper.example.com:alice",
            order_id="order-123",
            items=[...],
            total_amount=MoneyAmount(currency="CNY", value=120.0),
            shopper_did="did:wba:shopper.example.com:alice",
        )

        # YOU manage state
        verified_cart = CartMandateValidator(...).validate(cart_mandate, expected_shopper_did)
        await my_db.save_cart_hash(order_id="order-123", cart_hash=verified_cart.cart_hash)

        # Verify PaymentMandate (stateless - you provide VerifiedCartMandate)
        verified_payment = agent.verify_payment_mandate(
            payment_mandate=payment_request.data,
            verified_cart=verified_cart,
            shopper_public_key=await resolve_did(shopper_did),
        )

        # YOU store verified_payment.pmt_hash for credential issuance
        await my_db.save_pmt_hash(order_id="order-123", pmt_hash=verified_payment.pmt_hash)
        ```
    """

    def __init__(
        self,
        merchant_private_key: str,
        merchant_did: str,
        merchant_kid: str,
        algorithm: str = "RS256",
    ):
        """Initialize the Merchant Agent.

        Args:
            merchant_private_key: Merchant's private key for JWS signing
            merchant_did: Merchant's DID
            merchant_kid: Merchant's key ID for JWS signing
            algorithm: JWT algorithm (RS256 or ES256K)

        Note:
            This agent is STATELESS. It does not store sessions or business data.
            You must manage cart_hash, pmt_hash, and other state yourself.
        """
        self.merchant_private_key = merchant_private_key
        self.merchant_did = merchant_did
        self.merchant_kid = merchant_kid
        self.algorithm = algorithm

    def verify_cart_mandate_request(
        self,
        request: ANPMessage,
    ) -> dict[str, Any]:
        """Verify an incoming cart creation request.

        Args:
            request: ANPMessage containing CartMandateRequestData

        Returns:
            Dict containing extracted business data

        Raises:
            ValueError: If request validation fails
            TypeError: If message data payload is not CartMandateRequestData

        Example:
            >>> order_data = agent.verify_cart_mandate_request(cart_request)
            >>> # order_data contains: cart_mandate_id, items, shipping_address, etc.
        """
        if request.to != self.merchant_did:
            raise ValueError(f"Request not for this merchant: {request.to}")

        if not isinstance(request.data, CartMandateRequestData):
            raise TypeError(
                "Invalid message data type: expected CartMandateRequestData"
            )

        return {
            "cart_mandate_id": request.data.cart_mandate_id,
            "items": [item.model_dump() for item in request.data.items],
            "shipping_address": request.data.shipping_address.model_dump()
            if request.data.shipping_address
            else None,
            "client_did": request.from_,
            "webhook_url": request.credential_webhook_url,
        }

    def build_cart_mandate_response(
        self,
        message_id: str,
        request_from: Optional[str],
        order_id: str,
        items: Sequence[DisplayItem],
        total_amount: MoneyAmount,
        shopper_did: Optional[str] = None,
        payment_method: str = "QR_CODE",
        payment_channel: str = "ALIPAY",
        qr_url: str = "",
        out_trade_no: str = "",
        shipping_address: Optional[ShippingAddress] = None,
        ttl_seconds: int = 900,
    ) -> ANPMessage:
        """Build a CartMandate response (stateless).

        This method builds a signed CartMandate and wraps it in an ANPMessage.
        You must extract and store cart_hash from the contained CartMandate yourself.

        Args:
            order_id: Order unique identifier
            items: List of items with full details
            total_amount: Total amount as MoneyAmount model
            shopper_did: Shopper's DID
            payment_method: Payment method (default: QR_CODE)
            payment_channel: Payment channel (default: ALIPAY)
            qr_url: QR code URL for payment
            out_trade_no: External trade number
            shipping_address: Shipping address (optional)
            ttl_seconds: JWT Time to live in seconds (default: 900 = 15 minutes)

        Returns:
            ANPMessage containing the CartMandate

        Example:
            >>> from anp.ap2.utils import compute_hash
            >>> from anp.ap2.models import CartMandate
            >>>
            >>> # 1. Build CartMandate response message
            >>> items = [
            ...     DisplayItem(
            ...         id="sku-001",
            ...         label="Product A",
            ...         quantity=1,
            ...         amount=MoneyAmount(currency="CNY", value=120.0),
            ...     )
            ... ]
            >>> response_message = agent.build_cart_mandate_response(
            ...     message_id="cart-response-order-123",
            ...     request_from="did:wba:shopper.example.com:alice",
            ...     order_id="order-123",
            ...     items=items,
            ...     total_amount=MoneyAmount(currency="CNY", value=120.0),
            ...     shopper_did="did:wba:shopper.example.com:alice",
            ...     qr_url="https://qr.alipay.com/12345",
            ...     out_trade_no="trade-order-123",
            ... )
            >>>
            >>> # 2. YOU extract and store cart_hash from the data payload
            >>> if isinstance(response_message.data, CartMandate):
            ...     cart_hash = compute_hash(
            ...         response_message.data.contents.model_dump(exclude_none=True)
            ...     )
            ...     await my_database.save(
            ...         order_id="order-123",
            ...         cart_hash=cart_hash,
            ...         shopper_did=shopper_did,
            ...     )
        """
        resolved_shopper_did = shopper_did or request_from
        if not resolved_shopper_did:
            raise ValueError("shopper_did or request_from must be provided")

        resolved_message_id = message_id or f"cart-response-{order_id}"

        if not all(isinstance(item, DisplayItem) for item in items):
            raise TypeError("All items must be DisplayItem instances")

        if not isinstance(total_amount, MoneyAmount):
            raise TypeError("total_amount must be a MoneyAmount instance")

        logger.info(f"Building CartMandate for order_id={order_id}")
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

        contents = CartContents(
            id=f"cart_{order_id}",
            user_signature_required=False,
            payment_request=payment_request,
        )

        cart_mandate_obj = build_cart_mandate(
            contents=contents,
            merchant_private_key=self.merchant_private_key,
            merchant_did=self.merchant_did,
            merchant_kid=self.merchant_kid,
            shopper_did=resolved_shopper_did,
            algorithm=self.algorithm,
            ttl_seconds=ttl_seconds,
        )

        response = ANPMessage(
            messageId=resolved_message_id,
            **{"from": self.merchant_did},
            to=resolved_shopper_did,
            data=cart_mandate_obj,
        )

        logger.debug(f"CartMandate built successfully for order_id={order_id}")

        return response

    def verify_payment_mandate(
        self,
        request: ANPMessage,
        cart_hash: str,
        shopper_public_key: str,
    ) -> dict[str, Any]:
        """Verify an incoming PaymentMandate message (stateless).

        This method verifies the signature and hash chain of a PaymentMandate
        contained within an ANPMessage. It does NOT store the resulting state.
        You must provide the cart_hash from your own storage.

        Args:
            request: ANPMessage containing the PaymentMandate to verify
            cart_hash: The cart_hash you stored earlier
            shopper_public_key: Shopper's public key for JWT verification

        Returns:
            Dict containing decoded JWT payload with pmt_hash computed.

        Raises:
            ValueError: If signature or hash chain verification fails
            TypeError: If the message data payload is not a PaymentMandate

        Example:
            >>> # 1. YOU retrieve cart_hash from your storage
            >>> cart_hash = await my_database.get_cart_hash(order_id)
            >>>
            >>> # 2. Resolve shopper's public key (your logic)
            >>> shopper_pubkey = await resolve_did(payment_request.from_)
            >>>
            >>> # 3. Verify (agent is stateless)
            >>> payload = agent.verify_payment_mandate(
            ...     request=payment_request_message,
            ...     cart_hash=cart_hash,
            ...     shopper_public_key=shopper_pubkey,
            ... )
            >>>
            >>> # 4. YOU compute and store pmt_hash
            >>> pmt_hash = compute_hash(request.data.payment_mandate_contents.model_dump(exclude_none=True))
            >>> await my_database.save_pmt_hash(order_id, pmt_hash)
            >>> logger.info(f"Payment verified for order {order_id}")
        """
        logger.info(f"Verifying ANPMessage with PaymentMandate from {request.from_}")

        # Verify ANP message routing
        if request.to != self.merchant_did:
            raise ValueError(
                f"Payment mandate not for this merchant: "
                f"expected {self.merchant_did}, got {request.to}"
            )

        # Extract PaymentMandate from ANP message
        if not isinstance(request.data, PaymentMandate):
            raise TypeError("Invalid message data type: expected PaymentMandate")

        payment_mandate = request.data
        logger.debug(f"Expected cart_hash: {cart_hash[:16]}...")

        # Verify payment mandate signature and hash chain
        payload = validate_payment_mandate(
            payment_mandate=payment_mandate,
            shopper_public_key=shopper_public_key,
            shopper_algorithm=self.algorithm,
            expected_merchant_did=self.merchant_did,
            expected_cart_hash=cart_hash,
        )

        # Additional security: JWT issuer should match message sender
        jwt_issuer = payload.get("iss")
        if jwt_issuer != request.from_:
            raise ValueError(
                f"JWT issuer ({jwt_issuer}) does not match "
                f"message sender ({request.from_})"
            )

        # Compute pmt_hash for caller
        pmt_hash = compute_hash(
            payment_mandate.payment_mandate_contents.model_dump(exclude_none=True)
        )
        logger.info("PaymentMandate verified: pmt_hash=%s...", pmt_hash[:16])

        return {"payload": payload, "pmt_hash": pmt_hash}

    def build_payment_receipt(
        self,
        payment_receipt_contents: Any,
        pmt_hash: str,
        shopper_did: str,
        ttl_seconds: int = 15552000,
    ) -> PaymentReceipt:
        """Build a PaymentReceipt credential (stateless).

        This method builds and signs a PaymentReceipt but does NOT retrieve stored state.
        You must provide the pmt_hash from your own storage.

        Args:
            payment_receipt_contents: Payment receipt contents
            pmt_hash: The pmt_hash you stored earlier
            shopper_did: Shopper's DID
            ttl_seconds: JWT Time to live in seconds (default: 180 days)

        Returns:
            PaymentReceipt with merchant authorization

        Example:
            >>> from anp.ap2.models import (
            ...     PaymentReceiptContents,
            ...     PaymentProvider,
            ...     PaymentStatus,
            ...     MoneyAmount,
            ... )
            >>>
            >>> # 1. YOU retrieve pmt_hash from your storage
            >>> pmt_hash = await my_db.get_pmt_hash(order_id)
            >>>
            >>> # 2. Build PaymentReceipt
            >>> contents = PaymentReceiptContents(
            ...     payment_mandate_id="pm-123",
            ...     provider=PaymentProvider.ALIPAY,
            ...     status=PaymentStatus.SUCCEEDED,
            ...     transaction_id="alipay_txn_123",
            ...     out_trade_no="trade-order-123",
            ...     paid_at="2025-01-18T08:00:00Z",
            ...     amount=MoneyAmount(currency="CNY", value=120.0),
            ... )
            >>>
            >>> receipt = agent.build_payment_receipt(
            ...     payment_receipt_contents=contents,
            ...     pmt_hash=pmt_hash,
            ...     shopper_did="did:wba:shopper.example.com:alice",
            ... )
            >>>
            >>> # 3. Send to shopper via webhook
            >>> await send_credential_to_shopper(receipt, webhook_url)
        """
        logger.info("Building PaymentReceipt")

        return build_payment_receipt(
            contents=payment_receipt_contents,
            pmt_hash=pmt_hash,
            merchant_private_key=self.merchant_private_key,
            merchant_did=self.merchant_did,
            merchant_kid=self.merchant_kid,
            algorithm=self.algorithm,
            shopper_did=shopper_did,
            ttl_seconds=ttl_seconds,
        )

    def build_fulfillment_receipt(
        self,
        fulfillment_receipt_contents: Any,
        pmt_hash: str,
        shopper_did: str,
        ttl_seconds: int = 15552000,
    ) -> FulfillmentReceipt:
        """Build a FulfillmentReceipt credential (stateless).

        This method builds and signs a FulfillmentReceipt but does NOT retrieve stored state.
        You must provide the pmt_hash from your own storage.

        Args:
            fulfillment_receipt_contents: Fulfillment receipt contents
            pmt_hash: The pmt_hash you stored earlier
            shopper_did: Shopper's DID
            ttl_seconds: JWT Time to live in seconds (default: 180 days)

        Returns:
            FulfillmentReceipt with merchant authorization

        Example:
            >>> from anp.ap2.models import FulfillmentReceiptContents, FulfillmentItem
            >>>
            >>> # 1. YOU retrieve pmt_hash from your storage
            >>> pmt_hash = await my_db.get_pmt_hash(order_id)
            >>>
            >>> # 2. Build FulfillmentReceipt
            >>> contents = FulfillmentReceiptContents(
            ...     order_id="order-123",
            ...     items=[FulfillmentItem(id="sku-001", quantity=1)],
            ...     fulfilled_at="2025-01-18T10:00:00Z",
            ...     tracking_number="SF1234567890",
            ... )
            >>>
            >>> receipt = agent.build_fulfillment_receipt(
            ...     fulfillment_receipt_contents=contents,
            ...     pmt_hash=pmt_hash,
            ...     shopper_did="did:wba:shopper.example.com:alice",
            ... )
            >>>
            >>> # 3. Send to shopper via webhook
            >>> await send_credential_to_shopper(receipt, webhook_url)
        """
        logger.info("Building FulfillmentReceipt")

        return build_fulfillment_receipt(
            contents=fulfillment_receipt_contents,
            pmt_hash=pmt_hash,
            merchant_private_key=self.merchant_private_key,
            merchant_did=self.merchant_did,
            merchant_kid=self.merchant_kid,
            algorithm=self.algorithm,
            shopper_did=shopper_did,
            ttl_seconds=ttl_seconds,
        )


__all__ = ["MerchantAgent"]
