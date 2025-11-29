"""AP2 Merchant Agent - Stateless Protocol Implementation.

This module provides a stateless Merchant Agent for the AP2 protocol.
The agent DOES NOT manage business state - that's your responsibility.
启动顺序：请将 merchant_agent 作为独立服务先运行，再启动 shopper_agent（参考 ap2_complete_flow.py）。

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
    CartMandateRequestData,
    DisplayItem,
    FulfillmentReceipt,
    MoneyAmount,
    PaymentDetails,
    PaymentDetailsTotal,
    PaymentMandate,
    PaymentMethodData,
    PaymentProvider,
    PaymentReceipt,
    PaymentRequest,
    PaymentRequestOptions,
    QRCodePaymentData,
    ShippingAddress,
)
from anp.ap2.cart_mandate import build_cart_mandate
from anp.ap2.credential_mandate import (
    build_fulfillment_receipt,
    build_payment_receipt,
)
from anp.ap2.mandate import compute_hash
from anp.ap2.payment_mandate import validate_payment_mandate

logger = logging.getLogger(__name__)


class MerchantAgent:
    """Stateless AP2 Merchant Agent.

    This agent provides protocol-level operations for building and verifying
    AP2 mandates. It does NOT manage business state (sessions, hashes, etc.).

    Design:
    - Stateless: No instance variables for business data
    - Pure methods: Same input -> same output
    - Your responsibility: State management, database, cache

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
        """
        if request.to != self.merchant_did:
            raise ValueError(f"Request not for this merchant: {request.to}")

        # Parse data dict to CartMandateRequestData
        try:
            data = CartMandateRequestData.model_validate(request.data)
        except Exception as e:
            raise TypeError(
                f"Invalid message data type: expected CartMandateRequestData, got {e}"
            ) from e

        return {
            "cart_mandate_id": data.cart_mandate_id,
            "items": [item.model_dump() for item in data.items],
            "shipping_address": data.shipping_address.model_dump()
            if data.shipping_address
            else None,
            "client_did": request.from_,
            "webhook_url": request.credential_webhook_url,
        }

    def build_cart_mandate_response(
        self,
        order_id: str,
        items: Sequence[DisplayItem],
        total_amount: MoneyAmount,
        shopper_did: Optional[str] = None,
        payment_method: str = "QR_CODE",
        payment_channel: PaymentProvider | str = PaymentProvider.ALIPAY,
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
            payment_channel: PaymentProvider enum or string (default: ALIPAY)
            qr_url: QR code URL for payment
            out_trade_no: External trade number
            shipping_address: Shipping address (optional)
            ttl_seconds: JWT Time to live in seconds (default: 900 = 15 minutes)

        Returns:
            ANPMessage containing the CartMandate
        """
        resolved_shopper_did = shopper_did
        if not resolved_shopper_did:
            raise ValueError("shopper_did or request_from must be provided")

        resolved_message_id = f"cart-response-{order_id}"

        if not all(isinstance(item, DisplayItem) for item in items):
            raise TypeError("All items must be DisplayItem instances")

        if not isinstance(total_amount, MoneyAmount):
            raise TypeError("total_amount must be a MoneyAmount instance")

        logger.info(f"Building CartMandate for order_id={order_id}")
        provider = payment_channel

        # Ensure provider is PaymentProvider enum
        if isinstance(payment_channel, str):
            provider = PaymentProvider(payment_channel)
        else:
            provider = payment_channel

        payment_request = PaymentRequest(
            method_data=[
                PaymentMethodData(
                    supported_methods=payment_method,
                    data=QRCodePaymentData(
                        channel=provider,
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
            contents=contents.model_dump(exclude_none=True),
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
            data=cart_mandate_obj.model_dump(exclude_none=True),
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

        """
        logger.info(f"Verifying ANPMessage with PaymentMandate from {request.from_}")

        # Verify ANP message routing
        if request.to != self.merchant_did:
            raise ValueError(
                f"Payment mandate not for this merchant: "
                f"expected {self.merchant_did}, got {request.to}"
            )

        # Parse data dict to PaymentMandate
        try:
            payment_mandate = PaymentMandate.model_validate(request.data)
        except Exception as e:
            raise TypeError(
                f"Invalid message data type: expected PaymentMandate, got {e}"
            ) from e
        logger.debug(f"Expected cart_hash: {cart_hash[:16]}...")

        # Verify payment mandate signature and hash chain
        if not validate_payment_mandate(
            payment_mandate=payment_mandate,
            shopper_public_key=shopper_public_key,
            shopper_algorithm=self.algorithm,
            expected_merchant_did=self.merchant_did,
            expected_cart_hash=cart_hash,
        ):
            raise ValueError("PaymentMandate validation failed")

        # Compute pmt_hash for caller
        # payment_mandate_contents is already a dict
        pmt_hash = compute_hash(payment_mandate.payment_mandate_contents)
        logger.info("PaymentMandate verified: pmt_hash=%s...", pmt_hash[:16])

        return {"pmt_hash": pmt_hash}

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
