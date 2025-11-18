"""AP2 Merchant Agent (Server/Merchant Agent).

This module provides a complete Merchant Agent implementation for the AP2 protocol.
The Merchant Agent handles the server-side workflow:
1. Receive and verify cart creation requests
2. Build and return CartMandate
3. Receive and verify PaymentMandate
4. Build and send credentials (PaymentReceipt, FulfillmentReceipt)
"""

import logging
from typing import Any, Callable, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

from anp.ap2 import cart_mandate, credential_mandate
from anp.ap2.models import (
    CartMandate,
    CartMandateRequest,
    FulfillmentReceipt,
    PaymentMandate,
    PaymentMandateRequest,
    PaymentReceipt,
)
from anp.ap2.payment_mandate import PaymentMandateValidator
from anp.ap2.utils import JWTVerifier


class MerchantAgent:
    """AP2 Merchant Agent (Server Side).

    Handles the complete server-side AP2 workflow:
    - Verify cart creation requests
    - Build and return CartMandate
    - Verify received PaymentMandate
    - Build and send credentials
    - Maintain hash chain state
    """

    def __init__(
        self,
        merchant_private_key: str,
        merchant_public_key: str,
        merchant_did: str,
        merchant_kid: str,
        algorithm: str = "RS256",
    ):
        """Initialize the Merchant Agent.

        Args:
            merchant_private_key: Merchant's private key for JWS signing
            merchant_public_key: Merchant's public key
            merchant_did: Merchant's DID
            merchant_kid: Merchant's key ID for JWS signing
            algorithm: JWT algorithm (RS256 or ES256K)
        """
        self.merchant_private_key = merchant_private_key
        self.merchant_public_key = merchant_public_key
        self.merchant_did = merchant_did
        self.merchant_kid = merchant_kid
        self.algorithm = algorithm

        # Store verified hashes per session/order
        self.sessions: Dict[str, Dict[str, Any]] = {}

        # Store payment mandate validators per shopper (cached by shopper_public_key)
        self._pmt_validators: Dict[str, PaymentMandateValidator] = {}

    def verify_cart_request(
        self,
        request: CartMandateRequest,
    ) -> Dict[str, Any]:
        """Verify an incoming cart creation request.

        Args:
            request: CartMandateRequest from shopper

        Returns:
            Dict containing extracted business data

        Raises:
            ValueError: If request validation fails

        Example:
            >>> agent = MerchantAgent(priv_key, pub_key, merchant_did, kid)
            >>> order_data = agent.verify_cart_request(request)
            >>> # Use order_data to process the order
        """
        return cart_mandate.verify_cart_mandate_request(
            request=request,
            expected_merchant_did=self.merchant_did,
        )

    def build_cart_mandate(
        self,
        order_id: str,
        items: List[Dict[str, Any]],
        total_amount: Dict[str, Any],
        shopper_did: str,
        payment_method: str = "QR_CODE",
        payment_channel: str = "ALIPAY",
        qr_url: str = "",
        out_trade_no: str = "",
        shipping_address: Optional[Dict[str, str]] = None,
        algorithm: str = "RS256",
        ttl_seconds: int = 900,
    ) -> CartMandate:
        """Build a CartMandate response for the shopper.

        Args:
            order_id: Order unique identifier
            items: List of items with full details
            total_amount: Total amount dict
            shopper_did: Shopper's DID
            payment_method: Payment method
            payment_channel: Payment channel
            qr_url: QR code URL for payment
            out_trade_no: External trade number
            shipping_address: Shipping address (optional)
            algorithm: JWT algorithm
            ttl_seconds: Time to live

        Returns:
            CartMandate with merchant authorization

        Example:
            >>> cart_mandate = agent.build_cart_mandate(
            ...     order_id="order_123",
            ...     items=[{...}],
            ...     total_amount={"currency": "CNY", "value": 120.0},
            ...     shopper_did="did:wba:didhost.cc:shopper",
            ...     qr_url="https://qr.alipay.com/...",
            ...     out_trade_no="trade_20250118_001"
            ... )
        """
        cart_mandate_obj = cart_mandate.build_cart_mandate_response(
            order_id=order_id,
            items=items,
            total_amount=total_amount,
            merchant_private_key=self.merchant_private_key,
            merchant_did=self.merchant_did,
            merchant_kid=self.merchant_kid,
            shopper_did=shopper_did,
            payment_method=payment_method,
            payment_channel=payment_channel,
            qr_url=qr_url,
            out_trade_no=out_trade_no,
            shipping_address=shipping_address,
            algorithm=algorithm,
            ttl_seconds=ttl_seconds,
        )

        # Store cart_hash for this order (extract from contents)
        from anp.ap2.utils import compute_hash

        contents_dict = cart_mandate_obj.contents.model_dump(exclude_none=True)
        cart_hash = compute_hash(contents_dict)

        self.sessions[order_id] = {
            "cart_hash": cart_hash,
            "shopper_did": shopper_did,
        }

        return cart_mandate_obj

    def verify_payment_mandate(
        self,
        request: PaymentMandateRequest,
        order_id: str,
        shopper_public_key: str,
    ) -> Dict[str, Any]:
        """Verify an incoming payment mandate.

        Args:
            request: PaymentMandateRequest from shopper
            order_id: Order ID to retrieve stored cart_hash
            shopper_public_key: Shopper's public key for verification

        Returns:
            Dict containing JWT payload with pmt_hash

        Raises:
            ValueError: If verification fails or order not found

        Example:
            >>> payload = agent.verify_payment_mandate(
            ...     request=payment_request,
            ...     order_id="order_123",
            ...     shopper_public_key=shopper_pub_key
            ... )
            >>> # Payment verified, proceed with business logic
        """
        # Retrieve cart_hash for this order
        if order_id not in self.sessions:
            raise ValueError(f"Order {order_id} not found in sessions")

        cart_hash = self.sessions[order_id]["cart_hash"]

        # Get or create validator for this shopper
        if shopper_public_key not in self._pmt_validators:
            shopper_verifier = JWTVerifier(
                public_key=shopper_public_key,
                algorithm=self.algorithm,
            )
            self._pmt_validators[shopper_public_key] = PaymentMandateValidator(
                shopper_verifier
            )

        validator = self._pmt_validators[shopper_public_key]

        # Verify payment mandate
        payload, pmt_hash = validator.validate(
            payment_mandate=request.data,
            expected_merchant_did=self.merchant_did,
            expected_cart_hash=cart_hash,
        )

        # Store pmt_hash for credential generation
        self.sessions[order_id]["pmt_hash"] = pmt_hash

        return payload

    def build_payment_receipt(
        self,
        order_id: str,
        payment_receipt_contents: Any,
        shopper_did: Optional[str] = None,
        algorithm: str = "RS256",
        ttl_seconds: int = 15552000,
    ) -> PaymentReceipt:
        """Build a PaymentReceipt credential.

        Args:
            order_id: Order ID to retrieve stored hashes
            payment_receipt_contents: Payment receipt contents
            shopper_did: Shopper's DID (optional, uses stored value if not provided)
            algorithm: JWT algorithm
            ttl_seconds: Time to live

        Returns:
            PaymentReceipt with merchant authorization

        Raises:
            ValueError: If order not found or hashes missing

        Example:
            >>> from anp.ap2.models import PaymentReceiptContents, PaymentProvider, PaymentStatus, MoneyAmount
            >>> contents = PaymentReceiptContents(
            ...     payment_mandate_id="pm_123",
            ...     provider=PaymentProvider.ALIPAY,
            ...     status=PaymentStatus.SUCCEEDED,
            ...     transaction_id="alipay_txn_123",
            ...     out_trade_no="trade_001",
            ...     paid_at="2025-01-18T08:00:00Z",
            ...     amount=MoneyAmount(currency="CNY", value=120.0)
            ... )
            >>> receipt = agent.build_payment_receipt(
            ...     order_id="order_123",
            ...     payment_receipt_contents=contents
            ... )
        """
        # Retrieve stored hashes
        if order_id not in self.sessions:
            raise ValueError(f"Order {order_id} not found in sessions")

        session = self.sessions[order_id]
        pmt_hash = session.get("pmt_hash")

        if not pmt_hash:
            raise ValueError(
                f"pmt_hash not found for order {order_id}. Payment not verified yet?"
            )

        if not shopper_did:
            shopper_did = session.get("shopper_did")

        # Build credential
        return credential_mandate.build_payment_receipt(
            contents=payment_receipt_contents,
            pmt_hash=pmt_hash,
            merchant_private_key=self.merchant_private_key,
            merchant_did=self.merchant_did,
            merchant_kid=self.merchant_kid,
            algorithm=algorithm,
            shopper_did=shopper_did,
            ttl_seconds=ttl_seconds,
        )

    def build_fulfillment_receipt(
        self,
        order_id: str,
        fulfillment_receipt_contents: Any,
        shopper_did: Optional[str] = None,
        algorithm: str = "RS256",
        ttl_seconds: int = 15552000,
    ) -> FulfillmentReceipt:
        """Build a FulfillmentReceipt credential.

        Args:
            order_id: Order ID to retrieve stored hashes
            fulfillment_receipt_contents: Fulfillment receipt contents
            shopper_did: Shopper's DID (optional, uses stored value if not provided)
            algorithm: JWT algorithm
            ttl_seconds: Time to live

        Returns:
            FulfillmentReceipt with merchant authorization

        Raises:
            ValueError: If order not found or hashes missing

        Example:
            >>> from anp.ap2.models import FulfillmentReceiptContents, FulfillmentItem
            >>> contents = FulfillmentReceiptContents(
            ...     order_id="order_123",
            ...     items=[FulfillmentItem(id="sku-001", quantity=1)],
            ...     fulfilled_at="2025-01-18T10:00:00Z"
            ... )
            >>> receipt = agent.build_fulfillment_receipt(
            ...     order_id="order_123",
            ...     fulfillment_receipt_contents=contents
            ... )
        """
        # Retrieve stored hashes
        if order_id not in self.sessions:
            raise ValueError(f"Order {order_id} not found in sessions")

        session = self.sessions[order_id]
        pmt_hash = session.get("pmt_hash")

        if not pmt_hash:
            raise ValueError(
                f"pmt_hash not found for order {order_id}. Payment not verified yet?"
            )

        if not shopper_did:
            shopper_did = session.get("shopper_did")

        # Build credential
        return credential_mandate.build_fulfillment_receipt(
            contents=fulfillment_receipt_contents,
            pmt_hash=pmt_hash,
            merchant_private_key=self.merchant_private_key,
            merchant_did=self.merchant_did,
            merchant_kid=self.merchant_kid,
            algorithm=algorithm,
            shopper_did=shopper_did,
            ttl_seconds=ttl_seconds,
        )

    def clear_session(self, order_id: str):
        """Clear session data for an order.

        Args:
            order_id: Order ID to clear
        """
        if order_id in self.sessions:
            del self.sessions[order_id]

    # =========================================================================
    # FastAPI Router Integration
    # =========================================================================

    def create_fastapi_router(
        self,
        cart_handler: Callable[[Dict[str, Any]], tuple],
        payment_handler: Optional[Callable[[PaymentMandateRequest], str]] = None,
        prefix: str = "",
    ) -> "APIRouter":
        """Create FastAPI router for Merchant Agent endpoints.

        Args:
            cart_handler: Callback function to handle cart creation business logic
                         Should take (order_data: Dict) and return (items, total_amount, payment_info)
            payment_handler: Optional callback to get shopper's public key
                           Should take (payment_request: PaymentMandateRequest) and return shopper_public_key
            prefix: Optional prefix for all routes (default: "")

        Returns:
            APIRouter ready to be included in FastAPI app

        Raises:
            ImportError: If FastAPI is not installed

        Example:
            >>> from fastapi import FastAPI
            >>> from anp.ap2 import MerchantAgent
            >>>
            >>> # Initialize merchant agent
            >>> merchant = MerchantAgent(priv_key, pub_key, did, kid)
            >>>
            >>> # Define business logic
            >>> def handle_cart(order_data):
            ...     items = [{"id": "sku-001", "label": "Product", "quantity": 1, ...}]
            ...     total = {"currency": "CNY", "value": 120.0}
            ...     payment = {"qr_url": "https://pay.example.com/qr/...", ...}
            ...     return items, total, payment
            >>>
            >>> def get_shopper_pubkey(payment_request):
            ...     # Resolve DID to get public key
            ...     return "-----BEGIN PUBLIC KEY-----\\n..."
            >>>
            >>> # Create router
            >>> app = FastAPI()
            >>> merchant_router = merchant.create_fastapi_router(
            ...     cart_handler=handle_cart,
            ...     payment_handler=get_shopper_pubkey
            ... )
            >>> app.include_router(merchant_router, prefix="/ap2")
        """
        router = APIRouter(prefix=prefix)

        @router.post("/cart_mandate")
        async def create_cart_mandate(
            request: Request,
            cart_request: CartMandateRequest,
        ):
            """Endpoint to create CartMandate."""
            try:
                logger.info(f"Received cart mandate request from {cart_request.from_}")

                # Verify the cart request (will raise ValueError if verification fails)
                order_data = self.verify_cart_request(cart_request)
                logger.info(
                    f"Cart request verified successfully: order_id={order_data['cart_mandate_id']}"
                )

                # Request verification successful, call business logic handler
                items, total_amount, payment_info = cart_handler(order_data)
                logger.debug(
                    f"Business logic processed: {len(items)} items, total={total_amount}"
                )

                # Build CartMandate (signs with merchant key)
                cart_mandate_obj = self.build_cart_mandate(
                    order_id=order_data["cart_mandate_id"],
                    items=items,
                    total_amount=total_amount,
                    shopper_did=order_data["client_did"],
                    qr_url=payment_info.get("qr_url", ""),
                    out_trade_no=payment_info.get("out_trade_no", ""),
                    payment_method=payment_info.get("method", "QR_CODE"),
                    payment_channel=payment_info.get("channel", "ALIPAY"),
                    shipping_address=order_data.get("shipping_address"),
                )

                # Get cart_hash from session (stored in build_cart_mandate)
                cart_hash = self.sessions[order_data["cart_mandate_id"]]["cart_hash"]
                logger.info(
                    f"CartMandate created successfully: cart_hash={cart_hash[:16]}..."
                )

                # Return response with cart_hash for debugging
                return JSONResponse(
                    status_code=200,
                    content={
                        "messageId": f"cart-response-{order_data['cart_mandate_id']}",
                        "from": self.merchant_did,
                        "to": order_data["client_did"],
                        "data": {
                            "contents": cart_mandate_obj.contents.model_dump(
                                exclude_none=True
                            ),
                            "merchant_authorization": cart_mandate_obj.merchant_authorization,
                        },
                        "_meta": {
                            "cart_hash": cart_hash,
                        },
                    },
                )

            except ValueError as e:
                logger.warning(f"Cart request validation failed: {str(e)}")
                raise HTTPException(status_code=400, detail=str(e))
            except Exception as e:
                logger.error(
                    f"Internal error processing cart request: {str(e)}", exc_info=True
                )
                raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")

        @router.post("/payment_mandate")
        async def receive_payment_mandate(
            request: Request,
            payment_request: PaymentMandateRequest,
        ):
            """Endpoint to receive and verify PaymentMandate."""
            try:
                # Extract order_id from payment mandate
                # payment_request.data is PaymentMandate type
                order_id = (
                    payment_request.data.payment_mandate_contents.payment_details_id
                )
                logger.info(f"Received payment mandate for order_id={order_id}")

                # Get shopper public key
                if payment_handler:
                    shopper_public_key = payment_handler(payment_request)
                else:
                    logger.error("payment_handler not provided")
                    raise ValueError(
                        "payment_handler not provided - cannot verify payment mandate"
                    )

                if not shopper_public_key:
                    logger.error("Shopper public key not available")
                    raise ValueError(
                        "Shopper public key not available for verification"
                    )

                logger.debug("Verifying payment mandate with shopper public key")

                # Verify payment mandate (will raise ValueError if verification fails)
                payload = self.verify_payment_mandate(
                    request=payment_request,
                    order_id=order_id,
                    shopper_public_key=shopper_public_key,
                )

                # Verification successful, extract verified pmt_hash
                verified_pmt_hash = payload.get("pmt_hash")
                logger.info(
                    f"Payment mandate verified successfully: pmt_hash={verified_pmt_hash[:16]}..."
                )

                # Return success response
                return JSONResponse(
                    status_code=200,
                    content={
                        "messageId": f"payment-response-{order_id}",
                        "from": self.merchant_did,
                        "to": payment_request.model_dump(by_alias=True).get("from", ""),
                        "data": {
                            "status": "accepted",
                            "payment_id": payment_request.data.payment_mandate_contents.payment_mandate_id,
                            "order_id": order_id,
                            "pmt_hash": verified_pmt_hash,
                        },
                    },
                )

            except ValueError as e:
                logger.warning(f"Payment mandate validation failed: {str(e)}")
                raise HTTPException(status_code=400, detail=str(e))
            except Exception as e:
                logger.error(
                    f"Internal error processing payment mandate: {str(e)}",
                    exc_info=True,
                )
                raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")

        return router


__all__ = [
    "MerchantAgent",
]
