"""AP2 Shopper Agent (Client/Travel Agent).

This module provides a complete Shopper Agent implementation for the AP2 protocol.
The Shopper Agent handles the client-side workflow:
1. Request cart creation from merchant
2. Verify received CartMandate
3. Build and send PaymentMandate
4. Receive and verify credentials
"""

import logging
from typing import Any, Callable, Optional, Union

import aiohttp
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from anp.ap2 import (
    CartContents,
    CartMandate,
    FulfillmentReceipt,
    MoneyAmount,
    PaymentDetailsTotal,
    PaymentMandate,
    PaymentMandateContents,
    PaymentReceipt,
    PaymentResponse,
    PaymentResponseDetails,
    ShippingAddress,
)
from anp.ap2.cart_mandate import validate_cart_mandate
from anp.ap2.credential_mandate import validate_credential
from anp.ap2.payment_mandate import build_payment_mandate
from anp.ap2.utils import compute_hash
from anp.authentication import DIDWbaAuthHeader

logger = logging.getLogger(__name__)

class ShopperAgent:
    """Stateless AP2 Shopper Agent.

    This agent provides protocol-level operations for a shopper, such as
    building mandates and verifying credentials. It does not manage state
    (like `cart_hash` or `pmt_hash`) or handle HTTP communication.

    Design:
    - Stateless: No instance variables for business data.
    - Pure Methods: Methods are deterministic. Same input -> same output.
    - Your Responsibility: State management, database/cache, and HTTP clients.
    """

    def __init__(
        self,
        shopper_private_key: str,
        shopper_did: str,
        shopper_kid: str,
        algorithm: str = "RS256",
    ):
        """Initialize the stateless Shopper Agent.

        Args:
            shopper_private_key: Shopper's private key for JWS signing.
            shopper_did: Shopper's DID.
            shopper_kid: Shopper's key ID for JWS signing.
            algorithm: JWS algorithm (e.g., "RS256").
        """
        self.shopper_private_key = shopper_private_key
        self.shopper_did = shopper_did
        self.shopper_kid = shopper_kid
        self.algorithm = algorithm
        self.cart_hash: Optional[str] = None
        self.pmt_hash: Optional[str] = None



    def verify_cart_mandate(
        self,
        cart_mandate: CartMandate,
        merchant_public_key: str,
    ) -> dict[str, Any]:
        """Verify a CartMandate received from a merchant (stateless).

        This method verifies the merchant's signature on the CartMandate.
        It returns the decoded payload and computed cart_hash for later chaining.

        Args:
            cart_mandate: The CartMandate object to verify.
            merchant_public_key: The merchant's public key for signature verification.

        Returns:
            Dict containing decoded payload and cart_hash.

        Raises:
            ValueError: If the signature is invalid or the mandate is not
                        intended for the current shopper.
        """
        payload = validate_cart_mandate(
            cart_mandate=cart_mandate,
            merchant_public_key=merchant_public_key,
            merchant_algorithm=self.algorithm,
            expected_shopper_did=self.shopper_did,
        )

        cart_hash = compute_hash(cart_mandate.contents.model_dump(exclude_none=True))
        self.cart_hash = cart_hash
        logger.info("CartMandate verified: cart_hash=%s...", cart_hash[:16])

        return {"payload": payload, "cart_hash": cart_hash}

    def build_payment_mandate(
        self,
        payment_mandate_id: str,
        order_id: str,
        total_amount: dict[str, Any],
        payment_details: dict[str, Any],
        merchant_did: str,
        cart_hash: str,
        merchant_agent: str = "MerchantAgent",
        refund_period: int = 30,
        shipping_address: Optional[dict[str, str]] = None,
        algorithm: str = "RS256",
    ) -> PaymentMandate:
        """Build a PaymentMandate using stored cart_hash.

        Args:
            payment_mandate_id: Unique payment ID
            order_id: Order ID from CartMandate
            total_amount: Total amount dict
            payment_details: Payment method details
            merchant_did: Merchant's DID
            cart_hash: The cart_hash from verified CartMandate
            merchant_agent: Merchant agent identifier
            refund_period: Refund period in days
            shipping_address: Shipping address (optional)
            algorithm: JWT algorithm

        Returns:
            PaymentMandate ready to send

        Example:
            >>> # After verifying CartMandate
            >>> result = agent.verify_cart_mandate(cart_mandate, merchant_public_key)
            >>> pmt_mandate = agent.build_payment_mandate(
            ...     payment_mandate_id="pm_123",
            ...     order_id="order_123",
            ...     total_amount={"currency": "CNY", "value": 120.0},
            ...     payment_details={"channel": "ALIPAY", "out_trade_no": "trade_001"},
            ...     merchant_did="did:wba:merchant.example.com:merchant",
            ...     cart_hash=result["cart_hash"],
            ... )
        """
        if not cart_hash:
            raise ValueError("cart_hash is required")

        amount_model = (
            total_amount
            if isinstance(total_amount, MoneyAmount)
            else MoneyAmount(**total_amount)
        )

        if isinstance(payment_details, PaymentResponseDetails):
            method_name = "QR_CODE"
            details_model = payment_details
        else:
            method_name = payment_details.get("method_name", "QR_CODE")
            details_payload = {
                key: value
                for key, value in payment_details.items()
                if key != "method_name"
            }
            details_model = PaymentResponseDetails(**details_payload)

        shipping_model: Optional[ShippingAddress] = None
        if shipping_address:
            shipping_model = (
                shipping_address
                if isinstance(shipping_address, ShippingAddress)
                else ShippingAddress(**shipping_address)
            )

        payment_response = PaymentResponse(
            request_id=order_id,
            method_name=method_name,
            details=details_model,
            shipping_address=shipping_model,
        )

        contents = PaymentMandateContents(
            payment_mandate_id=payment_mandate_id,
            payment_details_id=order_id,
            payment_details_total=PaymentDetailsTotal(
                label="Total",
                amount=amount_model,
                refund_period=refund_period,
            ),
            payment_response=payment_response,
            merchant_agent=merchant_agent,
            cart_hash=cart_hash,
        )

        contents_dict = contents.model_dump(exclude_none=True)
        self.pmt_hash = compute_hash(contents_dict)

        return build_payment_mandate(
            contents=contents,
            user_private_key=self.shopper_private_key,
            user_did=self.shopper_did,
            user_kid=self.shopper_kid,
            merchant_did=merchant_did,
            algorithm=algorithm,
        )

    async def send_payment_mandate(
        self,
        merchant_url: str,
        merchant_did: str,
        payment_mandate: PaymentMandate,
    ) -> dict[str, Any]:
        """Send a PaymentMandate to the merchant.

        Args:
            merchant_url: Merchant API base URL (e.g., https://merchant.example.com)
            merchant_did: Merchant DID
            payment_mandate: Payment mandate object

        Returns:
            Dict: Response data from the merchant

        Raises:
            Exception: HTTP request failed or response error

        Example:
            >>> # First create a PaymentMandate
            >>> from anp.ap2 import PaymentMandateBuilder
            >>> builder = PaymentMandateBuilder(
            ...     user_private_key=private_key,
            ...     user_did="did:wba:didhost.cc:shopper",
            ...     user_kid="shopper-key-001",
            ...     algorithm="RS256",
            ...     merchant_did=merchant_did
            ... )
            >>> payment_mandate = builder.build(pmt_contents, cart_hash)
            >>>
            >>> # Send the PaymentMandate
            >>> response = await client.send_payment_mandate(
            ...     merchant_url="https://merchant.example.com",
            ...     merchant_did="did:wba:merchant.example.com:merchant",
            ...     payment_mandate=payment_mandate
            ... )
        """
        # Build request URL
        endpoint = f"{merchant_url.rstrip('/')}/ap2/merchant/send_payment_mandate"

        # Build request data
        request_data = {
            "messageId": f"payment-mandate-{payment_mandate.payment_mandate_contents.payment_mandate_id}",
            "from": self.shopper_did,
            "to": merchant_did,
            "data": {
                "payment_mandate_contents": payment_mandate.payment_mandate_contents.model_dump(
                    exclude_none=True
                ),
                "user_authorization": payment_mandate.user_authorization,
            },
        }

        # Get DID WBA authentication header
        # Note: Use force_new=True to generate a new nonce for each request
        auth_headers = self.auth_header.get_auth_header(endpoint, force_new=True)

        # Send HTTP POST request
        async with aiohttp.ClientSession() as session:
            async with session.post(
                endpoint,
                json=request_data,
                headers={
                    **auth_headers,
                    "Content-Type": "application/json",
                },
            ) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise Exception(
                        f"Failed to send payment mandate: HTTP {response.status}, {error_text}"
                    )

                result = await response.json()
                return result

    # =========================================================================
    # FastAPI Router Integration
    # =========================================================================

    def set_credential_callback(
        self,
        callback: Callable[[Union[PaymentReceipt, FulfillmentReceipt]], None],
    ):
        """Set a callback function to handle received credentials.

        Args:
            callback: Function that will be called when a credential is received and verified
                     Takes one argument: the credential object (PaymentReceipt or FulfillmentReceipt)

        Example:
            >>> def handle_credential(credential):
            ...     if isinstance(credential, PaymentReceipt):
            ...         print(f"Payment receipt: {credential.contents.transaction_id}")
            ...     elif isinstance(credential, FulfillmentReceipt):
            ...         print(f"Fulfillment receipt: {credential.contents.order_id}")
            >>>
            >>> agent.set_credential_callback(handle_credential)
        """
        self.credential_callback = callback

    def create_fastapi_router(
        self,
        prefix: str = "",
    ) -> "APIRouter":
        """Create FastAPI router for Shopper Agent webhook endpoints.

        Args:
            prefix: Optional prefix for all routes (default: "")

        Returns:
            APIRouter ready to be included in FastAPI app

        Raises:
            ImportError: If FastAPI is not installed
            ValueError: If credential_validator is not configured

        Example:
            >>> from fastapi import FastAPI
            >>> from anp.ap2 import ShopperAgent
            >>>
            >>> # Initialize shopper agent with merchant's public key
            >>> shopper = ShopperAgent(
            ...     did_document_path="did.json",
            ...     private_key_path="key.pem",
            ...     shopper_did="did:wba:shopper.example.com:alice",
            ...     shopper_kid="key-1",
            ...     merchant_public_key=merchant_pub_key
            ... )
            >>>
            >>> # Set callback
            >>> def handle_credential(cred):
            ...     print(f"Received: {cred.id}")
            >>>
            >>> shopper.set_credential_callback(handle_credential)
            >>>
            >>> # Create router
            >>> app = FastAPI()
            >>> shopper_router = shopper.create_fastapi_router()
            >>> app.include_router(shopper_router, prefix="/webhook")
            >>>
            >>> # Now merchant can POST credentials to /webhook/credential
        """
        if not FASTAPI_AVAILABLE:
            raise ImportError(
                "FastAPI is not installed. Install with: pip install fastapi"
            )

        if not self.credential_validator:
            raise ValueError(
                "credential_validator not configured. "
                "Please provide merchant_public_key when initializing ShopperAgent."
            )

        router = APIRouter(prefix=prefix)

        @router.post("/credential")
        async def receive_credential(request: Request):
            """Webhook endpoint to receive credentials from merchant."""
            try:
                # Parse request body
                body = await request.json()
                credential_data = body.get("data", {})
                credential_type = credential_data.get("type")
                logger.info(f"Received credential of type: {credential_type}")

                # Parse credential based on type
                if credential_type == "PaymentReceipt":
                    credential = PaymentReceipt(**credential_data)
                elif credential_type == "FulfillmentReceipt":
                    credential = FulfillmentReceipt(**credential_data)
                else:
                    logger.warning(f"Unknown credential type: {credential_type}")
                    raise HTTPException(
                        status_code=400,
                        detail=f"Unknown credential type: {credential_type}",
                    )

                # Verify credential (will raise ValueError if verification fails)
                if not self.cart_hash or not self.pmt_hash:
                    logger.error("Hash chain incomplete: missing cart_hash or pmt_hash")
                    raise HTTPException(
                        status_code=400,
                        detail="Hash chain not complete. Missing cart_hash or pmt_hash.",
                    )

                logger.debug("Validating credential signature and hash chain")

                # Validate will raise ValueError if verification fails
                payload = self.credential_validator.validate(
                    credential=credential,
                    expected_shopper_did=self.shopper_did,
                    expected_cart_hash=self.cart_hash,
                    expected_pmt_hash=self.pmt_hash,
                )

                # Verification successful - extract verified data
                verified_cred_hash = payload.get("cred_hash")
                logger.info(
                    f"Credential verified successfully: cred_hash={verified_cred_hash[:16]}..."
                )

                # Call callback if set
                if self.credential_callback:
                    logger.debug("Calling credential callback")
                    self.credential_callback(credential)

                # Return success with verified data
                return JSONResponse(
                    status_code=200,
                    content={
                        "status": "success",
                        "message": "Credential received and verified",
                        "credential_id": credential.id,
                        "credential_type": credential_type,
                        "cred_hash": verified_cred_hash,
                    },
                )

            except ValueError as e:
                logger.warning(f"Credential verification failed: {str(e)}")
                raise HTTPException(
                    status_code=400, detail=f"Verification failed: {str(e)}"
                )
            except HTTPException:
                raise
            except Exception as e:
                logger.error(
                    f"Internal error processing credential: {str(e)}", exc_info=True
                )
                raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")

        return router


__all__ = [
    "ShopperAgent",
]
