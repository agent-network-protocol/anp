"""AP2 Shopper Agent (Client/Travel Agent).

This module provides a complete Shopper Agent implementation for the AP2 protocol.
The Shopper Agent handles the client-side workflow:
1. Request cart creation from merchant
2. Verify received CartMandate
3. Build and send PaymentMandate
4. Receive and verify credentials

启动顺序：请先启动 merchant_agent 服务，再启动 shopper_agent（可参考 ap2_complete_flow.py 的 orchestration）。
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Optional, Union

import aiohttp
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from anp.ap2 import (
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
from anp.ap2.mandate import compute_hash
from anp.ap2.payment_mandate import build_payment_mandate
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
        merchant_public_key: str,
        *,
        did_document_path: str | None = None,
        auth_private_key_path: str | None = None,
        algorithm: str = "RS256",
    ):
        """Initialize the stateless Shopper Agent.

        Args:
            shopper_private_key: Shopper's private key for JWS signing.
            shopper_did: Shopper's DID.
            shopper_kid: Shopper's key ID for JWS signing.
            merchant_public_key: Merchant public key for credential validation.
            did_document_path: Path to DID document for DIDWbaAuthHeader (optional).
            auth_private_key_path: Private key path for DIDWbaAuthHeader (optional).
            algorithm: JWS algorithm (e.g., "RS256").
        """
        self.shopper_private_key = shopper_private_key
        self.shopper_did = shopper_did
        self.shopper_kid = shopper_kid
        self.merchant_public_key = merchant_public_key
        self.algorithm = algorithm
        self.cart_hash: Optional[str] = None
        self.pmt_hash: Optional[str] = None
        self.auth_header = (
            DIDWbaAuthHeader(
                did_document_path=did_document_path,
                private_key_path=auth_private_key_path,
            )
            if did_document_path and auth_private_key_path
            else None
        )

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
        if not validate_cart_mandate(
            cart_mandate=cart_mandate,
            merchant_public_key=merchant_public_key,
            merchant_algorithm=self.algorithm,
            expected_shopper_did=self.shopper_did,
        ):
            raise ValueError("CartMandate validation failed")

        # contents is already a dict
        cart_hash = compute_hash(cart_mandate.contents)
        self.cart_hash = cart_hash
        logger.info("CartMandate verified: cart_hash=%s...", cart_hash[:16])

        return {"cart_hash": cart_hash}

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
            RuntimeError: If auth header is not configured
        """
        if self.auth_header is None:
            raise RuntimeError("DIDWbaAuthHeader is required to send payment mandates")

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

        # Get DID WBA authentication header if available
        auth_headers = (
            self.auth_header.get_auth_header(endpoint, force_new=True)
            if self.auth_header
            else {}
        )

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

        """

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
                    credential = PaymentReceipt.model_validate(credential_data)
                elif credential_type == "FulfillmentReceipt":
                    credential = FulfillmentReceipt.model_validate(credential_data)
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

                _ = validate_credential(
                    credential=credential,
                    merchant_public_key=self.merchant_public_key,
                    merchant_algorithm=self.algorithm,
                    expected_shopper_did=self.shopper_did,
                    expected_pmt_hash=self.pmt_hash,
                )
                verified_cred_hash = compute_hash(
                    credential.contents.model_dump(exclude_none=True)
                )
                logger.info("Credential verified successfully")

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
                        "credential_id": getattr(credential.contents, "id", None),
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
