"""AP2 Shopper Agent (Client/Travel Agent).

This module provides a complete Shopper Agent implementation for the AP2 protocol.
The Shopper Agent handles the client-side workflow:
1. Request cart creation from merchant
2. Verify received CartMandate
3. Build and send PaymentMandate
4. Receive and verify credentials
"""

import logging
from typing import Any, Callable, Dict, List, Optional, Union

import aiohttp
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

from anp.ap2 import payment_mandate
from anp.ap2.cart_mandate import CartMandateValidator
from anp.ap2.credential_mandate import CredentialValidator
from anp.ap2.models import (
    CartContents,
    CartMandate,
    FulfillmentReceipt,
    PaymentMandate,
    PaymentReceipt,
)
from anp.ap2.utils import JWTVerifier
from anp.authentication import DIDWbaAuthHeader


class ShopperAgent:
    """AP2 Shopper Agent (Travel Agent/Client).

    Handles the complete client-side AP2 workflow:
    - Request cart creation from merchant
    - Verify received CartMandate from merchant
    - Build and send PaymentMandate
    - Store verified hashes for the credential chain
    """

    def __init__(
        self,
        did_document_path: str,
        private_key_path: str,
        shopper_did: str,
        shopper_kid: str,
        merchant_public_key: Optional[str] = None,
        algorithm: str = "RS256",
    ):
        """Initialize the Shopper Agent.

        Args:
            did_document_path: Path to the DID document
            private_key_path: Path to the DID private key (for both DID auth and JWS signing)
            shopper_did: Shopper's DID
            shopper_kid: Shopper's key ID for JWS signing
            merchant_public_key: Merchant's public key for verification (optional, can be set later)
            algorithm: JWT algorithm (RS256 or ES256K)
        """
        self.auth_header = DIDWbaAuthHeader(
            did_document_path=did_document_path,
            private_key_path=private_key_path,
        )
        self.shopper_did = shopper_did
        self.shopper_kid = shopper_kid
        self.algorithm = algorithm

        # Read private key for JWS signing
        with open(private_key_path, "r") as f:
            self.private_key = f.read()

        # Setup cart mandate validator if merchant public key provided
        self.cart_validator: Optional[CartMandateValidator] = None
        self.credential_validator: Optional[CredentialValidator] = None
        if merchant_public_key:
            merchant_verifier = JWTVerifier(
                public_key=merchant_public_key,
                algorithm=algorithm,
            )
            self.cart_validator = CartMandateValidator(merchant_verifier)
            self.credential_validator = CredentialValidator(merchant_verifier)

        # Store verified hashes
        self.cart_hash: Optional[str] = None
        self.pmt_hash: Optional[str] = None

        # Credential callback for webhook
        self.credential_callback: Optional[Callable] = None

    async def create_cart_mandate(
        self,
        merchant_url: str,
        merchant_did: str,
        cart_mandate_id: str,
        items: List[Dict[str, Any]],
        shipping_address: Dict[str, str],
        remark: Optional[str] = None,
    ) -> CartMandate:
        """Send a create_cart_mandate request to the merchant.

        Args:
            merchant_url: Merchant API base URL (e.g., https://merchant.example.com)
            merchant_did: Merchant DID
            cart_mandate_id: Cart mandate ID
            items: List of items, each containing id, sku, quantity, options, remark, etc.
            shipping_address: Shipping address containing recipient_name, phone, region, city, address_line, postal_code
            remark: Optional remark

        Returns:
            CartMandate: Cart mandate returned by the merchant

        Raises:
            Exception: HTTP request failed or response error

        Example:
            >>> client = AP2Client(did_doc_path, key_path, "did:wba:didhost.cc:shopper")
            >>> items = [{
            ...     "id": "sku-001",
            ...     "sku": "Nike-Air-Max-90",
            ...     "quantity": 1,
            ...     "options": {"color": "red", "size": "42"},
            ...     "remark": "Please ship as soon as possible"
            ... }]
            >>> address = {
            ...     "recipient_name": "John Doe",
            ...     "phone": "13800138000",
            ...     "region": "Beijing",
            ...     "city": "Beijing",
            ...     "address_line": "123 Some Street, Chaoyang District",
            ...     "postal_code": "100000"
            ... }
            >>> cart = await client.create_cart_mandate(
            ...     merchant_url="https://merchant.example.com",
            ...     merchant_did="did:wba:merchant.example.com:merchant",
            ...     cart_mandate_id="cart-123",
            ...     items=items,
            ...     shipping_address=address
            ... )
        """
        # Build request URL
        endpoint = f"{merchant_url.rstrip('/')}/ap2/merchant/create_cart_mandate"

        # Build request data
        request_data = {
            "messageId": f"cart-request-{cart_mandate_id}",
            "from": self.shopper_did,
            "to": merchant_did,
            "data": {
                "cart_mandate_id": cart_mandate_id,
                "items": items,
                "shipping_address": shipping_address,
            },
        }

        if remark:
            request_data["data"]["remark"] = remark

        # Get DID WBA authentication header
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
                        f"Failed to create cart mandate: HTTP {response.status}, {error_text}"
                    )

                result = await response.json()

                # Parse response into CartMandate object
                data = result.get("data", {})
                cart_mandate_obj = CartMandate(
                    contents=CartContents(**data["contents"]),
                    merchant_authorization=data["merchant_authorization"],
                )

                # Verify CartMandate if merchant public key is available
                if self.merchant_public_key:
                    payload, verified_cart_hash = cart_mandate.verify_cart_mandate(
                        cart_mandate=cart_mandate_obj,
                        merchant_public_key=self.merchant_public_key,
                        expected_shopper_did=self.shopper_did,
                    )
                    self.cart_hash = verified_cart_hash

                return cart_mandate_obj

    def build_payment_mandate(
        self,
        payment_mandate_id: str,
        order_id: str,
        total_amount: Dict[str, Any],
        payment_details: Dict[str, Any],
        merchant_did: str,
        merchant_agent: str = "MerchantAgent",
        refund_period: int = 30,
        shipping_address: Optional[Dict[str, str]] = None,
        algorithm: str = "RS256",
    ) -> PaymentMandate:
        """Build a PaymentMandate using stored cart_hash.

        Args:
            payment_mandate_id: Unique payment ID
            order_id: Order ID from CartMandate
            total_amount: Total amount dict
            payment_details: Payment method details
            merchant_did: Merchant's DID
            merchant_agent: Merchant agent identifier
            refund_period: Refund period in days
            shipping_address: Shipping address (optional)
            algorithm: JWT algorithm

        Returns:
            PaymentMandate ready to send

        Raises:
            ValueError: If cart_hash is not available

        Example:
            >>> # After verifying CartMandate
            >>> pmt_mandate = agent.build_payment_mandate(
            ...     payment_mandate_id="pm_123",
            ...     order_id="order_123",
            ...     total_amount={"currency": "CNY", "value": 120.0},
            ...     payment_details={"channel": "ALIPAY", "out_trade_no": "trade_001"},
            ...     merchant_did="did:wba:merchant.example.com:merchant"
            ... )
        """
        if not self.cart_hash:
            raise ValueError(
                "cart_hash not available. Please verify CartMandate first."
            )

        return payment_mandate.build_payment_mandate_response(
            payment_mandate_id=payment_mandate_id,
            order_id=order_id,
            total_amount=total_amount,
            payment_details=payment_details,
            cart_hash=self.cart_hash,
            user_private_key=self.private_key,
            user_did=self.shopper_did,
            user_kid=self.shopper_kid,
            merchant_did=merchant_did,
            merchant_agent=merchant_agent,
            refund_period=refund_period,
            shipping_address=shipping_address,
            algorithm=algorithm,
        )

    async def send_payment_mandate(
        self,
        merchant_url: str,
        merchant_did: str,
        payment_mandate: PaymentMandate,
    ) -> Dict[str, Any]:
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
                logger.info(f"Credential verified successfully: cred_hash={verified_cred_hash[:16]}...")
                
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
                logger.error(f"Internal error processing credential: {str(e)}", exc_info=True)
                raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")

        return router


__all__ = [
    "ShopperAgent",
]
