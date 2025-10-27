#!/usr/bin/env python3
"""AP2 Protocol Complete Flow Example.

This example demonstrates the complete AP2 payment flow:
1. Shopper sends create_cart_mandate request to Merchant
2. Merchant returns CartMandate with merchant_authorization
3. Shopper verifies CartMandate and creates PaymentMandate
4. Shopper sends PaymentMandate to Merchant
5. Merchant verifies PaymentMandate

All HTTP requests use DID WBA authentication headers.
"""

import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

import aiohttp

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from anp.ap2 import (
    CartContents,
    CartMandateBuilder,
    CartMandateVerifier,
    DisplayItem,
    MoneyAmount,
    PaymentDetails,
    PaymentDetailsTotal,
    PaymentMandateBuilder,
    PaymentMandateContents,
    PaymentMandateVerifier,
    PaymentMethodData,
    PaymentRequest,
    PaymentRequestOptions,
    PaymentResponse,
    PaymentTotal,
    QRCodePaymentData,
    ShippingAddress,
)
from anp.authentication import DIDWbaAuthHeader


def load_text(path: Path) -> str:
    """Read a UTF-8 text file."""
    return path.read_text(encoding="utf-8")


def load_json(path: Path) -> Dict[str, Any]:
    """Load JSON content as a dictionary."""
    return json.loads(load_text(path))


class ShopperAgent:
    """Shopper Agent - handles user interaction and payment requests."""

    def __init__(
        self,
        did_document_path: str,
        private_key_path: str,
        user_private_key: str,
        user_did: str,
        user_kid: str,
    ):
        """Initialize Shopper Agent.

        Args:
            did_document_path: Path to DID document
            private_key_path: Path to DID private key
            user_private_key: User's payment signing private key
            user_did: User DID
            user_kid: User key identifier
        """
        self.auth_header = DIDWbaAuthHeader(
            did_document_path=did_document_path,
            private_key_path=private_key_path,
        )
        self.user_private_key = user_private_key
        self.user_did = user_did
        self.user_kid = user_kid

    async def create_cart_mandate(
        self,
        merchant_url: str,
        cart_mandate_id: str,
        items: list,
        shipping_address: Dict,
    ) -> Dict:
        """Send create_cart_mandate request to merchant.

        Args:
            merchant_url: Merchant API endpoint
            cart_mandate_id: Cart mandate ID
            items: List of items to purchase
            shipping_address: Shipping address information

        Returns:
            CartMandate response from merchant
        """
        endpoint = f"{merchant_url}/ap2/merchant/create_cart_mandate"

        # Prepare request data
        request_data = {
            "messageId": f"cart-request-{cart_mandate_id}",
            "from": self.user_did,
            "to": "did:wba:merchant.example.com:merchant",
            "data": {
                "cart_mandate_id": cart_mandate_id,
                "items": items,
                "shipping_address": shipping_address,
            },
        }

        # Get DID WBA authentication headers
        auth_headers = self.auth_header.get_auth_header(endpoint, force_new=True)

        print(f"\n[Shopper] Sending create_cart_mandate request to {endpoint}")
        print(f"[Shopper] Request data: {json.dumps(request_data, indent=2)}")

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
                    raise Exception(
                        f"Failed to create cart mandate: {response.status}"
                    )

                result = await response.json()
                print("[Shopper] Received CartMandate from merchant")
                return result

    async def send_payment_mandate(
        self,
        merchant_url: str,
        cart_mandate: Dict,
        cart_hash: str,
        merchant_public_key: str,
    ) -> Dict:
        """Send payment_mandate to merchant.

        Args:
            merchant_url: Merchant API endpoint
            cart_mandate: Verified CartMandate
            cart_hash: Hash of cart contents
            merchant_public_key: Merchant's public key for verification

        Returns:
            Response from merchant
        """
        endpoint = f"{merchant_url}/ap2/merchant/send_payment_mandate"

        # Build PaymentMandate
        payment_builder = PaymentMandateBuilder(
            user_private_key=self.user_private_key,
            user_did=self.user_did,
            user_kid=self.user_kid,
            algorithm="RS256",
            merchant_did="did:wba:merchant.example.com:merchant",
        )

        # Create payment mandate contents
        contents_data = cart_mandate["data"]["contents"]
        pmt_contents = PaymentMandateContents(
            payment_mandate_id=f"pm_{contents_data['id']}",
            payment_details_id=contents_data["payment_request"]["details"]["id"],
            payment_details_total=PaymentDetailsTotal(
                label="Total",
                amount=MoneyAmount(
                    currency=contents_data["payment_request"]["details"]["total"][
                        "amount"
                    ]["currency"],
                    value=contents_data["payment_request"]["details"]["total"][
                        "amount"
                    ]["value"],
                ),
                refund_period=30,
            ),
            payment_response=PaymentResponse(
                request_id=contents_data["payment_request"]["details"]["id"],
                method_name="QR_CODE",
                details={
                    "channel": contents_data["payment_request"]["method_data"][0][
                        "data"
                    ]["channel"],
                    "out_trade_no": contents_data["payment_request"]["method_data"][0][
                        "data"
                    ]["out_trade_no"],
                },
            ),
            merchant_agent="MerchantAgent",
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        # Build PaymentMandate
        payment_mandate = payment_builder.build(
            payment_mandate_contents=pmt_contents,
            cart_hash=cart_hash,
            extensions=["anp.ap2.qr.v1"],
        )

        # Prepare request data
        request_data = {
            "messageId": f"payment-mandate-{pmt_contents.payment_mandate_id}",
            "from": self.user_did,
            "to": "did:wba:merchant.example.com:merchant",
            "data": {
                "payment_mandate_contents": payment_mandate.payment_mandate_contents.model_dump(
                    exclude_none=True
                ),
                "user_authorization": payment_mandate.user_authorization,
            },
        }

        # Get DID WBA authentication headers
        auth_headers = self.auth_header.get_auth_header(endpoint)

        print(f"\n[Shopper] Sending PaymentMandate to {endpoint}")
        print(
            f"[Shopper] Payment mandate ID: {pmt_contents.payment_mandate_id}"
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
                    raise Exception(
                        f"Failed to send payment mandate: {response.status}"
                    )

                result = await response.json()
                print("[Shopper] Payment accepted by merchant")
                return result


class MerchantAgent:
    """Merchant Agent - generates cart, creates QR orders."""

    def __init__(
        self,
        merchant_private_key: str,
        merchant_public_key: str,
        merchant_did: str,
        merchant_kid: str,
    ):
        """Initialize Merchant Agent.

        Args:
            merchant_private_key: Merchant's private key for signing
            merchant_public_key: Merchant's public key
            merchant_did: Merchant DID
            merchant_kid: Merchant key identifier
        """
        self.merchant_private_key = merchant_private_key
        self.merchant_public_key = merchant_public_key
        self.merchant_did = merchant_did
        self.merchant_kid = merchant_kid

    def handle_create_cart_mandate(
        self, request_data: Dict, shopper_did: str
    ) -> Dict:
        """Handle create_cart_mandate request.

        Args:
            request_data: Request data from shopper
            shopper_did: Shopper's DID

        Returns:
            CartMandate response
        """
        print("\n[Merchant] Processing create_cart_mandate request")

        data = request_data["data"]
        cart_mandate_id = data["cart_mandate_id"]
        items = data["items"]
        shipping_address = data["shipping_address"]

        # Build CartContents
        display_items = []
        total_amount = 0.0

        for item in items:
            # In real scenario, fetch price from database
            price = 120.0  # Example price
            total_amount += price * item["quantity"]

            display_items.append(
                DisplayItem(
                    id=item["id"],
                    sku=item["sku"],
                    label=f"Product {item['sku']}",
                    quantity=item["quantity"],
                    options=item.get("options", {}),
                    amount=MoneyAmount(currency="CNY", value=price),
                    remark=item.get("remark"),
                )
            )

        cart_contents = CartContents(
            id=cart_mandate_id,
            user_signature_required=False,
            payment_request=PaymentRequest(
                method_data=[
                    PaymentMethodData(
                        supported_methods="QR_CODE",
                        data=QRCodePaymentData(
                            channel="ALIPAY",
                            qr_url=f"https://pay.example.com/qrcode/{cart_mandate_id}",
                            out_trade_no=f"order_{cart_mandate_id}",
                            expires_at=(
                                datetime.now(timezone.utc).isoformat()
                            ),  # Should add 15 mins
                        ),
                    )
                ],
                details=PaymentDetails(
                    id=f"order_{cart_mandate_id}",
                    displayItems=display_items,
                    shipping_address=ShippingAddress(**shipping_address),
                    total=PaymentTotal(
                        label="Total",
                        amount=MoneyAmount(currency="CNY", value=total_amount),
                    ),
                ),
                options=PaymentRequestOptions(requestShipping=True),
            ),
        )

        # Build CartMandate with merchant_authorization
        cart_builder = CartMandateBuilder(
            merchant_private_key=self.merchant_private_key,
            merchant_did=self.merchant_did,
            merchant_kid=self.merchant_kid,
            algorithm="RS256",
            shopper_did=shopper_did,
        )

        cart_mandate = cart_builder.build(
            cart_contents=cart_contents,
            extensions=["anp.ap2.qr.v1", "anp.human_presence.v1"],
        )

        print(
            f"[Merchant] Generated CartMandate with ID: {cart_mandate_id}"
        )
        print(
            f"[Merchant] Total amount: {total_amount} CNY"
        )

        # Build response
        response = {
            "messageId": f"cart-response-{cart_mandate_id}",
            "from": self.merchant_did,
            "to": shopper_did,
            "data": {
                "contents": cart_mandate.contents.model_dump(exclude_none=True),
                "merchant_authorization": cart_mandate.merchant_authorization,
                "timestamp": cart_mandate.timestamp,
            },
        }

        return response

    def handle_send_payment_mandate(
        self, request_data: Dict, user_public_key: str
    ) -> Dict:
        """Handle send_payment_mandate request.

        Args:
            request_data: Request data containing PaymentMandate
            user_public_key: User's public key for verification

        Returns:
            Response confirming payment
        """
        print("\n[Merchant] Processing PaymentMandate")

        data = request_data["data"]

        # Verify PaymentMandate
        # Note: In real scenario, retrieve cart_hash from previous CartMandate
        # Here we'll skip verification for demo purposes
        print(
            f"[Merchant] Payment mandate ID: {data['payment_mandate_contents']['payment_mandate_id']}"
        )
        print("[Merchant] Payment accepted and verified")

        response = {
            "messageId": f"payment-response-{data['payment_mandate_contents']['payment_mandate_id']}",
            "from": self.merchant_did,
            "to": request_data["from"],
            "data": {
                "status": "accepted",
                "payment_id": data["payment_mandate_contents"][
                    "payment_mandate_id"
                ],
            },
        }

        return response


async def run_demo():
    """Run the complete AP2 flow demo."""
    root = project_root

    # Load keys and DID documents
    shopper_did_doc_path = root / "docs/did_public/public-did-doc.json"
    shopper_did_key_path = root / "docs/did_public/public-private-key.pem"

    # Load JWT keys for merchant and user
    merchant_private_key_path = root / "docs/jwt_rs256/RS256-private.pem"
    merchant_public_key_path = root / "docs/jwt_rs256/RS256-public.pem"

    merchant_private_key = load_text(merchant_private_key_path)
    merchant_public_key = load_text(merchant_public_key_path)

    # For demo, use same keys for user
    user_private_key = merchant_private_key
    user_public_key = merchant_public_key

    # Load DID document
    did_document = load_json(shopper_did_doc_path)
    shopper_did = did_document["id"]

    print("=" * 80)
    print("AP2 Protocol Complete Flow Demo")
    print("=" * 80)

    # Initialize agents
    shopper = ShopperAgent(
        did_document_path=str(shopper_did_doc_path),
        private_key_path=str(shopper_did_key_path),
        user_private_key=user_private_key,
        user_did=shopper_did,
        user_kid="shopper-key-001",
    )

    merchant = MerchantAgent(
        merchant_private_key=merchant_private_key,
        merchant_public_key=merchant_public_key,
        merchant_did="did:wba:merchant.example.com:merchant",
        merchant_kid="merchant-key-001",
    )

    # Step 1: Create cart mandate request
    print("\n" + "=" * 80)
    print("STEP 1: Shopper creates cart mandate request")
    print("=" * 80)

    cart_request = {
        "messageId": "cart-request-001",
        "from": shopper_did,
        "to": "did:wba:merchant.example.com:merchant",
        "data": {
            "cart_mandate_id": "cart-123",
            "items": [
                {
                    "id": "sku-001",
                    "sku": "Nike-Air-Max-90",
                    "quantity": 1,
                    "options": {"color": "red", "size": "42"},
                    "remark": "请尽快发货",
                }
            ],
            "shipping_address": {
                "recipient_name": "张三",
                "phone": "13800138000",
                "region": "北京市",
                "city": "北京市",
                "address_line": "朝阳区某某街道123号",
                "postal_code": "100000",
            },
        },
    }

    # Step 2: Merchant handles request and returns CartMandate
    print("\n" + "=" * 80)
    print("STEP 2: Merchant generates CartMandate")
    print("=" * 80)

    cart_response = merchant.handle_create_cart_mandate(cart_request, shopper_did)

    # Step 3: Shopper verifies CartMandate
    print("\n" + "=" * 80)
    print("STEP 3: Shopper verifies CartMandate")
    print("=" * 80)

    cart_verifier = CartMandateVerifier(
        merchant_public_key=merchant_public_key,
        algorithm="RS256"
    )

    # Reconstruct CartMandate from response
    from anp.ap2 import CartMandate as CartMandateModel
    cart_mandate_obj = CartMandateModel(
        contents=CartContents(**cart_response["data"]["contents"]),
        merchant_authorization=cart_response["data"]["merchant_authorization"],
        timestamp=cart_response["data"]["timestamp"],
    )

    cart_payload = cart_verifier.verify(
        cart_mandate=cart_mandate_obj,
        expected_aud=shopper_did,
    )

    cart_hash = cart_payload["cart_hash"]
    print("[Shopper] CartMandate verified successfully")
    print(f"[Shopper] Cart hash: {cart_hash}")
    print(f"[Shopper] Issued by: {cart_payload['iss']}")

    # Step 4: Shopper creates and sends PaymentMandate
    print("\n" + "=" * 80)
    print("STEP 4: Shopper creates PaymentMandate")
    print("=" * 80)

    payment_builder = PaymentMandateBuilder(
        user_private_key=user_private_key,
        user_did=shopper_did,
        user_kid="shopper-key-001",
        algorithm="RS256",
        merchant_did="did:wba:merchant.example.com:merchant",
    )

    pmt_contents = PaymentMandateContents(
        payment_mandate_id="pm_123",
        payment_details_id=cart_response["data"]["contents"]["payment_request"][
            "details"
        ]["id"],
        payment_details_total=PaymentDetailsTotal(
            label="Total",
            amount=MoneyAmount(
                currency="CNY",
                value=cart_response["data"]["contents"]["payment_request"][
                    "details"
                ]["total"]["amount"]["value"],
            ),
            refund_period=30,
        ),
        payment_response=PaymentResponse(
            request_id=cart_response["data"]["contents"]["payment_request"][
                "details"
            ]["id"],
            method_name="QR_CODE",
            details={
                "channel": "ALIPAY",
                "out_trade_no": cart_response["data"]["contents"][
                    "payment_request"
                ]["method_data"][0]["data"]["out_trade_no"],
            },
        ),
        merchant_agent="MerchantAgent",
        timestamp=datetime.now(timezone.utc).isoformat(),
    )

    payment_mandate = payment_builder.build(
        payment_mandate_contents=pmt_contents,
        cart_hash=cart_hash,
        extensions=["anp.ap2.qr.v1"],
    )

    print(f"[Shopper] Created PaymentMandate: {pmt_contents.payment_mandate_id}")

    # Step 5: Send PaymentMandate to merchant
    print("\n" + "=" * 80)
    print("STEP 5: Shopper sends PaymentMandate to Merchant")
    print("=" * 80)

    payment_request = {
        "messageId": "payment-mandate-001",
        "from": shopper_did,
        "to": "did:wba:merchant.example.com:merchant",
        "data": {
            "payment_mandate_contents": payment_mandate.payment_mandate_contents.model_dump(
                exclude_none=True
            ),
            "user_authorization": payment_mandate.user_authorization,
        },
    }

    # Step 6: Merchant verifies PaymentMandate
    print("\n" + "=" * 80)
    print("STEP 6: Merchant verifies PaymentMandate")
    print("=" * 80)

    payment_verifier = PaymentMandateVerifier(
        user_public_key=user_public_key,
        algorithm="RS256"
    )

    from anp.ap2 import PaymentMandate as PaymentMandateModel
    payment_mandate_obj = PaymentMandateModel(
        payment_mandate_contents=PaymentMandateContents(
            **payment_request["data"]["payment_mandate_contents"]
        ),
        user_authorization=payment_request["data"]["user_authorization"],
    )

    payment_payload = payment_verifier.verify(
        payment_mandate=payment_mandate_obj,
        expected_cart_hash=cart_hash,
        expected_aud="did:wba:merchant.example.com:merchant",
    )

    print("[Merchant] PaymentMandate verified successfully")
    print(f"[Merchant] Issued by: {payment_payload['iss']}")
    print(f"[Merchant] Transaction data: {payment_payload['transaction_data']}")

    payment_response = merchant.handle_send_payment_mandate(
        payment_request, user_public_key
    )

    print(f"\n[Merchant] Payment status: {payment_response['data']['status']}")

    print("\n" + "=" * 80)
    print("AP2 Flow Completed Successfully!")
    print("=" * 80)


def main():
    """Run the demo."""
    asyncio.run(run_demo())


if __name__ == "__main__":
    main()
