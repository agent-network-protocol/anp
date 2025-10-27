# -*- coding: utf-8 -*-
"""AP2 Complete Flow Example.

This example demonstrates the complete AP2 protocol flow:
1. Start Merchant Agent server (listening on local IP)
2. Start Shopper Agent client
3. Shopper sends create_cart_mandate request
4. Merchant verifies request, generates CartMandate and signs it
5. Shopper verifies CartMandate
6. Shopper creates and sends PaymentMandate
7. Merchant verifies PaymentMandate and responds

All processes include DID WBA authentication and mandate verification.
"""

import asyncio
import json
import socket
from datetime import datetime, timezone
from pathlib import Path

from aiohttp import web

from anp.ap2 import (
    AP2Client,
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
from anp.authentication import did_wba_verifier as verifier_module
from anp.authentication.did_wba_verifier import DidWbaVerifier, DidWbaVerifierConfig


def get_project_root() -> Path:
    """Get project root directory."""
    return Path(__file__).resolve().parents[3]


def load_text(path: Path) -> str:
    """Load text file."""
    return path.read_text(encoding="utf-8")


def load_json(path: Path) -> dict:
    """Load JSON file."""
    return json.loads(load_text(path))


def get_local_ip() -> str:
    """Get local IP address."""
    try:
        # Create a UDP socket (no data will be sent)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"


class MerchantAgent:
    """Merchant Agent server."""

    def __init__(
        self,
        merchant_private_key: str,
        merchant_public_key: str,
        merchant_did: str,
        jwt_private_key: str,
        jwt_public_key: str,
    ):
        """Initialize Merchant Agent.

        Args:
            merchant_private_key: Merchant signature private key
            merchant_public_key: Merchant signature public key
            merchant_did: Merchant DID
            jwt_private_key: JWT private key (for access token)
            jwt_public_key: JWT public key (for access token)
        """
        self.merchant_private_key = merchant_private_key
        self.merchant_public_key = merchant_public_key
        self.merchant_did = merchant_did

        # DID WBA verifier
        self.verifier = DidWbaVerifier(
            DidWbaVerifierConfig(
                jwt_private_key=jwt_private_key,
                jwt_public_key=jwt_public_key,
                jwt_algorithm="RS256",
                access_token_expire_minutes=5,
            )
        )

        # CartMandate builder (using ES256K for EC key)
        self.cart_builder = CartMandateBuilder(
            merchant_private_key=merchant_private_key,
            merchant_did=merchant_did,
            merchant_kid="merchant-key-001",
            algorithm="ES256K",
        )

        # Store generated CartMandate (for verifying PaymentMandate)
        self.cart_mandates = {}

        # Store user public keys (should parse from DID document in production)
        self.user_public_keys = {}

    async def handle_create_cart_mandate(self, request):
        """Handle create_cart_mandate request."""
        print("\n[Merchant] Received create_cart_mandate request")

        # 1. Verify DID WBA auth header
        auth_header = request.headers.get("Authorization", "")
        if not auth_header:
            print("[Merchant] X Missing Authorization header")
            return web.json_response(
                {"error": "Missing Authorization header"}, status=401
            )

        try:
            # Verify auth header
            auth_result = await self.verifier.verify_auth_header(
                authorization=auth_header,
                domain=get_local_ip(),  # Use local IP
            )
            shopper_did = auth_result["did"]
            print(f"[Merchant] V DID WBA auth success: {shopper_did}")
        except Exception as e:
            print(f"[Merchant] X DID WBA auth failed: {e}")
            return web.json_response({"error": f"Auth failed: {e}"}, status=401)

        # 2. Parse request data
        request_data = await request.json()
        data = request_data["data"]
        print(f"[Merchant]   Cart ID: {data['cart_mandate_id']}")
        print(f"[Merchant]   Items count: {len(data['items'])}")

        # 3. Build CartContents
        items = data["items"]
        display_items = []
        total_amount = 0.0

        # Calculate price for each item
        for item in items:
            price = 299.99  # Example price
            item_total = price * item["quantity"]
            total_amount += item_total

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

        print(f"[Merchant]   Total amount: CNY {total_amount}")

        # Build CartContents
        cart_contents = CartContents(
            id=data["cart_mandate_id"],
            user_signature_required=False,
            payment_request=PaymentRequest(
                method_data=[
                    PaymentMethodData(
                        supported_methods="QR_CODE",
                        data=QRCodePaymentData(
                            channel="ALIPAY",
                            qr_url=f"https://pay.example.com/qrcode/{data['cart_mandate_id']}",
                            out_trade_no=f"order_{data['cart_mandate_id']}",
                            expires_at=datetime.now(timezone.utc).isoformat(),
                        ),
                    )
                ],
                details=PaymentDetails(
                    id=f"order_{data['cart_mandate_id']}",
                    displayItems=display_items,
                    shipping_address=ShippingAddress(**data["shipping_address"]),
                    total=PaymentTotal(
                        label="Order Total",
                        amount=MoneyAmount(currency="CNY", value=total_amount),
                    ),
                ),
                options=PaymentRequestOptions(requestShipping=True),
            ),
        )

        # 4. Build CartMandate (with merchant signature)
        cart_mandate = self.cart_builder.build(
            cart_contents=cart_contents,
            extensions=["anp.ap2.qr.v1", "anp.human_presence.v1"],
        )

        # 5. Store CartMandate (for verifying PaymentMandate later)
        self.cart_mandates[data["cart_mandate_id"]] = cart_mandate
        print("[Merchant] V CartMandate created and signed")

        # 6. Build response
        response_data = {
            "messageId": f"cart-response-{data['cart_mandate_id']}",
            "from": self.merchant_did,
            "to": shopper_did,
            "data": {
                "contents": cart_mandate.contents.model_dump(exclude_none=True),
                "merchant_authorization": cart_mandate.merchant_authorization,
                "timestamp": cart_mandate.timestamp,
            },
        }

        print("[Merchant] -> Returning CartMandate")
        return web.json_response(response_data)

    async def handle_send_payment_mandate(self, request):
        """Handle send_payment_mandate request."""
        print("\n[Merchant] Received send_payment_mandate request")

        # 1. Verify DID WBA auth header
        auth_header = request.headers.get("Authorization", "")
        if not auth_header:
            print("[Merchant] X Missing Authorization header")
            return web.json_response(
                {"error": "Missing Authorization header"}, status=401
            )

        try:
            auth_result = await self.verifier.verify_auth_header(
                authorization=auth_header,
                domain=get_local_ip(),
            )
            shopper_did = auth_result["did"]
            print(f"[Merchant] V DID WBA auth success: {shopper_did}")
        except Exception as e:
            print(f"[Merchant] X DID WBA auth failed: {e}")
            return web.json_response({"error": f"Auth failed: {e}"}, status=401)

        # 2. Parse request data
        request_data = await request.json()
        data = request_data["data"]
        payment_mandate_id = data["payment_mandate_contents"]["payment_mandate_id"]
        print(f"[Merchant]   Payment ID: {payment_mandate_id}")

        # 3. Rebuild PaymentMandate object
        from anp.ap2 import PaymentMandate

        payment_mandate = PaymentMandate(
            payment_mandate_contents=PaymentMandateContents(
                **data["payment_mandate_contents"]
            ),
            user_authorization=data["user_authorization"],
        )

        # 4. Verify PaymentMandate
        try:
            # Get corresponding CartMandate
            # Note: In production, should extract cart_mandate_id from payment_mandate_contents
            # Here we assume there's only one CartMandate
            cart_mandate = list(self.cart_mandates.values())[0]

            # Extract cart_hash from CartMandate verifier
            verifier = CartMandateVerifier(
                merchant_public_key=self.merchant_public_key, algorithm="ES256K"
            )
            cart_payload = verifier.verify(
                cart_mandate=cart_mandate,
                expected_aud=None,
            )
            cart_hash = cart_payload["cart_hash"]

            # Verify PaymentMandate (requires user public key)
            # Note: Here use merchant public key for testing, in production should get from DID document
            payment_verifier = PaymentMandateVerifier(
                user_public_key=self.merchant_public_key,  # Test environment uses same key
                algorithm="ES256K",
            )

            payment_payload = payment_verifier.verify(
                payment_mandate=payment_mandate,
                expected_cart_hash=cart_hash,
                expected_aud=self.merchant_did,
            )

            print("[Merchant] V PaymentMandate verified")
            print(f"[Merchant]   - Issuer: {payment_payload['iss']}")
            print(f"[Merchant]   - Cart hash: {cart_hash[:32]}...")

        except Exception as e:
            print(f"[Merchant] X PaymentMandate verification failed: {e}")
            return web.json_response(
                {"error": f"PaymentMandate verification failed: {e}"}, status=400
            )

        # 5. Build response
        response_data = {
            "messageId": f"payment-response-{payment_mandate_id}",
            "from": self.merchant_did,
            "to": shopper_did,
            "data": {
                "status": "accepted",
                "payment_id": payment_mandate_id,
                "message": "Payment authorization accepted",
            },
        }

        print("[Merchant] -> Returning payment confirmation")
        return web.json_response(response_data)


class ShopperAgent:
    """Shopper Agent client."""

    def __init__(
        self,
        did_document_path: str,
        private_key_path: str,
        client_did: str,
        merchant_public_key: str,
        payment_private_key: str,
    ):
        """Initialize Shopper Agent.

        Args:
            did_document_path: DID document path
            private_key_path: Private key path (for DID WBA authentication)
            client_did: Client DID
            merchant_public_key: Merchant public key (for verifying CartMandate)
            payment_private_key: Private key for signing PaymentMandate (ES256K)
        """
        self.client = AP2Client(
            did_document_path=did_document_path,
            private_key_path=private_key_path,
            client_did=client_did,
        )
        self.client_did = client_did
        self.merchant_public_key = merchant_public_key
        self.payment_private_key = payment_private_key

    async def run_shopping_flow(self, merchant_url: str, merchant_did: str):
        """Run complete shopping flow.

        Args:
            merchant_url: Merchant URL
            merchant_did: Merchant DID
        """
        print("\n" + "=" * 60)
        print("Starting shopping flow")
        print("=" * 60)

        # ====================================================================
        # Step 1: Send create_cart_mandate request
        # ====================================================================
        print("\n[Shopper] Step 1: Create cart and send to merchant")

        items = [
            {
                "id": "sku-001",
                "sku": "MacBook-Pro-M3",
                "quantity": 1,
                "options": {"color": "Space Gray", "memory": "16GB", "storage": "512GB"},
                "remark": "Please ship as soon as possible",
            }
        ]

        shipping_address = {
            "recipient_name": "Zhang San",
            "phone": "13800138000",
            "region": "Beijing",
            "city": "Beijing",
            "address_line": "123 Some Street, Chaoyang District",
            "postal_code": "100000",
        }

        print(f"[Shopper]   Product: {items[0]['sku']} x {items[0]['quantity']}")
        print(f"[Shopper]   Recipient: {shipping_address['recipient_name']}")

        cart_mandate = await self.client.create_cart_mandate(
            merchant_url=merchant_url,
            merchant_did=merchant_did,
            cart_mandate_id="cart-20250127-001",
            items=items,
            shipping_address=shipping_address,
        )

        print(f"[Shopper] V Received CartMandate: {cart_mandate.contents.id}")

        # ====================================================================
        # Step 2: Verify CartMandate
        # ====================================================================
        print("\n[Shopper] Step 2: Verify merchant-signed CartMandate")

        cart_verifier = CartMandateVerifier(
            merchant_public_key=self.merchant_public_key, algorithm="ES256K"
        )

        cart_payload = cart_verifier.verify(
            cart_mandate=cart_mandate,
            expected_aud=None,  # Test environment doesn't verify aud
        )

        cart_hash = cart_payload["cart_hash"]
        print("[Shopper] V CartMandate verified")
        print(f"[Shopper]   - Issuer: {cart_payload['iss']}")
        print(f"[Shopper]   - Cart hash: {cart_hash[:32]}...")
        print(
            f"[Shopper]   - Total: CNY {cart_mandate.contents.payment_request.details.total.amount.value}"
        )

        # ====================================================================
        # Step 3: Create PaymentMandate
        # ====================================================================
        print("\n[Shopper] Step 3: Create payment authorization (PaymentMandate)")

        payment_builder = PaymentMandateBuilder(
            user_private_key=self.payment_private_key,
            user_did=self.client_did,
            user_kid="shopper-key-001",
            algorithm="ES256K",
            merchant_did=merchant_did,
        )

        pmt_contents = PaymentMandateContents(
            payment_mandate_id="pm_20250127_001",
            payment_details_id=cart_mandate.contents.payment_request.details.id,
            payment_details_total=PaymentDetailsTotal(
                label="Order Total",
                amount=MoneyAmount(
                    currency=cart_mandate.contents.payment_request.details.total.amount.currency,
                    value=cart_mandate.contents.payment_request.details.total.amount.value,
                ),
                refund_period=30,
            ),
            payment_response=PaymentResponse(
                request_id=cart_mandate.contents.payment_request.details.id,
                method_name="QR_CODE",
                details={
                    "channel": cart_mandate.contents.payment_request.method_data[
                        0
                    ].data.channel,
                    "out_trade_no": cart_mandate.contents.payment_request.method_data[
                        0
                    ].data.out_trade_no,
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

        print(f"[Shopper] V PaymentMandate created: {pmt_contents.payment_mandate_id}")

        # ====================================================================
        # Step 4: Local verification of PaymentMandate (optional, for self-check)
        # ====================================================================
        print("\n[Shopper] Step 4: Local verification of PaymentMandate (self-check)")

        payment_verifier = PaymentMandateVerifier(
            user_public_key=self.merchant_public_key,  # Test environment uses same public key
            algorithm="ES256K",
        )

        payment_payload = payment_verifier.verify(
            payment_mandate=payment_mandate,
            expected_cart_hash=cart_hash,
            expected_aud=merchant_did,
        )

        print("[Shopper] V PaymentMandate local verification passed")
        print(f"[Shopper]   - Issuer: {payment_payload['iss']}")

        # ====================================================================
        # Step 5: Send PaymentMandate
        # ====================================================================
        print("\n[Shopper] Step 5: Send PaymentMandate to merchant")

        # Wait a moment to ensure nonce timestamp is different
        await asyncio.sleep(0.1)

        response = await self.client.send_payment_mandate(
            merchant_url=merchant_url,
            merchant_did=merchant_did,
            payment_mandate=payment_mandate,
        )

        print("[Shopper] V Received merchant response")
        print(f"[Shopper]   - Status: {response['data']['status']}")
        print(f"[Shopper]   - Payment ID: {response['data']['payment_id']}")
        print(f"[Shopper]   - Message: {response['data']['message']}")

        print("\n" + "=" * 60)
        print("V Shopping flow complete!")
        print("=" * 60)


async def setup_did_resolver():
    """Setup DID resolver (using local files)."""
    root = get_project_root()
    did_document_path = root / "docs/did_public/public-did-doc.json"
    did_document = load_json(did_document_path)

    async def local_resolver(did: str):
        """Local DID resolver."""
        if did != did_document["id"]:
            # For test environment, return same DID document
            return did_document
        return did_document

    # Save original resolver
    original_resolver = verifier_module.resolve_did_wba_document
    verifier_module.resolve_did_wba_document = local_resolver

    return original_resolver


async def start_merchant_server(host: str, port: int):
    """Start merchant server.

    Args:
        host: Listen address
        port: Listen port
    """
    root = get_project_root()

    # Load EC keys for mandate signing (ES256K)
    merchant_private_key = load_text(root / "docs/did_public/public-private-key.pem")
    merchant_public_key = load_text(root / "docs/did_public/public-private-key.pem")

    # Load RSA keys for JWT authentication
    jwt_private_key = load_text(root / "docs/jwt_rs256/RS256-private.pem")
    jwt_public_key = load_text(root / "docs/jwt_rs256/RS256-public.pem")

    merchant_did = f"did:wba:{host}:merchant"

    # Create merchant server
    merchant = MerchantAgent(
        merchant_private_key=merchant_private_key,
        merchant_public_key=merchant_public_key,
        merchant_did=merchant_did,
        jwt_private_key=jwt_private_key,
        jwt_public_key=jwt_public_key,
    )

    # Create web application
    app = web.Application()
    app.router.add_post(
        "/ap2/merchant/create_cart_mandate", merchant.handle_create_cart_mandate
    )
    app.router.add_post(
        "/ap2/merchant/send_payment_mandate", merchant.handle_send_payment_mandate
    )

    # Start server
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()

    print("[Server] Merchant Agent started")
    print(f"[Server]   URL: http://{host}:{port}")
    print(f"[Server]   DID: {merchant_did}")

    return runner, merchant_did, merchant_public_key


async def main():
    """Main function."""
    # Get local IP
    local_ip = get_local_ip()
    port = 8889

    print("\n" + "=" * 60)
    print("AP2 Complete Flow Example")
    print("=" * 60)
    print(f"Local IP: {local_ip}")
    print(f"Port: {port}")

    # Setup DID resolver
    original_resolver = await setup_did_resolver()

    try:
        # Start merchant server
        runner, merchant_did, merchant_public_key = await start_merchant_server(
            local_ip, port
        )

        # Wait for server to start
        await asyncio.sleep(0.5)

        # Initialize shopper client
        root = get_project_root()
        did_document_path = root / "docs/did_public/public-did-doc.json"
        # Use EC key for both DID WBA authentication and AP2 mandate signing
        private_key_path = root / "docs/did_public/public-private-key.pem"
        did_document = load_json(did_document_path)
        client_did = did_document["id"]

        # For AP2, use same EC key (ES256K) for PaymentMandate signing
        shopper_payment_key = load_text(root / "docs/did_public/public-private-key.pem")

        shopper = ShopperAgent(
            did_document_path=str(did_document_path),
            private_key_path=str(private_key_path),
            client_did=client_did,
            merchant_public_key=merchant_public_key,
            payment_private_key=shopper_payment_key,
        )

        # Run shopping flow
        merchant_url = f"http://{local_ip}:{port}"
        await shopper.run_shopping_flow(
            merchant_url=merchant_url,
            merchant_did=merchant_did,
        )

        # Cleanup
        await runner.cleanup()

    finally:
        # Restore original resolver
        verifier_module.resolve_did_wba_document = original_resolver


if __name__ == "__main__":
    asyncio.run(main())
