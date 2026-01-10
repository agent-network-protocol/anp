# -*- coding: utf-8 -*-
"""AP2 Merchant Server Example.

This script runs a minimal merchant HTTP server that exposes the AP2 HTTP APIs.
The server handles cart mandate creation and payment mandate processing.
"""

import argparse
import asyncio
import json
import socket
from datetime import datetime, timezone
from pathlib import Path

from aiohttp import web
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from anp.ap2 import (
    ANPMessage,
    CartContents,
    CartMandate,
    CartMandateRequestData,
    DisplayItem,
    FulfillmentItem,
    FulfillmentReceipt,
    FulfillmentReceiptContents,
    MoneyAmount,
    PaymentDetails,
    PaymentDetailsTotal,
    PaymentMandate,
    PaymentMandateContents,
    PaymentMethodData,
    PaymentProvider,
    PaymentReceipt,
    PaymentReceiptContents,
    PaymentRequest,
    PaymentRequestOptions,
    PaymentStatus,
    QRCodePaymentData,
)
from anp.ap2.cart_mandate import build_cart_mandate, validate_cart_mandate
from anp.ap2.credential_mandate import build_fulfillment_receipt, build_payment_receipt
from anp.ap2.payment_mandate import validate_payment_mandate
from anp.ap2.utils import compute_hash
from anp.authentication import did_wba_verifier as verifier_module
from anp.authentication.did_wba_verifier import DidWbaVerifier, DidWbaVerifierConfig
from anp.authentication.verification_methods import EcdsaSecp256k1VerificationKey2019


def get_project_root() -> Path:
    return Path(__file__).resolve().parents[3]


def load_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def load_json(path: Path) -> dict:
    return json.loads(load_text(path))


def public_key_from_did_document(did_document: dict) -> str:
    """Extract the secp256k1 public key PEM from DID document verificationMethod."""
    method = did_document["verificationMethod"][0]
    verifier = EcdsaSecp256k1VerificationKey2019.from_dict(method)
    return verifier.public_key.public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")


def get_local_ip() -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
        return ip
    except Exception:
        return "127.0.0.1"


class MerchantServer:
    """Minimal merchant HTTP server that uses the AP2 builders."""

    def __init__(
        self,
        merchant_private_key: str,
        merchant_public_key: str,
        merchant_did: str,
        jwt_private_key: str,
        jwt_public_key: str,
        shopper_public_key: str,
    ):
        self.merchant_private_key = merchant_private_key
        self.merchant_public_key = merchant_public_key
        self.merchant_did = merchant_did
        self.merchant_kid = "merchant-key-001"
        self.algorithm = "ES256K"
        self.shopper_public_key = shopper_public_key

        self.verifier = DidWbaVerifier(
            DidWbaVerifierConfig(
                jwt_private_key=jwt_private_key,
                jwt_public_key=jwt_public_key,
                jwt_algorithm="RS256",
                access_token_expire_minutes=5,
            )
        )
        self.cart_mandates: dict[str, CartMandate] = {}
        self.cart_hashes: dict[str, str] = {}

    async def handle_create_cart_mandate(self, request: web.Request) -> web.Response:
        print("\n[Merchant] Received create_cart_mandate request")

        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return web.json_response({"error": "Missing Authorization"}, status=401)

        try:
            auth_result = await self.verifier.verify_auth_header(
                authorization=auth_header,
                domain=get_local_ip(),
            )
            shopper_did = auth_result["did"]
            access_token = auth_result.get("access_token")
            print(f"[Merchant] ✓ DID WBA auth: {shopper_did}")
        except Exception as exc:
            return web.json_response({"error": f"Auth failed: {exc}"}, status=401)

        payload = await request.json()
        message = ANPMessage(**payload)
        if not isinstance(message.data, CartMandateRequestData):
            return web.json_response(
                {"error": "Invalid payload: expected CartMandateRequestData"},
                status=400,
            )
        data: CartMandateRequestData = message.data

        display_items: list[DisplayItem] = []
        total = 0.0
        for item in data.items:
            price = 299.99
            display_items.append(
                DisplayItem(
                    id=item.id,
                    label=item.label or f"Product {item.id}",
                    quantity=item.quantity,
                    amount=MoneyAmount(currency="CNY", value=price),
                    options=item.options,
                    remark=item.remark,
                )
            )
            total += price * item.quantity

        order_id = f"order_{data.cart_mandate_id}"
        payment_request = PaymentRequest(
            method_data=[
                PaymentMethodData(
                    supported_methods="QR_CODE",
                    data=QRCodePaymentData(
                        channel="ALIPAY",
                        qr_url=f"https://pay.example.com/qrcode/{data.cart_mandate_id}",
                        out_trade_no=f"order_{data.cart_mandate_id}",
                        expires_at=datetime.now(timezone.utc).isoformat(),
                    ),
                )
            ],
            details=PaymentDetails(
                id=order_id,
                displayItems=display_items,
                shipping_address=data.shipping_address,
                total=PaymentDetailsTotal(
                    label="Total",
                    amount=MoneyAmount(currency="CNY", value=total),
                ),
            ),
            options=PaymentRequestOptions(requestShipping=True),
        )

        cart_contents = CartContents(
            id=f"cart_{order_id}",
            user_signature_required=False,
            payment_request=payment_request,
        )
        cart_mandate = build_cart_mandate(
            contents=cart_contents,
            merchant_private_key=self.merchant_private_key,
            merchant_did=self.merchant_did,
            merchant_kid=self.merchant_kid,
            shopper_did=shopper_did,
            algorithm=self.algorithm,
        )

        validate_cart_mandate(
            cart_mandate=cart_mandate,
            merchant_public_key=self.merchant_public_key,
            merchant_algorithm=self.algorithm,
            expected_shopper_did=shopper_did,
        )
        cart_hash = compute_hash(cart_mandate.contents.model_dump(exclude_none=True))
        self.cart_mandates[data.cart_mandate_id] = cart_mandate
        self.cart_hashes[data.cart_mandate_id] = cart_hash

        response = {
            "messageId": f"cart-response-{data.cart_mandate_id}",
            "from": self.merchant_did,
            "to": shopper_did,
            "data": cart_mandate.model_dump(exclude_none=True),
        }
        headers = {}
        if access_token:
            headers["Authorization"] = f"Bearer {access_token}"
        print("[Merchant] → returning CartMandate")
        return web.json_response(response, headers=headers)

    async def handle_send_payment_mandate(self, request: web.Request) -> web.Response:
        print("\n[Merchant] Received send_payment_mandate request")

        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return web.json_response({"error": "Missing Authorization"}, status=401)
        try:
            auth_result = await self.verifier.verify_auth_header(
                authorization=auth_header,
                domain=get_local_ip(),
            )
            shopper_did = auth_result["did"]
        except Exception as exc:
            return web.json_response({"error": f"Auth failed: {exc}"}, status=401)

        payload = await request.json()
        message = ANPMessage(**payload)
        if not isinstance(message.data, PaymentMandate):
            return web.json_response(
                {"error": "Invalid payload: expected PaymentMandate"}, status=400
            )
        payment_mandate = message.data
        contents: PaymentMandateContents = payment_mandate.payment_mandate_contents

        cart_id = contents.payment_details_id.replace("order_", "")
        cart_mandate = self.cart_mandates.get(cart_id)
        if not cart_mandate:
            return web.json_response({"error": "Unknown cart mandate"}, status=404)

        validate_cart_mandate(
            cart_mandate=cart_mandate,
            merchant_public_key=self.merchant_public_key,
            merchant_algorithm=self.algorithm,
            expected_shopper_did=shopper_did,
        )
        cart_hash = compute_hash(cart_mandate.contents.model_dump(exclude_none=True))

        payload = validate_payment_mandate(
            payment_mandate=payment_mandate,
            shopper_public_key=self.shopper_public_key,
            shopper_algorithm=self.algorithm,
            expected_merchant_did=self.merchant_did,
            expected_cart_hash=cart_hash,
        )
        pmt_hash = compute_hash(
            payment_mandate.payment_mandate_contents.model_dump(exclude_none=True)
        )

        print("[Merchant] ✓ PaymentMandate verified")
        print(f"[Merchant]   - Issuer: {payload['iss']}")
        print(f"[Merchant]   - Cart hash: {cart_hash[:32]}…")
        print(f"[Merchant]   - Payment hash: {pmt_hash[:32]}…")

        payment_receipt, fulfillment_receipt = self._issue_receipts(
            payment_mandate=payment_mandate,
            pmt_hash=pmt_hash,
            cart_mandate=cart_mandate,
            shopper_did=shopper_did,
        )

        response = {
            "messageId": f"payment-response-{contents.payment_mandate_id}",
            "from": self.merchant_did,
            "to": shopper_did,
            "data": {
                "status": "accepted",
                "payment_id": contents.payment_mandate_id,
                "message": "Payment authorization accepted",
                "payment_receipt": payment_receipt.model_dump(exclude_none=True),
                "fulfillment_receipt": fulfillment_receipt.model_dump(
                    exclude_none=True
                ),
            },
        }
        return web.json_response(response)

    def _issue_receipts(
        self,
        payment_mandate: PaymentMandate,
        pmt_hash: str,
        cart_mandate: CartMandate,
        shopper_did: str,
    ) -> tuple[PaymentReceipt, FulfillmentReceipt]:
        """Mock post-payment processing: issue PaymentReceipt and FulfillmentReceipt."""
        contents = payment_mandate.payment_mandate_contents
        now = datetime.now(timezone.utc).isoformat()

        payment_contents = PaymentReceiptContents(
            payment_mandate_id=contents.payment_mandate_id,
            provider=PaymentProvider.ALIPAY,
            status=PaymentStatus.SUCCEEDED,
            transaction_id=f"txn_{contents.payment_mandate_id}",
            out_trade_no=contents.payment_response.details.out_trade_no,
            paid_at=now,
            amount=contents.payment_details_total.amount,
            pmt_hash=pmt_hash,
        )
        payment_receipt = build_payment_receipt(
            contents=payment_contents,
            pmt_hash=pmt_hash,
            merchant_private_key=self.merchant_private_key,
            merchant_did=self.merchant_did,
            merchant_kid=self.merchant_kid,
            algorithm=self.algorithm,
            shopper_did=shopper_did,
        )
        print("[Merchant] → Issued PaymentReceipt (mock webhook)")

        fulfillment_items = [
            FulfillmentItem(id=item.id, quantity=item.quantity)
            for item in cart_mandate.contents.payment_request.details.displayItems
        ]
        fulfillment_contents = FulfillmentReceiptContents(
            order_id=cart_mandate.contents.payment_request.details.id,
            items=fulfillment_items,
            fulfilled_at=now,
            shipping=None,
            pmt_hash=pmt_hash,
            metadata={"note": "Fulfillment simulated for demo"},
        )
        fulfillment_receipt = build_fulfillment_receipt(
            contents=fulfillment_contents,
            pmt_hash=pmt_hash,
            merchant_private_key=self.merchant_private_key,
            merchant_did=self.merchant_did,
            merchant_kid=self.merchant_kid,
            algorithm=self.algorithm,
            shopper_did=shopper_did,
        )
        print("[Merchant] → Issued FulfillmentReceipt (mock webhook)")

        return payment_receipt, fulfillment_receipt


async def setup_did_resolver():
    root = get_project_root()
    did_document_path = root / "docs/did_public/public-did-doc.json"
    did_document = load_json(did_document_path)

    async def local_resolver(_: str):
        return did_document

    original = verifier_module.resolve_did_wba_document
    verifier_module.resolve_did_wba_document = local_resolver
    return original


async def main():
    parser = argparse.ArgumentParser(description="AP2 Merchant Server")
    parser.add_argument(
        "--host",
        type=str,
        default=None,
        help="Host to bind to (default: local IP)",
    )
    parser.add_argument(
        "--port", type=int, default=8889, help="Port to bind to (default: 8889)"
    )
    args = parser.parse_args()

    host = args.host or get_local_ip()
    port = args.port

    print("\n" + "=" * 60)
    print("AP2 Merchant Server")
    print("=" * 60)
    print(f"Host: {host}")
    print(f"Port: {port}")

    original_resolver = await setup_did_resolver()
    try:
        root = get_project_root()
        did_document_path = root / "docs/did_public/public-did-doc.json"
        private_key_path = root / "docs/did_public/public-private-key.pem"
        did_document = load_json(did_document_path)
        merchant_did = did_document["id"]
        merchant_private_key = load_text(private_key_path)
        merchant_public_key = public_key_from_did_document(did_document)
        shopper_public_key = public_key_from_did_document(
            did_document
        )  # reuse for demo simplicity
        jwt_private_key = load_text(root / "docs/jwt_rs256/RS256-private.pem")
        jwt_public_key = load_text(root / "docs/jwt_rs256/RS256-public.pem")

        merchant = MerchantServer(
            merchant_private_key=merchant_private_key,
            merchant_public_key=merchant_public_key,
            merchant_did=merchant_did,
            jwt_private_key=jwt_private_key,
            jwt_public_key=jwt_public_key,
            shopper_public_key=shopper_public_key,
        )

        app = web.Application()
        app.router.add_post(
            "/ap2/merchant/create_cart_mandate", merchant.handle_create_cart_mandate
        )
        app.router.add_post(
            "/ap2/merchant/send_payment_mandate", merchant.handle_send_payment_mandate
        )

        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, host, port)
        await site.start()

        print("[Server] Merchant server started")
        print(f"[Server]   URL: http://{host}:{port}")
        print(f"[Server]   DID: {merchant_did}")
        print("[Server] Server is running. Press Ctrl+C to stop.")

        try:
            await asyncio.Event().wait()  # Run forever until interrupted
        except KeyboardInterrupt:
            print("\n[Server] Shutting down...")
        finally:
            await runner.cleanup()
    finally:
        verifier_module.resolve_did_wba_document = original_resolver


if __name__ == "__main__":
    asyncio.run(main())

