# -*- coding: utf-8 -*-
"""AP2 Shopper Client Example.

This script runs a shopper client that interacts with the merchant server
to complete the AP2 payment flow: creating a cart mandate and sending a payment mandate.
"""

import argparse
import asyncio
import json
import socket
from pathlib import Path
from typing import Any, Dict, Tuple

from aiohttp import ClientSession
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from anp.ap2 import (
    ANPMessage,
    CartMandate,
    CartMandateRequestData,
    DisplayItem,
    MoneyAmount,
    PaymentDetailsTotal,
    PaymentMandateContents,
    PaymentResponse,
    PaymentResponseDetails,
    ShippingAddress,
)
from anp.ap2.cart_mandate import validate_cart_mandate
from anp.ap2.payment_mandate import build_payment_mandate, validate_payment_mandate
from anp.ap2.mandate import compute_hash
from anp.authentication.did_wba_authenticator import DIDWbaAuthHeader
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


def build_signed_json_request(
    auth_handler: DIDWbaAuthHeader,
    url: str,
    payload: Dict[str, Any],
    *,
    force_new: bool = False,
) -> Tuple[bytes, Dict[str, str]]:
    """Build headers and body bytes for a signed JSON request."""
    body = json.dumps(
        payload,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    headers.update(
        auth_handler.get_auth_header(
            url,
            force_new=force_new,
            method="POST",
            headers=headers,
            body=body,
        )
    )
    return body, headers


class ShopperAgent:
    """Ad-hoc shopper client that calls the merchant APIs."""

    def __init__(
        self,
        did_document_path: str,
        private_key_path: str,
        client_did: str,
        merchant_public_key: str,
        payment_private_key: str,
        shopper_public_key: str,
    ):
        self.auth_handler = DIDWbaAuthHeader(
            did_document_path=did_document_path,
            private_key_path=private_key_path,
        )
        self.client_did = client_did
        self.merchant_public_key = merchant_public_key
        self.payment_private_key = payment_private_key
        self.shopper_public_key = shopper_public_key

    async def run(self, merchant_url: str, merchant_did: str) -> None:
        print("[Shopper] Step 1: Build cart mandate request")
        cart_mandate_id = "cart-20250127-001"
        items = [
            {
                "id": "sku-001",
                "quantity": 1,
                "options": {
                    "color": "Space Gray",
                    "memory": "16GB",
                    "storage": "512GB",
                },
                "remark": "Please ship ASAP",
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

        request_data = CartMandateRequestData(
            cart_mandate_id=cart_mandate_id,
            items=[
                DisplayItem(
                    id=item["id"],
                    quantity=item["quantity"],
                    amount=MoneyAmount(currency="CNY", value=299.99),
                    label=f"Product {item['id']}",
                )
                for item in items
            ],
            shipping_address=ShippingAddress(**shipping_address),
            remark="Please ship ASAP",
        )
        message = ANPMessage(
            messageId=f"cart-request-{cart_mandate_id}",
            from_=self.client_did,
            to=merchant_did,
            data=request_data.model_dump(exclude_none=True),
        )
        create_cart_endpoint = (
            f"{merchant_url.rstrip('/')}/ap2/merchant/create_cart_mandate"
        )
        create_cart_payload = message.model_dump(by_alias=True, exclude_none=True)
        create_cart_body, create_cart_headers = build_signed_json_request(
            self.auth_handler,
            create_cart_endpoint,
            create_cart_payload,
            force_new=True,
        )

        async with ClientSession(trust_env=False) as session:
            print("[Shopper] Step 2: POST /ap2/merchant/create_cart_mandate")
            async with session.post(
                create_cart_endpoint,
                data=create_cart_body,
                headers=create_cart_headers,
            ) as response:
                response.raise_for_status()
                self.auth_handler.update_token(
                    create_cart_endpoint,
                    dict(response.headers),
                )
                cart_response = await response.json()

        received_cart = CartMandate.model_validate(cart_response["data"])
        if not validate_cart_mandate(
            cart_mandate=received_cart.model_dump(exclude_none=True),
            merchant_public_key=self.merchant_public_key,
            merchant_algorithm="ES256K",
            expected_shopper_did=self.client_did,
        ):
            raise ValueError("CartMandate validation failed")
        # contents is already a dict
        cart_hash = compute_hash(received_cart.contents)
        print("[Shopper] Step 3: ✓ CartMandate verified")

        # Parse received cart contents to access fields
        cart_contents_dict = received_cart.contents
        payment_request_dict = cart_contents_dict["payment_request"]
        details_dict = payment_request_dict["details"]
        method_data_list = payment_request_dict["method_data"]

        payment_response = PaymentResponse(
            request_id=details_dict["id"],
            method_name="QR_CODE",
            details=PaymentResponseDetails(
                channel=method_data_list[0]["data"]["channel"],
                out_trade_no=method_data_list[0]["data"]["out_trade_no"],
            ),
        )

        contents = PaymentMandateContents(
            payment_mandate_id="pm_20250127_001",
            payment_details_id=details_dict["id"],
            payment_details_total=PaymentDetailsTotal(
                label="Total",
                amount=MoneyAmount(**details_dict["total"]["amount"]),
                refund_period=30,
            ),
            payment_response=payment_response,
            merchant_agent="MerchantAgent",
            cart_hash=cart_hash,
        )
        payment_mandate = build_payment_mandate(
            contents=contents.model_dump(exclude_none=True),
            shopper_private_key=self.payment_private_key,
            shopper_did=self.client_did,
            shopper_kid="shopper-key-001",
            merchant_did=merchant_did,
            algorithm="ES256K",
        )

        if not validate_payment_mandate(
            payment_mandate=payment_mandate.model_dump(exclude_none=True),
            shopper_public_key=self.shopper_public_key,
            shopper_algorithm="ES256K",
            expected_merchant_did=merchant_did,
            expected_cart_hash=cart_hash,
        ):
            raise ValueError("PaymentMandate validation failed")

        payment_message = ANPMessage(
            messageId=f"payment-request-{contents.payment_mandate_id}",
            from_=self.client_did,
            to=merchant_did,
            data=payment_mandate.model_dump(exclude_none=True),
        )
        payment_endpoint = (
            f"{merchant_url.rstrip('/')}/ap2/merchant/send_payment_mandate"
        )
        payment_payload = payment_message.model_dump(by_alias=True, exclude_none=True)
        payment_body, payment_headers = build_signed_json_request(
            self.auth_handler,
            payment_endpoint,
            payment_payload,
        )
        async with ClientSession(trust_env=False) as session:
            print("[Shopper] Step 4: POST /ap2/merchant/send_payment_mandate")
            async with session.post(
                payment_endpoint,
                data=payment_body,
                headers=payment_headers,
            ) as response:
                response.raise_for_status()
                result = await response.json()

        print("[Shopper] Step 5: ✓ Received merchant response")
        print(f"[Shopper]   - Status: {result['data']['status']}")
        print(f"[Shopper]   - Payment ID: {result['data']['payment_id']}")
        if "payment_receipt" in result["data"]:
            print("[Shopper]   - PaymentReceipt credential received (mock)")
        if "fulfillment_receipt" in result["data"]:
            print("[Shopper]   - FulfillmentReceipt credential received (mock)")


async def main():
    parser = argparse.ArgumentParser(description="AP2 Shopper Client")
    parser.add_argument(
        "--merchant-url",
        type=str,
        default=None,
        help="Merchant server URL (default: http://<local-ip>:8889)",
    )
    parser.add_argument(
        "--merchant-did",
        type=str,
        default=None,
        help="Merchant DID (default: from public-did-doc.json)",
    )
    args = parser.parse_args()

    print("\n" + "=" * 60)
    print("AP2 Shopper Client")
    print("=" * 60)

    root = get_project_root()
    did_document_path = root / "docs/did_public/public-did-doc.json"
    private_key_path = root / "docs/did_public/public-private-key.pem"
    did_document = load_json(did_document_path)
    client_did = did_document["id"]
    payment_private_key = load_text(private_key_path)
    shopper_public_key = public_key_from_did_document(did_document)
    merchant_public_key = public_key_from_did_document(
        did_document
    )  # reuse for demo simplicity
    merchant_did = args.merchant_did or did_document["id"]

    if args.merchant_url:
        merchant_url = args.merchant_url
    else:
        local_ip = get_local_ip()
        merchant_url = f"http://{local_ip}:8889"

    print(f"[Client] Shopper DID: {client_did}")
    print(f"[Client] Merchant URL: {merchant_url}")
    print(f"[Client] Merchant DID: {merchant_did}")

    shopper = ShopperAgent(
        did_document_path=str(did_document_path),
        private_key_path=str(private_key_path),
        client_did=client_did,
        merchant_public_key=merchant_public_key,
        payment_private_key=payment_private_key,
        shopper_public_key=shopper_public_key,
    )

    print("\n[Flow] Starting AP2 payment flow...")
    await shopper.run(merchant_url=merchant_url, merchant_did=merchant_did)
    print("[Flow] ✓ Payment flow completed successfully")


if __name__ == "__main__":
    asyncio.run(main())
