#!/usr/bin/env python3
"""AP2 客户端简单示例.

演示如何使用 AP2Client 发送 create_cart_mandate 和 send_payment_mandate 请求。
"""

import asyncio
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from anp.ap2 import (
    AP2Client,
    CartMandateVerifier,
    PaymentMandateBuilder,
    PaymentMandateContents,
    PaymentDetailsTotal,
    PaymentResponse,
    MoneyAmount,
)
from datetime import datetime, timezone


def load_text(path: Path) -> str:
    """读取文本文件."""
    return path.read_text(encoding="utf-8")


async def main():
    """运行 AP2 客户端示例."""
    root = project_root

    # 加载 DID 文档和密钥
    did_document_path = root / "docs/did_public/public-did-doc.json"
    private_key_path = root / "docs/did_public/public-private-key.pem"

    # 加载支付签名密钥
    user_private_key_path = root / "docs/jwt_rs256/RS256-private.pem"
    merchant_public_key_path = root / "docs/jwt_rs256/RS256-public.pem"

    user_private_key = load_text(user_private_key_path)
    merchant_public_key = load_text(merchant_public_key_path)

    # 客户端 DID
    client_did = "did:wba:didhost.cc:public"

    # 商户信息
    merchant_url = "https://merchant.example.com"
    merchant_did = "did:wba:merchant.example.com:merchant"

    # 初始化 AP2 客户端
    client = AP2Client(
        did_document_path=str(did_document_path),
        private_key_path=str(private_key_path),
        client_did=client_did,
    )

    print("=" * 80)
    print("AP2 客户端示例")
    print("=" * 80)

    # ========================================================================
    # 步骤 1: 创建购物车授权请求
    # ========================================================================
    print("\n步骤 1: 发送 create_cart_mandate 请求")
    print("-" * 80)

    items = [
        {
            "id": "sku-001",
            "sku": "Nike-Air-Max-90",
            "quantity": 1,
            "options": {"color": "red", "size": "42"},
            "remark": "请尽快发货",
        }
    ]

    shipping_address = {
        "recipient_name": "张三",
        "phone": "13800138000",
        "region": "北京市",
        "city": "北京市",
        "address_line": "朝阳区某某街道123号",
        "postal_code": "100000",
    }

    try:
        # 发送请求（这里会失败，因为没有真实的商户服务器）
        cart_mandate = await client.create_cart_mandate(
            merchant_url=merchant_url,
            merchant_did=merchant_did,
            cart_mandate_id="cart-123",
            items=items,
            shipping_address=shipping_address,
            remark="尽快发货",
        )

        print(f"✓ 收到 CartMandate")
        print(f"  - Cart ID: {cart_mandate.contents.id}")
        print(f"  - Timestamp: {cart_mandate.timestamp}")

        # ====================================================================
        # 步骤 2: 验证 CartMandate
        # ====================================================================
        print("\n步骤 2: 验证 CartMandate")
        print("-" * 80)

        verifier = CartMandateVerifier(
            merchant_public_key=merchant_public_key,
            algorithm="RS256"
        )

        cart_payload = verifier.verify(
            cart_mandate=cart_mandate,
            expected_aud=client_did,
        )

        cart_hash = cart_payload["cart_hash"]
        print(f"✓ CartMandate 验证成功")
        print(f"  - Issuer: {cart_payload['iss']}")
        print(f"  - Cart hash: {cart_hash[:32]}...")

        # ====================================================================
        # 步骤 3: 创建并发送 PaymentMandate
        # ====================================================================
        print("\n步骤 3: 创建 PaymentMandate")
        print("-" * 80)

        # 构建 PaymentMandate
        payment_builder = PaymentMandateBuilder(
            user_private_key=user_private_key,
            user_did=client_did,
            user_kid="shopper-key-001",
            algorithm="RS256",
            merchant_did=merchant_did,
        )

        pmt_contents = PaymentMandateContents(
            payment_mandate_id="pm_123",
            payment_details_id=cart_mandate.contents.payment_request.details.id,
            payment_details_total=PaymentDetailsTotal(
                label="Total",
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
                    "channel": cart_mandate.contents.payment_request.method_data[0].data.channel,
                    "out_trade_no": cart_mandate.contents.payment_request.method_data[0].data.out_trade_no,
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

        print(f"✓ PaymentMandate 创建成功")
        print(f"  - Payment ID: {pmt_contents.payment_mandate_id}")

        # 发送 PaymentMandate
        print("\n步骤 4: 发送 PaymentMandate")
        print("-" * 80)

        response = await client.send_payment_mandate(
            merchant_url=merchant_url,
            merchant_did=merchant_did,
            payment_mandate=payment_mandate,
        )

        print(f"✓ PaymentMandate 发送成功")
        print(f"  - Response: {response}")

    except Exception as e:
        print(f"✗ 请求失败（这是正常的，因为没有真实的商户服务器）")
        print(f"  错误: {e}")
        print("\n注意: 这个示例演示了如何使用 AP2Client，")
        print("      实际使用时需要连接到真实的商户服务器。")

    print("\n" + "=" * 80)
    print("示例完成")
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(main())
