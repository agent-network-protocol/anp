"""AP2 Protocol Module Tests.

测试 AP2 协议模块的功能，包括：
- CartMandate 构建和验证
- PaymentMandate 构建和验证
- JCS 规范化和哈希计算
"""

import time
from datetime import datetime, timezone

import jwt
import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from anp.ap2 import (
    CartContents,
    CartMandate,
    CartMandateBuilder,
    CartMandateVerifier,
    DisplayItem,
    MoneyAmount,
    PaymentDetails,
    PaymentDetailsTotal,
    PaymentMandate,
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
from anp.ap2.utils import compute_cart_hash, compute_pmt_hash, jcs_canonicalize


# 测试用 RSA 密钥对生成
def generate_rsa_key_pair():
    """生成测试用 RSA 密钥对."""
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    public_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )

    return private_pem, public_pem


# 创建测试数据
def create_test_cart_contents():
    """创建测试用购物车内容."""
    return CartContents(
        id="cart_shoes_123",
        user_signature_required=False,
        payment_request=PaymentRequest(
            method_data=[
                PaymentMethodData(
                    supported_methods="QR_CODE",
                    data=QRCodePaymentData(
                        channel="ALIPAY",
                        qr_url="https://pay.example.com/qrcode/abc123",
                        out_trade_no="order_20250117_123456",
                        expires_at="2025-01-17T09:15:00Z",
                    ),
                )
            ],
            details=PaymentDetails(
                id="order_shoes_123",
                displayItems=[
                    DisplayItem(
                        id="sku-id-123",
                        sku="Nike-Air-Max-90",
                        label="Nike Air Max 90",
                        quantity=1,
                        options={"color": "red", "size": "42"},
                        amount=MoneyAmount(currency="CNY", value=120.0),
                        remark="请尽快发货",
                    )
                ],
                shipping_address=ShippingAddress(
                    recipient_name="张三",
                    phone="13800138000",
                    region="北京市",
                    city="北京市",
                    address_line="朝阳区某某街道123号",
                    postal_code="100000",
                ),
                total=PaymentTotal(
                    label="Total", amount=MoneyAmount(currency="CNY", value=120.0)
                ),
            ),
            options=PaymentRequestOptions(requestShipping=True),
        ),
    )


def create_test_payment_mandate_contents():
    """创建测试用支付授权内容."""
    return PaymentMandateContents(
        payment_mandate_id="pm_12345",
        payment_details_id="order_shoes_123",
        payment_details_total=PaymentDetailsTotal(
            label="Total",
            amount=MoneyAmount(currency="CNY", value=120.0),
            refund_period=30,
        ),
        payment_response=PaymentResponse(
            request_id="order_shoes_123",
            method_name="QR_CODE",
            details={"channel": "ALIPAY", "out_trade_no": "order_20250117_123456"},
        ),
        merchant_agent="MerchantAgent",
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


class TestUtils:
    """测试工具函数."""

    def test_jcs_canonicalize(self):
        """测试 JCS 规范化."""
        obj = {"z": 1, "a": 2, "m": 3}
        canonical = jcs_canonicalize(obj)
        assert canonical == '{"a":2,"m":3,"z":1}'

    def test_jcs_canonicalize_nested(self):
        """测试嵌套对象的 JCS 规范化."""
        obj = {"outer": {"z": 1, "a": 2}, "first": "value"}
        canonical = jcs_canonicalize(obj)
        assert canonical == '{"first":"value","outer":{"a":2,"z":1}}'

    def test_compute_cart_hash(self):
        """测试购物车哈希计算."""
        cart_contents = create_test_cart_contents()
        contents_dict = cart_contents.model_dump(exclude_none=True)
        cart_hash = compute_cart_hash(contents_dict)

        # 哈希应该是 base64url 编码的字符串
        assert isinstance(cart_hash, str)
        assert len(cart_hash) > 0
        # Base64url 不包含 '+' 和 '/'
        assert "+" not in cart_hash
        assert "/" not in cart_hash

    def test_compute_pmt_hash(self):
        """测试支付授权哈希计算."""
        pmt_contents = create_test_payment_mandate_contents()
        contents_dict = pmt_contents.model_dump(exclude_none=True)
        pmt_hash = compute_pmt_hash(contents_dict)

        # 哈希应该是 base64url 编码的字符串
        assert isinstance(pmt_hash, str)
        assert len(pmt_hash) > 0
        assert "+" not in pmt_hash
        assert "/" not in pmt_hash


class TestCartMandate:
    """测试 CartMandate 构建和验证."""

    def test_build_cart_mandate(self):
        """测试构建 CartMandate."""
        # 生成密钥对
        merchant_private_key, merchant_public_key = generate_rsa_key_pair()

        # 创建构建器
        builder = CartMandateBuilder(
            merchant_private_key=merchant_private_key,
            merchant_did="did:anp:merchant",
            merchant_kid="merchant-key-001",
            shopper_did="did:anp:shopper",
        )

        # 创建购物车内容
        cart_contents = create_test_cart_contents()

        # 构建 CartMandate
        cart_mandate = builder.build(
            cart_contents=cart_contents,
            extensions=["anp.ap2.qr.v1", "anp.human_presence.v1"],
        )

        # 验证结果
        assert isinstance(cart_mandate, CartMandate)
        assert cart_mandate.contents == cart_contents
        assert len(cart_mandate.merchant_authorization) > 0
        assert len(cart_mandate.timestamp) > 0

    def test_verify_cart_mandate(self):
        """测试验证 CartMandate."""
        # 生成密钥对
        merchant_private_key, merchant_public_key = generate_rsa_key_pair()

        # 构建 CartMandate
        builder = CartMandateBuilder(
            merchant_private_key=merchant_private_key,
            merchant_did="did:anp:merchant",
            merchant_kid="merchant-key-001",
            shopper_did="did:anp:shopper",
        )
        cart_contents = create_test_cart_contents()
        cart_mandate = builder.build(cart_contents)

        # 创建验证器并验证
        verifier = CartMandateVerifier(merchant_public_key=merchant_public_key)
        payload = verifier.verify(
            cart_mandate=cart_mandate, expected_aud="did:anp:shopper"
        )

        # 验证 payload
        assert payload["iss"] == "did:anp:merchant"
        assert payload["sub"] == "did:anp:merchant"
        assert payload["aud"] == "did:anp:shopper"
        assert "cart_hash" in payload
        assert "jti" in payload
        assert "iat" in payload
        assert "exp" in payload

    def test_verify_cart_mandate_with_wrong_key(self):
        """测试使用错误的公钥验证 CartMandate."""
        # 生成两对不同的密钥
        merchant_private_key, _ = generate_rsa_key_pair()
        _, wrong_public_key = generate_rsa_key_pair()

        # 构建 CartMandate
        builder = CartMandateBuilder(
            merchant_private_key=merchant_private_key,
            merchant_did="did:anp:merchant",
            merchant_kid="merchant-key-001",
        )
        cart_contents = create_test_cart_contents()
        cart_mandate = builder.build(cart_contents)

        # 使用错误的公钥验证
        verifier = CartMandateVerifier(merchant_public_key=wrong_public_key)
        with pytest.raises(jwt.InvalidSignatureError):
            verifier.verify(cart_mandate)

    def test_verify_cart_mandate_with_expired_token(self):
        """测试验证过期的 CartMandate."""
        # 生成密钥对
        merchant_private_key, merchant_public_key = generate_rsa_key_pair()

        # 构建已过期的 CartMandate（ttl=1 秒）
        builder = CartMandateBuilder(
            merchant_private_key=merchant_private_key,
            merchant_did="did:anp:merchant",
            merchant_kid="merchant-key-001",
        )
        cart_contents = create_test_cart_contents()
        cart_mandate = builder.build(cart_contents, ttl_seconds=1)

        # 等待过期
        time.sleep(2)

        # 验证应该失败
        verifier = CartMandateVerifier(merchant_public_key=merchant_public_key)
        with pytest.raises(jwt.ExpiredSignatureError):
            verifier.verify(cart_mandate)

    def test_verify_cart_mandate_skip_time_check(self):
        """测试跳过时间验证."""
        # 生成密钥对
        merchant_private_key, merchant_public_key = generate_rsa_key_pair()

        # 构建已过期的 CartMandate
        builder = CartMandateBuilder(
            merchant_private_key=merchant_private_key,
            merchant_did="did:anp:merchant",
            merchant_kid="merchant-key-001",
        )
        cart_contents = create_test_cart_contents()
        cart_mandate = builder.build(cart_contents, ttl_seconds=1)

        # 等待过期
        time.sleep(2)

        # 跳过时间验证应该成功
        verifier = CartMandateVerifier(merchant_public_key=merchant_public_key)
        payload = verifier.verify(cart_mandate, verify_time=False)
        assert payload["iss"] == "did:anp:merchant"


class TestPaymentMandate:
    """测试 PaymentMandate 构建和验证."""

    def test_build_payment_mandate(self):
        """测试构建 PaymentMandate."""
        # 生成密钥对
        user_private_key, user_public_key = generate_rsa_key_pair()

        # 创建构建器
        builder = PaymentMandateBuilder(
            user_private_key=user_private_key,
            user_did="did:anp:shopper",
            user_kid="shopper-key-001",
            merchant_did="did:anp:merchant",
        )

        # 创建支付授权内容
        pmt_contents = create_test_payment_mandate_contents()

        # 假设的 cart_hash
        cart_hash = "test_cart_hash_base64url"

        # 构建 PaymentMandate
        payment_mandate = builder.build(
            payment_mandate_contents=pmt_contents,
            cart_hash=cart_hash,
            extensions=["anp.ap2.qr.v1"],
        )

        # 验证结果
        assert isinstance(payment_mandate, PaymentMandate)
        assert payment_mandate.payment_mandate_contents == pmt_contents
        assert len(payment_mandate.user_authorization) > 0

    def test_verify_payment_mandate(self):
        """测试验证 PaymentMandate."""
        # 生成密钥对
        user_private_key, user_public_key = generate_rsa_key_pair()

        # 构建 PaymentMandate
        builder = PaymentMandateBuilder(
            user_private_key=user_private_key,
            user_did="did:anp:shopper",
            user_kid="shopper-key-001",
            merchant_did="did:anp:merchant",
        )
        pmt_contents = create_test_payment_mandate_contents()
        cart_hash = "test_cart_hash_base64url"
        payment_mandate = builder.build(pmt_contents, cart_hash)

        # 创建验证器并验证
        verifier = PaymentMandateVerifier(user_public_key=user_public_key)
        payload = verifier.verify(
            payment_mandate=payment_mandate,
            expected_cart_hash=cart_hash,
            expected_aud="did:anp:merchant",
        )

        # 验证 payload
        assert payload["iss"] == "did:anp:shopper"
        assert payload["sub"] == "did:anp:shopper"
        assert payload["aud"] == "did:anp:merchant"
        assert "transaction_data" in payload
        assert len(payload["transaction_data"]) == 2
        assert payload["transaction_data"][0] == cart_hash

    def test_verify_payment_mandate_with_wrong_cart_hash(self):
        """测试使用错误的 cart_hash 验证 PaymentMandate."""
        # 生成密钥对
        user_private_key, user_public_key = generate_rsa_key_pair()

        # 构建 PaymentMandate
        builder = PaymentMandateBuilder(
            user_private_key=user_private_key,
            user_did="did:anp:shopper",
            user_kid="shopper-key-001",
        )
        pmt_contents = create_test_payment_mandate_contents()
        cart_hash = "test_cart_hash_base64url"
        payment_mandate = builder.build(pmt_contents, cart_hash)

        # 使用错误的 cart_hash 验证
        verifier = PaymentMandateVerifier(user_public_key=user_public_key)
        with pytest.raises(ValueError, match="cart_hash mismatch"):
            verifier.verify(payment_mandate, expected_cart_hash="wrong_cart_hash")

    def test_end_to_end_flow(self):
        """测试完整的端到端流程."""
        # 1. 生成商户和用户的密钥对
        merchant_private_key, merchant_public_key = generate_rsa_key_pair()
        user_private_key, user_public_key = generate_rsa_key_pair()

        # 2. 商户创建 CartMandate
        cart_builder = CartMandateBuilder(
            merchant_private_key=merchant_private_key,
            merchant_did="did:anp:merchant",
            merchant_kid="merchant-key-001",
            shopper_did="did:anp:shopper",
        )
        cart_contents = create_test_cart_contents()
        cart_mandate = cart_builder.build(cart_contents)

        # 3. 用户验证 CartMandate
        cart_verifier = CartMandateVerifier(merchant_public_key=merchant_public_key)
        cart_payload = cart_verifier.verify(
            cart_mandate, expected_aud="did:anp:shopper"
        )
        cart_hash = cart_payload["cart_hash"]

        # 4. 用户创建 PaymentMandate
        payment_builder = PaymentMandateBuilder(
            user_private_key=user_private_key,
            user_did="did:anp:shopper",
            user_kid="shopper-key-001",
            merchant_did="did:anp:merchant",
        )
        pmt_contents = create_test_payment_mandate_contents()
        payment_mandate = payment_builder.build(pmt_contents, cart_hash)

        # 5. 商户验证 PaymentMandate
        payment_verifier = PaymentMandateVerifier(user_public_key=user_public_key)
        payment_payload = payment_verifier.verify(
            payment_mandate,
            expected_cart_hash=cart_hash,
            expected_aud="did:anp:merchant",
        )

        # 6. 验证完整流程
        assert cart_payload["iss"] == "did:anp:merchant"
        assert payment_payload["iss"] == "did:anp:shopper"
        assert payment_payload["transaction_data"][0] == cart_hash
