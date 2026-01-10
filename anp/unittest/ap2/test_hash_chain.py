"""AP2 Hash Chain Integrity Tests.

This module tests the hash chain integrity verification:
- cart_hash computation from CartMandate contents
- pmt_hash computation from PaymentMandate contents
- hash chain validation (cart_hash in PaymentMandate matches actual cart hash)
- hash chain break detection (tampered cart)
- credential hash verification (pmt_hash in receipts)
"""

import unittest
from pathlib import Path

from anp.ap2.cart_mandate import build_cart_mandate, validate_cart_mandate
from anp.ap2.mandate import compute_hash
from anp.ap2.payment_mandate import build_payment_mandate, validate_payment_mandate


class TestCartHashComputation(unittest.TestCase):
    """测试 CartMandate 哈希计算"""

    @classmethod
    def setUpClass(cls):
        """设置测试密钥"""
        project_root = Path(__file__).resolve().parents[3]
        private_key_path = project_root / "docs/did_public/public-private-key.pem"
        cls.private_key = private_key_path.read_text(encoding="utf-8")

        # 从 DID 文档中提取公钥
        import json
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        from anp.authentication.verification_methods import EcdsaSecp256k1VerificationKey2019

        did_doc_path = project_root / "docs/did_public/public-did-doc.json"
        did_doc = json.loads(did_doc_path.read_text(encoding="utf-8"))
        method = did_doc["verificationMethod"][0]
        verifier = EcdsaSecp256k1VerificationKey2019.from_dict(method)
        cls.public_key = verifier.public_key.public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

    def test_cart_hash_deterministic(self):
        """测试 cart hash 计算是确定性的"""
        contents = {
            "id": "cart-123",
            "items": [{"id": "item-1", "quantity": 2}],
        }

        cart_mandate = build_cart_mandate(
            contents=contents,
            merchant_private_key=self.private_key,
            merchant_did="did:wba:merchant",
            merchant_kid="key-1",
            shopper_did="did:wba:shopper",
            algorithm="ES256K",
        )

        # 计算两次哈希
        hash1 = compute_hash(cart_mandate.contents)
        hash2 = compute_hash(cart_mandate.contents)

        self.assertEqual(hash1, hash2)

    def test_cart_hash_in_jwt(self):
        """测试 cart_hash 正确存储在 JWT 中"""
        contents = {"id": "cart-123"}

        cart_mandate = build_cart_mandate(
            contents=contents,
            merchant_private_key=self.private_key,
            merchant_did="did:wba:merchant",
            merchant_kid="key-1",
            shopper_did="did:wba:shopper",
            algorithm="ES256K",
        )

        # 解码 JWT 检查 cart_hash
        import jwt
        payload = jwt.decode(cart_mandate.merchant_authorization, options={"verify_signature": False})

        self.assertIn("cart_hash", payload)

        # cart_hash 应该匹配实际计算的哈希
        expected_hash = compute_hash(contents)
        self.assertEqual(payload["cart_hash"], expected_hash)

    def test_cart_hash_changes_with_content(self):
        """测试不同内容产生不同的 cart hash"""
        contents1 = {"id": "cart-1", "total": 100}
        contents2 = {"id": "cart-2", "total": 200}

        cart1 = build_cart_mandate(
            contents=contents1,
            merchant_private_key=self.private_key,
            merchant_did="did:wba:merchant",
            merchant_kid="key-1",
            shopper_did="did:wba:shopper",
        )

        cart2 = build_cart_mandate(
            contents=contents2,
            merchant_private_key=self.private_key,
            merchant_did="did:wba:merchant",
            merchant_kid="key-1",
            shopper_did="did:wba:shopper",
        )

        hash1 = compute_hash(cart1.contents)
        hash2 = compute_hash(cart2.contents)

        self.assertNotEqual(hash1, hash2)


class TestPaymentHashComputation(unittest.TestCase):
    """测试 PaymentMandate 哈希计算"""

    @classmethod
    def setUpClass(cls):
        """设置测试密钥"""
        project_root = Path(__file__).resolve().parents[3]
        private_key_path = project_root / "docs/did_public/public-private-key.pem"
        cls.private_key = private_key_path.read_text(encoding="utf-8")

        import json
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        from anp.authentication.verification_methods import EcdsaSecp256k1VerificationKey2019

        did_doc_path = project_root / "docs/did_public/public-did-doc.json"
        did_doc = json.loads(did_doc_path.read_text(encoding="utf-8"))
        method = did_doc["verificationMethod"][0]
        verifier = EcdsaSecp256k1VerificationKey2019.from_dict(method)
        cls.public_key = verifier.public_key.public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

    def test_payment_hash_deterministic(self):
        """测试 payment hash 计算是确定性的"""
        contents = {
            "payment_mandate_id": "pm-123",
            "cart_hash": "dummy_cart_hash",
            "payment_details_id": "order-123",
            "payment_details_total": {"label": "Total", "amount": {"currency": "CNY", "value": 100}},
            "payment_response": {"request_id": "order-123", "method_name": "QR_CODE", "details": {}},
            "merchant_agent": "MerchantAgent",
        }

        payment_mandate = build_payment_mandate(
            contents=contents,
            shopper_private_key=self.private_key,
            shopper_did="did:wba:shopper",
            shopper_kid="key-1",
            merchant_did="did:wba:merchant",
            algorithm="ES256K",
        )

        # 计算两次哈希
        hash1 = compute_hash(payment_mandate.payment_mandate_contents)
        hash2 = compute_hash(payment_mandate.payment_mandate_contents)

        self.assertEqual(hash1, hash2)

    def test_payment_hash_in_jwt(self):
        """测试 pmt_hash 正确存储在 JWT 中"""
        contents = {
            "payment_mandate_id": "pm-123",
            "cart_hash": "dummy_cart_hash",
            "payment_details_id": "order-123",
            "payment_details_total": {"label": "Total", "amount": {"currency": "CNY", "value": 100}},
            "payment_response": {"request_id": "order-123", "method_name": "QR_CODE", "details": {}},
            "merchant_agent": "MerchantAgent",
        }

        payment_mandate = build_payment_mandate(
            contents=contents,
            shopper_private_key=self.private_key,
            shopper_did="did:wba:shopper",
            shopper_kid="key-1",
            merchant_did="did:wba:merchant",
            algorithm="ES256K",
        )

        # 解码 JWT 检查 pmt_hash
        import jwt
        payload = jwt.decode(payment_mandate.user_authorization, options={"verify_signature": False})

        self.assertIn("pmt_hash", payload)

        # pmt_hash 应该匹配实际计算的哈希
        expected_hash = compute_hash(contents)
        self.assertEqual(payload["pmt_hash"], expected_hash)


class TestHashChainIntegrity(unittest.TestCase):
    """测试 cart_hash → pmt_hash 哈希链完整性"""

    @classmethod
    def setUpClass(cls):
        """设置测试密钥"""
        project_root = Path(__file__).resolve().parents[3]
        private_key_path = project_root / "docs/did_public/public-private-key.pem"
        cls.private_key = private_key_path.read_text(encoding="utf-8")

        import json
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        from anp.authentication.verification_methods import EcdsaSecp256k1VerificationKey2019

        did_doc_path = project_root / "docs/did_public/public-did-doc.json"
        did_doc = json.loads(did_doc_path.read_text(encoding="utf-8"))
        method = did_doc["verificationMethod"][0]
        verifier = EcdsaSecp256k1VerificationKey2019.from_dict(method)
        cls.public_key = verifier.public_key.public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

    def test_hash_chain_valid(self):
        """测试有效的 hash chain (cart_hash 匹配)"""
        # 1. 创建 CartMandate
        cart_contents = {
            "id": "cart-123",
            "items": [{"id": "item-1", "quantity": 2}],
        }

        cart_mandate = build_cart_mandate(
            contents=cart_contents,
            merchant_private_key=self.private_key,
            merchant_did="did:wba:merchant",
            merchant_kid="merchant-key-1",
            shopper_did="did:wba:shopper",
            algorithm="ES256K",
        )

        cart_hash = compute_hash(cart_mandate.contents)

        # 2. 创建 PaymentMandate,包含正确的 cart_hash
        payment_contents = {
            "payment_mandate_id": "pm-123",
            "cart_hash": cart_hash,  # 正确的 cart_hash
            "payment_details_id": "order-123",
            "payment_details_total": {"label": "Total", "amount": {"currency": "CNY", "value": 100}},
            "payment_response": {"request_id": "order-123", "method_name": "QR_CODE", "details": {}},
            "merchant_agent": "MerchantAgent",
        }

        payment_mandate = build_payment_mandate(
            contents=payment_contents,
            shopper_private_key=self.private_key,
            shopper_did="did:wba:shopper",
            shopper_kid="shopper-key-1",
            merchant_did="did:wba:merchant",
            algorithm="ES256K",
        )

        # 3. 验证 hash chain
        is_valid = validate_payment_mandate(
            payment_mandate=payment_mandate,
            shopper_public_key=self.public_key,
            shopper_algorithm="ES256K",
            expected_merchant_did="did:wba:merchant",
            expected_cart_hash=cart_hash,
        )

        self.assertTrue(is_valid)

    def test_hash_chain_tampered_cart(self):
        """测试篡改的 cart 会破坏 hash chain"""
        # 1. 创建 CartMandate
        cart_contents = {
            "id": "cart-123",
            "items": [{"id": "item-1", "quantity": 2}],
        }

        cart_mandate = build_cart_mandate(
            contents=cart_contents,
            merchant_private_key=self.private_key,
            merchant_did="did:wba:merchant",
            merchant_kid="merchant-key-1",
            shopper_did="did:wba:shopper",
            algorithm="ES256K",
        )

        cart_hash = compute_hash(cart_mandate.contents)

        # 2. 创建 PaymentMandate
        payment_contents = {
            "payment_mandate_id": "pm-123",
            "cart_hash": cart_hash,
            "payment_details_id": "order-123",
            "payment_details_total": {"label": "Total", "amount": {"currency": "CNY", "value": 100}},
            "payment_response": {"request_id": "order-123", "method_name": "QR_CODE", "details": {}},
            "merchant_agent": "MerchantAgent",
        }

        payment_mandate = build_payment_mandate(
            contents=payment_contents,
            shopper_private_key=self.private_key,
            shopper_did="did:wba:shopper",
            shopper_kid="shopper-key-1",
            merchant_did="did:wba:merchant",
            algorithm="ES256K",
        )

        # 3. 篡改 cart 内容
        cart_mandate.contents["items"][0]["quantity"] = 999  # type: ignore

        # 重新计算篡改后的 cart_hash
        tampered_cart_hash = compute_hash(cart_mandate.contents)

        # 4. 验证应该失败,因为 cart_hash 不匹配
        is_valid = validate_payment_mandate(
            payment_mandate=payment_mandate,
            shopper_public_key=self.public_key,
            shopper_algorithm="ES256K",
            expected_merchant_did="did:wba:merchant",
            expected_cart_hash=tampered_cart_hash,  # 不同的 hash
        )

        self.assertFalse(is_valid)

    def test_hash_chain_wrong_cart_hash_in_payment(self):
        """测试 PaymentMandate 中的 cart_hash 错误"""
        # 1. 创建 CartMandate
        cart_contents = {"id": "cart-123"}

        cart_mandate = build_cart_mandate(
            contents=cart_contents,
            merchant_private_key=self.private_key,
            merchant_did="did:wba:merchant",
            merchant_kid="merchant-key-1",
            shopper_did="did:wba:shopper",
            algorithm="ES256K",
        )

        cart_hash = compute_hash(cart_mandate.contents)

        # 2. 创建 PaymentMandate,使用错误的 cart_hash
        payment_contents = {
            "payment_mandate_id": "pm-123",
            "cart_hash": "wrong_cart_hash_value",  # 错误的 cart_hash
            "payment_details_id": "order-123",
            "payment_details_total": {"label": "Total", "amount": {"currency": "CNY", "value": 100}},
            "payment_response": {"request_id": "order-123", "method_name": "QR_CODE", "details": {}},
            "merchant_agent": "MerchantAgent",
        }

        payment_mandate = build_payment_mandate(
            contents=payment_contents,
            shopper_private_key=self.private_key,
            shopper_did="did:wba:shopper",
            shopper_kid="shopper-key-1",
            merchant_did="did:wba:merchant",
            algorithm="ES256K",
        )

        # 3. 验证应该失败
        is_valid = validate_payment_mandate(
            payment_mandate=payment_mandate,
            shopper_public_key=self.public_key,
            shopper_algorithm="ES256K",
            expected_merchant_did="did:wba:merchant",
            expected_cart_hash=cart_hash,  # 正确的 hash
        )

        self.assertFalse(is_valid)

    def test_hash_chain_missing_cart_hash(self):
        """测试 PaymentMandate 缺少 cart_hash 会失败"""
        # PaymentMandate contents 必须包含 cart_hash
        payment_contents = {
            "payment_mandate_id": "pm-123",
            # 缺少 cart_hash
            "payment_details_id": "order-123",
            "payment_details_total": {"label": "Total", "amount": {"currency": "CNY", "value": 100}},
            "payment_response": {"request_id": "order-123", "method_name": "QR_CODE", "details": {}},
            "merchant_agent": "MerchantAgent",
        }

        # build_payment_mandate 应该抛出 ValueError
        with self.assertRaises(ValueError) as context:
            build_payment_mandate(
                contents=payment_contents,
                shopper_private_key=self.private_key,
                shopper_did="did:wba:shopper",
                shopper_kid="shopper-key-1",
                merchant_did="did:wba:merchant",
                algorithm="ES256K",
            )

        self.assertIn("cart_hash", str(context.exception))


class TestCredentialHashVerification(unittest.TestCase):
    """测试 credential (receipt) 中的 pmt_hash 验证"""

    @classmethod
    def setUpClass(cls):
        """设置测试密钥"""
        project_root = Path(__file__).resolve().parents[3]
        private_key_path = project_root / "docs/did_public/public-private-key.pem"
        cls.private_key = private_key_path.read_text(encoding="utf-8")

        import json
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        from anp.authentication.verification_methods import EcdsaSecp256k1VerificationKey2019

        did_doc_path = project_root / "docs/did_public/public-did-doc.json"
        did_doc = json.loads(did_doc_path.read_text(encoding="utf-8"))
        method = did_doc["verificationMethod"][0]
        verifier = EcdsaSecp256k1VerificationKey2019.from_dict(method)
        cls.public_key = verifier.public_key.public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

    def test_payment_receipt_pmt_hash(self):
        """测试 PaymentReceipt 包含正确的 pmt_hash"""
        from anp.ap2.credential_mandate import build_payment_receipt
        from anp.ap2.models import MoneyAmount, PaymentProvider, PaymentReceiptContents, PaymentStatus

        # 1. 创建 PaymentMandate
        payment_contents = {
            "payment_mandate_id": "pm-123",
            "cart_hash": "dummy_cart_hash",
            "payment_details_id": "order-123",
            "payment_details_total": {"label": "Total", "amount": {"currency": "CNY", "value": 100}},
            "payment_response": {"request_id": "order-123", "method_name": "QR_CODE", "details": {}},
            "merchant_agent": "MerchantAgent",
        }

        payment_mandate = build_payment_mandate(
            contents=payment_contents,
            shopper_private_key=self.private_key,
            shopper_did="did:wba:shopper",
            shopper_kid="shopper-key-1",
            merchant_did="did:wba:merchant",
            algorithm="ES256K",
        )

        pmt_hash = compute_hash(payment_mandate.payment_mandate_contents)

        # 2. 创建 PaymentReceipt
        receipt_contents = PaymentReceiptContents(
            payment_mandate_id="pm-123",
            provider=PaymentProvider.ALIPAY,
            status=PaymentStatus.SUCCEEDED,
            transaction_id="txn-123",
            out_trade_no="order-123",
            paid_at="2025-01-01T00:00:00Z",
            amount=MoneyAmount(currency="CNY", value=100),
            pmt_hash=pmt_hash,
        )

        receipt = build_payment_receipt(
            contents=receipt_contents,
            pmt_hash=pmt_hash,
            merchant_private_key=self.private_key,
            merchant_did="did:wba:merchant",
            merchant_kid="merchant-key-1",
            shopper_did="did:wba:shopper",
            algorithm="ES256K",
        )

        # 3. 验证 receipt contents 包含正确的 pmt_hash
        self.assertEqual(receipt.contents["pmt_hash"], pmt_hash)

    def test_fulfillment_receipt_pmt_hash(self):
        """测试 FulfillmentReceipt 包含正确的 pmt_hash"""
        from anp.ap2.credential_mandate import build_fulfillment_receipt
        from anp.ap2.models import DisplayItem, FulfillmentReceiptContents, MoneyAmount

        # 1. 创建 PaymentMandate
        payment_contents = {
            "payment_mandate_id": "pm-123",
            "cart_hash": "dummy_cart_hash",
            "payment_details_id": "order-123",
            "payment_details_total": {"label": "Total", "amount": {"currency": "CNY", "value": 100}},
            "payment_response": {"request_id": "order-123", "method_name": "QR_CODE", "details": {}},
            "merchant_agent": "MerchantAgent",
        }

        payment_mandate = build_payment_mandate(
            contents=payment_contents,
            shopper_private_key=self.private_key,
            shopper_did="did:wba:shopper",
            shopper_kid="shopper-key-1",
            merchant_did="did:wba:merchant",
            algorithm="ES256K",
        )

        pmt_hash = compute_hash(payment_mandate.payment_mandate_contents)

        # 2. 创建 FulfillmentReceipt
        fulfillment_contents = FulfillmentReceiptContents(
            order_id="order-123",
            items=[DisplayItem(id="item-1", label="Item 1", quantity=1, amount=MoneyAmount(currency="CNY", value=100))],
            fulfilled_at="2025-01-01T00:00:00Z",
            pmt_hash=pmt_hash,
        )

        receipt = build_fulfillment_receipt(
            contents=fulfillment_contents,
            pmt_hash=pmt_hash,
            merchant_private_key=self.private_key,
            merchant_did="did:wba:merchant",
            merchant_kid="merchant-key-1",
            shopper_did="did:wba:shopper",
            algorithm="ES256K",
        )

        # 3. 验证 receipt contents 包含正确的 pmt_hash
        self.assertEqual(receipt.contents["pmt_hash"], pmt_hash)


if __name__ == "__main__":
    unittest.main()
