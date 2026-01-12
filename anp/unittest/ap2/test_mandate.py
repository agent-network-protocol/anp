"""AP2 Mandate Core Functionality Tests.

This module tests the core mandate building and validation functionality:
- build_mandate() - JWT mandate creation with proper claims
- validate_mandate() - JWT signature and structure validation
- JCS canonicalization and hash computation
- Mandate with different verification methods
- Invalid mandate handling (expired, wrong signature, malformed)
"""

import time
import unittest
import uuid
from pathlib import Path

from anp.ap2.mandate import (
    b64url_no_pad,
    build_mandate,
    compute_hash,
    jcs_canonicalize,
    validate_mandate,
)


class TestJCSCanonicalization(unittest.TestCase):
    """测试 JCS (RFC 8785) JSON 规范化"""

    def test_jcs_canonicalize_sorts_keys(self):
        """测试 JCS 规范化会对键进行排序"""
        obj = {"z": 1, "a": 2, "m": 3}
        result = jcs_canonicalize(obj)
        # JCS 应该按字母顺序排序键
        self.assertEqual(result, '{"a":2,"m":3,"z":1}')

    def test_jcs_canonicalize_no_whitespace(self):
        """测试 JCS 规范化不包含空格"""
        obj = {"key": "value", "number": 42}
        result = jcs_canonicalize(obj)
        # 不应该有空格
        self.assertNotIn(" ", result)
        self.assertEqual(result, '{"key":"value","number":42}')

    def test_jcs_canonicalize_nested_objects(self):
        """测试 JCS 规范化嵌套对象"""
        obj = {"outer": {"z": 1, "a": 2}, "simple": "value"}
        result = jcs_canonicalize(obj)
        # 嵌套对象的键也应该排序
        self.assertEqual(result, '{"outer":{"a":2,"z":1},"simple":"value"}')


class TestHashComputation(unittest.TestCase):
    """测试哈希计算功能"""

    def test_compute_hash_deterministic(self):
        """测试哈希计算是确定性的"""
        contents = {"id": "test-123", "amount": 100}
        hash1 = compute_hash(contents)
        hash2 = compute_hash(contents)
        # 相同的内容应该产生相同的哈希
        self.assertEqual(hash1, hash2)

    def test_compute_hash_different_order_same_result(self):
        """测试不同键顺序产生相同哈希"""
        contents1 = {"z": 1, "a": 2}
        contents2 = {"a": 2, "z": 1}
        hash1 = compute_hash(contents1)
        hash2 = compute_hash(contents2)
        # JCS 规范化确保顺序无关
        self.assertEqual(hash1, hash2)

    def test_compute_hash_different_content(self):
        """测试不同内容产生不同哈希"""
        contents1 = {"id": "test-123"}
        contents2 = {"id": "test-456"}
        hash1 = compute_hash(contents1)
        hash2 = compute_hash(contents2)
        # 不同的内容应该产生不同的哈希
        self.assertNotEqual(hash1, hash2)

    def test_b64url_no_pad(self):
        """测试 Base64URL 编码无填充"""
        data = b"test data"
        result = b64url_no_pad(data)
        # 不应该有填充字符 '='
        self.assertNotIn("=", result)
        # 应该是有效的 Base64URL
        self.assertTrue(all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in result))


class TestBuildMandate(unittest.TestCase):
    """测试 mandate 构建功能"""

    @classmethod
    def setUpClass(cls):
        """设置测试密钥"""
        # 使用项目中的测试密钥
        project_root = Path(__file__).resolve().parents[3]
        private_key_path = project_root / "docs/did_public/public-private-key.pem"
        cls.private_key = private_key_path.read_text(encoding="utf-8")

    def test_build_mandate_basic(self):
        """测试基本 mandate 构建"""
        contents = {"id": "test-123", "amount": 100}
        headers = {"alg": "ES256K", "kid": "key-1", "typ": "JWT"}

        mandate = build_mandate(
            contents=contents,
            headers=headers,
            iss="did:wba:issuer",
            sub="did:wba:subject",
            aud="did:wba:audience",
            private_key=self.private_key,
            algorithm="ES256K",
            ttl_seconds=900,
        )

        # 检查返回结构
        self.assertIn("contents", mandate)
        self.assertIn("auth", mandate)
        self.assertEqual(mandate["contents"], contents)
        self.assertIsInstance(mandate["auth"], str)
        # JWT 应该有三个部分
        self.assertEqual(len(mandate["auth"].split(".")), 3)

    def test_build_mandate_custom_hash_field(self):
        """测试自定义哈希字段名"""
        contents = {"id": "cart-123"}
        headers = {"alg": "ES256K", "kid": "key-1", "typ": "JWT"}

        mandate = build_mandate(
            contents=contents,
            headers=headers,
            iss="did:wba:merchant",
            sub="did:wba:merchant",
            aud="did:wba:shopper",
            private_key=self.private_key,
            algorithm="ES256K",
            hash_field_name="cart_hash",
        )

        # 解码 JWT payload 检查字段名
        import jwt
        payload = jwt.decode(mandate["auth"], options={"verify_signature": False})
        self.assertIn("cart_hash", payload)
        self.assertNotIn("content_hash", payload)

    def test_build_mandate_jwt_claims(self):
        """测试 JWT claims 正确设置"""
        contents = {"id": "test"}
        headers = {"alg": "ES256K", "kid": "key-1", "typ": "JWT"}

        mandate = build_mandate(
            contents=contents,
            headers=headers,
            iss="did:wba:issuer",
            sub="did:wba:subject",
            aud="did:wba:audience",
            private_key=self.private_key,
            algorithm="ES256K",
            ttl_seconds=900,
        )

        import jwt
        payload = jwt.decode(mandate["auth"], options={"verify_signature": False})

        # 检查标准 claims
        self.assertEqual(payload["iss"], "did:wba:issuer")
        self.assertEqual(payload["sub"], "did:wba:subject")
        self.assertEqual(payload["aud"], "did:wba:audience")
        self.assertIn("iat", payload)
        self.assertIn("exp", payload)
        self.assertIn("jti", payload)
        # exp 应该是 iat + ttl_seconds
        self.assertEqual(payload["exp"], payload["iat"] + 900)


class TestValidateMandate(unittest.TestCase):
    """测试 mandate 验证功能"""

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

    def test_validate_mandate_valid(self):
        """测试验证有效的 mandate"""
        contents = {"id": "test-123", "amount": 100}
        headers = {"alg": "ES256K", "kid": "key-1", "typ": "JWT"}

        mandate = build_mandate(
            contents=contents,
            headers=headers,
            iss="did:wba:issuer",
            sub="did:wba:subject",
            aud="did:wba:audience",
            private_key=self.private_key,
            algorithm="ES256K",
            ttl_seconds=900,
        )

        is_valid = validate_mandate(
            mandate=mandate,
            public_key=self.public_key,
            algorithm="ES256K",
            expected_audience="did:wba:audience",
            verify_time=True,
        )

        self.assertTrue(is_valid)

    def test_validate_mandate_wrong_audience(self):
        """测试验证错误的 audience 应该失败"""
        contents = {"id": "test-123"}
        headers = {"alg": "ES256K", "kid": "key-1", "typ": "JWT"}

        mandate = build_mandate(
            contents=contents,
            headers=headers,
            iss="did:wba:issuer",
            sub="did:wba:subject",
            aud="did:wba:audience1",
            private_key=self.private_key,
            algorithm="ES256K",
        )

        is_valid = validate_mandate(
            mandate=mandate,
            public_key=self.public_key,
            algorithm="ES256K",
            expected_audience="did:wba:audience2",  # 不同的 audience
        )

        self.assertFalse(is_valid)

    def test_validate_mandate_tampered_contents(self):
        """测试验证被篡改的内容应该失败"""
        contents = {"id": "test-123", "amount": 100}
        headers = {"alg": "ES256K", "kid": "key-1", "typ": "JWT"}

        mandate = build_mandate(
            contents=contents,
            headers=headers,
            iss="did:wba:issuer",
            sub="did:wba:subject",
            aud="did:wba:audience",
            private_key=self.private_key,
            algorithm="ES256K",
        )

        # 篡改内容
        mandate["contents"]["amount"] = 999

        is_valid = validate_mandate(
            mandate=mandate,
            public_key=self.public_key,
            algorithm="ES256K",
            expected_audience="did:wba:audience",
        )

        # 哈希不匹配,验证应该失败
        self.assertFalse(is_valid)

    def test_validate_mandate_expired(self):
        """测试验证过期的 mandate 应该失败"""
        contents = {"id": "test-123"}
        headers = {"alg": "ES256K", "kid": "key-1", "typ": "JWT"}

        mandate = build_mandate(
            contents=contents,
            headers=headers,
            iss="did:wba:issuer",
            sub="did:wba:subject",
            aud="did:wba:audience",
            private_key=self.private_key,
            algorithm="ES256K",
            ttl_seconds=1,  # 1 秒后过期
        )

        # 等待过期
        time.sleep(2)

        is_valid = validate_mandate(
            mandate=mandate,
            public_key=self.public_key,
            algorithm="ES256K",
            expected_audience="did:wba:audience",
            verify_time=True,  # 验证时间
        )

        self.assertFalse(is_valid)

    def test_validate_mandate_expired_skip_time_check(self):
        """测试跳过时间验证可以验证过期的 mandate"""
        contents = {"id": "test-123"}
        headers = {"alg": "ES256K", "kid": "key-1", "typ": "JWT"}

        mandate = build_mandate(
            contents=contents,
            headers=headers,
            iss="did:wba:issuer",
            sub="did:wba:subject",
            aud="did:wba:audience",
            private_key=self.private_key,
            algorithm="ES256K",
            ttl_seconds=1,
        )

        time.sleep(2)

        is_valid = validate_mandate(
            mandate=mandate,
            public_key=self.public_key,
            algorithm="ES256K",
            expected_audience="did:wba:audience",
            verify_time=False,  # 跳过时间验证
        )

        # 只要签名和哈希正确,就应该通过
        self.assertTrue(is_valid)

    def test_validate_mandate_custom_hash_field(self):
        """测试验证自定义哈希字段名"""
        contents = {"id": "payment-123"}
        headers = {"alg": "ES256K", "kid": "key-1", "typ": "JWT"}

        mandate = build_mandate(
            contents=contents,
            headers=headers,
            iss="did:wba:shopper",
            sub="did:wba:shopper",
            aud="did:wba:merchant",
            private_key=self.private_key,
            algorithm="ES256K",
            hash_field_name="pmt_hash",
        )

        is_valid = validate_mandate(
            mandate=mandate,
            public_key=self.public_key,
            algorithm="ES256K",
            expected_audience="did:wba:merchant",
            hash_field_name="pmt_hash",  # 必须匹配
        )

        self.assertTrue(is_valid)

    def test_validate_mandate_missing_fields(self):
        """测试验证缺少字段的 mandate 应该失败"""
        # 缺少 contents
        mandate_no_contents = {"auth": "some.jwt.token"}
        is_valid = validate_mandate(
            mandate=mandate_no_contents,
            public_key=self.public_key,
            algorithm="ES256K",
        )
        self.assertFalse(is_valid)

        # 缺少 auth
        mandate_no_auth = {"contents": {"id": "test"}}
        is_valid = validate_mandate(
            mandate=mandate_no_auth,
            public_key=self.public_key,
            algorithm="ES256K",
        )
        self.assertFalse(is_valid)

    def test_validate_mandate_malformed_jwt(self):
        """测试验证格式错误的 JWT 应该失败"""
        mandate = {
            "contents": {"id": "test"},
            "auth": "not.a.valid.jwt.token.format",
        }

        is_valid = validate_mandate(
            mandate=mandate,
            public_key=self.public_key,
            algorithm="ES256K",
        )

        self.assertFalse(is_valid)


if __name__ == "__main__":
    unittest.main()
