"""W3C Data Integrity Proof Tests.

Tests for W3C proof generation and verification:
- generate_w3c_proof() with secp256k1 and Ed25519
- verify_w3c_proof() with valid and invalid proofs
- Proof options (domain, challenge, proofPurpose)
- Tamper detection
- Key type mismatch handling
"""

import copy
import unittest

from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from anp.proof import (
    PROOF_TYPE_ED25519,
    PROOF_TYPE_SECP256K1,
    generate_w3c_proof,
    verify_w3c_proof,
)


class TestGenerateProofSecp256k1(unittest.TestCase):
    """测试 secp256k1 Proof 生成"""

    def setUp(self):
        self.private_key = ec.generate_private_key(ec.SECP256K1())
        self.public_key = self.private_key.public_key()
        self.document = {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:wba:example.com:alice",
            "name": "Agent Alice",
        }
        self.verification_method = "did:wba:example.com:alice#key-1"

    def test_generate_proof_adds_proof_field(self):
        """测试生成的文档包含 proof 字段"""
        signed = generate_w3c_proof(
            document=self.document,
            private_key=self.private_key,
            verification_method=self.verification_method,
        )
        self.assertIn("proof", signed)

    def test_proof_has_required_fields(self):
        """测试 proof 包含所有 W3C 必需字段"""
        signed = generate_w3c_proof(
            document=self.document,
            private_key=self.private_key,
            verification_method=self.verification_method,
        )
        proof = signed["proof"]
        self.assertEqual(proof["type"], PROOF_TYPE_SECP256K1)
        self.assertIn("created", proof)
        self.assertEqual(proof["verificationMethod"], self.verification_method)
        self.assertEqual(proof["proofPurpose"], "assertionMethod")
        self.assertIn("proofValue", proof)

    def test_auto_detect_proof_type(self):
        """测试自动检测密钥类型 → proof type"""
        signed = generate_w3c_proof(
            document=self.document,
            private_key=self.private_key,
            verification_method=self.verification_method,
        )
        self.assertEqual(signed["proof"]["type"], PROOF_TYPE_SECP256K1)

    def test_original_document_not_modified(self):
        """测试原始文档未被修改"""
        original = copy.deepcopy(self.document)
        generate_w3c_proof(
            document=self.document,
            private_key=self.private_key,
            verification_method=self.verification_method,
        )
        self.assertEqual(self.document, original)

    def test_custom_proof_purpose(self):
        """测试自定义 proofPurpose"""
        signed = generate_w3c_proof(
            document=self.document,
            private_key=self.private_key,
            verification_method=self.verification_method,
            proof_purpose="authentication",
        )
        self.assertEqual(signed["proof"]["proofPurpose"], "authentication")

    def test_custom_created_timestamp(self):
        """测试自定义 created 时间戳"""
        ts = "2026-01-01T00:00:00Z"
        signed = generate_w3c_proof(
            document=self.document,
            private_key=self.private_key,
            verification_method=self.verification_method,
            created=ts,
        )
        self.assertEqual(signed["proof"]["created"], ts)

    def test_domain_and_challenge(self):
        """测试 domain 和 challenge 可选字段"""
        signed = generate_w3c_proof(
            document=self.document,
            private_key=self.private_key,
            verification_method=self.verification_method,
            domain="example.com",
            challenge="abc-123",
        )
        self.assertEqual(signed["proof"]["domain"], "example.com")
        self.assertEqual(signed["proof"]["challenge"], "abc-123")


class TestGenerateProofEd25519(unittest.TestCase):
    """测试 Ed25519 Proof 生成"""

    def setUp(self):
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.document = {
            "id": "did:wba:example.com:bob",
            "type": "VerifiableCredential",
            "issuer": "did:wba:example.com:issuer",
        }
        self.verification_method = "did:wba:example.com:bob#key-1"

    def test_generate_ed25519_proof(self):
        """测试 Ed25519 proof 生成"""
        signed = generate_w3c_proof(
            document=self.document,
            private_key=self.private_key,
            verification_method=self.verification_method,
        )
        self.assertEqual(signed["proof"]["type"], PROOF_TYPE_ED25519)

    def test_ed25519_proof_verifiable(self):
        """测试 Ed25519 proof 可以验证"""
        signed = generate_w3c_proof(
            document=self.document,
            private_key=self.private_key,
            verification_method=self.verification_method,
        )
        self.assertTrue(verify_w3c_proof(signed, self.public_key))


class TestVerifyProofSecp256k1(unittest.TestCase):
    """测试 secp256k1 Proof 验证"""

    def setUp(self):
        self.private_key = ec.generate_private_key(ec.SECP256K1())
        self.public_key = self.private_key.public_key()
        self.document = {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:wba:example.com:alice",
            "claim": "test-data",
        }
        self.verification_method = "did:wba:example.com:alice#key-1"

    def test_valid_proof_verifies(self):
        """测试有效的 proof 验证通过"""
        signed = generate_w3c_proof(
            document=self.document,
            private_key=self.private_key,
            verification_method=self.verification_method,
        )
        self.assertTrue(verify_w3c_proof(signed, self.public_key))

    def test_tampered_document_fails(self):
        """测试篡改文档后验证失败"""
        signed = generate_w3c_proof(
            document=self.document,
            private_key=self.private_key,
            verification_method=self.verification_method,
        )
        signed["claim"] = "tampered-data"
        self.assertFalse(verify_w3c_proof(signed, self.public_key))

    def test_tampered_proof_value_fails(self):
        """测试篡改 proofValue 后验证失败"""
        signed = generate_w3c_proof(
            document=self.document,
            private_key=self.private_key,
            verification_method=self.verification_method,
        )
        signed["proof"]["proofValue"] = "AAAA" + signed["proof"]["proofValue"][4:]
        self.assertFalse(verify_w3c_proof(signed, self.public_key))

    def test_wrong_public_key_fails(self):
        """测试错误的公钥验证失败"""
        other_key = ec.generate_private_key(ec.SECP256K1()).public_key()
        signed = generate_w3c_proof(
            document=self.document,
            private_key=self.private_key,
            verification_method=self.verification_method,
        )
        self.assertFalse(verify_w3c_proof(signed, other_key))

    def test_missing_proof_fails(self):
        """测试缺少 proof 字段时验证失败"""
        self.assertFalse(verify_w3c_proof(self.document, self.public_key))

    def test_missing_proof_fields_fails(self):
        """测试 proof 缺少必需字段时验证失败"""
        signed = generate_w3c_proof(
            document=self.document,
            private_key=self.private_key,
            verification_method=self.verification_method,
        )
        del signed["proof"]["proofValue"]
        self.assertFalse(verify_w3c_proof(signed, self.public_key))

    def test_expected_purpose_match(self):
        """测试验证 proofPurpose 匹配"""
        signed = generate_w3c_proof(
            document=self.document,
            private_key=self.private_key,
            verification_method=self.verification_method,
            proof_purpose="authentication",
        )
        self.assertTrue(
            verify_w3c_proof(signed, self.public_key, expected_purpose="authentication")
        )

    def test_expected_purpose_mismatch(self):
        """测试 proofPurpose 不匹配时验证失败"""
        signed = generate_w3c_proof(
            document=self.document,
            private_key=self.private_key,
            verification_method=self.verification_method,
            proof_purpose="assertionMethod",
        )
        self.assertFalse(
            verify_w3c_proof(signed, self.public_key, expected_purpose="authentication")
        )

    def test_expected_domain_match(self):
        """测试验证 domain 匹配"""
        signed = generate_w3c_proof(
            document=self.document,
            private_key=self.private_key,
            verification_method=self.verification_method,
            domain="example.com",
        )
        self.assertTrue(
            verify_w3c_proof(signed, self.public_key, expected_domain="example.com")
        )

    def test_expected_domain_mismatch(self):
        """测试 domain 不匹配时验证失败"""
        signed = generate_w3c_proof(
            document=self.document,
            private_key=self.private_key,
            verification_method=self.verification_method,
            domain="example.com",
        )
        self.assertFalse(
            verify_w3c_proof(signed, self.public_key, expected_domain="other.com")
        )

    def test_expected_challenge_match(self):
        """测试验证 challenge 匹配"""
        signed = generate_w3c_proof(
            document=self.document,
            private_key=self.private_key,
            verification_method=self.verification_method,
            challenge="nonce-xyz",
        )
        self.assertTrue(
            verify_w3c_proof(signed, self.public_key, expected_challenge="nonce-xyz")
        )

    def test_expected_challenge_mismatch(self):
        """测试 challenge 不匹配时验证失败"""
        signed = generate_w3c_proof(
            document=self.document,
            private_key=self.private_key,
            verification_method=self.verification_method,
            challenge="nonce-xyz",
        )
        self.assertFalse(
            verify_w3c_proof(signed, self.public_key, expected_challenge="wrong-nonce")
        )


class TestVerifyProofEd25519(unittest.TestCase):
    """测试 Ed25519 Proof 验证"""

    def setUp(self):
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.document = {"id": "did:wba:example.com:bob", "data": "test"}
        self.verification_method = "did:wba:example.com:bob#key-1"

    def test_valid_ed25519_proof(self):
        """测试有效的 Ed25519 proof 验证通过"""
        signed = generate_w3c_proof(
            document=self.document,
            private_key=self.private_key,
            verification_method=self.verification_method,
        )
        self.assertTrue(verify_w3c_proof(signed, self.public_key))

    def test_tampered_document_fails(self):
        """测试篡改文档后 Ed25519 验证失败"""
        signed = generate_w3c_proof(
            document=self.document,
            private_key=self.private_key,
            verification_method=self.verification_method,
        )
        signed["data"] = "tampered"
        self.assertFalse(verify_w3c_proof(signed, self.public_key))

    def test_wrong_ed25519_key_fails(self):
        """测试错误的 Ed25519 公钥验证失败"""
        other_key = ed25519.Ed25519PrivateKey.generate().public_key()
        signed = generate_w3c_proof(
            document=self.document,
            private_key=self.private_key,
            verification_method=self.verification_method,
        )
        self.assertFalse(verify_w3c_proof(signed, other_key))


class TestKeyTypeMismatch(unittest.TestCase):
    """测试密钥类型不匹配的错误处理"""

    def test_ed25519_key_with_secp256k1_type_raises(self):
        """测试 Ed25519 密钥指定 secp256k1 类型时抛出异常"""
        private_key = ed25519.Ed25519PrivateKey.generate()
        with self.assertRaises(ValueError):
            generate_w3c_proof(
                document={"id": "test"},
                private_key=private_key,
                verification_method="did:wba:example.com#key-1",
                proof_type=PROOF_TYPE_SECP256K1,
            )

    def test_secp256k1_key_with_ed25519_type_raises(self):
        """测试 secp256k1 密钥指定 Ed25519 类型时抛出异常"""
        private_key = ec.generate_private_key(ec.SECP256K1())
        with self.assertRaises(ValueError):
            generate_w3c_proof(
                document={"id": "test"},
                private_key=private_key,
                verification_method="did:wba:example.com#key-1",
                proof_type=PROOF_TYPE_ED25519,
            )

    def test_unsupported_proof_type_raises(self):
        """测试不支持的 proof type 抛出异常"""
        private_key = ec.generate_private_key(ec.SECP256K1())
        with self.assertRaises(ValueError):
            generate_w3c_proof(
                document={"id": "test"},
                private_key=private_key,
                verification_method="did:wba:example.com#key-1",
                proof_type="UnsupportedSignature2099",
            )

    def test_wrong_key_type_verify_fails(self):
        """测试验证时公钥类型不匹配返回 False"""
        sk = ec.generate_private_key(ec.SECP256K1())
        signed = generate_w3c_proof(
            document={"id": "test"},
            private_key=sk,
            verification_method="did:wba:example.com#key-1",
        )
        ed_pk = ed25519.Ed25519PrivateKey.generate().public_key()
        self.assertFalse(verify_w3c_proof(signed, ed_pk))


class TestProofWithComplexDocument(unittest.TestCase):
    """测试复杂文档结构的 Proof"""

    def test_nested_document(self):
        """测试嵌套文档的 proof 生成和验证"""
        private_key = ec.generate_private_key(ec.SECP256K1())
        doc = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1",
            ],
            "type": ["VerifiableCredential", "AgentCapability"],
            "issuer": "did:wba:example.com:issuer",
            "credentialSubject": {
                "id": "did:wba:example.com:agent-1",
                "capabilities": ["search", "booking", "payment"],
                "metadata": {"version": "1.0", "active": True},
            },
        }
        signed = generate_w3c_proof(
            document=doc,
            private_key=private_key,
            verification_method="did:wba:example.com:issuer#key-1",
        )
        self.assertTrue(verify_w3c_proof(signed, private_key.public_key()))

    def test_unicode_content(self):
        """测试包含 Unicode 内容的文档"""
        private_key = ed25519.Ed25519PrivateKey.generate()
        doc = {
            "id": "did:wba:example.com:agent",
            "name": "智能代理 Alice",
            "description": "这是一个测试用的 Agent 🤖",
        }
        signed = generate_w3c_proof(
            document=doc,
            private_key=private_key,
            verification_method="did:wba:example.com:agent#key-1",
        )
        self.assertTrue(verify_w3c_proof(signed, private_key.public_key()))

    def test_document_key_order_irrelevant(self):
        """测试文档键顺序不影响验证"""
        private_key = ec.generate_private_key(ec.SECP256K1())
        doc1 = {"z": 1, "a": 2, "m": 3}
        doc2 = {"a": 2, "m": 3, "z": 1}

        signed = generate_w3c_proof(
            document=doc1,
            private_key=private_key,
            verification_method="did:wba:example.com#key-1",
        )
        # 重建文档时用不同键顺序，proof 应仍然有效
        signed_reordered = {"a": 2, "m": 3, "z": 1, "proof": signed["proof"]}
        self.assertTrue(verify_w3c_proof(signed_reordered, private_key.public_key()))

    def test_existing_proof_field_excluded_from_signing(self):
        """测试已有 proof 字段不影响签名"""
        private_key = ec.generate_private_key(ec.SECP256K1())
        doc = {"id": "test", "proof": {"old": "proof-data"}}
        signed = generate_w3c_proof(
            document=doc,
            private_key=private_key,
            verification_method="did:wba:example.com#key-1",
        )
        # 新 proof 应覆盖旧 proof
        self.assertNotEqual(signed["proof"].get("old"), "proof-data")
        self.assertTrue(verify_w3c_proof(signed, private_key.public_key()))


if __name__ == "__main__":
    unittest.main()
