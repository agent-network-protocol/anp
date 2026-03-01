"""EcdsaSecp256r1Signature2019 proof 签名的单元测试。

使用真实 secp256r1 密钥对，不使用 mock。
"""

import copy
import unittest

from cryptography.hazmat.primitives.asymmetric import ec

from anp.e2e_encryption_hpke.models import PROOF_TYPE
from anp.e2e_encryption_hpke.proof import generate_proof, verify_proof


class TestGenerateProof(unittest.TestCase):
    """测试 generate_proof 函数。"""

    def setUp(self):
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()
        self.verification_method = "did:wba:example.com:user:alice#keys-1"
        self.content = {
            "session_id": "abc123",
            "hpke_suite": "DHKEM-X25519-HKDF-SHA256/HKDF-SHA256/AES-128-GCM",
            "sender_did": "did:wba:example.com:user:alice",
            "recipient_did": "did:wba:example.com:user:bob",
        }

    def test_generate_proof_adds_proof_field(self):
        """generate_proof 应为 content 添加包含所有必需子字段的 proof 字段。"""
        result = generate_proof(
            self.content, self.private_key, self.verification_method
        )

        self.assertIn("proof", result)
        proof = result["proof"]
        self.assertEqual(proof["type"], PROOF_TYPE)
        self.assertIn("created", proof)
        self.assertEqual(proof["verification_method"], self.verification_method)
        self.assertIn("proof_value", proof)
        # proof_value 应为非空字符串（Base64URL 编码）
        self.assertIsInstance(proof["proof_value"], str)
        self.assertGreater(len(proof["proof_value"]), 0)

    def test_generate_proof_does_not_mutate_original(self):
        """generate_proof 不应修改传入的原始 content。"""
        original = copy.deepcopy(self.content)
        generate_proof(self.content, self.private_key, self.verification_method)
        self.assertEqual(self.content, original)


class TestVerifyProof(unittest.TestCase):
    """测试 verify_proof 函数。"""

    def setUp(self):
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()
        self.verification_method = "did:wba:example.com:user:alice#keys-1"
        self.content = {
            "session_id": "abc123",
            "hpke_suite": "DHKEM-X25519-HKDF-SHA256/HKDF-SHA256/AES-128-GCM",
            "sender_did": "did:wba:example.com:user:alice",
            "recipient_did": "did:wba:example.com:user:bob",
        }

    def test_verify_proof_succeeds_for_valid_proof(self):
        """对正确签名的 content，verify_proof 应返回 True。"""
        signed = generate_proof(
            self.content, self.private_key, self.verification_method
        )
        self.assertTrue(verify_proof(signed, self.public_key))

    def test_verify_proof_fails_for_tampered_content(self):
        """篡改 content 后，verify_proof 应返回 False。"""
        signed = generate_proof(
            self.content, self.private_key, self.verification_method
        )
        signed["session_id"] = "tampered_value"
        self.assertFalse(verify_proof(signed, self.public_key))

    def test_verify_proof_fails_for_wrong_public_key(self):
        """使用错误的公钥验证时，verify_proof 应返回 False。"""
        signed = generate_proof(
            self.content, self.private_key, self.verification_method
        )
        wrong_key = ec.generate_private_key(ec.SECP256R1()).public_key()
        self.assertFalse(verify_proof(signed, wrong_key))

    def test_verify_proof_with_zero_time_drift(self):
        """max_time_drift=0 时跳过时间戳检查，刚生成的 proof 仍应验证通过。"""
        signed = generate_proof(
            self.content, self.private_key, self.verification_method
        )
        # max_time_drift=0 表示跳过时间检查（根据源码 if max_time_drift > 0）
        self.assertTrue(verify_proof(signed, self.public_key, max_time_drift=0))

    def test_verify_proof_with_default_drift_passes_for_recent_proof(self):
        """使用默认 max_time_drift=300，刚生成的 proof 应该验证通过。"""
        signed = generate_proof(
            self.content, self.private_key, self.verification_method
        )
        self.assertTrue(verify_proof(signed, self.public_key, max_time_drift=300))

    def test_verify_proof_fails_without_proof_field(self):
        """缺少 proof 字段时，verify_proof 应返回 False。"""
        self.assertFalse(verify_proof(self.content, self.public_key))

    def test_verify_proof_fails_without_proof_value(self):
        """proof 字段中缺少 proof_value 时，verify_proof 应返回 False。"""
        signed = generate_proof(
            self.content, self.private_key, self.verification_method
        )
        del signed["proof"]["proof_value"]
        self.assertFalse(verify_proof(signed, self.public_key))


if __name__ == "__main__":
    unittest.main()
