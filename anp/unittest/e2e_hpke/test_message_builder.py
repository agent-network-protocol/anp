"""消息构建函数的单元测试。

使用真实 X25519 和 secp256r1 密钥，不使用 mock。
"""

import os
import unittest

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from anp.e2e_encryption_hpke.message_builder import (
    build_e2ee_error,
    build_e2ee_init,
    build_e2ee_msg,
    build_e2ee_rekey,
    build_group_e2ee_key,
    build_group_e2ee_msg,
    build_group_epoch_advance,
)
from anp.e2e_encryption_hpke.models import HPKE_SUITE


class TestBuildE2eeInit(unittest.TestCase):
    """测试 build_e2ee_init 函数。"""

    def setUp(self):
        self.recipient_sk = X25519PrivateKey.generate()
        self.recipient_pk = self.recipient_sk.public_key()
        self.signing_key = ec.generate_private_key(ec.SECP256R1())
        self.root_seed = os.urandom(32)
        self.session_id = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
        self.sender_did = "did:wba:example.com:user:alice"
        self.recipient_did = "did:wba:example.com:user:bob"
        self.recipient_key_id = "did:wba:example.com:user:bob#key-x25519-1"
        self.verification_method = "did:wba:example.com:user:alice#keys-1"

    def test_build_e2ee_init_has_required_fields(self):
        """build_e2ee_init 应生成包含所有必需字段和 proof 的 content。"""
        content = build_e2ee_init(
            session_id=self.session_id,
            sender_did=self.sender_did,
            recipient_did=self.recipient_did,
            recipient_key_id=self.recipient_key_id,
            recipient_pk=self.recipient_pk,
            root_seed=self.root_seed,
            signing_key=self.signing_key,
            verification_method=self.verification_method,
        )

        self.assertEqual(content["session_id"], self.session_id)
        self.assertEqual(content["hpke_suite"], HPKE_SUITE)
        self.assertEqual(content["sender_did"], self.sender_did)
        self.assertEqual(content["recipient_did"], self.recipient_did)
        self.assertEqual(content["recipient_key_id"], self.recipient_key_id)
        self.assertIn("enc", content)
        self.assertIn("encrypted_seed", content)
        self.assertIn("expires", content)
        # proof 字段
        self.assertIn("proof", content)
        proof = content["proof"]
        self.assertEqual(proof["type"], "EcdsaSecp256r1Signature2019")
        self.assertIn("created", proof)
        self.assertEqual(proof["verification_method"], self.verification_method)
        self.assertIn("proof_value", proof)

    def test_build_e2ee_init_custom_expires(self):
        """build_e2ee_init 应支持自定义 expires 参数。"""
        content = build_e2ee_init(
            session_id=self.session_id,
            sender_did=self.sender_did,
            recipient_did=self.recipient_did,
            recipient_key_id=self.recipient_key_id,
            recipient_pk=self.recipient_pk,
            root_seed=self.root_seed,
            signing_key=self.signing_key,
            verification_method=self.verification_method,
            expires=3600,
        )
        self.assertEqual(content["expires"], 3600)


class TestBuildE2eeMsg(unittest.TestCase):
    """测试 build_e2ee_msg 函数。"""

    def test_build_e2ee_msg_has_required_fields(self):
        """build_e2ee_msg 应生成包含 session_id, seq, original_type, ciphertext 的 content。"""
        content = build_e2ee_msg(
            session_id="sess001",
            seq=1,
            original_type="text/plain",
            ciphertext_b64="Y2lwaGVydGV4dA==",
        )

        self.assertEqual(content["session_id"], "sess001")
        self.assertEqual(content["seq"], 1)
        self.assertEqual(content["original_type"], "text/plain")
        self.assertEqual(content["ciphertext"], "Y2lwaGVydGV4dA==")
        # e2ee_msg 不含 proof
        self.assertNotIn("proof", content)


class TestBuildE2eeRekey(unittest.TestCase):
    """测试 build_e2ee_rekey 函数。"""

    def setUp(self):
        self.recipient_sk = X25519PrivateKey.generate()
        self.recipient_pk = self.recipient_sk.public_key()
        self.signing_key = ec.generate_private_key(ec.SECP256R1())
        self.root_seed = os.urandom(32)

    def test_build_e2ee_rekey_structure_matches_init(self):
        """build_e2ee_rekey 应生成与 build_e2ee_init 结构相同的 content。"""
        content = build_e2ee_rekey(
            session_id="rekey_session_001",
            sender_did="did:wba:example.com:user:alice",
            recipient_did="did:wba:example.com:user:bob",
            recipient_key_id="did:wba:example.com:user:bob#key-x25519-1",
            recipient_pk=self.recipient_pk,
            root_seed=self.root_seed,
            signing_key=self.signing_key,
            verification_method="did:wba:example.com:user:alice#keys-1",
        )

        self.assertIn("session_id", content)
        self.assertIn("hpke_suite", content)
        self.assertIn("enc", content)
        self.assertIn("encrypted_seed", content)
        self.assertIn("proof", content)


class TestBuildE2eeError(unittest.TestCase):
    """测试 build_e2ee_error 函数。"""

    def test_build_e2ee_error_with_all_fields(self):
        """build_e2ee_error 应包含所有指定字段。"""
        content = build_e2ee_error(
            error_code="session_not_found",
            session_id="sess001",
            message="Session does not exist",
        )

        self.assertEqual(content["error_code"], "session_not_found")
        self.assertEqual(content["session_id"], "sess001")
        self.assertEqual(content["message"], "Session does not exist")

    def test_build_e2ee_error_with_only_error_code(self):
        """仅提供 error_code 时，content 不应包含 session_id 和 message。"""
        content = build_e2ee_error(error_code="decryption_failed")

        self.assertEqual(content["error_code"], "decryption_failed")
        self.assertNotIn("session_id", content)
        self.assertNotIn("message", content)


class TestBuildGroupE2eeKey(unittest.TestCase):
    """测试 build_group_e2ee_key 函数。"""

    def setUp(self):
        self.recipient_sk = X25519PrivateKey.generate()
        self.recipient_pk = self.recipient_sk.public_key()
        self.signing_key = ec.generate_private_key(ec.SECP256R1())
        self.sender_chain_key = os.urandom(32)

    def test_build_group_e2ee_key_has_required_fields(self):
        """build_group_e2ee_key 应生成包含所有必需字段和 proof 的 content。"""
        content = build_group_e2ee_key(
            group_did="did:wba:example.com:group:dev-team",
            epoch=1,
            sender_did="did:wba:example.com:user:alice",
            sender_key_id="did:wba:example.com:user:alice#sender-key-1",
            recipient_key_id="did:wba:example.com:user:bob#key-x25519-1",
            recipient_pk=self.recipient_pk,
            sender_chain_key=self.sender_chain_key,
            signing_key=self.signing_key,
            verification_method="did:wba:example.com:user:alice#keys-1",
        )

        self.assertEqual(content["group_did"], "did:wba:example.com:group:dev-team")
        self.assertEqual(content["epoch"], 1)
        self.assertEqual(content["sender_did"], "did:wba:example.com:user:alice")
        self.assertIn("sender_key_id", content)
        self.assertIn("recipient_key_id", content)
        self.assertEqual(content["hpke_suite"], HPKE_SUITE)
        self.assertIn("enc", content)
        self.assertIn("encrypted_sender_key", content)
        self.assertIn("expires", content)
        # proof 字段
        self.assertIn("proof", content)
        proof = content["proof"]
        self.assertEqual(proof["type"], "EcdsaSecp256r1Signature2019")
        self.assertIn("proof_value", proof)


class TestBuildGroupE2eeMsg(unittest.TestCase):
    """测试 build_group_e2ee_msg 函数。"""

    def test_build_group_e2ee_msg_has_required_fields(self):
        """build_group_e2ee_msg 应生成包含所有必需字段的 content（无 proof）。"""
        content = build_group_e2ee_msg(
            group_did="did:wba:example.com:group:dev-team",
            epoch=1,
            sender_did="did:wba:example.com:user:alice",
            sender_key_id="did:wba:example.com:user:alice#sender-key-1",
            seq=42,
            original_type="application/json",
            ciphertext_b64="ZW5jcnlwdGVk",
        )

        self.assertEqual(content["group_did"], "did:wba:example.com:group:dev-team")
        self.assertEqual(content["epoch"], 1)
        self.assertEqual(content["sender_did"], "did:wba:example.com:user:alice")
        self.assertEqual(
            content["sender_key_id"],
            "did:wba:example.com:user:alice#sender-key-1",
        )
        self.assertEqual(content["seq"], 42)
        self.assertEqual(content["original_type"], "application/json")
        self.assertEqual(content["ciphertext"], "ZW5jcnlwdGVk")
        # group_e2ee_msg 不含 proof
        self.assertNotIn("proof", content)


class TestBuildGroupEpochAdvance(unittest.TestCase):
    """测试 build_group_epoch_advance 函数。"""

    def setUp(self):
        self.signing_key = ec.generate_private_key(ec.SECP256R1())
        self.verification_method = "did:wba:example.com:user:admin#keys-1"

    def test_build_group_epoch_advance_has_required_fields(self):
        """build_group_epoch_advance 应生成包含所有必需字段和 proof 的 content。"""
        content = build_group_epoch_advance(
            group_did="did:wba:example.com:group:dev-team",
            new_epoch=2,
            reason="member_added",
            signing_key=self.signing_key,
            verification_method=self.verification_method,
            members_added=["did:wba:example.com:user:charlie"],
        )

        self.assertEqual(content["group_did"], "did:wba:example.com:group:dev-team")
        self.assertEqual(content["new_epoch"], 2)
        self.assertEqual(content["reason"], "member_added")
        self.assertEqual(
            content["members_added"], ["did:wba:example.com:user:charlie"]
        )
        # proof 字段
        self.assertIn("proof", content)
        proof = content["proof"]
        self.assertEqual(proof["type"], "EcdsaSecp256r1Signature2019")
        self.assertIn("proof_value", proof)

    def test_build_group_epoch_advance_without_optional_members(self):
        """不提供 members_added/members_removed 时，content 不应包含这些字段。"""
        content = build_group_epoch_advance(
            group_did="did:wba:example.com:group:dev-team",
            new_epoch=3,
            reason="key_rotation",
            signing_key=self.signing_key,
            verification_method=self.verification_method,
        )

        self.assertEqual(content["reason"], "key_rotation")
        self.assertNotIn("members_added", content)
        self.assertNotIn("members_removed", content)
        self.assertIn("proof", content)

    def test_build_group_epoch_advance_with_members_removed(self):
        """提供 members_removed 时，content 应包含该字段。"""
        content = build_group_epoch_advance(
            group_did="did:wba:example.com:group:dev-team",
            new_epoch=4,
            reason="member_removed",
            signing_key=self.signing_key,
            verification_method=self.verification_method,
            members_removed=["did:wba:example.com:user:dave"],
        )

        self.assertEqual(
            content["members_removed"], ["did:wba:example.com:user:dave"]
        )
        self.assertNotIn("members_added", content)


if __name__ == "__main__":
    unittest.main()
