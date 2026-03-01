"""E2eeHpkeSession 单元测试。

使用真实 X25519 和 secp256r1 密钥，不使用 mock。
"""

import unittest

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from anp.e2e_encryption_hpke.session import E2eeHpkeSession, SessionState


class TestE2eeHpkeSession(unittest.TestCase):
    """测试 E2eeHpkeSession 私聊 E2EE 会话。"""

    def setUp(self):
        self.alice_did = "did:wba:example.com:alice"
        self.bob_did = "did:wba:example.com:bob"

        # Alice 密钥
        self.alice_x25519_sk = X25519PrivateKey.generate()
        self.alice_signing_key = ec.generate_private_key(ec.SECP256R1())

        # Bob 密钥
        self.bob_x25519_sk = X25519PrivateKey.generate()
        self.bob_signing_key = ec.generate_private_key(ec.SECP256R1())

        # Alice 会话（本地为 Alice，对端为 Bob）
        self.alice_session = E2eeHpkeSession(
            local_did=self.alice_did,
            peer_did=self.bob_did,
            local_x25519_private_key=self.alice_x25519_sk,
            local_x25519_key_id=f"{self.alice_did}#key-x25519-1",
            signing_private_key=self.alice_signing_key,
            signing_verification_method=f"{self.alice_did}#keys-1",
        )

        # Bob 会话（本地为 Bob，对端为 Alice）
        self.bob_session = E2eeHpkeSession(
            local_did=self.bob_did,
            peer_did=self.alice_did,
            local_x25519_private_key=self.bob_x25519_sk,
            local_x25519_key_id=f"{self.bob_did}#key-x25519-1",
            signing_private_key=self.bob_signing_key,
            signing_verification_method=f"{self.bob_did}#keys-1",
        )

    def test_initial_state_is_idle(self):
        """新建会话的初始状态应为 IDLE。"""
        self.assertEqual(self.alice_session.state, SessionState.IDLE)
        self.assertEqual(self.bob_session.state, SessionState.IDLE)

    def test_initiate_session_returns_e2ee_init_and_transitions_to_active(self):
        """initiate_session 应返回 ('e2ee_init', content) 并将状态转为 ACTIVE。"""
        bob_pk = self.bob_x25519_sk.public_key()
        msg_type, content = self.alice_session.initiate_session(
            peer_pk=bob_pk,
            peer_key_id=f"{self.bob_did}#key-x25519-1",
        )

        self.assertEqual(msg_type, "e2ee_init")
        self.assertIn("session_id", content)
        self.assertIn("enc", content)
        self.assertIn("encrypted_seed", content)
        self.assertIn("sender_did", content)
        self.assertIn("recipient_did", content)
        self.assertIn("proof", content)
        self.assertEqual(content["sender_did"], self.alice_did)
        self.assertEqual(content["recipient_did"], self.bob_did)
        self.assertEqual(self.alice_session.state, SessionState.ACTIVE)

    def test_process_init_transitions_to_active(self):
        """process_init 应将接收方会话状态转为 ACTIVE。"""
        bob_pk = self.bob_x25519_sk.public_key()
        _, content = self.alice_session.initiate_session(
            peer_pk=bob_pk,
            peer_key_id=f"{self.bob_did}#key-x25519-1",
        )

        alice_signing_pk = self.alice_signing_key.public_key()
        self.bob_session.process_init(content, alice_signing_pk)

        self.assertEqual(self.bob_session.state, SessionState.ACTIVE)

    def test_initiate_session_from_non_idle_raises_runtime_error(self):
        """从非 IDLE 状态调用 initiate_session 应抛出 RuntimeError。"""
        bob_pk = self.bob_x25519_sk.public_key()
        # 先发起一次，变为 ACTIVE
        self.alice_session.initiate_session(
            peer_pk=bob_pk,
            peer_key_id=f"{self.bob_did}#key-x25519-1",
        )
        self.assertEqual(self.alice_session.state, SessionState.ACTIVE)

        # 再次调用应抛出 RuntimeError
        with self.assertRaises(RuntimeError):
            self.alice_session.initiate_session(
                peer_pk=bob_pk,
                peer_key_id=f"{self.bob_did}#key-x25519-1",
            )

    def test_encrypt_message_returns_e2ee_msg(self):
        """encrypt_message 应返回 ('e2ee_msg', content)。"""
        bob_pk = self.bob_x25519_sk.public_key()
        self.alice_session.initiate_session(
            peer_pk=bob_pk,
            peer_key_id=f"{self.bob_did}#key-x25519-1",
        )

        msg_type, content = self.alice_session.encrypt_message("text", "Hello Bob!")

        self.assertEqual(msg_type, "e2ee_msg")
        self.assertIn("session_id", content)
        self.assertIn("seq", content)
        self.assertIn("original_type", content)
        self.assertIn("ciphertext", content)
        self.assertEqual(content["original_type"], "text")
        self.assertEqual(content["seq"], 0)

    def test_encrypt_message_from_non_active_raises_runtime_error(self):
        """从非 ACTIVE 状态调用 encrypt_message 应抛出 RuntimeError。"""
        self.assertEqual(self.alice_session.state, SessionState.IDLE)

        with self.assertRaises(RuntimeError):
            self.alice_session.encrypt_message("text", "Hello!")

    def test_is_expired_returns_false_initially(self):
        """新建会话调用 is_expired 应返回 False（expires_at 为 None）。"""
        self.assertFalse(self.alice_session.is_expired())

    def test_get_session_info_returns_correct_dict(self):
        """get_session_info 应返回包含正确字段的字典。"""
        info = self.alice_session.get_session_info()

        self.assertIsInstance(info, dict)
        self.assertIsNone(info["session_id"])
        self.assertEqual(info["local_did"], self.alice_did)
        self.assertEqual(info["peer_did"], self.bob_did)
        self.assertEqual(info["state"], "idle")
        self.assertIsNone(info["is_initiator"])
        self.assertIsNone(info["expires_at"])
        self.assertIsNotNone(info["created_at"])
        self.assertIsNone(info["active_at"])

    def test_get_session_info_after_initiate(self):
        """发起会话后 get_session_info 应反映 ACTIVE 状态。"""
        bob_pk = self.bob_x25519_sk.public_key()
        self.alice_session.initiate_session(
            peer_pk=bob_pk,
            peer_key_id=f"{self.bob_did}#key-x25519-1",
        )

        info = self.alice_session.get_session_info()

        self.assertIsNotNone(info["session_id"])
        self.assertEqual(info["state"], "active")
        self.assertIsNotNone(info["is_initiator"])
        self.assertIsNotNone(info["expires_at"])
        self.assertIsNotNone(info["active_at"])


if __name__ == "__main__":
    unittest.main()
