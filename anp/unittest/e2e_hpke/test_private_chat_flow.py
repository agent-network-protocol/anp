"""私聊完整集成测试：Alice <-> Bob E2EE 全流程。

不使用 mock，使用真实 X25519 和 secp256r1 密钥对。
"""

import unittest

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from anp.e2e_encryption_hpke.session import E2eeHpkeSession, SessionState


class TestPrivateChatFlow(unittest.TestCase):
    """Alice <-> Bob 私聊 E2EE 完整流程。"""

    def setUp(self):
        self.alice_did = "did:wba:example.com:user:alice"
        self.bob_did = "did:wba:example.com:user:bob"

        # Alice 密钥
        self.alice_x25519_sk = X25519PrivateKey.generate()
        self.alice_x25519_pk = self.alice_x25519_sk.public_key()
        self.alice_signing_key = ec.generate_private_key(ec.SECP256R1())
        self.alice_signing_pk = self.alice_signing_key.public_key()

        # Bob 密钥
        self.bob_x25519_sk = X25519PrivateKey.generate()
        self.bob_x25519_pk = self.bob_x25519_sk.public_key()
        self.bob_signing_key = ec.generate_private_key(ec.SECP256R1())
        self.bob_signing_pk = self.bob_signing_key.public_key()

    def _make_alice_session(self) -> E2eeHpkeSession:
        return E2eeHpkeSession(
            local_did=self.alice_did,
            peer_did=self.bob_did,
            local_x25519_private_key=self.alice_x25519_sk,
            local_x25519_key_id=f"{self.alice_did}#key-x25519-1",
            signing_private_key=self.alice_signing_key,
            signing_verification_method=f"{self.alice_did}#keys-1",
        )

    def _make_bob_session(self) -> E2eeHpkeSession:
        return E2eeHpkeSession(
            local_did=self.bob_did,
            peer_did=self.alice_did,
            local_x25519_private_key=self.bob_x25519_sk,
            local_x25519_key_id=f"{self.bob_did}#key-x25519-1",
            signing_private_key=self.bob_signing_key,
            signing_verification_method=f"{self.bob_did}#keys-1",
        )

    def test_full_init_and_communication(self):
        """完整的会话初始化 + 双向加密通信。"""
        alice = self._make_alice_session()
        bob = self._make_bob_session()

        # 1. Alice 发起会话
        self.assertEqual(alice.state, SessionState.IDLE)
        msg_type, init_content = alice.initiate_session(
            self.bob_x25519_pk, f"{self.bob_did}#key-x25519-1"
        )
        self.assertEqual(msg_type, "e2ee_init")
        self.assertEqual(alice.state, SessionState.ACTIVE)
        self.assertIn("proof", init_content)
        self.assertIn("enc", init_content)
        self.assertIn("encrypted_seed", init_content)

        # 2. Bob 处理 init
        self.assertEqual(bob.state, SessionState.IDLE)
        bob.process_init(init_content, self.alice_signing_pk)
        self.assertEqual(bob.state, SessionState.ACTIVE)

        # 3. Alice -> Bob 加密消息
        msg_type, encrypted = alice.encrypt_message("text", "Hello Bob!")
        self.assertEqual(msg_type, "e2ee_msg")
        self.assertEqual(encrypted["original_type"], "text")
        self.assertEqual(encrypted["seq"], 0)

        orig_type, plaintext = bob.decrypt_message(encrypted)
        self.assertEqual(orig_type, "text")
        self.assertEqual(plaintext, "Hello Bob!")

        # 4. Bob -> Alice 加密消息
        msg_type2, encrypted2 = bob.encrypt_message("text", "Hi Alice!")
        orig_type2, plaintext2 = alice.decrypt_message(encrypted2)
        self.assertEqual(orig_type2, "text")
        self.assertEqual(plaintext2, "Hi Alice!")

    def test_multiple_messages(self):
        """多条消息的加密通信。"""
        alice = self._make_alice_session()
        bob = self._make_bob_session()

        # 初始化
        _, init_content = alice.initiate_session(
            self.bob_x25519_pk, f"{self.bob_did}#key-x25519-1"
        )
        bob.process_init(init_content, self.alice_signing_pk)

        # Alice 发送多条消息
        messages = ["Hello", "How are you?", "Fine, thanks!", "中文消息测试"]
        for i, msg in enumerate(messages):
            _, encrypted = alice.encrypt_message("text", msg)
            self.assertEqual(encrypted["seq"], i)
            orig_type, plaintext = bob.decrypt_message(encrypted)
            self.assertEqual(plaintext, msg)

        # Bob 也发送多条
        for i, msg in enumerate(["Reply 1", "Reply 2"]):
            _, encrypted = bob.encrypt_message("text", msg)
            self.assertEqual(encrypted["seq"], i)
            orig_type, plaintext = alice.decrypt_message(encrypted)
            self.assertEqual(plaintext, msg)

    def test_session_id_consistency(self):
        """双方 session_id 一致。"""
        alice = self._make_alice_session()
        bob = self._make_bob_session()

        _, init_content = alice.initiate_session(
            self.bob_x25519_pk, f"{self.bob_did}#key-x25519-1"
        )
        bob.process_init(init_content, self.alice_signing_pk)

        self.assertIsNotNone(alice.session_id)
        self.assertEqual(alice.session_id, bob.session_id)

    def test_rekey(self):
        """会话重建（rekey）。"""
        alice = self._make_alice_session()
        bob = self._make_bob_session()

        # 初始化
        _, init_content = alice.initiate_session(
            self.bob_x25519_pk, f"{self.bob_did}#key-x25519-1"
        )
        bob.process_init(init_content, self.alice_signing_pk)
        old_session_id = alice.session_id

        # 发送几条消息
        _, encrypted = alice.encrypt_message("text", "Before rekey")
        bob.decrypt_message(encrypted)

        # Alice 发起 rekey
        msg_type, rekey_content = alice.initiate_rekey(
            self.bob_x25519_pk, f"{self.bob_did}#key-x25519-1"
        )
        self.assertEqual(msg_type, "e2ee_rekey")
        self.assertNotEqual(alice.session_id, old_session_id)

        # Bob 处理 rekey
        bob.process_rekey(rekey_content, self.alice_signing_pk)
        self.assertEqual(alice.session_id, bob.session_id)

        # rekey 后继续通信
        _, encrypted = alice.encrypt_message("text", "After rekey")
        orig_type, plaintext = bob.decrypt_message(encrypted)
        self.assertEqual(plaintext, "After rekey")

        # seq 应该重置为 0
        _, encrypted = alice.encrypt_message("text", "Second after rekey")
        self.assertEqual(encrypted["seq"], 1)  # 第二条消息 seq=1

    def test_direction_consistency(self):
        """确保无论谁发起 init，send/recv 密钥分配一致。

        DID 字典序较小方为 initiator。
        """
        # 场景 1: Alice DID < Bob DID，Alice 发起
        alice = self._make_alice_session()
        bob = self._make_bob_session()
        _, init_content = alice.initiate_session(
            self.bob_x25519_pk, f"{self.bob_did}#key-x25519-1"
        )
        bob.process_init(init_content, self.alice_signing_pk)

        _, enc1 = alice.encrypt_message("text", "Test from Alice")
        _, dec1 = bob.decrypt_message(enc1)
        self.assertEqual(dec1, "Test from Alice")

        # 场景 2: Bob 发起（但 DID 字典序不变）
        bob2 = self._make_bob_session()
        alice2 = self._make_alice_session()
        _, init_content2 = bob2.initiate_session(
            self.alice_x25519_pk, f"{self.alice_did}#key-x25519-1"
        )
        alice2.process_init(init_content2, self.bob_signing_pk)

        _, enc2 = bob2.encrypt_message("text", "Test from Bob")
        _, dec2 = alice2.decrypt_message(enc2)
        self.assertEqual(dec2, "Test from Bob")

    def test_wrong_signing_key_rejected(self):
        """错误的签名公钥应被拒绝。"""
        alice = self._make_alice_session()
        bob = self._make_bob_session()

        _, init_content = alice.initiate_session(
            self.bob_x25519_pk, f"{self.bob_did}#key-x25519-1"
        )

        # 使用错误的签名公钥验证
        wrong_key = ec.generate_private_key(ec.SECP256R1()).public_key()
        with self.assertRaises(ValueError):
            bob.process_init(init_content, wrong_key)

    def test_replay_rejected(self):
        """重放消息应被拒绝。"""
        alice = self._make_alice_session()
        bob = self._make_bob_session()

        _, init_content = alice.initiate_session(
            self.bob_x25519_pk, f"{self.bob_did}#key-x25519-1"
        )
        bob.process_init(init_content, self.alice_signing_pk)

        _, encrypted = alice.encrypt_message("text", "Original")
        bob.decrypt_message(encrypted)

        # 重放同一条消息
        with self.assertRaises(ValueError):
            bob.decrypt_message(encrypted)


if __name__ == "__main__":
    unittest.main()
