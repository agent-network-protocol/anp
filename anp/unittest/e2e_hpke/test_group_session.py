"""GroupE2eeSession 单元测试。

使用真实 X25519 和 secp256r1 密钥，不使用 mock。
"""

import unittest

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from anp.e2e_encryption_hpke.group_session import GroupE2eeSession


class TestGroupE2eeSession(unittest.TestCase):
    """测试 GroupE2eeSession 群聊 Sender Key 会话。"""

    def setUp(self):
        self.group_did = "did:wba:example.com:group:chat-room"
        self.alice_did = "did:wba:example.com:alice"
        self.bob_did = "did:wba:example.com:bob"

        # Alice 密钥
        self.alice_x25519_sk = X25519PrivateKey.generate()
        self.alice_signing_key = ec.generate_private_key(ec.SECP256R1())

        # Bob 密钥
        self.bob_x25519_sk = X25519PrivateKey.generate()
        self.bob_signing_key = ec.generate_private_key(ec.SECP256R1())

        # Alice 群会话
        self.alice_group = GroupE2eeSession(
            group_did=self.group_did,
            local_did=self.alice_did,
            local_x25519_private_key=self.alice_x25519_sk,
            local_x25519_key_id=f"{self.alice_did}#key-x25519-1",
            signing_private_key=self.alice_signing_key,
            signing_verification_method=f"{self.alice_did}#keys-1",
        )

        # Bob 群会话
        self.bob_group = GroupE2eeSession(
            group_did=self.group_did,
            local_did=self.bob_did,
            local_x25519_private_key=self.bob_x25519_sk,
            local_x25519_key_id=f"{self.bob_did}#key-x25519-1",
            signing_private_key=self.bob_signing_key,
            signing_verification_method=f"{self.bob_did}#keys-1",
        )

    def test_initial_epoch_is_zero(self):
        """新建群会话的初始 epoch 应为 0。"""
        self.assertEqual(self.alice_group.epoch, 0)
        self.assertEqual(self.bob_group.epoch, 0)

    def test_generate_sender_key_returns_32_bytes(self):
        """generate_sender_key 应返回 32 字节的密钥。"""
        sender_key = self.alice_group.generate_sender_key()

        self.assertIsInstance(sender_key, bytes)
        self.assertEqual(len(sender_key), 32)

    def test_build_sender_key_distribution_returns_group_e2ee_key(self):
        """build_sender_key_distribution 应返回 ('group_e2ee_key', content)，且包含 proof。"""
        self.alice_group.generate_sender_key()

        bob_pk = self.bob_x25519_sk.public_key()
        msg_type, content = self.alice_group.build_sender_key_distribution(
            recipient_did=self.bob_did,
            recipient_pk=bob_pk,
            recipient_key_id=f"{self.bob_did}#key-x25519-1",
        )

        self.assertEqual(msg_type, "group_e2ee_key")
        self.assertIn("group_did", content)
        self.assertIn("epoch", content)
        self.assertIn("sender_did", content)
        self.assertIn("sender_key_id", content)
        self.assertIn("enc", content)
        self.assertIn("encrypted_sender_key", content)
        self.assertIn("proof", content)
        self.assertEqual(content["group_did"], self.group_did)
        self.assertEqual(content["sender_did"], self.alice_did)
        self.assertEqual(content["epoch"], 0)

    def test_process_sender_key_stores_key(self):
        """process_sender_key 应成功存储发送方密钥。"""
        # Alice 生成 sender key 并构建分发消息给 Bob
        self.alice_group.generate_sender_key()
        bob_pk = self.bob_x25519_sk.public_key()
        _, content = self.alice_group.build_sender_key_distribution(
            recipient_did=self.bob_did,
            recipient_pk=bob_pk,
            recipient_key_id=f"{self.bob_did}#key-x25519-1",
        )

        # Bob 处理分发消息
        alice_signing_pk = self.alice_signing_key.public_key()
        self.bob_group.process_sender_key(content, alice_signing_pk)

        # 验证 Bob 已存储远端密钥
        sender_key_id = content["sender_key_id"]
        key_tuple = (self.alice_did, 0, sender_key_id)
        self.assertIn(key_tuple, self.bob_group._remote_sender_keys)

    def test_encrypt_group_message_returns_group_e2ee_msg(self):
        """encrypt_group_message 应返回 ('group_e2ee_msg', content)。"""
        self.alice_group.generate_sender_key()

        msg_type, content = self.alice_group.encrypt_group_message(
            "text", "Hello group!"
        )

        self.assertEqual(msg_type, "group_e2ee_msg")
        self.assertIn("group_did", content)
        self.assertIn("epoch", content)
        self.assertIn("sender_did", content)
        self.assertIn("sender_key_id", content)
        self.assertIn("seq", content)
        self.assertIn("original_type", content)
        self.assertIn("ciphertext", content)
        self.assertEqual(content["original_type"], "text")
        self.assertEqual(content["seq"], 0)

    def test_encrypt_without_sender_key_raises_runtime_error(self):
        """未生成 sender key 时调用 encrypt_group_message 应抛出 RuntimeError。"""
        with self.assertRaises(RuntimeError):
            self.alice_group.encrypt_group_message("text", "No key yet")

    def test_process_sender_key_duplicate_raises_value_error(self):
        """重复处理同一 sender key 分发消息应抛出 ValueError。"""
        self.alice_group.generate_sender_key()
        bob_pk = self.bob_x25519_sk.public_key()
        _, content = self.alice_group.build_sender_key_distribution(
            recipient_did=self.bob_did,
            recipient_pk=bob_pk,
            recipient_key_id=f"{self.bob_did}#key-x25519-1",
        )

        alice_signing_pk = self.alice_signing_key.public_key()
        # 第一次处理成功
        self.bob_group.process_sender_key(content, alice_signing_pk)

        # 第二次处理应抛出 ValueError（防重放）
        with self.assertRaises(ValueError):
            self.bob_group.process_sender_key(content, alice_signing_pk)

    def test_advance_epoch_increments_and_marks_old_keys_read_only(self):
        """advance_epoch 应递增 epoch 并将旧密钥标记为只读。"""
        self.alice_group.generate_sender_key()
        old_sender_key = self.alice_group._local_sender_key

        self.assertEqual(self.alice_group.epoch, 0)
        self.assertFalse(old_sender_key.read_only)

        # 推进到 epoch 1
        self.alice_group.advance_epoch(1)

        self.assertEqual(self.alice_group.epoch, 1)
        # 旧的 sender key 应标记为只读
        self.assertTrue(old_sender_key.read_only)
        # 本地 sender key 应被重置为 None（需要重新生成）
        self.assertIsNone(self.alice_group._local_sender_key)


if __name__ == "__main__":
    unittest.main()
