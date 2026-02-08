"""完整端到端握手 + 双向加密通信集成测试。

不使用 mock，使用真实 secp256r1 密钥对。
"""

import unittest

from cryptography.hazmat.primitives.asymmetric import ec

from anp.e2e_encryption_v2.session import E2eeSession, SessionState
from anp.utils.crypto_tool import generate_ec_key_pair, get_pem_from_private_key


def _make_did_pem():
    priv, _, _ = generate_ec_key_pair(ec.SECP256R1())
    return get_pem_from_private_key(priv)


class TestFullE2EFlow(unittest.TestCase):
    """完整的 Alice <-> Bob 握手 + 双向加密通信集成测试。"""

    def setUp(self):
        self.alice_did = "did:wba:example.com:user:alice"
        self.bob_did = "did:wba:example.com:user:bob"
        self.alice_pem = _make_did_pem()
        self.bob_pem = _make_did_pem()

    def test_full_handshake_and_communication(self):
        # Step 1: Alice 创建会话并发起握手
        alice = E2eeSession(
            local_did=self.alice_did,
            did_private_key_pem=self.alice_pem,
            peer_did=self.bob_did,
        )
        self.assertEqual(alice.state, SessionState.IDLE)

        msg_type, source_hello = alice.initiate_handshake()
        self.assertEqual(msg_type, "e2ee_hello")
        self.assertEqual(source_hello["e2ee_type"], "source_hello")
        self.assertEqual(alice.state, SessionState.HANDSHAKE_INITIATED)

        # Step 2: Bob 收到 SourceHello，处理并返回 DestinationHello + Finished
        bob = E2eeSession(
            local_did=self.bob_did,
            did_private_key_pem=self.bob_pem,
            peer_did=self.alice_did,
        )
        self.assertEqual(bob.state, SessionState.IDLE)

        (dh_type, dest_hello), (bf_type, bob_finished) = bob.process_source_hello(
            source_hello
        )
        self.assertEqual(dh_type, "e2ee_hello")
        self.assertEqual(dest_hello["e2ee_type"], "destination_hello")
        self.assertEqual(bf_type, "e2ee_finished")
        self.assertEqual(bob_finished["e2ee_type"], "finished")
        self.assertEqual(bob.state, SessionState.HANDSHAKE_COMPLETING)

        # Step 3: Alice 收到 DestinationHello，处理并返回 Finished
        af_type, alice_finished = alice.process_destination_hello(dest_hello)
        self.assertEqual(af_type, "e2ee_finished")
        self.assertEqual(alice.state, SessionState.HANDSHAKE_COMPLETING)

        # Step 4: 双方处理对方的 Finished
        alice.process_finished(bob_finished)
        self.assertEqual(alice.state, SessionState.ACTIVE)

        bob.process_finished(alice_finished)
        self.assertEqual(bob.state, SessionState.ACTIVE)

        # 验证双方的 secret_key_id 一致
        self.assertIsNotNone(alice.secret_key_id)
        self.assertEqual(alice.secret_key_id, bob.secret_key_id)

        # Step 5: Alice -> Bob 发送加密消息
        msg_type, encrypted_content = alice.encrypt_message("text", "Hello Bob!")
        self.assertEqual(msg_type, "e2ee")
        self.assertEqual(encrypted_content["original_type"], "text")
        self.assertEqual(encrypted_content["secret_key_id"], alice.secret_key_id)

        orig_type, plaintext = bob.decrypt_message(encrypted_content)
        self.assertEqual(orig_type, "text")
        self.assertEqual(plaintext, "Hello Bob!")

        # Step 6: Bob -> Alice 发送加密消息
        msg_type2, encrypted_content2 = bob.encrypt_message("text", "Hi Alice!")
        orig_type2, plaintext2 = alice.decrypt_message(encrypted_content2)
        self.assertEqual(orig_type2, "text")
        self.assertEqual(plaintext2, "Hi Alice!")

    def test_multiple_messages(self):
        """测试多条消息的加密通信。"""
        alice = E2eeSession(
            local_did=self.alice_did,
            did_private_key_pem=self.alice_pem,
            peer_did=self.bob_did,
        )
        bob = E2eeSession(
            local_did=self.bob_did,
            did_private_key_pem=self.bob_pem,
            peer_did=self.alice_did,
        )

        # 完成握手
        _, source_hello = alice.initiate_handshake()
        (_, dest_hello), (_, bob_finished) = bob.process_source_hello(source_hello)
        _, alice_finished = alice.process_destination_hello(dest_hello)
        alice.process_finished(bob_finished)
        bob.process_finished(alice_finished)

        # 发送多条消息
        messages = [
            ("text", "Message 1"),
            ("text", "Message 2 with 中文"),
            ("image", '{"url": "https://example.com/img.png"}'),
            ("file", '{"name": "doc.pdf", "size": 1024}'),
        ]
        for orig_type, content_text in messages:
            _, enc = alice.encrypt_message(orig_type, content_text)
            dec_type, dec_text = bob.decrypt_message(enc)
            self.assertEqual(dec_type, orig_type)
            self.assertEqual(dec_text, content_text)

        # Bob -> Alice 也测试
        for orig_type, content_text in messages:
            _, enc = bob.encrypt_message(orig_type, content_text)
            dec_type, dec_text = alice.decrypt_message(enc)
            self.assertEqual(dec_type, orig_type)
            self.assertEqual(dec_text, content_text)

    def test_wrong_key_decryption_fails(self):
        """测试用错误密钥解密会失败。"""
        alice = E2eeSession(
            local_did=self.alice_did,
            did_private_key_pem=self.alice_pem,
            peer_did=self.bob_did,
        )
        bob = E2eeSession(
            local_did=self.bob_did,
            did_private_key_pem=self.bob_pem,
            peer_did=self.alice_did,
        )

        # 完成握手
        _, source_hello = alice.initiate_handshake()
        (_, dest_hello), (_, bob_finished) = bob.process_source_hello(source_hello)
        _, alice_finished = alice.process_destination_hello(dest_hello)
        alice.process_finished(bob_finished)
        bob.process_finished(alice_finished)

        # Alice 加密的消息，Alice 自己不能解密（因为她用 send_key 加密，需要 recv_key 解密）
        _, enc = alice.encrypt_message("text", "secret")
        # Alice 的 decrypt_message 使用 recv_key（Bob 发给 Alice 时的密钥）
        # 尝试解密 Alice 自己发出的消息应该失败
        with self.assertRaises(Exception):
            alice.decrypt_message(enc)

    def test_session_info(self):
        """测试完成握手后的 session info。"""
        alice = E2eeSession(
            local_did=self.alice_did,
            did_private_key_pem=self.alice_pem,
            peer_did=self.bob_did,
        )
        bob = E2eeSession(
            local_did=self.bob_did,
            did_private_key_pem=self.bob_pem,
            peer_did=self.alice_did,
        )

        _, source_hello = alice.initiate_handshake()
        (_, dest_hello), (_, bob_finished) = bob.process_source_hello(source_hello)
        _, alice_finished = alice.process_destination_hello(dest_hello)
        alice.process_finished(bob_finished)
        bob.process_finished(alice_finished)

        alice_info = alice.get_session_info()
        bob_info = bob.get_session_info()

        self.assertEqual(alice_info["state"], "active")
        self.assertEqual(bob_info["state"], "active")
        self.assertTrue(alice_info["is_initiator"])
        self.assertFalse(bob_info["is_initiator"])
        self.assertEqual(alice_info["secret_key_id"], bob_info["secret_key_id"])
        self.assertEqual(alice_info["cipher_suite"], "TLS_AES_128_GCM_SHA256")


if __name__ == "__main__":
    unittest.main()
