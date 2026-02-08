"""session.py 单元测试。"""

import unittest

from cryptography.hazmat.primitives.asymmetric import ec

from anp.e2e_encryption_v2.session import E2eeSession, SessionState
from anp.utils.crypto_tool import generate_ec_key_pair, get_pem_from_private_key


def _make_did_pem():
    """生成真实的 secp256r1 DID 私钥 PEM。"""
    priv, _, _ = generate_ec_key_pair(ec.SECP256R1())
    return get_pem_from_private_key(priv)


class TestSessionStateTransitions(unittest.TestCase):

    def setUp(self):
        self.alice_pem = _make_did_pem()
        self.bob_pem = _make_did_pem()

    def test_initial_state_is_idle(self):
        session = E2eeSession(
            local_did="did:wba:example.com:user:alice",
            did_private_key_pem=self.alice_pem,
            peer_did="did:wba:example.com:user:bob",
        )
        self.assertEqual(session.state, SessionState.IDLE)

    def test_initiate_handshake_transitions_to_initiated(self):
        session = E2eeSession(
            local_did="did:wba:example.com:user:alice",
            did_private_key_pem=self.alice_pem,
            peer_did="did:wba:example.com:user:bob",
        )
        msg_type, content = session.initiate_handshake()
        self.assertEqual(msg_type, "e2ee_hello")
        self.assertEqual(session.state, SessionState.HANDSHAKE_INITIATED)
        self.assertEqual(content["e2ee_type"], "source_hello")

    def test_cannot_initiate_twice(self):
        session = E2eeSession(
            local_did="did:wba:example.com:user:alice",
            did_private_key_pem=self.alice_pem,
            peer_did="did:wba:example.com:user:bob",
        )
        session.initiate_handshake()
        with self.assertRaises(RuntimeError):
            session.initiate_handshake()

    def test_cannot_encrypt_before_active(self):
        session = E2eeSession(
            local_did="did:wba:example.com:user:alice",
            did_private_key_pem=self.alice_pem,
            peer_did="did:wba:example.com:user:bob",
        )
        with self.assertRaises(RuntimeError):
            session.encrypt_message("text", "hello")

    def test_cannot_decrypt_before_active(self):
        session = E2eeSession(
            local_did="did:wba:example.com:user:alice",
            did_private_key_pem=self.alice_pem,
            peer_did="did:wba:example.com:user:bob",
        )
        with self.assertRaises(RuntimeError):
            session.decrypt_message({"secret_key_id": "a", "original_type": "text", "encrypted": {}})


class TestSessionHandshake(unittest.TestCase):
    """测试完整的握手状态转换（不含 Finished 验证，那在集成测试中做）。"""

    def setUp(self):
        self.alice_pem = _make_did_pem()
        self.bob_pem = _make_did_pem()

    def test_responder_process_source_hello(self):
        alice = E2eeSession(
            local_did="did:wba:example.com:user:alice",
            did_private_key_pem=self.alice_pem,
            peer_did="did:wba:example.com:user:bob",
        )
        _, source_hello = alice.initiate_handshake()

        bob = E2eeSession(
            local_did="did:wba:example.com:user:bob",
            did_private_key_pem=self.bob_pem,
            peer_did="did:wba:example.com:user:alice",
        )
        (dh_type, dh_content), (f_type, f_content) = bob.process_source_hello(source_hello)

        self.assertEqual(dh_type, "e2ee_hello")
        self.assertEqual(dh_content["e2ee_type"], "destination_hello")
        self.assertEqual(f_type, "e2ee_finished")
        self.assertEqual(f_content["e2ee_type"], "finished")
        self.assertEqual(bob.state, SessionState.HANDSHAKE_COMPLETING)

    def test_initiator_process_destination_hello(self):
        alice = E2eeSession(
            local_did="did:wba:example.com:user:alice",
            did_private_key_pem=self.alice_pem,
            peer_did="did:wba:example.com:user:bob",
        )
        _, source_hello = alice.initiate_handshake()

        bob = E2eeSession(
            local_did="did:wba:example.com:user:bob",
            did_private_key_pem=self.bob_pem,
            peer_did="did:wba:example.com:user:alice",
        )
        (_, dest_hello), (_, bob_finished) = bob.process_source_hello(source_hello)

        f_type, f_content = alice.process_destination_hello(dest_hello)
        self.assertEqual(f_type, "e2ee_finished")
        self.assertEqual(alice.state, SessionState.HANDSHAKE_COMPLETING)


class TestSessionExpiry(unittest.TestCase):

    def test_not_expired_initially(self):
        session = E2eeSession(
            local_did="did:wba:example.com:user:alice",
            did_private_key_pem=_make_did_pem(),
            peer_did="did:wba:example.com:user:bob",
        )
        self.assertFalse(session.is_expired())

    def test_should_not_renew_initially(self):
        session = E2eeSession(
            local_did="did:wba:example.com:user:alice",
            did_private_key_pem=_make_did_pem(),
            peer_did="did:wba:example.com:user:bob",
        )
        self.assertFalse(session.should_renew())


class TestSessionInfo(unittest.TestCase):

    def test_get_session_info(self):
        session = E2eeSession(
            local_did="did:wba:example.com:user:alice",
            did_private_key_pem=_make_did_pem(),
            peer_did="did:wba:example.com:user:bob",
        )
        info = session.get_session_info()
        self.assertEqual(info["local_did"], "did:wba:example.com:user:alice")
        self.assertEqual(info["peer_did"], "did:wba:example.com:user:bob")
        self.assertEqual(info["state"], "idle")


if __name__ == "__main__":
    unittest.main()
