"""key_manager.py 单元测试。"""

import time
import unittest

from cryptography.hazmat.primitives.asymmetric import ec

from anp.e2e_encryption_v2.key_manager import E2eeKeyManager
from anp.e2e_encryption_v2.session import E2eeSession, SessionState
from anp.utils.crypto_tool import generate_ec_key_pair, get_pem_from_private_key


def _make_did_pem():
    priv, _, _ = generate_ec_key_pair(ec.SECP256R1())
    return get_pem_from_private_key(priv)


def _make_active_session_pair():
    """创建一对完成握手的 ACTIVE 会话（Alice 和 Bob）。"""
    alice_pem = _make_did_pem()
    bob_pem = _make_did_pem()

    alice = E2eeSession(
        local_did="did:wba:example.com:user:alice",
        did_private_key_pem=alice_pem,
        peer_did="did:wba:example.com:user:bob",
    )
    _, source_hello = alice.initiate_handshake()

    bob = E2eeSession(
        local_did="did:wba:example.com:user:bob",
        did_private_key_pem=bob_pem,
        peer_did="did:wba:example.com:user:alice",
    )
    (_, dest_hello), (_, bob_finished) = bob.process_source_hello(source_hello)
    _, alice_finished = alice.process_destination_hello(dest_hello)

    bob.process_finished(alice_finished)
    alice.process_finished(bob_finished)

    return alice, bob


class TestKeyManagerRegistration(unittest.TestCase):

    def test_register_and_get_active(self):
        alice, bob = _make_active_session_pair()
        mgr = E2eeKeyManager()
        mgr.register_session(alice)

        found = mgr.get_active_session(
            "did:wba:example.com:user:alice",
            "did:wba:example.com:user:bob",
        )
        self.assertIsNotNone(found)
        self.assertEqual(found.session_id, alice.session_id)

    def test_get_session_by_key_id(self):
        alice, _ = _make_active_session_pair()
        mgr = E2eeKeyManager()
        mgr.register_session(alice)

        found = mgr.get_session_by_key_id(alice.secret_key_id)
        self.assertIsNotNone(found)
        self.assertEqual(found.session_id, alice.session_id)

    def test_no_session_returns_none(self):
        mgr = E2eeKeyManager()
        self.assertIsNone(
            mgr.get_active_session("did:a", "did:b")
        )
        self.assertIsNone(mgr.get_session_by_key_id("nonexist"))


class TestKeyManagerPending(unittest.TestCase):

    def test_register_and_get_pending(self):
        pem = _make_did_pem()
        session = E2eeSession(
            local_did="did:wba:example.com:user:alice",
            did_private_key_pem=pem,
            peer_did="did:wba:example.com:user:bob",
        )
        session.initiate_handshake()

        mgr = E2eeKeyManager()
        mgr.register_pending_session(session)
        found = mgr.get_pending_session(session.session_id)
        self.assertIsNotNone(found)

    def test_promote_pending(self):
        alice, bob = _make_active_session_pair()
        mgr = E2eeKeyManager()

        # 先注册为 pending
        mgr.register_pending_session(alice)
        self.assertIsNotNone(mgr.get_pending_session(alice.session_id))

        # 提升为 active
        mgr.promote_pending_session(alice.session_id)
        self.assertIsNone(mgr.get_pending_session(alice.session_id))
        self.assertIsNotNone(
            mgr.get_active_session(alice.local_did, alice.peer_did)
        )


class TestKeyManagerMaxConcurrent(unittest.TestCase):

    def test_max_concurrent_eviction(self):
        mgr = E2eeKeyManager()
        sessions = []
        for _ in range(3):
            alice, _ = _make_active_session_pair()
            sessions.append(alice)
            mgr.register_session(alice)

        # 最多保留 2 个，最早的应被淘汰
        found_first = mgr.get_session_by_key_id(sessions[0].secret_key_id)
        self.assertIsNone(found_first)

        # 后两个应存在
        found_second = mgr.get_session_by_key_id(sessions[1].secret_key_id)
        found_third = mgr.get_session_by_key_id(sessions[2].secret_key_id)
        self.assertIsNotNone(found_second)
        self.assertIsNotNone(found_third)


class TestKeyManagerCleanup(unittest.TestCase):

    def test_cleanup_expired_sessions(self):
        alice, _ = _make_active_session_pair()
        # 模拟过期：将 active_at 设到很早以前，key_expires 设为 1 秒
        alice._active_at = time.time() - 100
        alice._key_expires = 1

        mgr = E2eeKeyManager()
        mgr.register_session(alice)

        need_rehandshake = mgr.cleanup_expired()
        self.assertEqual(len(need_rehandshake), 1)
        self.assertEqual(
            need_rehandshake[0],
            ("did:wba:example.com:user:alice", "did:wba:example.com:user:bob"),
        )
        # 会话应被清理
        self.assertIsNone(mgr.get_session_by_key_id(alice.secret_key_id))


class TestKeyManagerRemove(unittest.TestCase):

    def test_remove_session(self):
        alice, _ = _make_active_session_pair()
        mgr = E2eeKeyManager()
        mgr.register_session(alice)

        mgr.remove_session(alice)
        self.assertIsNone(mgr.get_session_by_key_id(alice.secret_key_id))
        self.assertIsNone(
            mgr.get_active_session(alice.local_did, alice.peer_did)
        )


if __name__ == "__main__":
    unittest.main()
