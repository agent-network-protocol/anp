"""HpkeKeyManager 单元测试。

使用真实 X25519 和 secp256r1 密钥，不使用 mock。
"""

import unittest

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from anp.e2e_encryption_hpke.group_session import GroupE2eeSession
from anp.e2e_encryption_hpke.key_manager import HpkeKeyManager
from anp.e2e_encryption_hpke.session import E2eeHpkeSession


def _make_session(local_did: str, peer_did: str) -> E2eeHpkeSession:
    """创建一个 E2eeHpkeSession 实例（IDLE 状态）。"""
    return E2eeHpkeSession(
        local_did=local_did,
        peer_did=peer_did,
        local_x25519_private_key=X25519PrivateKey.generate(),
        local_x25519_key_id=f"{local_did}#key-x25519-1",
        signing_private_key=ec.generate_private_key(ec.SECP256R1()),
        signing_verification_method=f"{local_did}#keys-1",
    )


def _activate_session(session: E2eeHpkeSession) -> None:
    """将会话激活到 ACTIVE 状态（通过 initiate_session）。"""
    peer_x25519_sk = X25519PrivateKey.generate()
    peer_pk = peer_x25519_sk.public_key()
    session.initiate_session(
        peer_pk=peer_pk,
        peer_key_id=f"{session.peer_did}#key-x25519-1",
    )


class TestHpkeKeyManager(unittest.TestCase):
    """测试 HpkeKeyManager 多会话密钥管理器。"""

    def setUp(self):
        self.manager = HpkeKeyManager()
        self.alice_did = "did:wba:example.com:alice"
        self.bob_did = "did:wba:example.com:bob"
        self.carol_did = "did:wba:example.com:carol"

    def test_register_and_get_active_session(self):
        """注册会话后应能通过 DID 对获取活跃会话。"""
        session = _make_session(self.alice_did, self.bob_did)
        _activate_session(session)

        self.manager.register_session(session)
        result = self.manager.get_active_session(self.alice_did, self.bob_did)

        self.assertIs(result, session)

    def test_get_active_session_returns_none_for_unknown_pair(self):
        """查询未注册的 DID 对应返回 None。"""
        result = self.manager.get_active_session(self.alice_did, self.bob_did)
        self.assertIsNone(result)

    def test_get_session_by_id(self):
        """注册会话后应能通过 session_id 获取。"""
        session = _make_session(self.alice_did, self.bob_did)
        _activate_session(session)

        self.manager.register_session(session)
        result = self.manager.get_session_by_id(session.session_id)

        self.assertIs(result, session)

    def test_get_session_by_id_returns_none_for_unknown_id(self):
        """查询未知 session_id 应返回 None。"""
        result = self.manager.get_session_by_id("nonexistent-session-id")
        self.assertIsNone(result)

    def test_remove_session(self):
        """移除会话后，两种索引都应查询不到。"""
        session = _make_session(self.alice_did, self.bob_did)
        _activate_session(session)
        session_id = session.session_id

        self.manager.register_session(session)
        # 确认注册成功
        self.assertIsNotNone(self.manager.get_active_session(
            self.alice_did, self.bob_did
        ))

        # 移除
        self.manager.remove_session(self.alice_did, self.bob_did)

        self.assertIsNone(self.manager.get_active_session(
            self.alice_did, self.bob_did
        ))
        self.assertIsNone(self.manager.get_session_by_id(session_id))

    def test_register_group_session_and_get(self):
        """注册群会话后应能通过 group_did 获取。"""
        group_did = "did:wba:example.com:group:room1"
        group_session = GroupE2eeSession(
            group_did=group_did,
            local_did=self.alice_did,
            local_x25519_private_key=X25519PrivateKey.generate(),
            local_x25519_key_id=f"{self.alice_did}#key-x25519-1",
            signing_private_key=ec.generate_private_key(ec.SECP256R1()),
            signing_verification_method=f"{self.alice_did}#keys-1",
        )

        self.manager.register_group_session(group_session)
        result = self.manager.get_group_session(group_did)

        self.assertIs(result, group_session)

    def test_get_group_session_returns_none_for_unknown(self):
        """查询未注册的 group_did 应返回 None。"""
        result = self.manager.get_group_session("did:wba:example.com:group:unknown")
        self.assertIsNone(result)

    def test_remove_group_session(self):
        """移除群会话后应查询不到。"""
        group_did = "did:wba:example.com:group:room2"
        group_session = GroupE2eeSession(
            group_did=group_did,
            local_did=self.alice_did,
            local_x25519_private_key=X25519PrivateKey.generate(),
            local_x25519_key_id=f"{self.alice_did}#key-x25519-1",
            signing_private_key=ec.generate_private_key(ec.SECP256R1()),
            signing_verification_method=f"{self.alice_did}#keys-1",
        )

        self.manager.register_group_session(group_session)
        self.assertIsNotNone(self.manager.get_group_session(group_did))

        self.manager.remove_group_session(group_did)
        self.assertIsNone(self.manager.get_group_session(group_did))

    def test_cleanup_expired_removes_expired_sessions(self):
        """cleanup_expired 应移除过期的私聊会话。"""
        session = _make_session(self.alice_did, self.bob_did)

        # 使用极短过期时间（1 秒）激活会话
        session._default_expires = 1
        peer_x25519_sk = X25519PrivateKey.generate()
        peer_pk = peer_x25519_sk.public_key()
        session.initiate_session(
            peer_pk=peer_pk,
            peer_key_id=f"{self.bob_did}#key-x25519-1",
        )

        self.manager.register_session(session)
        self.assertIsNotNone(self.manager.get_active_session(
            self.alice_did, self.bob_did
        ))

        # 手动将过期时间设为过去
        session._expires_at = 0.0

        self.manager.cleanup_expired()

        # 通过 DID 对和 session_id 都应查询不到
        self.assertIsNone(self.manager.get_active_session(
            self.alice_did, self.bob_did
        ))
        self.assertIsNone(self.manager.get_session_by_id(session.session_id))

    def test_register_replaces_old_session(self):
        """对同一 DID 对注册新会话时应替换旧会话。"""
        session1 = _make_session(self.alice_did, self.bob_did)
        _activate_session(session1)
        session1_id = session1.session_id

        session2 = _make_session(self.alice_did, self.bob_did)
        _activate_session(session2)
        session2_id = session2.session_id

        self.manager.register_session(session1)
        self.manager.register_session(session2)

        # DID 对应返回新会话
        result = self.manager.get_active_session(self.alice_did, self.bob_did)
        self.assertIs(result, session2)

        # 旧 session_id 不再可查询
        self.assertIsNone(self.manager.get_session_by_id(session1_id))

        # 新 session_id 可查询
        self.assertIsNotNone(self.manager.get_session_by_id(session2_id))


if __name__ == "__main__":
    unittest.main()
