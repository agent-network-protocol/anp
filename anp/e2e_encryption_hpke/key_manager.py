"""多会话/多群组密钥管理器。"""

from typing import Dict, Optional

from anp.e2e_encryption_hpke.group_session import GroupE2eeSession
from anp.e2e_encryption_hpke.session import E2eeHpkeSession


class HpkeKeyManager:
    """管理多个私聊和群聊 E2EE 会话。"""

    def __init__(self):
        # 私聊：按 DID 对索引
        self._sessions_by_did_pair: Dict[str, E2eeHpkeSession] = {}
        # 私聊：按 session_id 索引
        self._sessions_by_session_id: Dict[str, E2eeHpkeSession] = {}
        # 群聊：按 group_did 索引
        self._group_sessions: Dict[str, GroupE2eeSession] = {}

    @staticmethod
    def _did_pair_key(local_did: str, peer_did: str) -> str:
        return f"{local_did}|{peer_did}"

    def get_active_session(
        self, local_did: str, peer_did: str
    ) -> Optional[E2eeHpkeSession]:
        """获取指定 DID 对的活跃会话。"""
        key = self._did_pair_key(local_did, peer_did)
        session = self._sessions_by_did_pair.get(key)
        if session and not session.is_expired():
            return session
        return None

    def get_session_by_id(self, session_id: str) -> Optional[E2eeHpkeSession]:
        """按 session_id 获取会话。"""
        session = self._sessions_by_session_id.get(session_id)
        if session and not session.is_expired():
            return session
        return None

    def register_session(self, session: E2eeHpkeSession) -> None:
        """注册会话到管理器。"""
        key = self._did_pair_key(session.local_did, session.peer_did)
        # 移除旧会话
        old = self._sessions_by_did_pair.get(key)
        if old and old.session_id:
            self._sessions_by_session_id.pop(old.session_id, None)
        self._sessions_by_did_pair[key] = session
        if session.session_id:
            self._sessions_by_session_id[session.session_id] = session

    def remove_session(self, local_did: str, peer_did: str) -> None:
        """移除指定 DID 对的会话。"""
        key = self._did_pair_key(local_did, peer_did)
        session = self._sessions_by_did_pair.pop(key, None)
        if session and session.session_id:
            self._sessions_by_session_id.pop(session.session_id, None)

    def get_group_session(self, group_did: str) -> Optional[GroupE2eeSession]:
        """获取群聊会话。"""
        return self._group_sessions.get(group_did)

    def register_group_session(self, session: GroupE2eeSession) -> None:
        """注册群聊会话。"""
        self._group_sessions[session.group_did] = session

    def remove_group_session(self, group_did: str) -> None:
        """移除群聊会话。"""
        self._group_sessions.pop(group_did, None)

    def cleanup_expired(self) -> None:
        """清理所有过期的私聊和群聊会话。"""
        # 私聊
        expired_pairs = [
            key for key, s in self._sessions_by_did_pair.items()
            if s.is_expired()
        ]
        for key in expired_pairs:
            session = self._sessions_by_did_pair.pop(key)
            if session.session_id:
                self._sessions_by_session_id.pop(session.session_id, None)

        # 群聊
        for gs in self._group_sessions.values():
            gs.cleanup_expired()
