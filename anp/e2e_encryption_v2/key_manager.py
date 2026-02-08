"""基于 HTTP RESTful 的端到端加密通信协议 - 多会话密钥管理。

[INPUT]: E2eeSession 实例
[OUTPUT]: 按 DID 对 / secret_key_id / session_id 索引的会话查找和管理
[POS]: L2 管理层，管理多个并发 E2EE 会话的生命周期

[PROTOCOL]:
1. 逻辑变更时同步更新此头部
2. 更新后检查所在文件夹的 CLAUDE.md
"""

import logging
import time
from typing import Dict, List, Optional, Tuple

from anp.e2e_encryption_v2.session import E2eeSession, SessionState


class E2eeKeyManager:
    """管理多个 E2EE 会话的密钥生命周期。

    索引结构：
    - _sessions_by_did_pair: {"{local_did}|{peer_did}": [E2eeSession, ...]}
    - _sessions_by_key_id: {secret_key_id: E2eeSession}
    - _pending_sessions: {session_id: E2eeSession}（握手中的会话）
    """

    MAX_CONCURRENT_KEYS = 2
    HANDSHAKE_TIMEOUT = 300  # 秒

    def __init__(self):
        self._sessions_by_did_pair: Dict[str, List[E2eeSession]] = {}
        self._sessions_by_key_id: Dict[str, E2eeSession] = {}
        self._pending_sessions: Dict[str, E2eeSession] = {}

    @staticmethod
    def _did_pair_key(local_did: str, peer_did: str) -> str:
        return f"{local_did}|{peer_did}"

    def get_active_session(
        self, local_did: str, peer_did: str
    ) -> Optional[E2eeSession]:
        """获取指定 DID 对的活跃会话。

        返回第一个处于 ACTIVE 状态且未过期的会话。
        """
        key = self._did_pair_key(local_did, peer_did)
        sessions = self._sessions_by_did_pair.get(key, [])
        for session in sessions:
            if session.state == SessionState.ACTIVE and not session.is_expired():
                return session
        return None

    def get_session_by_key_id(
        self, secret_key_id: str
    ) -> Optional[E2eeSession]:
        """根据 secret_key_id 查找会话。"""
        return self._sessions_by_key_id.get(secret_key_id)

    def register_pending_session(self, session: E2eeSession) -> None:
        """注册一个握手中的会话。"""
        self._pending_sessions[session.session_id] = session

    def get_pending_session(
        self, session_id: str
    ) -> Optional[E2eeSession]:
        """根据 session_id 查找握手中的会话。"""
        session = self._pending_sessions.get(session_id)
        if session is None:
            return None
        # 检查握手超时
        elapsed = time.time() - session._created_at
        if elapsed > self.HANDSHAKE_TIMEOUT:
            logging.warning(
                "握手会话 %s 已超时 (%.0f 秒)", session_id, elapsed
            )
            del self._pending_sessions[session_id]
            return None
        return session

    def promote_pending_session(self, session_id: str) -> None:
        """将握手完成的会话从 pending 提升为 active。"""
        session = self._pending_sessions.pop(session_id, None)
        if session is None:
            logging.warning("未找到 pending 会话: %s", session_id)
            return
        self._register_active(session)

    def register_session(self, session: E2eeSession) -> None:
        """直接注册一个已 ACTIVE 的会话（跳过 pending 阶段）。"""
        self._register_active(session)

    def cleanup_expired(self) -> List[Tuple[str, str]]:
        """清理所有过期的会话。

        Returns:
            需要重新握手的 (local_did, peer_did) 列表。
        """
        need_rehandshake: List[Tuple[str, str]] = []

        for key in list(self._sessions_by_did_pair.keys()):
            sessions = self._sessions_by_did_pair[key]
            active_remaining = []

            for session in sessions:
                if session.is_expired():
                    logging.info(
                        "清理过期会话: %s (key_id=%s)",
                        session.session_id,
                        session.secret_key_id,
                    )
                    if session.secret_key_id:
                        self._sessions_by_key_id.pop(
                            session.secret_key_id, None
                        )
                else:
                    active_remaining.append(session)

            if active_remaining:
                self._sessions_by_did_pair[key] = active_remaining
            else:
                del self._sessions_by_did_pair[key]
                parts = key.split("|", 1)
                need_rehandshake.append((parts[0], parts[1]))

        # 清理超时的 pending 会话
        for sid in list(self._pending_sessions.keys()):
            session = self._pending_sessions[sid]
            elapsed = time.time() - session._created_at
            if elapsed > self.HANDSHAKE_TIMEOUT:
                logging.info("清理超时握手会话: %s", sid)
                del self._pending_sessions[sid]

        return need_rehandshake

    def remove_session(self, session: E2eeSession) -> None:
        """移除指定会话。"""
        # 从 pending 移除
        self._pending_sessions.pop(session.session_id, None)

        # 从 key_id 索引移除
        if session.secret_key_id:
            self._sessions_by_key_id.pop(session.secret_key_id, None)

        # 从 did_pair 索引移除
        key = self._did_pair_key(session.local_did, session.peer_did)
        sessions = self._sessions_by_did_pair.get(key, [])
        self._sessions_by_did_pair[key] = [
            s for s in sessions if s.session_id != session.session_id
        ]
        if not self._sessions_by_did_pair[key]:
            del self._sessions_by_did_pair[key]

    def _register_active(self, session: E2eeSession) -> None:
        """内部方法：注册一个 ACTIVE 会话到索引中。"""
        key = self._did_pair_key(session.local_did, session.peer_did)

        if key not in self._sessions_by_did_pair:
            self._sessions_by_did_pair[key] = []

        sessions = self._sessions_by_did_pair[key]

        # 限制最大并存密钥数
        while len(sessions) >= self.MAX_CONCURRENT_KEYS:
            oldest = sessions.pop(0)
            logging.info(
                "淘汰最旧会话: %s (key_id=%s)",
                oldest.session_id,
                oldest.secret_key_id,
            )
            if oldest.secret_key_id:
                self._sessions_by_key_id.pop(oldest.secret_key_id, None)

        sessions.append(session)

        # 注册 key_id 索引
        if session.secret_key_id:
            self._sessions_by_key_id[session.secret_key_id] = session
