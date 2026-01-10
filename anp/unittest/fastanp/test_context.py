"""FastANP Context and Session Tests.

This module tests context and session management:
- Session creation and lifecycle
- Session data storage and retrieval
- Session timeout and cleanup
- Context creation and properties
- DID-based session identification
"""

import time
import unittest
from datetime import datetime, timedelta
from unittest.mock import Mock

from anp.fastanp.context import Context, Session, SessionManager


class TestSession(unittest.TestCase):
    """测试 Session 功能"""

    def test_session_creation(self):
        """测试创建 Session"""
        session = Session(
            session_id="test-session-id",
            did="did:wba:test"
        )

        self.assertEqual(session.id, "test-session-id")
        self.assertEqual(session.did, "did:wba:test")
        self.assertIsInstance(session.created_at, datetime)
        self.assertIsInstance(session.last_accessed, datetime)
        self.assertEqual(len(session.data), 0)

    def test_session_set_and_get(self):
        """测试 Session 数据存储和获取"""
        session = Session("test-id", "did:wba:test")

        # 设置数据
        session.set("key1", "value1")
        session.set("key2", 123)
        session.set("key3", {"nested": "data"})

        # 获取数据
        self.assertEqual(session.get("key1"), "value1")
        self.assertEqual(session.get("key2"), 123)
        self.assertEqual(session.get("key3"), {"nested": "data"})

    def test_session_get_default(self):
        """测试 Session.get 的默认值"""
        session = Session("test-id", "did:wba:test")

        # 不存在的键应该返回默认值
        self.assertIsNone(session.get("nonexistent"))
        self.assertEqual(session.get("nonexistent", "default"), "default")

    def test_session_touch(self):
        """测试 Session.touch 更新访问时间"""
        session = Session("test-id", "did:wba:test")

        original_time = session.last_accessed
        time.sleep(0.01)  # 等待一点时间
        session.touch()

        self.assertGreater(session.last_accessed, original_time)

    def test_session_clear(self):
        """测试 Session.clear 清空数据"""
        session = Session("test-id", "did:wba:test")

        session.set("key1", "value1")
        session.set("key2", "value2")

        # 清空数据
        session.clear()

        self.assertEqual(len(session.data), 0)
        self.assertIsNone(session.get("key1"))
        self.assertIsNone(session.get("key2"))


class TestSessionManager(unittest.TestCase):
    """测试 SessionManager 功能"""

    def test_session_manager_creation(self):
        """测试创建 SessionManager"""
        manager = SessionManager(
            session_timeout_minutes=30,
            cleanup_interval_minutes=5
        )

        self.assertEqual(len(manager.sessions), 0)
        self.assertEqual(manager.session_timeout, timedelta(minutes=30))
        self.assertEqual(manager.cleanup_interval, timedelta(minutes=5))

    def test_get_or_create_new_session(self):
        """测试创建新 Session"""
        manager = SessionManager()

        session = manager.get_or_create(did="did:wba:user1")

        self.assertIsNotNone(session)
        self.assertEqual(session.did, "did:wba:user1")
        self.assertEqual(len(manager.sessions), 1)

    def test_get_or_create_existing_session(self):
        """测试获取已存在的 Session"""
        manager = SessionManager()

        # 创建 session
        session1 = manager.get_or_create(did="did:wba:user1")

        # 使用相同的 DID 应该返回同一个 session
        session2 = manager.get_or_create(did="did:wba:user1")

        self.assertEqual(session1.id, session2.id)
        self.assertEqual(len(manager.sessions), 1)

    def test_session_id_based_on_did_only(self):
        """测试 session ID 只基于 DID (不包含 token)"""
        manager = SessionManager()

        # 相同的 DID 应该产生相同的 session ID
        session1 = manager.get_or_create(did="did:wba:user1")
        session2 = manager.get_or_create(did="did:wba:user1")

        self.assertEqual(session1.id, session2.id)

    def test_different_dids_different_sessions(self):
        """测试不同的 DID 创建不同的 session"""
        manager = SessionManager()

        session1 = manager.get_or_create(did="did:wba:user1")
        session2 = manager.get_or_create(did="did:wba:user2")

        self.assertNotEqual(session1.id, session2.id)
        self.assertEqual(len(manager.sessions), 2)

    def test_get_session_by_id(self):
        """测试通过 ID 获取 session"""
        manager = SessionManager()

        session = manager.get_or_create(did="did:wba:user1")
        session_id = session.id

        # 通过 ID 获取
        retrieved = manager.get(session_id)

        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.id, session_id)

    def test_get_nonexistent_session(self):
        """测试获取不存在的 session 返回 None"""
        manager = SessionManager()

        session = manager.get("nonexistent-id")

        self.assertIsNone(session)

    def test_remove_session(self):
        """测试删除 session"""
        manager = SessionManager()

        session = manager.get_or_create(did="did:wba:user1")
        session_id = session.id

        # 删除 session
        manager.remove(session_id)

        self.assertEqual(len(manager.sessions), 0)
        self.assertIsNone(manager.get(session_id))

    def test_clear_all_sessions(self):
        """测试清空所有 sessions"""
        manager = SessionManager()

        # 创建多个 sessions
        manager.get_or_create(did="did:wba:user1")
        manager.get_or_create(did="did:wba:user2")
        manager.get_or_create(did="did:wba:user3")

        self.assertEqual(len(manager.sessions), 3)

        # 清空所有
        manager.clear_all()

        self.assertEqual(len(manager.sessions), 0)

    def test_session_cleanup_expired(self):
        """测试清理过期的 sessions"""
        # 使用很短的超时时间
        manager = SessionManager(
            session_timeout_minutes=0,  # 立即过期
            cleanup_interval_minutes=0  # 立即清理
        )

        # 创建 session
        session = manager.get_or_create(did="did:wba:user1")

        # 手动修改 last_accessed 使其过期
        session.last_accessed = datetime.now() - timedelta(minutes=1)

        # 触发清理 (通过 get_or_create)
        manager.get_or_create(did="did:wba:user2")

        # 过期的 session 应该被删除
        self.assertIsNone(manager.get(session.id))

    def test_session_touch_on_get(self):
        """测试获取 session 时自动更新访问时间"""
        manager = SessionManager()

        session = manager.get_or_create(did="did:wba:user1")
        original_time = session.last_accessed

        time.sleep(0.01)

        # 获取 session 应该更新访问时间
        manager.get(session.id)

        self.assertGreater(session.last_accessed, original_time)


class TestContext(unittest.TestCase):
    """测试 Context 功能"""

    def test_context_creation(self):
        """测试创建 Context"""
        session = Session("test-id", "did:wba:test")
        mock_request = Mock()
        mock_request.headers = {"Authorization": "Bearer token"}
        mock_request.client = Mock()
        mock_request.client.host = "127.0.0.1"

        auth_result = {"did": "did:wba:test", "verified": True}

        context = Context(
            session=session,
            did="did:wba:test",
            request=mock_request,
            auth_result=auth_result
        )

        self.assertEqual(context.session, session)
        self.assertEqual(context.did, "did:wba:test")
        self.assertEqual(context.request, mock_request)
        self.assertEqual(context.auth_result, auth_result)

    def test_context_headers(self):
        """测试 Context.headers 属性"""
        session = Session("test-id", "did:wba:test")
        mock_request = Mock()
        mock_request.headers = {
            "Authorization": "Bearer token",
            "Content-Type": "application/json"
        }

        context = Context(
            session=session,
            did="did:wba:test",
            request=mock_request
        )

        headers = context.headers

        self.assertEqual(headers["Authorization"], "Bearer token")
        self.assertEqual(headers["Content-Type"], "application/json")

    def test_context_client_host(self):
        """测试 Context.client_host 属性"""
        session = Session("test-id", "did:wba:test")
        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = "192.168.1.1"

        context = Context(
            session=session,
            did="did:wba:test",
            request=mock_request
        )

        self.assertEqual(context.client_host, "192.168.1.1")

    def test_context_client_host_no_client(self):
        """测试没有 client 时 client_host 返回 None"""
        session = Session("test-id", "did:wba:test")
        mock_request = Mock()
        mock_request.client = None

        context = Context(
            session=session,
            did="did:wba:test",
            request=mock_request
        )

        self.assertIsNone(context.client_host)

    def test_context_auth_result_default(self):
        """测试 Context auth_result 的默认值"""
        session = Session("test-id", "did:wba:test")
        mock_request = Mock()

        context = Context(
            session=session,
            did="did:wba:test",
            request=mock_request
        )

        # 未提供 auth_result 应该默认为空字典
        self.assertEqual(context.auth_result, {})

    def test_context_session_data_access(self):
        """测试通过 Context 访问 session 数据"""
        session = Session("test-id", "did:wba:test")
        session.set("user_data", {"name": "Test User"})

        mock_request = Mock()
        context = Context(
            session=session,
            did="did:wba:test",
            request=mock_request
        )

        # 应该能够通过 context.session 访问数据
        user_data = context.session.get("user_data")
        self.assertEqual(user_data, {"name": "Test User"})


class TestSessionPersistence(unittest.TestCase):
    """测试 Session 持久化场景"""

    def test_session_data_persists_across_requests(self):
        """测试 session 数据在多次请求间持久化"""
        manager = SessionManager()

        # 第一次请求
        session1 = manager.get_or_create(did="did:wba:user1")
        session1.set("counter", 1)

        # 第二次请求 (相同 DID)
        session2 = manager.get_or_create(did="did:wba:user1")

        # 应该是同一个 session,数据应该保留
        self.assertEqual(session2.get("counter"), 1)

        # 更新数据
        session2.set("counter", 2)

        # 第三次请求
        session3 = manager.get_or_create(did="did:wba:user1")

        # 数据应该仍然保留
        self.assertEqual(session3.get("counter"), 2)


if __name__ == "__main__":
    unittest.main()
