"""seq_manager.py 的单元测试：序号管理与防重放。"""

import time
import unittest

from anp.e2e_encryption_hpke.models import SeqMode
from anp.e2e_encryption_hpke.seq_manager import SeqManager


class TestSeqManagerStrictMode(unittest.TestCase):
    """严格模式序号验证测试。"""

    def setUp(self):
        self.mgr = SeqManager(mode=SeqMode.STRICT)

    def test_valid_seq_0_accepted(self):
        """初始状态下 seq=0 应被接受。"""
        self.assertTrue(self.mgr.validate_recv_seq(0))

    def test_sequential_acceptance(self):
        """接受 seq=0 后推进，seq=1 也应被接受。"""
        self.assertTrue(self.mgr.validate_recv_seq(0))
        self.mgr.mark_seq_used(0)
        self.mgr.advance_recv_to(0)

        self.assertTrue(self.mgr.validate_recv_seq(1))

    def test_replay_rejected(self):
        """已使用的 seq=0 被重放应被拒绝。"""
        self.assertTrue(self.mgr.validate_recv_seq(0))
        self.mgr.mark_seq_used(0)
        self.mgr.advance_recv_to(0)

        # seq=0 已标记使用，重放应失败
        self.assertFalse(self.mgr.validate_recv_seq(0))

    def test_out_of_order_rejected(self):
        """严格模式下，期望 seq=0 时收到 seq=1 应被拒绝。"""
        self.assertFalse(self.mgr.validate_recv_seq(1))


class TestSeqManagerWindowMode(unittest.TestCase):
    """窗口模式序号验证测试。"""

    def setUp(self):
        self.mgr = SeqManager(mode=SeqMode.WINDOW, max_skip=256)

    def test_allows_gap_within_window(self):
        """窗口模式下，recv_seq=0 时 seq=5 应被接受（5 < 256）。"""
        self.assertTrue(self.mgr.validate_recv_seq(5))

    def test_rejects_seq_beyond_window(self):
        """窗口模式下，seq 超出 max_skip 范围应被拒绝。"""
        self.assertFalse(self.mgr.validate_recv_seq(256))

    def test_rejects_replay_in_window_mode(self):
        """窗口模式下，已使用的 seq 同样应被拒绝。"""
        self.assertTrue(self.mgr.validate_recv_seq(3))
        self.mgr.mark_seq_used(3)

        self.assertFalse(self.mgr.validate_recv_seq(3))


class TestMarkAndCheckSeq(unittest.TestCase):
    """mark_seq_used / is_seq_used 测试。"""

    def setUp(self):
        self.mgr = SeqManager(mode=SeqMode.STRICT)

    def test_unmarked_seq_not_used(self):
        """未标记的 seq 应返回 False。"""
        self.assertFalse(self.mgr.is_seq_used(0))

    def test_marked_seq_is_used(self):
        """标记后的 seq 应返回 True。"""
        self.mgr.mark_seq_used(0)
        self.assertTrue(self.mgr.is_seq_used(0))

    def test_multiple_marks(self):
        """可标记多个不同的 seq。"""
        self.mgr.mark_seq_used(0)
        self.mgr.mark_seq_used(1)
        self.mgr.mark_seq_used(5)

        self.assertTrue(self.mgr.is_seq_used(0))
        self.assertTrue(self.mgr.is_seq_used(1))
        self.assertTrue(self.mgr.is_seq_used(5))
        self.assertFalse(self.mgr.is_seq_used(3))


class TestNextSendSeq(unittest.TestCase):
    """next_send_seq 发送序号递增测试。"""

    def test_starts_at_zero(self):
        """初始发送序号应为 0。"""
        mgr = SeqManager()
        self.assertEqual(mgr.next_send_seq(), 0)

    def test_increments(self):
        """连续调用应依次返回 0, 1, 2。"""
        mgr = SeqManager()
        self.assertEqual(mgr.next_send_seq(), 0)
        self.assertEqual(mgr.next_send_seq(), 1)
        self.assertEqual(mgr.next_send_seq(), 2)


class TestReset(unittest.TestCase):
    """reset 状态重置测试。"""

    def test_reset_clears_all_state(self):
        """重置后 send_seq / recv_seq 回零，已标记 seq 清空。"""
        mgr = SeqManager(mode=SeqMode.STRICT)

        # 推进状态
        mgr.next_send_seq()
        mgr.next_send_seq()
        mgr.mark_seq_used(0)
        mgr.advance_recv_to(0)

        # 重置
        mgr.reset()

        self.assertEqual(mgr.send_seq, 0)
        self.assertEqual(mgr.recv_seq, 0)
        self.assertFalse(mgr.is_seq_used(0))


class TestCleanupExpiredCache(unittest.TestCase):
    """cleanup_expired_cache 过期缓存清理测试。"""

    def test_expired_entries_removed(self):
        """TTL 过期后，cleanup 应移除对应条目。"""
        # 使用极短 TTL 以便立即过期
        mgr = SeqManager(mode=SeqMode.STRICT, skip_key_ttl=0)
        mgr.mark_seq_used(42)

        # mark_seq_used 中 expire_time = time.time() + 0，立即过期
        time.sleep(0.01)
        mgr.cleanup_expired_cache()

        self.assertFalse(mgr.is_seq_used(42))

    def test_valid_entries_kept(self):
        """未过期的条目在 cleanup 后应保留。"""
        mgr = SeqManager(mode=SeqMode.STRICT, skip_key_ttl=3600)
        mgr.mark_seq_used(10)

        mgr.cleanup_expired_cache()

        self.assertTrue(mgr.is_seq_used(10))


if __name__ == "__main__":
    unittest.main()
