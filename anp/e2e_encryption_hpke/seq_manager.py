"""序号管理和防重放。"""

import time
from typing import Dict, Optional, Tuple

from anp.e2e_encryption_hpke.models import (
    DEFAULT_MAX_SKIP,
    DEFAULT_SKIP_KEY_TTL,
    SeqMode,
)


class SeqManager:
    """消息序号管理器，支持严格模式和窗口模式。

    Args:
        mode: 序号验证策略。
        max_skip: 窗口模式最大允许跳跃量。
        skip_key_ttl: 跳跃密钥缓存有效期（秒）。
    """

    def __init__(
        self,
        mode: SeqMode = SeqMode.STRICT,
        max_skip: int = DEFAULT_MAX_SKIP,
        skip_key_ttl: int = DEFAULT_SKIP_KEY_TTL,
    ):
        self._mode = mode
        self._max_skip = max_skip
        self._skip_key_ttl = skip_key_ttl

        self._send_seq: int = 0
        self._recv_seq: int = 0
        # 防重放：已使用的 seq 集合 {seq: expire_time}
        self._used_seqs: Dict[int, float] = {}

    @property
    def send_seq(self) -> int:
        return self._send_seq

    @property
    def recv_seq(self) -> int:
        return self._recv_seq

    def next_send_seq(self) -> int:
        """获取并递增发送序号。"""
        seq = self._send_seq
        self._send_seq += 1
        return seq

    def validate_recv_seq(self, seq: int) -> bool:
        """验证接收序号合法性。

        Returns:
            True 表示序号合法。
        """
        # 防重放检查
        if self.is_seq_used(seq):
            return False

        if self._mode == SeqMode.STRICT:
            return seq == self._recv_seq
        else:
            # 窗口模式
            return self._recv_seq <= seq < self._recv_seq + self._max_skip

    def advance_recv_to(self, seq: int) -> None:
        """推进接收序号到指定值的下一个。"""
        self._recv_seq = seq + 1

    def mark_seq_used(self, seq: int) -> None:
        """标记序号已使用（防重放）。"""
        self._used_seqs[seq] = time.time() + self._skip_key_ttl

    def is_seq_used(self, seq: int) -> bool:
        """检查序号是否已使用。"""
        if seq in self._used_seqs:
            if self._used_seqs[seq] > time.time():
                return True
            # 已过期，移除
            del self._used_seqs[seq]
        return False

    def cleanup_expired_cache(self) -> None:
        """清理过期的防重放缓存。"""
        now = time.time()
        expired = [s for s, t in self._used_seqs.items() if t <= now]
        for s in expired:
            del self._used_seqs[s]

    def reset(self) -> None:
        """重置序号状态（会话重建时调用）。"""
        self._send_seq = 0
        self._recv_seq = 0
        self._used_seqs.clear()
