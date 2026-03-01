"""ratchet.py 的单元测试：链式 ratchet 密钥派生。"""

import os
import unittest

from anp.e2e_encryption_hpke.ratchet import (
    assign_chain_keys,
    derive_chain_keys,
    derive_group_message_key,
    derive_message_key,
    determine_direction,
)


class TestDeriveChainKeys(unittest.TestCase):
    """derive_chain_keys 密钥派生测试。"""

    def test_returns_two_different_32_byte_keys(self):
        """派生出的两个链密钥应各 32 字节且互不相同。"""
        root_seed = os.urandom(32)
        init_ck, resp_ck = derive_chain_keys(root_seed)

        self.assertEqual(len(init_ck), 32)
        self.assertEqual(len(resp_ck), 32)
        self.assertNotEqual(init_ck, resp_ck)

    def test_deterministic(self):
        """相同 root_seed 必须产生相同的派生结果。"""
        root_seed = os.urandom(32)
        first = derive_chain_keys(root_seed)
        second = derive_chain_keys(root_seed)

        self.assertEqual(first, second)


class TestDetermineDirection(unittest.TestCase):
    """determine_direction 方向判定测试。"""

    def test_returns_true_when_local_less_than_peer(self):
        """local_did 字典序小于 peer_did 时应返回 True（本端为 initiator）。"""
        self.assertTrue(determine_direction("did:wba:aaa", "did:wba:bbb"))

    def test_returns_false_when_local_greater_than_peer(self):
        """local_did 字典序大于 peer_did 时应返回 False。"""
        self.assertFalse(determine_direction("did:wba:bbb", "did:wba:aaa"))


class TestAssignChainKeys(unittest.TestCase):
    """assign_chain_keys 角色密钥分配测试。"""

    def test_initiator_gets_init_as_send(self):
        """initiator 的 send_ck 应为 init_ck，recv_ck 应为 resp_ck。"""
        init_ck = os.urandom(32)
        resp_ck = os.urandom(32)

        send_ck, recv_ck = assign_chain_keys(init_ck, resp_ck, is_initiator=True)

        self.assertEqual(send_ck, init_ck)
        self.assertEqual(recv_ck, resp_ck)

    def test_responder_gets_resp_as_send(self):
        """responder 的 send_ck 应为 resp_ck，recv_ck 应为 init_ck。"""
        init_ck = os.urandom(32)
        resp_ck = os.urandom(32)

        send_ck, recv_ck = assign_chain_keys(init_ck, resp_ck, is_initiator=False)

        self.assertEqual(send_ck, resp_ck)
        self.assertEqual(recv_ck, init_ck)

    def test_initiator_and_responder_swapped(self):
        """initiator 与 responder 的 send/recv 密钥恰好互换。"""
        init_ck = os.urandom(32)
        resp_ck = os.urandom(32)

        i_send, i_recv = assign_chain_keys(init_ck, resp_ck, is_initiator=True)
        r_send, r_recv = assign_chain_keys(init_ck, resp_ck, is_initiator=False)

        self.assertEqual(i_send, r_recv)
        self.assertEqual(i_recv, r_send)


class TestDeriveMessageKey(unittest.TestCase):
    """derive_message_key 私聊消息密钥派生测试。"""

    def test_output_lengths(self):
        """enc_key 应 16 字节，nonce 应 12 字节，new_chain_key 应 32 字节。"""
        chain_key = os.urandom(32)
        enc_key, nonce, new_ck = derive_message_key(chain_key, seq=0)

        self.assertEqual(len(enc_key), 16)
        self.assertEqual(len(nonce), 12)
        self.assertEqual(len(new_ck), 32)

    def test_different_seq_produces_different_keys(self):
        """不同 seq 应产生不同的 enc_key 和 nonce。"""
        chain_key = os.urandom(32)
        enc0, nonce0, _ = derive_message_key(chain_key, seq=0)
        enc1, nonce1, _ = derive_message_key(chain_key, seq=1)

        self.assertNotEqual(enc0, enc1)
        self.assertNotEqual(nonce0, nonce1)

    def test_chain_key_updates(self):
        """new_chain_key 必须不同于原 chain_key。"""
        chain_key = os.urandom(32)
        _, _, new_ck = derive_message_key(chain_key, seq=0)

        self.assertNotEqual(new_ck, chain_key)

    def test_deterministic(self):
        """相同输入必须产生相同输出。"""
        chain_key = os.urandom(32)
        result1 = derive_message_key(chain_key, seq=42)
        result2 = derive_message_key(chain_key, seq=42)

        self.assertEqual(result1, result2)


class TestDeriveGroupMessageKey(unittest.TestCase):
    """derive_group_message_key 群聊消息密钥派生测试。"""

    def test_output_lengths(self):
        """群聊派生的 enc_key 应 16 字节，nonce 应 12 字节，new_chain_key 应 32 字节。"""
        sender_ck = os.urandom(32)
        enc_key, nonce, new_ck = derive_group_message_key(sender_ck, seq=0)

        self.assertEqual(len(enc_key), 16)
        self.assertEqual(len(nonce), 12)
        self.assertEqual(len(new_ck), 32)

    def test_different_seq_produces_different_keys(self):
        """不同 seq 应产生不同的群聊密钥。"""
        sender_ck = os.urandom(32)
        enc0, nonce0, _ = derive_group_message_key(sender_ck, seq=0)
        enc1, nonce1, _ = derive_group_message_key(sender_ck, seq=1)

        self.assertNotEqual(enc0, enc1)
        self.assertNotEqual(nonce0, nonce1)

    def test_chain_key_updates(self):
        """群聊 new_chain_key 必须不同于原 sender_chain_key。"""
        sender_ck = os.urandom(32)
        _, _, new_ck = derive_group_message_key(sender_ck, seq=0)

        self.assertNotEqual(new_ck, sender_ck)

    def test_differs_from_private_message_key(self):
        """相同输入下，群聊派生结果应与私聊派生结果不同（标签不同）。"""
        ck = os.urandom(32)
        private_result = derive_message_key(ck, seq=0)
        group_result = derive_group_message_key(ck, seq=0)

        self.assertNotEqual(private_result, group_result)


if __name__ == "__main__":
    unittest.main()
