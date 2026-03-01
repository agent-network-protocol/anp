"""群聊完整集成测试：含 epoch 轮转。

不使用 mock，使用真实 X25519 和 secp256r1 密钥对。
"""

import unittest

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from anp.e2e_encryption_hpke.group_session import GroupE2eeSession
from anp.e2e_encryption_hpke.message_builder import build_group_epoch_advance
from anp.e2e_encryption_hpke.models import EpochReason


class _Member:
    """测试辅助：群成员。"""

    def __init__(self, did: str):
        self.did = did
        self.x25519_sk = X25519PrivateKey.generate()
        self.x25519_pk = self.x25519_sk.public_key()
        self.signing_key = ec.generate_private_key(ec.SECP256R1())
        self.signing_pk = self.signing_key.public_key()
        self.x25519_key_id = f"{did}#key-x25519-1"
        self.signing_vm = f"{did}#keys-1"

    def make_group_session(self, group_did: str, epoch: int = 0) -> GroupE2eeSession:
        return GroupE2eeSession(
            group_did=group_did,
            local_did=self.did,
            local_x25519_private_key=self.x25519_sk,
            local_x25519_key_id=self.x25519_key_id,
            signing_private_key=self.signing_key,
            signing_verification_method=self.signing_vm,
            epoch=epoch,
        )


class TestGroupChatFlow(unittest.TestCase):
    """群聊 E2EE 完整流程。"""

    def setUp(self):
        self.group_did = "did:wba:example.com:group:group_dev"
        self.alice = _Member("did:wba:example.com:user:alice")
        self.bob = _Member("did:wba:example.com:user:bob")
        self.carol = _Member("did:wba:example.com:user:carol")
        # 管理员
        self.admin = self.alice

    def _distribute_sender_key(
        self, sender_session: GroupE2eeSession, sender: _Member,
        receivers: list, receiver_sessions: dict
    ):
        """辅助：分发 sender key 给所有接收者。"""
        sender_session.generate_sender_key()
        for receiver in receivers:
            if receiver.did == sender.did:
                continue
            _, content = sender_session.build_sender_key_distribution(
                recipient_did=receiver.did,
                recipient_pk=receiver.x25519_pk,
                recipient_key_id=receiver.x25519_key_id,
            )
            receiver_sessions[receiver.did].process_sender_key(
                content, sender.signing_pk
            )

    def test_basic_group_messaging(self):
        """基本群消息加密/解密。"""
        alice_gs = self.alice.make_group_session(self.group_did)
        bob_gs = self.bob.make_group_session(self.group_did)

        # Alice 生成并分发 Sender Key 给 Bob
        alice_gs.generate_sender_key()
        _, key_content = alice_gs.build_sender_key_distribution(
            recipient_did=self.bob.did,
            recipient_pk=self.bob.x25519_pk,
            recipient_key_id=self.bob.x25519_key_id,
        )
        bob_gs.process_sender_key(key_content, self.alice.signing_pk)

        # Alice 发送群消息
        msg_type, encrypted = alice_gs.encrypt_group_message("text", "Hello group!")
        self.assertEqual(msg_type, "group_e2ee_msg")
        self.assertEqual(encrypted["epoch"], 0)
        self.assertEqual(encrypted["seq"], 0)

        # Bob 解密
        orig_type, plaintext = bob_gs.decrypt_group_message(encrypted)
        self.assertEqual(orig_type, "text")
        self.assertEqual(plaintext, "Hello group!")

    def test_three_member_group(self):
        """三人群组：Alice、Bob、Carol。"""
        members = [self.alice, self.bob, self.carol]
        sessions = {m.did: m.make_group_session(self.group_did) for m in members}

        # 每个成员分发 Sender Key 给其他人
        for sender in members:
            self._distribute_sender_key(
                sessions[sender.did], sender, members, sessions
            )

        # Alice 发消息，Bob 和 Carol 都能解密
        _, encrypted = sessions[self.alice.did].encrypt_group_message("text", "Hi all!")
        for receiver in [self.bob, self.carol]:
            orig_type, plaintext = sessions[receiver.did].decrypt_group_message(encrypted)
            self.assertEqual(plaintext, "Hi all!")

        # Bob 发消息，Alice 和 Carol 都能解密
        _, encrypted2 = sessions[self.bob.did].encrypt_group_message("text", "Hey!")
        for receiver in [self.alice, self.carol]:
            orig_type2, plaintext2 = sessions[receiver.did].decrypt_group_message(encrypted2)
            self.assertEqual(plaintext2, "Hey!")

    def test_multiple_messages(self):
        """多条群消息。"""
        alice_gs = self.alice.make_group_session(self.group_did)
        bob_gs = self.bob.make_group_session(self.group_did)

        alice_gs.generate_sender_key()
        _, key_content = alice_gs.build_sender_key_distribution(
            self.bob.did, self.bob.x25519_pk, self.bob.x25519_key_id,
        )
        bob_gs.process_sender_key(key_content, self.alice.signing_pk)

        messages = ["msg1", "msg2", "msg3", "中文群消息"]
        for i, msg in enumerate(messages):
            _, encrypted = alice_gs.encrypt_group_message("text", msg)
            self.assertEqual(encrypted["seq"], i)
            _, plaintext = bob_gs.decrypt_group_message(encrypted)
            self.assertEqual(plaintext, msg)

    def test_epoch_advance_member_removed(self):
        """epoch 轮转：移除成员。"""
        members = [self.alice, self.bob, self.carol]
        sessions = {m.did: m.make_group_session(self.group_did) for m in members}

        # epoch 0: 三人群组
        for sender in members:
            self._distribute_sender_key(
                sessions[sender.did], sender, members, sessions
            )

        # Alice 发消息（epoch 0）
        _, encrypted_e0 = sessions[self.alice.did].encrypt_group_message("text", "Epoch 0 msg")
        _, p = sessions[self.bob.did].decrypt_group_message(encrypted_e0)
        self.assertEqual(p, "Epoch 0 msg")

        # 管理员发出 epoch advance: 移除 Carol
        epoch_content = build_group_epoch_advance(
            group_did=self.group_did,
            new_epoch=1,
            reason=EpochReason.MEMBER_REMOVED.value,
            signing_key=self.admin.signing_key,
            verification_method=self.admin.signing_vm,
            members_removed=[self.carol.did],
        )

        # Alice 和 Bob 处理 epoch advance
        remaining = [self.alice, self.bob]
        for member in remaining:
            sessions[member.did].process_epoch_advance(
                epoch_content, self.admin.signing_pk
            )
            self.assertEqual(sessions[member.did].epoch, 1)

        # 重新分发 Sender Keys（仅 Alice 和 Bob）
        remaining_sessions = {m.did: sessions[m.did] for m in remaining}
        for sender in remaining:
            self._distribute_sender_key(
                remaining_sessions[sender.did], sender, remaining, remaining_sessions
            )

        # Alice 在新 epoch 发消息
        _, encrypted_e1 = sessions[self.alice.did].encrypt_group_message("text", "Epoch 1 msg")
        self.assertEqual(encrypted_e1["epoch"], 1)

        _, p = sessions[self.bob.did].decrypt_group_message(encrypted_e1)
        self.assertEqual(p, "Epoch 1 msg")

        # Carol 的旧 session 无法解密新 epoch 消息（没有新 Sender Key）
        with self.assertRaises(ValueError):
            sessions[self.carol.did].decrypt_group_message(encrypted_e1)

    def test_epoch_advance_member_added(self):
        """epoch 轮转：添加成员。"""
        # 初始：Alice 和 Bob
        initial_members = [self.alice, self.bob]
        sessions = {m.did: m.make_group_session(self.group_did) for m in initial_members}

        for sender in initial_members:
            self._distribute_sender_key(
                sessions[sender.did], sender, initial_members, sessions
            )

        # 管理员发出 epoch advance: 添加 Carol
        epoch_content = build_group_epoch_advance(
            group_did=self.group_did,
            new_epoch=1,
            reason=EpochReason.MEMBER_ADDED.value,
            signing_key=self.admin.signing_key,
            verification_method=self.admin.signing_vm,
            members_added=[self.carol.did],
        )

        # 所有旧成员处理 epoch advance
        for member in initial_members:
            sessions[member.did].process_epoch_advance(
                epoch_content, self.admin.signing_pk
            )

        # Carol 加入（创建新的 epoch=1 session）
        sessions[self.carol.did] = self.carol.make_group_session(self.group_did, epoch=1)

        # 所有成员重新分发 Sender Keys
        all_members = [self.alice, self.bob, self.carol]
        for sender in all_members:
            self._distribute_sender_key(
                sessions[sender.did], sender, all_members, sessions
            )

        # Carol 发消息
        _, encrypted = sessions[self.carol.did].encrypt_group_message("text", "Hello from Carol!")
        for receiver in [self.alice, self.bob]:
            _, plaintext = sessions[receiver.did].decrypt_group_message(encrypted)
            self.assertEqual(plaintext, "Hello from Carol!")

    def test_sender_key_replay_rejected(self):
        """重复的 Sender Key 分发应被拒绝。"""
        alice_gs = self.alice.make_group_session(self.group_did)
        bob_gs = self.bob.make_group_session(self.group_did)

        alice_gs.generate_sender_key()
        _, key_content = alice_gs.build_sender_key_distribution(
            self.bob.did, self.bob.x25519_pk, self.bob.x25519_key_id,
        )

        # 第一次接收
        bob_gs.process_sender_key(key_content, self.alice.signing_pk)

        # 重放
        with self.assertRaises(ValueError):
            bob_gs.process_sender_key(key_content, self.alice.signing_pk)

    def test_message_replay_rejected(self):
        """群消息重放应被拒绝。"""
        alice_gs = self.alice.make_group_session(self.group_did)
        bob_gs = self.bob.make_group_session(self.group_did)

        alice_gs.generate_sender_key()
        _, key_content = alice_gs.build_sender_key_distribution(
            self.bob.did, self.bob.x25519_pk, self.bob.x25519_key_id,
        )
        bob_gs.process_sender_key(key_content, self.alice.signing_pk)

        _, encrypted = alice_gs.encrypt_group_message("text", "Test")
        bob_gs.decrypt_group_message(encrypted)

        # 重放
        with self.assertRaises(ValueError):
            bob_gs.decrypt_group_message(encrypted)


if __name__ == "__main__":
    unittest.main()
