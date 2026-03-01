"""群聊 Sender Key 会话（epoch 管理）。"""

import base64
import hashlib
import logging
import os
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from anp.e2e_encryption_hpke.crypto import decrypt_aes_128_gcm, encrypt_aes_128_gcm
from anp.e2e_encryption_hpke.hpke import hpke_open
from anp.e2e_encryption_hpke.message_builder import (
    build_group_e2ee_key,
    build_group_e2ee_msg,
    build_group_epoch_advance,
)
from anp.e2e_encryption_hpke.models import DEFAULT_EXPIRES, OLD_EPOCH_TTL, SeqMode
from anp.e2e_encryption_hpke.proof import verify_proof
from anp.e2e_encryption_hpke.ratchet import derive_group_message_key
from anp.e2e_encryption_hpke.seq_manager import SeqManager


class SenderKeyState:
    """管理单个 Sender Key 的 chain_key、seq、过期时间。"""

    def __init__(
        self,
        sender_chain_key: bytes,
        sender_did: str,
        epoch: int,
        sender_key_id: str,
        expires: int = DEFAULT_EXPIRES,
        is_local: bool = False,
    ):
        self.sender_chain_key = sender_chain_key
        self.sender_did = sender_did
        self.epoch = epoch
        self.sender_key_id = sender_key_id
        self.is_local = is_local
        self.read_only = False
        self._created_at = time.time()
        self._expires_at = self._created_at + expires
        self._seq_manager = SeqManager(mode=SeqMode.STRICT)

    @property
    def is_expired(self) -> bool:
        return time.time() > self._expires_at

    @property
    def seq_manager(self) -> SeqManager:
        return self._seq_manager


def _generate_sender_key_id(sender_did: str, epoch: int) -> str:
    """生成 sender_key_id: {short_hash}:{epoch}。"""
    short_hash = hashlib.sha256(sender_did.encode("utf-8")).hexdigest()[:6]
    return f"{short_hash}:{epoch}"


class GroupE2eeSession:
    """管理一个群组的所有 Sender Key。

    Args:
        group_did: 群组 DID。
        local_did: 本地 DID。
        local_x25519_private_key: 本地 X25519 私钥。
        local_x25519_key_id: 本地 keyAgreement 的 id。
        signing_private_key: 本地 secp256r1 签名私钥。
        signing_verification_method: 签名用的 verificationMethod id。
        epoch: 初始 epoch。
        seq_mode: 序号验证策略。
    """

    def __init__(
        self,
        group_did: str,
        local_did: str,
        local_x25519_private_key: X25519PrivateKey,
        local_x25519_key_id: str,
        signing_private_key: ec.EllipticCurvePrivateKey,
        signing_verification_method: str,
        epoch: int = 0,
        seq_mode: SeqMode = SeqMode.STRICT,
    ):
        self.group_did = group_did
        self.local_did = local_did
        self._local_x25519_sk = local_x25519_private_key
        self._local_x25519_key_id = local_x25519_key_id
        self._signing_key = signing_private_key
        self._signing_vm = signing_verification_method
        self._epoch = epoch
        self._seq_mode = seq_mode

        # 本地 sender key（当前 epoch）
        self._local_sender_key: Optional[SenderKeyState] = None

        # 远端 sender keys: {(sender_did, epoch, sender_key_id): SenderKeyState}
        self._remote_sender_keys: Dict[Tuple[str, int, str], SenderKeyState] = {}

        # 防重放：已收到的 (sender_did, epoch, sender_key_id) 集合
        self._received_key_ids: Set[Tuple[str, int, str]] = set()

    @property
    def epoch(self) -> int:
        return self._epoch

    @property
    def local_sender_key_id(self) -> Optional[str]:
        return self._local_sender_key.sender_key_id if self._local_sender_key else None

    def generate_sender_key(self) -> bytes:
        """生成并设置本地 Sender Key。

        Returns:
            32 字节 sender_chain_key。
        """
        sender_chain_key = os.urandom(32)
        sender_key_id = _generate_sender_key_id(self.local_did, self._epoch)

        self._local_sender_key = SenderKeyState(
            sender_chain_key=sender_chain_key,
            sender_did=self.local_did,
            epoch=self._epoch,
            sender_key_id=sender_key_id,
            is_local=True,
        )
        return sender_chain_key

    def build_sender_key_distribution(
        self,
        recipient_did: str,
        recipient_pk: X25519PublicKey,
        recipient_key_id: str,
    ) -> Tuple[str, Dict[str, Any]]:
        """构建 Sender Key 分发消息。

        Args:
            recipient_did: 接收方 DID。
            recipient_pk: 接收方 X25519 公钥。
            recipient_key_id: 接收方 keyAgreement 的 id。

        Returns:
            ("group_e2ee_key", content_dict)

        Raises:
            RuntimeError: 未生成本地 Sender Key。
        """
        if self._local_sender_key is None:
            raise RuntimeError("No local sender key generated")

        content = build_group_e2ee_key(
            group_did=self.group_did,
            epoch=self._epoch,
            sender_did=self.local_did,
            sender_key_id=self._local_sender_key.sender_key_id,
            recipient_key_id=recipient_key_id,
            recipient_pk=recipient_pk,
            sender_chain_key=self._local_sender_key.sender_chain_key,
            signing_key=self._signing_key,
            verification_method=self._signing_vm,
        )

        return "group_e2ee_key", content

    def process_sender_key(
        self,
        content: Dict[str, Any],
        sender_signing_pk: ec.EllipticCurvePublicKey,
    ) -> None:
        """处理收到的 Sender Key 分发消息。

        Args:
            content: group_e2ee_key content dict。
            sender_signing_pk: 发送方 secp256r1 签名公钥。

        Raises:
            ValueError: 验证失败或重复 Sender Key。
        """
        # 验证 proof
        if not verify_proof(content, sender_signing_pk):
            raise ValueError("group_e2ee_key proof verification failed")

        sender_did = content["sender_did"]
        epoch = content["epoch"]
        sender_key_id = content["sender_key_id"]

        # 防重放：拒绝重复的 (sender_did, epoch, sender_key_id)
        key_tuple = (sender_did, epoch, sender_key_id)
        if key_tuple in self._received_key_ids:
            raise ValueError(
                f"Duplicate sender key: {key_tuple}"
            )

        # HPKE 解封装
        enc_bytes = base64.b64decode(content["enc"])
        ct_bytes = base64.b64decode(content["encrypted_sender_key"])
        aad = f"{content['group_did']}:{epoch}:{sender_key_id}".encode("utf-8")
        sender_chain_key = hpke_open(self._local_x25519_sk, enc_bytes, ct_bytes, aad=aad)

        # 存储
        expires = content.get("expires", DEFAULT_EXPIRES)
        state = SenderKeyState(
            sender_chain_key=sender_chain_key,
            sender_did=sender_did,
            epoch=epoch,
            sender_key_id=sender_key_id,
            expires=expires,
        )
        self._remote_sender_keys[key_tuple] = state
        self._received_key_ids.add(key_tuple)

    def encrypt_group_message(
        self, original_type: str, plaintext: str
    ) -> Tuple[str, Dict[str, Any]]:
        """加密群消息。

        Returns:
            ("group_e2ee_msg", content_dict)

        Raises:
            RuntimeError: 未生成本地 Sender Key 或 Sender Key 只读。
        """
        if self._local_sender_key is None:
            raise RuntimeError("No local sender key generated")
        if self._local_sender_key.read_only:
            raise RuntimeError("Local sender key is read-only (epoch expired)")

        sk = self._local_sender_key
        seq = sk.seq_manager.next_send_seq()
        enc_key, nonce, new_chain_key = derive_group_message_key(
            sk.sender_chain_key, seq
        )
        sk.sender_chain_key = new_chain_key

        aad = f"{self.group_did}:{self._epoch}".encode("utf-8")
        ciphertext_b64 = encrypt_aes_128_gcm(
            plaintext.encode("utf-8"), enc_key, nonce, aad
        )

        content = build_group_e2ee_msg(
            group_did=self.group_did,
            epoch=self._epoch,
            sender_did=self.local_did,
            sender_key_id=sk.sender_key_id,
            seq=seq,
            original_type=original_type,
            ciphertext_b64=ciphertext_b64,
        )

        return "group_e2ee_msg", content

    def decrypt_group_message(
        self, content: Dict[str, Any]
    ) -> Tuple[str, str]:
        """解密群消息。

        Returns:
            (original_type, plaintext)

        Raises:
            ValueError: 未找到对应 Sender Key 或序号验证失败。
        """
        sender_did = content["sender_did"]
        epoch = content["epoch"]
        sender_key_id = content["sender_key_id"]
        seq = content["seq"]

        key_tuple = (sender_did, epoch, sender_key_id)
        state = self._remote_sender_keys.get(key_tuple)
        if state is None:
            raise ValueError(f"Sender key not found: {key_tuple}")

        if not state.seq_manager.validate_recv_seq(seq):
            raise ValueError(f"Invalid seq: {seq}")

        # 快进 chain_key 到目标 seq
        current_recv_seq = state.seq_manager.recv_seq
        temp_chain_key = state.sender_chain_key
        for s in range(current_recv_seq, seq):
            _, _, temp_chain_key = derive_group_message_key(temp_chain_key, s)

        enc_key, nonce, new_chain_key = derive_group_message_key(temp_chain_key, seq)

        aad = f"{content['group_did']}:{epoch}".encode("utf-8")
        plaintext_bytes = decrypt_aes_128_gcm(content["ciphertext"], enc_key, nonce, aad)

        # 更新状态
        state.sender_chain_key = new_chain_key
        state.seq_manager.mark_seq_used(seq)
        state.seq_manager.advance_recv_to(seq)

        return content["original_type"], plaintext_bytes.decode("utf-8")

    def advance_epoch(self, new_epoch: int) -> None:
        """推进本地 epoch（发起方）。

        旧 epoch 的 Sender Key 标记为只读，生成新 sender_chain_key。
        """
        if new_epoch <= self._epoch:
            raise ValueError(f"New epoch must be greater: {new_epoch} <= {self._epoch}")

        # 旧 epoch 只读
        if self._local_sender_key:
            self._local_sender_key.read_only = True
        for state in self._remote_sender_keys.values():
            if state.epoch == self._epoch:
                state.read_only = True

        self._epoch = new_epoch
        self._local_sender_key = None  # 需要重新 generate_sender_key

    def process_epoch_advance(
        self,
        content: Dict[str, Any],
        admin_signing_pk: ec.EllipticCurvePublicKey,
    ) -> None:
        """处理收到的 group_epoch_advance 消息。

        Args:
            content: group_epoch_advance content dict。
            admin_signing_pk: 管理员 secp256r1 签名公钥。

        Raises:
            ValueError: 签名验证失败或 epoch 非递增。
        """
        if not verify_proof(content, admin_signing_pk):
            raise ValueError("group_epoch_advance proof verification failed")

        new_epoch = content["new_epoch"]
        if new_epoch <= self._epoch:
            raise ValueError(f"Epoch not increasing: {new_epoch} <= {self._epoch}")

        self.advance_epoch(new_epoch)

    def cleanup_expired(self) -> None:
        """清理过期的 Sender Key 状态。"""
        expired = [
            key for key, state in self._remote_sender_keys.items()
            if state.is_expired
        ]
        for key in expired:
            del self._remote_sender_keys[key]
