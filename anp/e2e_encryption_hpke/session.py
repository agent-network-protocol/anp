"""私聊 E2EE 会话（IDLE → ACTIVE 两态）。

与传输层完全解耦：所有方法只接收/返回 dict，不直接发送 HTTP 请求。
"""

import base64
import logging
import os
import time
from enum import Enum
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from anp.e2e_encryption_hpke.crypto import decrypt_aes_128_gcm, encrypt_aes_128_gcm
from anp.e2e_encryption_hpke.hpke import hpke_open
from anp.e2e_encryption_hpke.message_builder import build_e2ee_init, build_e2ee_msg
from anp.e2e_encryption_hpke.models import DEFAULT_EXPIRES, SeqMode
from anp.e2e_encryption_hpke.proof import verify_proof
from anp.e2e_encryption_hpke.ratchet import (
    assign_chain_keys,
    derive_chain_keys,
    derive_message_key,
    determine_direction,
)
from anp.e2e_encryption_hpke.seq_manager import SeqManager
from anp.utils.crypto_tool import generate_random_hex


class SessionState(Enum):
    """E2EE 会话状态。"""
    IDLE = "idle"
    ACTIVE = "active"


class E2eeHpkeSession:
    """基于 HPKE 的私聊 E2EE 会话。

    Args:
        local_did: 本地 DID。
        peer_did: 对端 DID。
        local_x25519_private_key: 本地 X25519 私钥。
        local_x25519_key_id: 本地 keyAgreement 的 id。
        signing_private_key: 本地 secp256r1 签名私钥。
        signing_verification_method: 签名用的 verificationMethod id。
        seq_mode: 序号验证策略。
        default_expires: 默认有效期（秒）。
    """

    def __init__(
        self,
        local_did: str,
        peer_did: str,
        local_x25519_private_key: X25519PrivateKey,
        local_x25519_key_id: str,
        signing_private_key: ec.EllipticCurvePrivateKey,
        signing_verification_method: str,
        seq_mode: SeqMode = SeqMode.STRICT,
        default_expires: int = DEFAULT_EXPIRES,
    ):
        self.local_did = local_did
        self.peer_did = peer_did
        self._local_x25519_sk = local_x25519_private_key
        self._local_x25519_key_id = local_x25519_key_id
        self._signing_key = signing_private_key
        self._signing_vm = signing_verification_method
        self._default_expires = default_expires

        self._state = SessionState.IDLE
        self._session_id: Optional[str] = None
        self._send_chain_key: Optional[bytes] = None
        self._recv_chain_key: Optional[bytes] = None
        self._seq_manager = SeqManager(mode=seq_mode)
        self._is_initiator: Optional[bool] = None
        self._expires_at: Optional[float] = None
        self._created_at: float = time.time()
        self._active_at: Optional[float] = None

    @property
    def state(self) -> SessionState:
        return self._state

    @property
    def session_id(self) -> Optional[str]:
        return self._session_id

    def initiate_session(
        self,
        peer_pk: X25519PublicKey,
        peer_key_id: str,
    ) -> Tuple[str, Dict[str, Any]]:
        """发起会话初始化。

        Args:
            peer_pk: 对端 X25519 公钥。
            peer_key_id: 对端 keyAgreement 的 id。

        Returns:
            ("e2ee_init", content_dict)

        Raises:
            RuntimeError: 当前状态不是 IDLE。
        """
        if self._state != SessionState.IDLE:
            raise RuntimeError(
                f"Cannot initiate from {self._state.value} state, need IDLE"
            )

        self._session_id = generate_random_hex(16)
        root_seed = os.urandom(32)

        content = build_e2ee_init(
            session_id=self._session_id,
            sender_did=self.local_did,
            recipient_did=self.peer_did,
            recipient_key_id=peer_key_id,
            recipient_pk=peer_pk,
            root_seed=root_seed,
            signing_key=self._signing_key,
            verification_method=self._signing_vm,
            expires=self._default_expires,
        )

        self._setup_chain_keys(root_seed, content.get("expires", self._default_expires))
        return "e2ee_init", content

    def process_init(
        self,
        content: Dict[str, Any],
        sender_signing_pk: ec.EllipticCurvePublicKey,
    ) -> None:
        """处理收到的 e2ee_init 消息。

        Args:
            content: e2ee_init content dict。
            sender_signing_pk: 发送方 secp256r1 签名公钥。

        Raises:
            RuntimeError: 当前状态不是 IDLE。
            ValueError: 验证失败。
        """
        if self._state != SessionState.IDLE:
            raise RuntimeError(
                f"Cannot process init from {self._state.value} state, need IDLE"
            )

        # 验证 proof
        if not verify_proof(content, sender_signing_pk):
            raise ValueError("e2ee_init proof verification failed")

        # 验证接收方是否为本地
        if content["recipient_did"] != self.local_did:
            raise ValueError("recipient_did does not match local DID")

        # HPKE 解封装
        enc_bytes = base64.b64decode(content["enc"])
        ct_bytes = base64.b64decode(content["encrypted_seed"])
        aad = content["session_id"].encode("utf-8")
        root_seed = hpke_open(self._local_x25519_sk, enc_bytes, ct_bytes, aad=aad)

        self._session_id = content["session_id"]
        expires = content.get("expires", self._default_expires)
        self._setup_chain_keys(root_seed, expires)

    def encrypt_message(
        self, original_type: str, plaintext: str
    ) -> Tuple[str, Dict[str, Any]]:
        """加密消息。

        Args:
            original_type: 原始消息类型（text/image/file）。
            plaintext: 明文内容。

        Returns:
            ("e2ee_msg", content_dict)

        Raises:
            RuntimeError: 会话不在 ACTIVE 状态。
        """
        if self._state != SessionState.ACTIVE:
            raise RuntimeError(
                f"Cannot encrypt from {self._state.value} state, need ACTIVE"
            )

        seq = self._seq_manager.next_send_seq()
        enc_key, nonce, new_chain_key = derive_message_key(self._send_chain_key, seq)
        self._send_chain_key = new_chain_key

        aad = self._session_id.encode("utf-8")
        ciphertext_b64 = encrypt_aes_128_gcm(
            plaintext.encode("utf-8"), enc_key, nonce, aad
        )

        content = build_e2ee_msg(self._session_id, seq, original_type, ciphertext_b64)
        return "e2ee_msg", content

    def decrypt_message(
        self, content: Dict[str, Any]
    ) -> Tuple[str, str]:
        """解密消息。

        Args:
            content: e2ee_msg content dict。

        Returns:
            (original_type, plaintext)

        Raises:
            RuntimeError: 会话不在 ACTIVE 状态。
            ValueError: 序号验证失败。
        """
        if self._state != SessionState.ACTIVE:
            raise RuntimeError(
                f"Cannot decrypt from {self._state.value} state, need ACTIVE"
            )

        seq = content["seq"]
        if not self._seq_manager.validate_recv_seq(seq):
            raise ValueError(f"Invalid seq: {seq}")

        # 窗口模式：快进 recv_chain_key 到目标 seq
        current_recv_seq = self._seq_manager.recv_seq
        temp_chain_key = self._recv_chain_key
        for s in range(current_recv_seq, seq):
            _, _, temp_chain_key = derive_message_key(temp_chain_key, s)

        enc_key, nonce, new_chain_key = derive_message_key(temp_chain_key, seq)

        aad = self._session_id.encode("utf-8")
        plaintext_bytes = decrypt_aes_128_gcm(content["ciphertext"], enc_key, nonce, aad)

        # 更新状态
        self._recv_chain_key = new_chain_key
        self._seq_manager.mark_seq_used(seq)
        self._seq_manager.advance_recv_to(seq)

        return content["original_type"], plaintext_bytes.decode("utf-8")

    def initiate_rekey(
        self,
        peer_pk: X25519PublicKey,
        peer_key_id: str,
    ) -> Tuple[str, Dict[str, Any]]:
        """发起会话重建（rekey）。

        Returns:
            ("e2ee_rekey", content_dict)
        """
        # 重置为 IDLE 状态
        self._state = SessionState.IDLE
        self._seq_manager.reset()
        self._send_chain_key = None
        self._recv_chain_key = None

        self._session_id = generate_random_hex(16)
        root_seed = os.urandom(32)

        content = build_e2ee_init(
            session_id=self._session_id,
            sender_did=self.local_did,
            recipient_did=self.peer_did,
            recipient_key_id=peer_key_id,
            recipient_pk=peer_pk,
            root_seed=root_seed,
            signing_key=self._signing_key,
            verification_method=self._signing_vm,
            expires=self._default_expires,
        )

        self._setup_chain_keys(root_seed, content.get("expires", self._default_expires))
        return "e2ee_rekey", content

    def process_rekey(
        self,
        content: Dict[str, Any],
        sender_signing_pk: ec.EllipticCurvePublicKey,
    ) -> None:
        """处理收到的 e2ee_rekey 消息。"""
        # 销毁旧状态
        self._state = SessionState.IDLE
        self._seq_manager.reset()
        self._send_chain_key = None
        self._recv_chain_key = None

        # 复用 process_init 逻辑
        self.process_init(content, sender_signing_pk)

    def is_expired(self) -> bool:
        """检查会话是否已过期。"""
        if self._expires_at is None:
            return False
        return time.time() > self._expires_at

    def get_session_info(self) -> Dict[str, Any]:
        """获取可序列化的会话信息。"""
        return {
            "session_id": self._session_id,
            "local_did": self.local_did,
            "peer_did": self.peer_did,
            "state": self._state.value,
            "is_initiator": self._is_initiator,
            "expires_at": self._expires_at,
            "created_at": self._created_at,
            "active_at": self._active_at,
        }

    def _setup_chain_keys(self, root_seed: bytes, expires: int) -> None:
        """从 root_seed 派生链密钥并激活会话。"""
        init_ck, resp_ck = derive_chain_keys(root_seed)
        self._is_initiator = determine_direction(self.local_did, self.peer_did)
        self._send_chain_key, self._recv_chain_key = assign_chain_keys(
            init_ck, resp_ck, self._is_initiator
        )
        self._active_at = time.time()
        self._expires_at = self._active_at + expires
        self._state = SessionState.ACTIVE
