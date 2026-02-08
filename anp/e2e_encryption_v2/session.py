"""基于 HTTP RESTful 的端到端加密通信协议 - 会话管理。

[INPUT]: 本地 DID 信息、对端 DID、协议消息 dict
[OUTPUT]: 协议响应消息 dict、加解密结果
[POS]: L2 核心层，E2EE 会话状态机 + 密钥派生 + 加解密

[PROTOCOL]:
1. 逻辑变更时同步更新此头部
2. 更新后检查所在文件夹的 CLAUDE.md
"""

import json
import logging
import time
from enum import Enum
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import ec

from anp.e2e_encryption_v2.message_builder import (
    build_destination_hello,
    build_encrypted_message,
    build_finished,
    build_source_hello,
)
from anp.e2e_encryption_v2.message_parser import verify_hello_proof
from anp.utils.crypto_tool import (
    decrypt_aes_gcm_sha256,
    derive_tls13_data_keys,
    generate_16_char_from_random_num,
    generate_ec_key_pair,
    generate_random_hex,
    generate_shared_secret,
    get_key_length_from_cipher_suite,
    get_public_key_from_hex,
    load_private_key_from_pem,
)


class SessionState(Enum):
    """E2EE 会话状态。"""
    IDLE = "idle"
    HANDSHAKE_INITIATED = "handshake_initiated"
    HANDSHAKE_COMPLETING = "handshake_completing"
    ACTIVE = "active"


class E2eeSession:
    """基于 HTTP RESTful 的 E2EE 会话。

    与传输层完全解耦：所有方法只接收 dict、返回 dict，
    不直接发送 HTTP 请求。调用方负责将返回的 dict 通过
    消息服务 API 发送。
    """

    DEFAULT_CIPHER_SUITES = ["TLS_AES_128_GCM_SHA256"]
    DEFAULT_SUPPORTED_GROUPS = ["secp256r1"]

    def __init__(
        self,
        local_did: str,
        did_private_key_pem: str,
        peer_did: str,
        session_id: Optional[str] = None,
        default_expires: int = 86400,
    ):
        """初始化 E2EE 会话。

        Args:
            local_did: 本地 DID。
            did_private_key_pem: 本地 DID 私钥 PEM 字符串。
            peer_did: 对端 DID。
            session_id: 会话 ID，不指定则自动生成。
            default_expires: 密钥默认有效期（秒）。
        """
        self.local_did = local_did
        self.peer_did = peer_did
        self.session_id = session_id or generate_random_hex(8)
        self.default_expires = default_expires

        # 加载 DID 长期密钥
        self._did_private_key = load_private_key_from_pem(did_private_key_pem)
        pub = self._did_private_key.public_key()
        pub_numbers = pub.public_numbers()
        self._did_public_key_hex = (
            "04"
            + format(pub_numbers.x, "064x")
            + format(pub_numbers.y, "064x")
        )

        # 生成 ECDHE 临时密钥对
        self._eph_private_key, self._eph_public_key, self._eph_public_key_hex = (
            generate_ec_key_pair(ec.SECP256R1())
        )
        self._local_key_share = {
            "group": "secp256r1",
            "expires": self.default_expires,
            "key_exchange": self._eph_public_key_hex,
        }

        # 随机数
        self._local_random: str = generate_random_hex(32)
        self._peer_random: Optional[str] = None

        # 角色标识（在握手过程中确定）
        self._is_initiator: Optional[bool] = None

        # 密钥派生结果
        self._send_key: Optional[bytes] = None
        self._recv_key: Optional[bytes] = None
        self._secret_key_id: Optional[str] = None
        self._cipher_suite: Optional[str] = None
        self._key_expires: Optional[int] = None

        # 时间戳
        self._created_at: float = time.time()
        self._active_at: Optional[float] = None

        # 状态
        self._state: SessionState = SessionState.IDLE

    @property
    def state(self) -> SessionState:
        return self._state

    @property
    def secret_key_id(self) -> Optional[str]:
        return self._secret_key_id

    @property
    def send_key(self) -> Optional[bytes]:
        return self._send_key

    @property
    def recv_key(self) -> Optional[bytes]:
        return self._recv_key

    @property
    def cipher_suite(self) -> Optional[str]:
        return self._cipher_suite

    def initiate_handshake(self) -> Tuple[str, Dict[str, Any]]:
        """发起握手（作为 initiator）。

        Returns:
            (message_type, content_dict) 元组，message_type 为 "e2ee_hello"。

        Raises:
            RuntimeError: 当前状态不是 IDLE。
        """
        if self._state != SessionState.IDLE:
            raise RuntimeError(
                f"无法从 {self._state.value} 状态发起握手，需要 IDLE 状态"
            )

        self._is_initiator = True

        content = build_source_hello(
            session_id=self.session_id,
            source_did=self.local_did,
            destination_did=self.peer_did,
            random_hex=self._local_random,
            did_private_key=self._did_private_key,
            did_public_key_hex=self._did_public_key_hex,
            key_shares=[self._local_key_share],
            cipher_suites=self.DEFAULT_CIPHER_SUITES,
            supported_groups=self.DEFAULT_SUPPORTED_GROUPS,
        )

        self._state = SessionState.HANDSHAKE_INITIATED
        return "e2ee_hello", content

    def process_source_hello(
        self, content: Dict[str, Any]
    ) -> Tuple[Tuple[str, Dict[str, Any]], Tuple[str, Dict[str, Any]]]:
        """处理收到的 SourceHello（作为 responder）。

        Args:
            content: SourceHello 的 content dict。

        Returns:
            ((dest_hello_type, dest_hello_content), (finished_type, finished_content))
            两条待发送消息。

        Raises:
            RuntimeError: 当前状态不是 IDLE。
            ValueError: 消息验证失败。
        """
        if self._state != SessionState.IDLE:
            raise RuntimeError(
                f"无法从 {self._state.value} 状态处理 SourceHello，需要 IDLE 状态"
            )

        self._is_initiator = False

        # 验证 proof
        is_valid, _peer_pub_key = verify_hello_proof(content)
        if not is_valid:
            raise ValueError("SourceHello proof 验证失败")

        # 提取对端信息
        self.session_id = content["session_id"]
        self._peer_random = content["random"]

        # 选择 cipher suite
        peer_suites = content.get("cipher_suites", [])
        self._cipher_suite = None
        for suite in self.DEFAULT_CIPHER_SUITES:
            if suite in peer_suites:
                self._cipher_suite = suite
                break
        if not self._cipher_suite:
            raise ValueError(f"不支持的加密套件: {peer_suites}")

        # 选择 key_share
        peer_key_share = None
        for ks in content.get("key_shares", []):
            if ks.get("group") == "secp256r1":
                peer_key_share = ks
                break
        if not peer_key_share:
            raise ValueError("SourceHello 中未找到 secp256r1 key_share")

        # 计算密钥有效期
        peer_expires = int(peer_key_share.get("expires", self.default_expires))
        self._key_expires = min(peer_expires, self.default_expires)

        # 派生密钥
        self._derive_keys(peer_key_share["key_exchange"])

        # 构建 DestinationHello
        dest_hello = build_destination_hello(
            session_id=self.session_id,
            source_did=self.local_did,
            destination_did=self.peer_did,
            random_hex=self._local_random,
            did_private_key=self._did_private_key,
            did_public_key_hex=self._did_public_key_hex,
            key_share=self._local_key_share,
            cipher_suite=self._cipher_suite,
        )

        # 构建 Finished（发送方用 send_key 加密）
        finished = build_finished(
            session_id=self.session_id,
            source_random=self._peer_random,  # initiator 的 random 作为 source
            destination_random=self._local_random,  # responder 的 random 作为 dest
            send_key=self._send_key,
        )

        self._state = SessionState.HANDSHAKE_COMPLETING
        return ("e2ee_hello", dest_hello), ("e2ee_finished", finished)

    def process_destination_hello(
        self, content: Dict[str, Any]
    ) -> Tuple[str, Dict[str, Any]]:
        """处理收到的 DestinationHello（作为 initiator）。

        Args:
            content: DestinationHello 的 content dict。

        Returns:
            (finished_type, finished_content) 待发送的 Finished 消息。

        Raises:
            RuntimeError: 当前状态不是 HANDSHAKE_INITIATED。
            ValueError: 消息验证失败。
        """
        if self._state != SessionState.HANDSHAKE_INITIATED:
            raise RuntimeError(
                f"无法从 {self._state.value} 状态处理 DestinationHello，"
                f"需要 HANDSHAKE_INITIATED 状态"
            )

        # 验证 proof
        is_valid, _peer_pub_key = verify_hello_proof(content)
        if not is_valid:
            raise ValueError("DestinationHello proof 验证失败")

        # 提取对端信息
        self._peer_random = content["random"]
        self._cipher_suite = content["cipher_suite"]

        peer_key_share = content["key_share"]
        if peer_key_share.get("group") != "secp256r1":
            raise ValueError("不支持的椭圆曲线组")

        peer_expires = int(peer_key_share.get("expires", self.default_expires))
        self._key_expires = min(peer_expires, self.default_expires)

        # 派生密钥
        self._derive_keys(peer_key_share["key_exchange"])

        # 构建 Finished
        finished = build_finished(
            session_id=self.session_id,
            source_random=self._local_random,  # initiator 的 random 作为 source
            destination_random=self._peer_random,  # responder 的 random 作为 dest
            send_key=self._send_key,
        )

        self._state = SessionState.HANDSHAKE_COMPLETING
        return "e2ee_finished", finished

    def process_finished(self, content: Dict[str, Any]) -> None:
        """处理收到的 Finished 消息。

        Args:
            content: Finished 的 content dict。

        Raises:
            RuntimeError: 当前状态不是 HANDSHAKE_COMPLETING。
            ValueError: Finished 验证失败。
        """
        if self._state != SessionState.HANDSHAKE_COMPLETING:
            raise RuntimeError(
                f"无法从 {self._state.value} 状态处理 Finished，"
                f"需要 HANDSHAKE_COMPLETING 状态"
            )

        verify_data = content.get("verify_data")
        if not verify_data:
            raise ValueError("Finished 消息中缺少 verify_data")

        # 用接收密钥解密
        plaintext = decrypt_aes_gcm_sha256(verify_data, self._recv_key)
        content_dict = json.loads(plaintext)

        received_key_id = content_dict.get("secretKeyId")
        if not received_key_id:
            raise ValueError("Finished 密文中缺少 secretKeyId")

        # 计算期望的 secretKeyId
        if self._is_initiator:
            expected = generate_16_char_from_random_num(
                self._local_random, self._peer_random
            )
        else:
            expected = generate_16_char_from_random_num(
                self._peer_random, self._local_random
            )

        if received_key_id != expected:
            raise ValueError(
                f"secretKeyId 不匹配: 收到 {received_key_id}，期望 {expected}"
            )

        self._secret_key_id = expected
        self._active_at = time.time()
        self._state = SessionState.ACTIVE

    def encrypt_message(
        self, original_type: str, plaintext: str
    ) -> Tuple[str, Dict[str, Any]]:
        """加密消息。

        Args:
            original_type: 原始消息类型。
            plaintext: 明文内容。

        Returns:
            (message_type, content_dict) 元组。

        Raises:
            RuntimeError: 会话不在 ACTIVE 状态。
        """
        if self._state != SessionState.ACTIVE:
            raise RuntimeError(
                f"无法在 {self._state.value} 状态加密消息，需要 ACTIVE 状态"
            )

        content = build_encrypted_message(
            secret_key_id=self._secret_key_id,
            original_type=original_type,
            plaintext=plaintext,
            key=self._send_key,
        )
        return "e2ee", content

    def decrypt_message(self, content: Dict[str, Any]) -> Tuple[str, str]:
        """解密消息。

        Args:
            content: 加密消息的 content dict。

        Returns:
            (original_type, plaintext) 元组。

        Raises:
            RuntimeError: 会话不在 ACTIVE 状态。
        """
        if self._state != SessionState.ACTIVE:
            raise RuntimeError(
                f"无法在 {self._state.value} 状态解密消息，需要 ACTIVE 状态"
            )

        original_type = content["original_type"]
        encrypted_data = content["encrypted"]
        plaintext = decrypt_aes_gcm_sha256(encrypted_data, self._recv_key)
        return original_type, plaintext

    def is_expired(self) -> bool:
        """检查密钥是否已过期。"""
        if self._active_at is None or self._key_expires is None:
            return False
        return time.time() > self._active_at + self._key_expires

    def should_renew(self, threshold: float = 0.2) -> bool:
        """检查是否应提前续期。

        Args:
            threshold: 剩余有效期占比阈值，低于此值时应续期。
        """
        if self._active_at is None or self._key_expires is None:
            return False
        elapsed = time.time() - self._active_at
        remaining_ratio = max(0, 1 - elapsed / self._key_expires)
        return remaining_ratio < threshold

    def get_session_info(self) -> Dict[str, Any]:
        """获取可序列化的会话信息。"""
        return {
            "session_id": self.session_id,
            "local_did": self.local_did,
            "peer_did": self.peer_did,
            "state": self._state.value,
            "is_initiator": self._is_initiator,
            "secret_key_id": self._secret_key_id,
            "cipher_suite": self._cipher_suite,
            "key_expires": self._key_expires,
            "created_at": self._created_at,
            "active_at": self._active_at,
        }

    def _derive_keys(self, peer_key_exchange_hex: str) -> None:
        """从 ECDHE 共享密钥派生收发密钥。

        Args:
            peer_key_exchange_hex: 对端 ECDHE 临时公钥 hex。
        """
        peer_pub = get_public_key_from_hex(peer_key_exchange_hex, ec.SECP256R1())
        shared_secret = generate_shared_secret(self._eph_private_key, peer_pub)
        key_length = get_key_length_from_cipher_suite(self._cipher_suite)

        # source_random = initiator 的 random
        # destination_random = responder 的 random
        if self._is_initiator:
            source_random = self._local_random
            destination_random = self._peer_random
        else:
            source_random = self._peer_random
            destination_random = self._local_random

        src_key, dst_key, _, _ = derive_tls13_data_keys(
            shared_secret,
            source_random.encode("utf-8"),
            destination_random.encode("utf-8"),
            key_length=key_length,
        )

        # initiator: send=src_key, recv=dst_key
        # responder: send=dst_key, recv=src_key
        if self._is_initiator:
            self._send_key = src_key
            self._recv_key = dst_key
        else:
            self._send_key = dst_key
            self._recv_key = src_key
