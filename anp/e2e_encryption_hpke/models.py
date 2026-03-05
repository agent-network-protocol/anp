"""基于 HPKE 的端到端加密协议 - 数据模型。

常量、枚举和 Pydantic 数据模型，供模块内其他文件使用。
协议规范：09-ANP-端到端即时消息协议规范.md
"""

from enum import Enum
from typing import List, Optional

from pydantic import BaseModel


# ── 常量 ──────────────────────────────────────────────────────────

HPKE_SUITE = "DHKEM-X25519-HKDF-SHA256/HKDF-SHA256/AES-128-GCM"
PROOF_TYPE = "EcdsaSecp256r1Signature2019"
DEFAULT_EXPIRES = 86400  # 会话 / Sender Key 默认有效期（秒）
DEFAULT_MAX_SKIP = 256  # 窗口模式最大允许跳跃量
DEFAULT_SKIP_KEY_TTL = 300  # 跳跃 msg_key 缓存有效期（秒）
OLD_EPOCH_TTL = 3600  # 旧 epoch Sender Key 保留时间（秒）


# ── 枚举 ──────────────────────────────────────────────────────────

class MessageType(str, Enum):
    """消息 type 字段的 E2EE 类型。"""
    E2EE_INIT = "e2ee_init"
    E2EE_MSG = "e2ee_msg"
    E2EE_REKEY = "e2ee_rekey"
    E2EE_ERROR = "e2ee_error"
    GROUP_E2EE_KEY = "group_e2ee_key"
    GROUP_E2EE_MSG = "group_e2ee_msg"
    GROUP_EPOCH_ADVANCE = "group_epoch_advance"


class ErrorCode(str, Enum):
    """E2EE 错误码。"""
    SESSION_NOT_FOUND = "session_not_found"
    SESSION_EXPIRED = "session_expired"
    DECRYPTION_FAILED = "decryption_failed"
    INVALID_SEQ = "invalid_seq"
    UNSUPPORTED_SUITE = "unsupported_suite"
    NO_KEY_AGREEMENT = "no_key_agreement"
    SENDER_KEY_NOT_FOUND = "sender_key_not_found"


class EpochReason(str, Enum):
    """epoch 轮转原因。"""
    MEMBER_ADDED = "member_added"
    MEMBER_REMOVED = "member_removed"
    KEY_ROTATION = "key_rotation"


class SeqMode(str, Enum):
    """序号验证策略。"""
    STRICT = "strict"
    WINDOW = "window"


# ── Pydantic 数据模型 ────────────────────────────────────────────

class Proof(BaseModel):
    """EcdsaSecp256r1Signature2019 签名证明。"""
    type: str = PROOF_TYPE
    created: str
    verification_method: str
    proof_value: Optional[str] = None


class E2eeInitContent(BaseModel):
    """e2ee_init / e2ee_rekey 消息 content 结构。"""
    session_id: str
    hpke_suite: str = HPKE_SUITE
    sender_did: str
    recipient_did: str
    recipient_key_id: str
    enc: str  # Base64，32 字节 X25519 临时公钥
    encrypted_seed: str  # Base64，AEAD 密文 + GCM tag
    expires: int = DEFAULT_EXPIRES
    proof: Proof


class E2eeMsgContent(BaseModel):
    """e2ee_msg 加密消息 content 结构。"""
    session_id: str
    seq: int
    original_type: str
    ciphertext: str  # Base64，AES-128-GCM 密文 + tag


class E2eeErrorContent(BaseModel):
    """e2ee_error 错误通知 content 结构。"""
    error_code: str
    session_id: Optional[str] = None
    failed_msg_id: Optional[str] = None
    message: Optional[str] = None


class GroupE2eeKeyContent(BaseModel):
    """group_e2ee_key — Sender Key 分发 content 结构。"""
    group_did: str
    epoch: int
    sender_did: str
    sender_key_id: str
    recipient_key_id: str
    hpke_suite: str = HPKE_SUITE
    enc: str  # Base64
    encrypted_sender_key: str  # Base64
    expires: int = DEFAULT_EXPIRES
    proof: Proof


class GroupE2eeMsgContent(BaseModel):
    """group_e2ee_msg 群密文消息 content 结构。"""
    group_did: str
    epoch: int
    sender_did: str
    sender_key_id: str
    seq: int
    original_type: str
    ciphertext: str  # Base64


class GroupEpochAdvanceContent(BaseModel):
    """group_epoch_advance 群纪元变化通知 content 结构。"""
    group_did: str
    new_epoch: int
    reason: str
    members_added: Optional[List[str]] = None
    members_removed: Optional[List[str]] = None
    proof: Proof
