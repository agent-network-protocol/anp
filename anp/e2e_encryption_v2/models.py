"""基于 HTTP RESTful 的端到端加密通信协议 - 数据模型。

[INPUT]: 协议规范 docs/e2e/05-e2e.md 中的消息格式定义
[OUTPUT]: Pydantic 数据模型和枚举类型，供 message_builder / message_parser / session 使用
[POS]: L2 数据层，所有消息类型的类型定义

[PROTOCOL]:
1. 逻辑变更时同步更新此头部
2. 更新后检查所在文件夹的 CLAUDE.md
"""

from enum import Enum
from typing import List, Optional

from pydantic import BaseModel


class MessageType(str, Enum):
    """HTTP 消息 type 字段的 E2EE 扩展类型。"""
    E2EE_HELLO = "e2ee_hello"
    E2EE_FINISHED = "e2ee_finished"
    E2EE = "e2ee"
    E2EE_ERROR = "e2ee_error"


class E2eeType(str, Enum):
    """e2ee_hello 消息中 e2ee_type 子字段的取值。"""
    SOURCE_HELLO = "source_hello"
    DESTINATION_HELLO = "destination_hello"


class FinishedE2eeType(str, Enum):
    """e2ee_finished 消息中 e2ee_type 子字段的取值。"""
    FINISHED = "finished"


class ErrorCode(str, Enum):
    """错误通知中的错误码。"""
    KEY_EXPIRED = "key_expired"
    KEY_NOT_FOUND = "key_not_found"


class KeyShare(BaseModel):
    """密钥交换信息。"""
    group: str
    expires: int
    key_exchange: str


class VerificationMethod(BaseModel):
    """DID 验证方法。"""
    id: str
    type: str
    public_key_hex: str


class Proof(BaseModel):
    """签名证明。"""
    type: str
    created: str
    verification_method: str
    proof_value: Optional[str] = None


class EncryptedData(BaseModel):
    """AES-GCM 加密数据。"""
    iv: str
    tag: str
    ciphertext: str


class SourceHelloContent(BaseModel):
    """SourceHello 消息 content 结构。"""
    e2ee_type: str  # "source_hello"
    version: str
    session_id: str
    source_did: str
    destination_did: str
    random: str
    supported_versions: List[str]
    cipher_suites: List[str]
    supported_groups: List[str]
    key_shares: List[KeyShare]
    verification_method: VerificationMethod
    proof: Proof


class DestinationHelloContent(BaseModel):
    """DestinationHello 消息 content 结构。"""
    e2ee_type: str  # "destination_hello"
    version: str
    session_id: str
    source_did: str
    destination_did: str
    random: str
    selected_version: str
    cipher_suite: str
    key_share: KeyShare
    verification_method: VerificationMethod
    proof: Proof


class FinishedContent(BaseModel):
    """Finished 消息 content 结构。"""
    e2ee_type: str  # "finished"
    session_id: str
    verify_data: EncryptedData


class EncryptedMessageContent(BaseModel):
    """加密消息 content 结构。"""
    secret_key_id: str
    original_type: str
    encrypted: EncryptedData


class ErrorContent(BaseModel):
    """错误通知 content 结构。"""
    error_code: str
    secret_key_id: str
