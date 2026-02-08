"""基于 HTTP RESTful 的端到端加密通信协议模块。

[INPUT]: 外部调用方导入本模块
[OUTPUT]: 核心类和函数的统一导出
[POS]: L2 入口层，模块公共 API

[PROTOCOL]:
1. 逻辑变更时同步更新此头部
2. 更新后检查所在文件夹的 CLAUDE.md
"""

from anp.e2e_encryption_v2.key_manager import E2eeKeyManager
from anp.e2e_encryption_v2.message_builder import (
    build_destination_hello,
    build_encrypted_message,
    build_error,
    build_finished,
    build_source_hello,
)
from anp.e2e_encryption_v2.message_parser import (
    decrypt_message,
    detect_message_type,
    parse_destination_hello,
    parse_encrypted_message,
    parse_error,
    parse_finished,
    parse_source_hello,
    verify_hello_proof,
)
from anp.e2e_encryption_v2.models import (
    DestinationHelloContent,
    E2eeType,
    EncryptedData,
    EncryptedMessageContent,
    ErrorCode,
    ErrorContent,
    FinishedContent,
    FinishedE2eeType,
    KeyShare,
    MessageType,
    Proof,
    SourceHelloContent,
    VerificationMethod,
)
from anp.e2e_encryption_v2.session import E2eeSession, SessionState

__all__ = [
    # session
    "E2eeSession",
    "SessionState",
    # key_manager
    "E2eeKeyManager",
    # models
    "MessageType",
    "E2eeType",
    "FinishedE2eeType",
    "ErrorCode",
    "KeyShare",
    "VerificationMethod",
    "Proof",
    "EncryptedData",
    "SourceHelloContent",
    "DestinationHelloContent",
    "FinishedContent",
    "EncryptedMessageContent",
    "ErrorContent",
    # message_builder
    "build_source_hello",
    "build_destination_hello",
    "build_finished",
    "build_encrypted_message",
    "build_error",
    # message_parser
    "detect_message_type",
    "parse_source_hello",
    "parse_destination_hello",
    "parse_finished",
    "parse_encrypted_message",
    "parse_error",
    "verify_hello_proof",
    "decrypt_message",
]
