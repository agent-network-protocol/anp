"""基于 HTTP RESTful 的端到端加密通信协议 - 消息解析与验证。

[INPUT]: HTTP 消息的 type 字段和 content dict
[OUTPUT]: 解析后的 Pydantic 模型 / 验证结果 / 解密明文
[POS]: L2 解析层，负责解析、验证协议消息

[PROTOCOL]:
1. 逻辑变更时同步更新此头部
2. 更新后检查所在文件夹的 CLAUDE.md
"""

import logging
from copy import deepcopy
from datetime import datetime, timezone
from typing import Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import ec

from anp.e2e_encryption_v2.models import (
    DestinationHelloContent,
    EncryptedMessageContent,
    ErrorContent,
    FinishedContent,
    MessageType,
    SourceHelloContent,
)
from anp.utils.crypto_tool import (
    decrypt_aes_gcm_sha256,
    get_public_key_from_hex,
    verify_signature_for_json,
)


def detect_message_type(type_field: str, content: dict) -> Optional[str]:
    """根据 HTTP 消息的 type 字段和 content 中的 e2ee_type 判断具体消息类型。

    Args:
        type_field: HTTP 消息的 type 字段值。
        content: 解析后的 content dict。

    Returns:
        具体消息类型字符串：source_hello / destination_hello / finished /
        encrypted / error，或 None（无法识别）。
    """
    if type_field == MessageType.E2EE_HELLO:
        e2ee_type = content.get("e2ee_type")
        if e2ee_type == "source_hello":
            return "source_hello"
        elif e2ee_type == "destination_hello":
            return "destination_hello"
        return None
    elif type_field == MessageType.E2EE_FINISHED:
        return "finished"
    elif type_field == MessageType.E2EE:
        return "encrypted"
    elif type_field == MessageType.E2EE_ERROR:
        return "error"
    return None


def parse_source_hello(content: dict) -> SourceHelloContent:
    """解析 SourceHello content dict 为模型对象。"""
    return SourceHelloContent.model_validate(content)


def parse_destination_hello(content: dict) -> DestinationHelloContent:
    """解析 DestinationHello content dict 为模型对象。"""
    return DestinationHelloContent.model_validate(content)


def parse_finished(content: dict) -> FinishedContent:
    """解析 Finished content dict 为模型对象。"""
    return FinishedContent.model_validate(content)


def parse_encrypted_message(content: dict) -> EncryptedMessageContent:
    """解析加密消息 content dict 为模型对象。"""
    return EncryptedMessageContent.model_validate(content)


def parse_error(content: dict) -> ErrorContent:
    """解析错误通知 content dict 为模型对象。"""
    return ErrorContent.model_validate(content)


def verify_hello_proof(
    content: dict, max_time_drift: int = 30
) -> Tuple[bool, Optional[ec.EllipticCurvePublicKey]]:
    """验证 Hello 消息（SourceHello / DestinationHello）的 proof 签名。

    Args:
        content: Hello 消息的 content dict。
        max_time_drift: 允许的最大时间偏差（秒）。

    Returns:
        (is_valid, public_key) 元组。验证通过返回 (True, 公钥对象)，
        失败返回 (False, None)。
    """
    try:
        # 1. 提取公钥
        vm = content.get("verification_method", {})
        public_key_hex = vm.get("public_key_hex")
        if not public_key_hex:
            logging.error("verification_method 中缺少 public_key_hex")
            return False, None

        public_key = get_public_key_from_hex(public_key_hex, ec.SECP256R1())

        # 2. 验证签名：复制消息，删除 proof_value
        proof = content.get("proof", {})
        proof_value = proof.get("proof_value")
        if not proof_value:
            logging.error("proof 中缺少 proof_value")
            return False, None

        stripped = deepcopy(content)
        del stripped["proof"]["proof_value"]

        is_valid = verify_signature_for_json(public_key, stripped, proof_value)
        if not is_valid:
            logging.error("proof 签名验证失败")
            return False, None

        # 3. 检查时间戳偏差
        created_str = proof.get("created")
        if created_str:
            created_time = datetime.strptime(
                created_str, "%Y-%m-%dT%H:%M:%SZ"
            ).replace(tzinfo=timezone.utc)
            current_time = datetime.now(timezone.utc)
            drift = abs((current_time - created_time).total_seconds())
            if drift > max_time_drift:
                logging.error(
                    "proof 时间戳偏差 %.1f 秒，超过阈值 %d 秒",
                    drift,
                    max_time_drift,
                )
                return False, None

        return True, public_key

    except Exception as e:
        logging.error("验证 hello proof 失败: %s", e)
        return False, None


def decrypt_message(
    encrypted_content: dict, key: bytes
) -> Tuple[str, str]:
    """解密加密消息。

    Args:
        encrypted_content: 加密消息的 content dict（包含 secret_key_id、
            original_type、encrypted）。
        key: 解密密钥。

    Returns:
        (original_type, plaintext) 元组。
    """
    original_type = encrypted_content["original_type"]
    encrypted_data = encrypted_content["encrypted"]
    plaintext = decrypt_aes_gcm_sha256(encrypted_data, key)
    return original_type, plaintext
