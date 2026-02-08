"""基于 HTTP RESTful 的端到端加密通信协议 - 消息构建。

[INPUT]: 会话参数（DID、密钥、random 等）
[OUTPUT]: 各类 E2EE 消息的 dict（可 json.dumps 后放入 HTTP content 字段）
[POS]: L2 构建层，负责生成协议消息

[PROTOCOL]:
1. 逻辑变更时同步更新此头部
2. 更新后检查所在文件夹的 CLAUDE.md
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives.asymmetric import ec

from anp.utils.crypto_tool import (
    encrypt_aes_gcm_sha256,
    generate_16_char_from_random_num,
    generate_signature_for_json,
)


def build_source_hello(
    session_id: str,
    source_did: str,
    destination_did: str,
    random_hex: str,
    did_private_key: ec.EllipticCurvePrivateKey,
    did_public_key_hex: str,
    key_shares: List[Dict[str, Any]],
    cipher_suites: Optional[List[str]] = None,
    supported_versions: Optional[List[str]] = None,
    supported_groups: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """构建 SourceHello 消息 content dict。

    Args:
        session_id: 16 位随机会话标识。
        source_did: 发起方 DID。
        destination_did: 目标方 DID。
        random_hex: 32 字节随机数的 hex 编码。
        did_private_key: DID 长期私钥，用于 proof 签名。
        did_public_key_hex: DID 长期公钥 hex。
        key_shares: ECDHE 临时公钥信息列表。
        cipher_suites: 支持的加密套件列表。
        supported_versions: 支持的协议版本列表。
        supported_groups: 支持的椭圆曲线组列表。

    Returns:
        完整的 SourceHello content dict，包含 proof 签名。
    """
    if cipher_suites is None:
        cipher_suites = ["TLS_AES_128_GCM_SHA256"]
    if supported_versions is None:
        supported_versions = ["1.0"]
    if supported_groups is None:
        supported_groups = ["secp256r1"]

    content = {
        "e2ee_type": "source_hello",
        "version": "1.0",
        "session_id": session_id,
        "source_did": source_did,
        "destination_did": destination_did,
        "random": random_hex,
        "supported_versions": supported_versions,
        "cipher_suites": cipher_suites,
        "supported_groups": supported_groups,
        "key_shares": key_shares,
        "verification_method": {
            "id": f"{source_did}#keys-1",
            "type": "EcdsaSecp256r1VerificationKey2019",
            "public_key_hex": did_public_key_hex,
        },
        "proof": {
            "type": "EcdsaSecp256r1Signature2019",
            "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "verification_method": f"{source_did}#keys-1",
        },
    }

    # 签名：对不含 proof_value 的完整消息签名
    proof_value = generate_signature_for_json(did_private_key, content)
    content["proof"]["proof_value"] = proof_value

    return content


def build_destination_hello(
    session_id: str,
    source_did: str,
    destination_did: str,
    random_hex: str,
    did_private_key: ec.EllipticCurvePrivateKey,
    did_public_key_hex: str,
    key_share: Dict[str, Any],
    cipher_suite: str,
    selected_version: str = "1.0",
) -> Dict[str, Any]:
    """构建 DestinationHello 消息 content dict。

    Args:
        session_id: 使用 SourceHello 中的 session_id。
        source_did: 响应方自己的 DID。
        destination_did: 发起方的 DID。
        random_hex: 响应方 32 字节随机数的 hex 编码。
        did_private_key: 响应方 DID 长期私钥。
        did_public_key_hex: 响应方 DID 长期公钥 hex。
        key_share: 单个密钥交换信息。
        cipher_suite: 选定的加密套件。
        selected_version: 选定的协议版本。

    Returns:
        完整的 DestinationHello content dict，包含 proof 签名。
    """
    content = {
        "e2ee_type": "destination_hello",
        "version": "1.0",
        "session_id": session_id,
        "source_did": source_did,
        "destination_did": destination_did,
        "random": random_hex,
        "selected_version": selected_version,
        "cipher_suite": cipher_suite,
        "key_share": key_share,
        "verification_method": {
            "id": f"{source_did}#keys-1",
            "type": "EcdsaSecp256r1VerificationKey2019",
            "public_key_hex": did_public_key_hex,
        },
        "proof": {
            "type": "EcdsaSecp256r1Signature2019",
            "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "verification_method": f"{source_did}#keys-1",
        },
    }

    proof_value = generate_signature_for_json(did_private_key, content)
    content["proof"]["proof_value"] = proof_value

    return content


def build_finished(
    session_id: str,
    source_random: str,
    destination_random: str,
    send_key: bytes,
) -> Dict[str, Any]:
    """构建 Finished 消息 content dict。

    Args:
        session_id: 会话标识。
        source_random: 发起方的 random hex。
        destination_random: 响应方的 random hex。
        send_key: 发送方的加密密钥。

    Returns:
        Finished content dict，verify_data 为加密后的 secretKeyId。
    """
    secret_key_id = generate_16_char_from_random_num(
        source_random, destination_random
    )

    # 协议文档 4.3 节：密文内部使用 camelCase
    plaintext = json.dumps({"secretKeyId": secret_key_id}).encode("utf-8")
    verify_data = encrypt_aes_gcm_sha256(plaintext, send_key)

    return {
        "e2ee_type": "finished",
        "session_id": session_id,
        "verify_data": verify_data,
    }


def build_encrypted_message(
    secret_key_id: str,
    original_type: str,
    plaintext: str,
    key: bytes,
) -> Dict[str, Any]:
    """构建加密消息 content dict。

    Args:
        secret_key_id: 密钥标识。
        original_type: 原始消息类型（text/image/file）。
        plaintext: 原始消息内容明文。
        key: 加密密钥。

    Returns:
        加密消息 content dict。
    """
    encrypted = encrypt_aes_gcm_sha256(plaintext.encode("utf-8"), key)

    return {
        "secret_key_id": secret_key_id,
        "original_type": original_type,
        "encrypted": encrypted,
    }


def build_error(
    error_code: str,
    secret_key_id: str,
) -> Dict[str, Any]:
    """构建错误通知 content dict。

    Args:
        error_code: 错误码（key_expired / key_not_found）。
        secret_key_id: 关联的密钥标识。

    Returns:
        错误通知 content dict。
    """
    return {
        "error_code": error_code,
        "secret_key_id": secret_key_id,
    }
