"""7 种消息 content 构建函数。"""

import base64
import os
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from anp.e2e_encryption_hpke.hpke import hpke_seal
from anp.e2e_encryption_hpke.models import DEFAULT_EXPIRES, E2EE_VERSION, HPKE_SUITE
from anp.e2e_encryption_hpke.proof import generate_proof
from anp.utils.crypto_tool import generate_random_hex


def build_e2ee_init(
    session_id: str,
    sender_did: str,
    recipient_did: str,
    recipient_key_id: str,
    recipient_pk: X25519PublicKey,
    root_seed: bytes,
    signing_key: ec.EllipticCurvePrivateKey,
    verification_method: str,
    expires: int = DEFAULT_EXPIRES,
) -> Dict[str, Any]:
    """构建 e2ee_init 消息 content。

    Args:
        session_id: 会话 ID（32 hex 字符）。
        sender_did: 发送方 DID。
        recipient_did: 接收方 DID。
        recipient_key_id: 接收方 keyAgreement 的 id。
        recipient_pk: 接收方 X25519 公钥。
        root_seed: 32 字节随机种子。
        signing_key: 发送方 secp256r1 签名私钥。
        verification_method: 签名用的 verificationMethod id。
        expires: 会话有效期（秒）。

    Returns:
        含 proof 签名的 content dict。
    """
    aad = session_id.encode("utf-8")
    enc_bytes, ct_bytes = hpke_seal(recipient_pk, root_seed, aad=aad)

    content = {
        "e2ee_version": E2EE_VERSION,
        "session_id": session_id,
        "hpke_suite": HPKE_SUITE,
        "sender_did": sender_did,
        "recipient_did": recipient_did,
        "recipient_key_id": recipient_key_id,
        "enc": base64.b64encode(enc_bytes).decode("utf-8"),
        "encrypted_seed": base64.b64encode(ct_bytes).decode("utf-8"),
        "expires": expires,
    }

    return generate_proof(content, signing_key, verification_method)


def build_e2ee_msg(
    session_id: str,
    seq: int,
    original_type: str,
    ciphertext_b64: str,
) -> Dict[str, Any]:
    """构建 e2ee_msg 消息 content（无 proof）。"""
    return {
        "e2ee_version": E2EE_VERSION,
        "session_id": session_id,
        "seq": seq,
        "original_type": original_type,
        "ciphertext": ciphertext_b64,
    }


def build_e2ee_ack(
    session_id: str,
    sender_did: str,
    recipient_did: str,
    signing_key: ec.EllipticCurvePrivateKey,
    verification_method: str,
    expires: int = DEFAULT_EXPIRES,
) -> Dict[str, Any]:
    """构建 e2ee_ack 消息 content。"""
    content = {
        "e2ee_version": E2EE_VERSION,
        "session_id": session_id,
        "sender_did": sender_did,
        "recipient_did": recipient_did,
        "expires": expires,
    }
    return generate_proof(content, signing_key, verification_method)


def build_e2ee_rekey(
    session_id: str,
    sender_did: str,
    recipient_did: str,
    recipient_key_id: str,
    recipient_pk: X25519PublicKey,
    root_seed: bytes,
    signing_key: ec.EllipticCurvePrivateKey,
    verification_method: str,
    expires: int = DEFAULT_EXPIRES,
) -> Dict[str, Any]:
    """构建 e2ee_rekey 消息 content（结构同 e2ee_init）。"""
    return build_e2ee_init(
        session_id=session_id,
        sender_did=sender_did,
        recipient_did=recipient_did,
        recipient_key_id=recipient_key_id,
        recipient_pk=recipient_pk,
        root_seed=root_seed,
        signing_key=signing_key,
        verification_method=verification_method,
        expires=expires,
    )


def build_e2ee_error(
    error_code: str,
    session_id: Optional[str] = None,
    failed_msg_id: Optional[str] = None,
    failed_server_seq: Optional[int] = None,
    retry_hint: Optional[str] = None,
    required_e2ee_version: Optional[str] = None,
    message: Optional[str] = None,
) -> Dict[str, Any]:
    """构建 e2ee_error 消息 content。"""
    content: Dict[str, Any] = {
        "e2ee_version": E2EE_VERSION,
        "error_code": error_code,
    }
    if session_id is not None:
        content["session_id"] = session_id
    if failed_msg_id is not None:
        content["failed_msg_id"] = failed_msg_id
    if failed_server_seq is not None:
        content["failed_server_seq"] = failed_server_seq
    if retry_hint is not None:
        content["retry_hint"] = retry_hint
    if required_e2ee_version is not None:
        content["required_e2ee_version"] = required_e2ee_version
    if message is not None:
        content["message"] = message
    return content


def build_group_e2ee_key(
    group_did: str,
    epoch: int,
    sender_did: str,
    sender_key_id: str,
    recipient_key_id: str,
    recipient_pk: X25519PublicKey,
    sender_chain_key: bytes,
    signing_key: ec.EllipticCurvePrivateKey,
    verification_method: str,
    expires: int = DEFAULT_EXPIRES,
) -> Dict[str, Any]:
    """构建 group_e2ee_key 消息 content（Sender Key 分发）。

    HPKE AAD = `group_did:epoch:sender_key_id`
    """
    aad = f"{group_did}:{epoch}:{sender_key_id}".encode("utf-8")
    enc_bytes, ct_bytes = hpke_seal(recipient_pk, sender_chain_key, aad=aad)

    content = {
        "e2ee_version": E2EE_VERSION,
        "group_did": group_did,
        "epoch": epoch,
        "sender_did": sender_did,
        "sender_key_id": sender_key_id,
        "recipient_key_id": recipient_key_id,
        "hpke_suite": HPKE_SUITE,
        "enc": base64.b64encode(enc_bytes).decode("utf-8"),
        "encrypted_sender_key": base64.b64encode(ct_bytes).decode("utf-8"),
        "expires": expires,
    }

    return generate_proof(content, signing_key, verification_method)


def build_group_e2ee_msg(
    group_did: str,
    epoch: int,
    sender_did: str,
    sender_key_id: str,
    seq: int,
    original_type: str,
    ciphertext_b64: str,
) -> Dict[str, Any]:
    """构建 group_e2ee_msg 消息 content（无 proof）。"""
    return {
        "e2ee_version": E2EE_VERSION,
        "group_did": group_did,
        "epoch": epoch,
        "sender_did": sender_did,
        "sender_key_id": sender_key_id,
        "seq": seq,
        "original_type": original_type,
        "ciphertext": ciphertext_b64,
    }


def build_group_epoch_advance(
    group_did: str,
    new_epoch: int,
    reason: str,
    signing_key: ec.EllipticCurvePrivateKey,
    verification_method: str,
    members_added: Optional[List[str]] = None,
    members_removed: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """构建 group_epoch_advance 消息 content。"""
    content: Dict[str, Any] = {
        "e2ee_version": E2EE_VERSION,
        "group_did": group_did,
        "new_epoch": new_epoch,
        "reason": reason,
    }
    if members_added is not None:
        content["members_added"] = members_added
    if members_removed is not None:
        content["members_removed"] = members_removed

    return generate_proof(content, signing_key, verification_method)
