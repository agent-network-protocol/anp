"""链式 ratchet 密钥派生（私聊 + 群聊）。

私聊：root_seed → HKDFExpand → init_chain_key / resp_chain_key
       方向由 DID 字典序决定。
群聊：sender_chain_key + seq → gmsg/gck 派生。
"""

import hashlib
import hmac
from typing import Tuple

from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand


def derive_chain_keys(root_seed: bytes) -> Tuple[bytes, bytes]:
    """从 root_seed 派生两个方向的初始链密钥。

    Returns:
        (init_chain_key, resp_chain_key)
    """
    init_chain_key = HKDFExpand(
        algorithm=SHA256(),
        length=32,
        info=b"anp-e2ee-init",
    ).derive(root_seed)

    resp_chain_key = HKDFExpand(
        algorithm=SHA256(),
        length=32,
        info=b"anp-e2ee-resp",
    ).derive(root_seed)

    return init_chain_key, resp_chain_key


def determine_direction(local_did: str, peer_did: str) -> bool:
    """判断本端是否为 initiator（DID UTF-8 字节序较小方）。

    Returns:
        True 表示本端为 initiator。
    """
    return local_did.encode("utf-8") < peer_did.encode("utf-8")


def assign_chain_keys(
    init_ck: bytes, resp_ck: bytes, is_initiator: bool
) -> Tuple[bytes, bytes]:
    """根据角色分配 send/recv 链密钥。

    Args:
        init_ck: initiator 方向链密钥。
        resp_ck: responder 方向链密钥。
        is_initiator: 本端是否为 initiator。

    Returns:
        (send_chain_key, recv_chain_key)
    """
    if is_initiator:
        return init_ck, resp_ck
    else:
        return resp_ck, init_ck


def derive_message_key(
    chain_key: bytes, seq: int
) -> Tuple[bytes, bytes, bytes]:
    """私聊消息密钥派生。

    Args:
        chain_key: 当前链密钥。
        seq: 消息序号。

    Returns:
        (enc_key, nonce, new_chain_key)
        enc_key: 16 字节 AES-128 密钥。
        nonce: 12 字节 GCM nonce。
        new_chain_key: 更新后的链密钥。
    """
    seq_bytes = seq.to_bytes(8, "big")

    msg_key = hmac.new(chain_key, b"msg" + seq_bytes, hashlib.sha256).digest()
    new_chain_key = hmac.new(chain_key, b"ck", hashlib.sha256).digest()

    enc_key = hmac.new(msg_key, b"key", hashlib.sha256).digest()[:16]
    nonce = hmac.new(msg_key, b"nonce", hashlib.sha256).digest()[:12]

    return enc_key, nonce, new_chain_key


def derive_group_message_key(
    sender_chain_key: bytes, seq: int
) -> Tuple[bytes, bytes, bytes]:
    """群聊消息密钥派生。

    Args:
        sender_chain_key: 发送者链密钥。
        seq: 消息序号。

    Returns:
        (enc_key, nonce, new_chain_key)
    """
    seq_bytes = seq.to_bytes(8, "big")

    msg_key = hmac.new(sender_chain_key, b"gmsg" + seq_bytes, hashlib.sha256).digest()
    new_chain_key = hmac.new(sender_chain_key, b"gck", hashlib.sha256).digest()

    enc_key = hmac.new(msg_key, b"key", hashlib.sha256).digest()[:16]
    nonce = hmac.new(msg_key, b"nonce", hashlib.sha256).digest()[:12]

    return enc_key, nonce, new_chain_key
