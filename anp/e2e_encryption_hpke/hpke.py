"""HPKE Base 模式封装（RFC 9180 手动实现）。

DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM
cryptography 库无内置 HPKE API，基于 X25519/HKDF/AESGCM 原语实现。
"""

import os

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

# ── RFC 9180 常量 ────────────────────────────────────────────────

_KEM_ID = (0x0020).to_bytes(2, "big")  # DHKEM(X25519, HKDF-SHA256)
_KDF_ID = (0x0001).to_bytes(2, "big")  # HKDF-SHA256
_AEAD_ID = (0x0001).to_bytes(2, "big")  # AES-128-GCM

_KEM_SUITE_ID = b"KEM" + _KEM_ID
_HPKE_SUITE_ID = b"HPKE" + _KEM_ID + _KDF_ID + _AEAD_ID

_N_SECRET = 32  # KEM shared secret length
_N_ENC = 32  # encapsulated key length
_N_PK = 32  # public key length
_NK = 16  # AES-128 key length
_NN = 12  # GCM nonce length


def _labeled_extract(
    salt: bytes, label: bytes, ikm: bytes, suite_id: bytes
) -> bytes:
    """LabeledExtract(salt, label, ikm) per RFC 9180 Section 4."""
    labeled_ikm = b"HPKE-v1" + suite_id + label + ikm
    return HKDF(
        algorithm=SHA256(),
        length=32,
        salt=salt if salt else None,
        info=labeled_ikm,
    ).derive(b"\x00" * 32 if not ikm else ikm)


def _labeled_expand(
    prk: bytes, label: bytes, info_data: bytes, length: int, suite_id: bytes
) -> bytes:
    """LabeledExpand(prk, label, info, L) per RFC 9180 Section 4."""
    labeled_info = (
        length.to_bytes(2, "big") + b"HPKE-v1" + suite_id + label + info_data
    )
    return HKDFExpand(
        algorithm=SHA256(),
        length=length,
        info=labeled_info,
    ).derive(prk)


def _extract_and_expand(dh: bytes, kem_context: bytes) -> bytes:
    """ExtractAndExpand per RFC 9180 Section 4.1."""
    suite_id = _KEM_SUITE_ID
    # labeled extract: salt=b"", label="shared_secret", ikm=dh
    prk = _labeled_extract(b"", b"shared_secret", dh, suite_id)
    return _labeled_expand(prk, b"shared_secret", kem_context, _N_SECRET, suite_id)


def _encap(
    recipient_pk: X25519PublicKey,
) -> tuple[bytes, bytes]:
    """Encap(pkR) -> (shared_secret, enc)."""
    ek_private = X25519PrivateKey.generate()
    ek_public = ek_private.public_key()

    dh = ek_private.exchange(recipient_pk)
    enc = ek_public.public_bytes_raw()
    pk_r = recipient_pk.public_bytes_raw()
    kem_context = enc + pk_r

    shared_secret = _extract_and_expand(dh, kem_context)
    return shared_secret, enc


def _decap(
    enc: bytes, recipient_sk: X25519PrivateKey
) -> bytes:
    """Decap(enc, skR) -> shared_secret."""
    ek_public = X25519PublicKey.from_public_bytes(enc)
    dh = recipient_sk.exchange(ek_public)
    pk_r = recipient_sk.public_key().public_bytes_raw()
    kem_context = enc + pk_r

    return _extract_and_expand(dh, kem_context)


def _key_schedule_s(
    shared_secret: bytes, info: bytes
) -> tuple[bytes, bytes]:
    """KeyScheduleS(mode_base, shared_secret, info) -> (key, base_nonce).

    mode_base = 0x00, psk/psk_id 为空。
    """
    mode = b"\x00"
    suite_id = _HPKE_SUITE_ID

    psk_id_hash = _labeled_extract(b"", b"psk_id_hash", b"", suite_id)
    info_hash = _labeled_extract(b"", b"info_hash", info, suite_id)
    ks_context = mode + psk_id_hash + info_hash

    secret = _labeled_extract(
        shared_secret, b"secret", b"", suite_id
    )
    key = _labeled_expand(secret, b"key", ks_context, _NK, suite_id)
    base_nonce = _labeled_expand(secret, b"base_nonce", ks_context, _NN, suite_id)
    return key, base_nonce


# ── 公开 API ─────────────────────────────────────────────────────

def hpke_seal(
    recipient_pk: X25519PublicKey,
    plaintext: bytes,
    aad: bytes = b"",
    info: bytes = b"",
) -> tuple[bytes, bytes]:
    """HPKE Base 模式 Seal。

    Args:
        recipient_pk: 接收方 X25519 公钥。
        plaintext: 待加密明文。
        aad: 附加认证数据。
        info: 密钥调度 info 参数。

    Returns:
        (enc, ciphertext) 元组。
        enc: 32 字节封装密钥（发送方临时公钥原始字节）。
        ciphertext: AEAD 密文 + GCM tag。
    """
    shared_secret, enc = _encap(recipient_pk)
    key, base_nonce = _key_schedule_s(shared_secret, info)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(base_nonce, plaintext, aad)
    return enc, ct


def hpke_open(
    recipient_sk: X25519PrivateKey,
    enc: bytes,
    ciphertext: bytes,
    aad: bytes = b"",
    info: bytes = b"",
) -> bytes:
    """HPKE Base 模式 Open。

    Args:
        recipient_sk: 接收方 X25519 私钥。
        enc: 封装密钥（发送方临时公钥原始字节）。
        ciphertext: AEAD 密文 + GCM tag。
        aad: 附加认证数据。
        info: 密钥调度 info 参数。

    Returns:
        解密后的明文。

    Raises:
        cryptography.exceptions.InvalidTag: 解密失败。
    """
    shared_secret = _decap(enc, recipient_sk)
    key, base_nonce = _key_schedule_s(shared_secret, info)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(base_nonce, ciphertext, aad)
