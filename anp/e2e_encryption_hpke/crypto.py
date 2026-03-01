"""AES-128-GCM 加解密（确定性 nonce）。"""

import base64

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_aes_128_gcm(
    plaintext: bytes, key: bytes, nonce: bytes, aad: bytes = b""
) -> str:
    """AES-128-GCM 加密。

    Args:
        plaintext: 明文字节。
        key: 16 字节密钥。
        nonce: 12 字节 nonce。
        aad: 附加认证数据。

    Returns:
        Base64 编码的密文（含 GCM tag）。
    """
    aesgcm = AESGCM(key)
    ct_with_tag = aesgcm.encrypt(nonce, plaintext, aad)
    return base64.b64encode(ct_with_tag).decode("utf-8")


def decrypt_aes_128_gcm(
    ciphertext_b64: str, key: bytes, nonce: bytes, aad: bytes = b""
) -> bytes:
    """AES-128-GCM 解密。

    Args:
        ciphertext_b64: Base64 编码的密文（含 GCM tag）。
        key: 16 字节密钥。
        nonce: 12 字节 nonce。
        aad: 附加认证数据。

    Returns:
        解密后的明文字节。

    Raises:
        cryptography.exceptions.InvalidTag: 解密失败。
    """
    ct_with_tag = base64.b64decode(ciphertext_b64)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct_with_tag, aad)
