"""crypto.py 的单元测试：AES-128-GCM 加解密。"""

import base64
import os
import unittest

from cryptography.exceptions import InvalidTag

from anp.e2e_encryption_hpke.crypto import decrypt_aes_128_gcm, encrypt_aes_128_gcm


class TestAes128GcmRoundtrip(unittest.TestCase):
    """AES-128-GCM 加解密往返测试。"""

    def setUp(self):
        self.key = os.urandom(16)
        self.nonce = os.urandom(12)

    def test_encrypt_decrypt_roundtrip(self):
        """加密后解密应还原明文。"""
        plaintext = b"Hello, ANP E2EE!"
        ciphertext_b64 = encrypt_aes_128_gcm(plaintext, self.key, self.nonce)
        recovered = decrypt_aes_128_gcm(ciphertext_b64, self.key, self.nonce)

        self.assertEqual(recovered, plaintext)

    def test_roundtrip_with_aad(self):
        """带 AAD 的加解密应正确还原明文。"""
        plaintext = b"payload with aad"
        aad = b"additional-authenticated-data"

        ciphertext_b64 = encrypt_aes_128_gcm(
            plaintext, self.key, self.nonce, aad=aad
        )
        recovered = decrypt_aes_128_gcm(
            ciphertext_b64, self.key, self.nonce, aad=aad
        )

        self.assertEqual(recovered, plaintext)

    def test_empty_plaintext(self):
        """空明文加解密应正常工作。"""
        plaintext = b""
        ciphertext_b64 = encrypt_aes_128_gcm(plaintext, self.key, self.nonce)
        recovered = decrypt_aes_128_gcm(ciphertext_b64, self.key, self.nonce)

        self.assertEqual(recovered, plaintext)


class TestAes128GcmErrors(unittest.TestCase):
    """AES-128-GCM 错误场景测试。"""

    def setUp(self):
        self.key = os.urandom(16)
        self.nonce = os.urandom(12)
        self.plaintext = b"secret message"

    def test_wrong_key_fails(self):
        """使用错误密钥解密应抛出 InvalidTag。"""
        ciphertext_b64 = encrypt_aes_128_gcm(
            self.plaintext, self.key, self.nonce
        )
        wrong_key = os.urandom(16)

        with self.assertRaises(InvalidTag):
            decrypt_aes_128_gcm(ciphertext_b64, wrong_key, self.nonce)

    def test_wrong_aad_fails(self):
        """使用错误 AAD 解密应抛出 InvalidTag。"""
        aad = b"correct-aad"
        ciphertext_b64 = encrypt_aes_128_gcm(
            self.plaintext, self.key, self.nonce, aad=aad
        )

        with self.assertRaises(InvalidTag):
            decrypt_aes_128_gcm(
                ciphertext_b64, self.key, self.nonce, aad=b"wrong-aad"
            )


class TestAes128GcmOutputFormat(unittest.TestCase):
    """AES-128-GCM 输出格式测试。"""

    def test_ciphertext_is_valid_base64(self):
        """加密输出应为合法 Base64 编码字符串。"""
        key = os.urandom(16)
        nonce = os.urandom(12)
        plaintext = b"test base64 format"

        ciphertext_b64 = encrypt_aes_128_gcm(plaintext, key, nonce)

        # 应为 str 类型
        self.assertIsInstance(ciphertext_b64, str)

        # 应可被 Base64 解码，且解码后长度 = 明文长度 + 16 (GCM tag)
        raw = base64.b64decode(ciphertext_b64)
        self.assertEqual(len(raw), len(plaintext) + 16)


if __name__ == "__main__":
    unittest.main()
