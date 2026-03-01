"""HPKE Base 模式 (RFC 9180) 单元测试。

测试 DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM 的
seal/open 往返正确性，使用真实密钥，不使用 mock。
"""

import unittest

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from anp.e2e_encryption_hpke.hpke import hpke_open, hpke_seal


class TestHpkeSealOpen(unittest.TestCase):
    """测试 hpke_seal / hpke_open 基本往返。"""

    def setUp(self):
        self.recipient_sk = X25519PrivateKey.generate()
        self.recipient_pk = self.recipient_sk.public_key()

    def test_basic_roundtrip(self):
        """生成 X25519 密钥对，seal 后 open 应还原明文。"""
        plaintext = b"Hello, HPKE!"
        enc, ciphertext = hpke_seal(self.recipient_pk, plaintext)
        recovered = hpke_open(self.recipient_sk, enc, ciphertext)
        self.assertEqual(recovered, plaintext)

    def test_with_aad(self):
        """使用不同 AAD 值进行 seal/open。"""
        plaintext = b"authenticated data test"
        aad = b"additional-authenticated-data-value"
        enc, ciphertext = hpke_seal(self.recipient_pk, plaintext, aad=aad)
        recovered = hpke_open(self.recipient_sk, enc, ciphertext, aad=aad)
        self.assertEqual(recovered, plaintext)

    def test_wrong_aad_fails(self):
        """AAD 不匹配时 open 应失败。"""
        plaintext = b"aad mismatch"
        enc, ciphertext = hpke_seal(self.recipient_pk, plaintext, aad=b"correct-aad")
        with self.assertRaises(InvalidTag):
            hpke_open(self.recipient_sk, enc, ciphertext, aad=b"wrong-aad")

    def test_with_info_parameter(self):
        """使用 info 参数进行密钥调度。"""
        plaintext = b"info parameter test"
        info = b"application-context-v1"
        enc, ciphertext = hpke_seal(self.recipient_pk, plaintext, info=info)
        recovered = hpke_open(self.recipient_sk, enc, ciphertext, info=info)
        self.assertEqual(recovered, plaintext)

    def test_wrong_info_fails(self):
        """info 不匹配时 open 应失败。"""
        plaintext = b"info mismatch"
        enc, ciphertext = hpke_seal(self.recipient_pk, plaintext, info=b"correct-info")
        with self.assertRaises(InvalidTag):
            hpke_open(self.recipient_sk, enc, ciphertext, info=b"wrong-info")

    def test_wrong_private_key_fails(self):
        """使用错误私钥解密应失败。"""
        plaintext = b"wrong key test"
        enc, ciphertext = hpke_seal(self.recipient_pk, plaintext)
        wrong_sk = X25519PrivateKey.generate()
        with self.assertRaises(InvalidTag):
            hpke_open(wrong_sk, enc, ciphertext)

    def test_empty_plaintext(self):
        """空明文 seal/open 往返。"""
        plaintext = b""
        enc, ciphertext = hpke_seal(self.recipient_pk, plaintext)
        recovered = hpke_open(self.recipient_sk, enc, ciphertext)
        self.assertEqual(recovered, plaintext)

    def test_large_plaintext(self):
        """1KB 明文 seal/open 往返。"""
        plaintext = b"A" * 1024
        enc, ciphertext = hpke_seal(self.recipient_pk, plaintext)
        recovered = hpke_open(self.recipient_sk, enc, ciphertext)
        self.assertEqual(recovered, plaintext)
        self.assertEqual(len(recovered), 1024)

    def test_ciphertext_differs_for_same_plaintext(self):
        """同一明文多次加密，密文应不同（因为使用临时密钥）。"""
        plaintext = b"determinism check"
        enc1, ct1 = hpke_seal(self.recipient_pk, plaintext)
        enc2, ct2 = hpke_seal(self.recipient_pk, plaintext)
        # 临时密钥不同，所以 enc 不同
        self.assertNotEqual(enc1, enc2)
        # 密文也不同
        self.assertNotEqual(ct1, ct2)
        # 但两者都能正确解密
        self.assertEqual(hpke_open(self.recipient_sk, enc1, ct1), plaintext)
        self.assertEqual(hpke_open(self.recipient_sk, enc2, ct2), plaintext)

    def test_with_aad_and_info_combined(self):
        """同时使用 AAD 和 info 参数。"""
        plaintext = b"combined parameters"
        aad = b"my-aad"
        info = b"my-info"
        enc, ciphertext = hpke_seal(
            self.recipient_pk, plaintext, aad=aad, info=info
        )
        recovered = hpke_open(
            self.recipient_sk, enc, ciphertext, aad=aad, info=info
        )
        self.assertEqual(recovered, plaintext)

    def test_enc_is_32_bytes(self):
        """enc（封装密钥）应为 32 字节。"""
        enc, _ = hpke_seal(self.recipient_pk, b"test")
        self.assertEqual(len(enc), 32)


if __name__ == "__main__":
    unittest.main()
