"""X25519 密钥对管理和 DID 文档公钥提取单元测试。

使用真实密钥，不使用 mock。
"""

import base64
import unittest

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from anp.e2e_encryption_hpke.key_pair import (
    extract_signing_public_key_from_did_document,
    extract_x25519_public_key_from_did_document,
    generate_x25519_key_pair,
    private_key_from_bytes,
    private_key_to_bytes,
    public_key_from_bytes,
    public_key_from_multibase,
    public_key_to_bytes,
    public_key_to_multibase,
)


class TestGenerateX25519KeyPair(unittest.TestCase):
    """测试 generate_x25519_key_pair。"""

    def test_returns_valid_key_pair(self):
        """生成的密钥对类型正确，且公钥可由私钥派生。"""
        sk, pk = generate_x25519_key_pair()
        self.assertIsInstance(sk, X25519PrivateKey)
        self.assertIsInstance(pk, X25519PublicKey)
        # 公钥应与私钥派生的公钥一致
        self.assertEqual(
            pk.public_bytes_raw(),
            sk.public_key().public_bytes_raw(),
        )

    def test_different_key_pairs(self):
        """连续生成的密钥对应不同。"""
        sk1, pk1 = generate_x25519_key_pair()
        sk2, pk2 = generate_x25519_key_pair()
        self.assertNotEqual(
            public_key_to_bytes(pk1),
            public_key_to_bytes(pk2),
        )


class TestPublicKeyBytes(unittest.TestCase):
    """测试 public_key_to_bytes / public_key_from_bytes 往返。"""

    def test_roundtrip(self):
        sk, pk = generate_x25519_key_pair()
        raw = public_key_to_bytes(pk)
        self.assertIsInstance(raw, bytes)
        self.assertEqual(len(raw), 32)
        restored = public_key_from_bytes(raw)
        self.assertEqual(
            public_key_to_bytes(restored),
            raw,
        )


class TestPrivateKeyBytes(unittest.TestCase):
    """测试 private_key_to_bytes / private_key_from_bytes 往返。"""

    def test_roundtrip(self):
        sk, pk = generate_x25519_key_pair()
        raw = private_key_to_bytes(sk)
        self.assertIsInstance(raw, bytes)
        self.assertEqual(len(raw), 32)
        restored = private_key_from_bytes(raw)
        # 还原后的私钥派生出相同的公钥
        self.assertEqual(
            restored.public_key().public_bytes_raw(),
            pk.public_bytes_raw(),
        )


class TestPublicKeyMultibase(unittest.TestCase):
    """测试 public_key_to_multibase / public_key_from_multibase 往返（z + base58btc）。"""

    def test_roundtrip(self):
        sk, pk = generate_x25519_key_pair()
        multibase = public_key_to_multibase(pk)
        # 应以 'z' 前缀开头
        self.assertTrue(multibase.startswith("z"))
        restored = public_key_from_multibase(multibase)
        self.assertEqual(
            public_key_to_bytes(restored),
            public_key_to_bytes(pk),
        )

    def test_invalid_prefix_raises(self):
        """非 'z' 前缀应抛出 ValueError。"""
        with self.assertRaises(ValueError):
            public_key_from_multibase("m" + "A" * 43)


def _build_sample_did_document():
    """构建一个包含 X25519 keyAgreement 和 secp256r1 签名密钥的示例 DID 文档。

    返回 (did_doc, x25519_public_key, signing_private_key)。
    """
    # 生成 X25519 密钥对
    x25519_sk, x25519_pk = generate_x25519_key_pair()
    x25519_multibase = public_key_to_multibase(x25519_pk)

    # 生成 secp256r1 签名密钥对
    signing_key = ec.generate_private_key(ec.SECP256R1())
    numbers = signing_key.public_key().public_numbers()
    x = (
        base64.urlsafe_b64encode(numbers.x.to_bytes(32, "big"))
        .rstrip(b"=")
        .decode()
    )
    y = (
        base64.urlsafe_b64encode(numbers.y.to_bytes(32, "big"))
        .rstrip(b"=")
        .decode()
    )

    did_doc = {
        "id": "did:wba:example.com:user:alice",
        "verificationMethod": [
            {
                "id": "did:wba:example.com:user:alice#keys-1",
                "type": "EcdsaSecp256r1VerificationKey2019",
                "controller": "did:wba:example.com:user:alice",
                "publicKeyJwk": {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": x,
                    "y": y,
                },
            },
            {
                "id": "did:wba:example.com:user:alice#key-x25519-1",
                "type": "X25519KeyAgreementKey2019",
                "controller": "did:wba:example.com:user:alice",
                "publicKeyMultibase": x25519_multibase,
            },
        ],
        "authentication": ["did:wba:example.com:user:alice#keys-1"],
        "keyAgreement": ["did:wba:example.com:user:alice#key-x25519-1"],
    }
    return did_doc, x25519_pk, signing_key


class TestExtractX25519PublicKey(unittest.TestCase):
    """测试 extract_x25519_public_key_from_did_document。"""

    def setUp(self):
        self.did_doc, self.x25519_pk, self.signing_key = (
            _build_sample_did_document()
        )

    def test_extract_default(self):
        """不指定 key_id 时，应返回第一个 X25519 keyAgreement 条目。"""
        pk, key_id = extract_x25519_public_key_from_did_document(self.did_doc)
        self.assertEqual(
            public_key_to_bytes(pk),
            public_key_to_bytes(self.x25519_pk),
        )
        self.assertEqual(
            key_id, "did:wba:example.com:user:alice#key-x25519-1"
        )

    def test_extract_with_key_id(self):
        """指定 key_id 时，应返回对应的条目。"""
        target_id = "did:wba:example.com:user:alice#key-x25519-1"
        pk, key_id = extract_x25519_public_key_from_did_document(
            self.did_doc, key_id=target_id
        )
        self.assertEqual(
            public_key_to_bytes(pk),
            public_key_to_bytes(self.x25519_pk),
        )
        self.assertEqual(key_id, target_id)

    def test_extract_with_wrong_key_id_raises(self):
        """指定不存在的 key_id 应抛出 ValueError。"""
        with self.assertRaises(ValueError):
            extract_x25519_public_key_from_did_document(
                self.did_doc, key_id="did:wba:example.com:user:alice#nonexistent"
            )

    def test_no_key_agreement_raises(self):
        """DID 文档没有 keyAgreement 时应抛出 ValueError。"""
        doc_no_ka = {
            "id": "did:wba:example.com:user:bob",
            "verificationMethod": [],
        }
        with self.assertRaises(ValueError) as cm:
            extract_x25519_public_key_from_did_document(doc_no_ka)
        self.assertIn("X25519KeyAgreementKey2019", str(cm.exception))

    def test_empty_key_agreement_raises(self):
        """keyAgreement 列表为空时应抛出 ValueError。"""
        doc_empty_ka = {
            "id": "did:wba:example.com:user:bob",
            "verificationMethod": [],
            "keyAgreement": [],
        }
        with self.assertRaises(ValueError):
            extract_x25519_public_key_from_did_document(doc_empty_ka)

    def test_key_agreement_with_non_x25519_type_raises(self):
        """keyAgreement 中没有 X25519KeyAgreementKey2019 类型时应抛出 ValueError。"""
        doc = {
            "id": "did:wba:example.com:user:bob",
            "verificationMethod": [
                {
                    "id": "did:wba:example.com:user:bob#keys-1",
                    "type": "SomeOtherKeyType",
                    "controller": "did:wba:example.com:user:bob",
                    "publicKeyMultibase": "zFakeKey",
                }
            ],
            "keyAgreement": ["did:wba:example.com:user:bob#keys-1"],
        }
        with self.assertRaises(ValueError):
            extract_x25519_public_key_from_did_document(doc)


class TestExtractSigningPublicKey(unittest.TestCase):
    """测试 extract_signing_public_key_from_did_document（publicKeyJwk）。"""

    def setUp(self):
        self.did_doc, self.x25519_pk, self.signing_key = (
            _build_sample_did_document()
        )

    def test_extract_signing_key_jwk(self):
        """从 publicKeyJwk 提取 secp256r1 签名公钥。"""
        vm_id = "did:wba:example.com:user:alice#keys-1"
        extracted_pk = extract_signing_public_key_from_did_document(
            self.did_doc, vm_id
        )
        self.assertIsInstance(extracted_pk, ec.EllipticCurvePublicKey)
        # 验证提取的公钥与原始公钥数值一致
        original_numbers = self.signing_key.public_key().public_numbers()
        extracted_numbers = extracted_pk.public_numbers()
        self.assertEqual(extracted_numbers.x, original_numbers.x)
        self.assertEqual(extracted_numbers.y, original_numbers.y)

    def test_extract_nonexistent_vm_raises(self):
        """指定不存在的 verificationMethod id 应抛出 ValueError。"""
        with self.assertRaises(ValueError):
            extract_signing_public_key_from_did_document(
                self.did_doc, "did:wba:example.com:user:alice#nonexistent"
            )

    def test_vm_without_key_material_raises(self):
        """verificationMethod 没有 publicKeyJwk 或 publicKeyHex 时应抛出 ValueError。"""
        doc = {
            "id": "did:wba:example.com:user:carol",
            "verificationMethod": [
                {
                    "id": "did:wba:example.com:user:carol#keys-1",
                    "type": "EcdsaSecp256r1VerificationKey2019",
                    "controller": "did:wba:example.com:user:carol",
                    # 没有 publicKeyJwk 或 publicKeyHex
                }
            ],
        }
        with self.assertRaises(ValueError):
            extract_signing_public_key_from_did_document(
                doc, "did:wba:example.com:user:carol#keys-1"
            )

    def test_wrong_vm_type_raises(self):
        """传入 secp256k1 类型的 VM ID 应抛出 ValueError（期望 secp256r1）。"""
        signing_key = ec.generate_private_key(ec.SECP256K1())
        numbers = signing_key.public_key().public_numbers()
        x = (
            base64.urlsafe_b64encode(numbers.x.to_bytes(32, "big"))
            .rstrip(b"=")
            .decode()
        )
        y = (
            base64.urlsafe_b64encode(numbers.y.to_bytes(32, "big"))
            .rstrip(b"=")
            .decode()
        )
        doc = {
            "id": "did:wba:example.com:user:dave",
            "verificationMethod": [
                {
                    "id": "did:wba:example.com:user:dave#key-1",
                    "type": "EcdsaSecp256k1VerificationKey2019",
                    "controller": "did:wba:example.com:user:dave",
                    "publicKeyJwk": {
                        "kty": "EC",
                        "crv": "secp256k1",
                        "x": x,
                        "y": y,
                    },
                }
            ],
        }
        with self.assertRaises(ValueError) as cm:
            extract_signing_public_key_from_did_document(
                doc, "did:wba:example.com:user:dave#key-1"
            )
        self.assertIn("EcdsaSecp256r1VerificationKey2019", str(cm.exception))
        self.assertIn("EcdsaSecp256k1VerificationKey2019", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
