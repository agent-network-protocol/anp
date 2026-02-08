"""message_builder.py 单元测试。"""

import json
import unittest

from cryptography.hazmat.primitives.asymmetric import ec

from anp.e2e_encryption_v2.message_builder import (
    build_destination_hello,
    build_encrypted_message,
    build_error,
    build_finished,
    build_source_hello,
)
from anp.utils.crypto_tool import (
    decrypt_aes_gcm_sha256,
    generate_ec_key_pair,
    generate_random_hex,
    get_pem_from_private_key,
    verify_signature_for_json,
)


def _generate_did_keys():
    """生成真实的 secp256r1 DID 密钥对，供测试使用。"""
    priv, pub, pub_hex = generate_ec_key_pair(ec.SECP256R1())
    return priv, pub, pub_hex


class TestBuildSourceHello(unittest.TestCase):

    def setUp(self):
        self.priv, self.pub, self.pub_hex = _generate_did_keys()
        self.session_id = generate_random_hex(8)
        self.random_hex = generate_random_hex(32)
        # 生成 ECDHE 临时密钥
        _, _, eph_pub_hex = generate_ec_key_pair(ec.SECP256R1())
        self.key_shares = [
            {"group": "secp256r1", "expires": 86400, "key_exchange": eph_pub_hex}
        ]

    def test_contains_required_fields(self):
        content = build_source_hello(
            session_id=self.session_id,
            source_did="did:wba:example.com:user:alice",
            destination_did="did:wba:example.com:user:bob",
            random_hex=self.random_hex,
            did_private_key=self.priv,
            did_public_key_hex=self.pub_hex,
            key_shares=self.key_shares,
        )
        self.assertEqual(content["e2ee_type"], "source_hello")
        self.assertEqual(content["session_id"], self.session_id)
        self.assertEqual(content["random"], self.random_hex)
        self.assertIn("proof", content)
        self.assertIn("proof_value", content["proof"])
        self.assertIn("verification_method", content)
        self.assertIn("key_shares", content)

    def test_proof_is_verifiable(self):
        content = build_source_hello(
            session_id=self.session_id,
            source_did="did:wba:example.com:user:alice",
            destination_did="did:wba:example.com:user:bob",
            random_hex=self.random_hex,
            did_private_key=self.priv,
            did_public_key_hex=self.pub_hex,
            key_shares=self.key_shares,
        )
        # 验证签名
        proof_value = content["proof"]["proof_value"]
        stripped = json.loads(json.dumps(content))
        del stripped["proof"]["proof_value"]
        self.assertTrue(verify_signature_for_json(self.pub, stripped, proof_value))

    def test_proof_type_is_secp256r1(self):
        content = build_source_hello(
            session_id=self.session_id,
            source_did="did:wba:example.com:user:alice",
            destination_did="did:wba:example.com:user:bob",
            random_hex=self.random_hex,
            did_private_key=self.priv,
            did_public_key_hex=self.pub_hex,
            key_shares=self.key_shares,
        )
        self.assertEqual(content["proof"]["type"], "EcdsaSecp256r1Signature2019")


class TestBuildDestinationHello(unittest.TestCase):

    def setUp(self):
        self.priv, self.pub, self.pub_hex = _generate_did_keys()
        _, _, eph_pub_hex = generate_ec_key_pair(ec.SECP256R1())
        self.key_share = {
            "group": "secp256r1", "expires": 86400, "key_exchange": eph_pub_hex
        }

    def test_key_share_is_single_object(self):
        content = build_destination_hello(
            session_id="test_session",
            source_did="did:wba:example.com:user:bob",
            destination_did="did:wba:example.com:user:alice",
            random_hex=generate_random_hex(32),
            did_private_key=self.priv,
            did_public_key_hex=self.pub_hex,
            key_share=self.key_share,
            cipher_suite="TLS_AES_128_GCM_SHA256",
        )
        # key_share 应该是单个对象，不是数组
        self.assertIsInstance(content["key_share"], dict)
        self.assertEqual(content["e2ee_type"], "destination_hello")
        self.assertEqual(content["cipher_suite"], "TLS_AES_128_GCM_SHA256")

    def test_proof_is_verifiable(self):
        content = build_destination_hello(
            session_id="test_session",
            source_did="did:wba:example.com:user:bob",
            destination_did="did:wba:example.com:user:alice",
            random_hex=generate_random_hex(32),
            did_private_key=self.priv,
            did_public_key_hex=self.pub_hex,
            key_share=self.key_share,
            cipher_suite="TLS_AES_128_GCM_SHA256",
        )
        proof_value = content["proof"]["proof_value"]
        stripped = json.loads(json.dumps(content))
        del stripped["proof"]["proof_value"]
        self.assertTrue(verify_signature_for_json(self.pub, stripped, proof_value))


class TestBuildFinished(unittest.TestCase):

    def test_verify_data_decryptable(self):
        src_random = generate_random_hex(32)
        dst_random = generate_random_hex(32)
        # 需要一个 16 字节的密钥
        key = bytes.fromhex(generate_random_hex(16))

        content = build_finished(
            session_id="test_session",
            source_random=src_random,
            destination_random=dst_random,
            send_key=key,
        )
        self.assertEqual(content["e2ee_type"], "finished")
        self.assertIn("verify_data", content)

        # 解密 verify_data
        plaintext = decrypt_aes_gcm_sha256(content["verify_data"], key)
        data = json.loads(plaintext)
        self.assertIn("secretKeyId", data)
        self.assertEqual(len(data["secretKeyId"]), 16)


class TestBuildEncryptedMessage(unittest.TestCase):

    def test_encrypt_and_decrypt(self):
        key = bytes.fromhex(generate_random_hex(16))
        original = "Hello, E2EE!"
        content = build_encrypted_message(
            secret_key_id="0123456789abcdef",
            original_type="text",
            plaintext=original,
            key=key,
        )
        self.assertEqual(content["secret_key_id"], "0123456789abcdef")
        self.assertEqual(content["original_type"], "text")

        # 解密
        decrypted = decrypt_aes_gcm_sha256(content["encrypted"], key)
        self.assertEqual(decrypted, original)


class TestBuildError(unittest.TestCase):

    def test_error_format(self):
        content = build_error("key_expired", "0123456789abcdef")
        self.assertEqual(content["error_code"], "key_expired")
        self.assertEqual(content["secret_key_id"], "0123456789abcdef")


if __name__ == "__main__":
    unittest.main()
