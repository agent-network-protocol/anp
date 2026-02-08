"""message_parser.py 单元测试。"""

import json
import unittest
from copy import deepcopy

from cryptography.hazmat.primitives.asymmetric import ec

from anp.e2e_encryption_v2.message_builder import (
    build_encrypted_message,
    build_source_hello,
)
from anp.e2e_encryption_v2.message_parser import (
    decrypt_message,
    detect_message_type,
    parse_encrypted_message,
    parse_error,
    parse_finished,
    parse_source_hello,
    verify_hello_proof,
)
from anp.utils.crypto_tool import (
    generate_ec_key_pair,
    generate_random_hex,
)


class TestDetectMessageType(unittest.TestCase):

    def test_source_hello(self):
        result = detect_message_type(
            "e2ee_hello", {"e2ee_type": "source_hello"}
        )
        self.assertEqual(result, "source_hello")

    def test_destination_hello(self):
        result = detect_message_type(
            "e2ee_hello", {"e2ee_type": "destination_hello"}
        )
        self.assertEqual(result, "destination_hello")

    def test_finished(self):
        result = detect_message_type("e2ee_finished", {})
        self.assertEqual(result, "finished")

    def test_encrypted(self):
        result = detect_message_type("e2ee", {})
        self.assertEqual(result, "encrypted")

    def test_error(self):
        result = detect_message_type("e2ee_error", {})
        self.assertEqual(result, "error")

    def test_unknown_type(self):
        result = detect_message_type("text", {})
        self.assertIsNone(result)

    def test_unknown_e2ee_type(self):
        result = detect_message_type("e2ee_hello", {"e2ee_type": "unknown"})
        self.assertIsNone(result)


class TestVerifyHelloProof(unittest.TestCase):

    def setUp(self):
        self.priv, self.pub, self.pub_hex = generate_ec_key_pair(ec.SECP256R1())
        _, _, eph_pub_hex = generate_ec_key_pair(ec.SECP256R1())
        self.content = build_source_hello(
            session_id=generate_random_hex(8),
            source_did="did:wba:example.com:user:alice",
            destination_did="did:wba:example.com:user:bob",
            random_hex=generate_random_hex(32),
            did_private_key=self.priv,
            did_public_key_hex=self.pub_hex,
            key_shares=[
                {"group": "secp256r1", "expires": 86400, "key_exchange": eph_pub_hex}
            ],
        )

    def test_valid_proof(self):
        is_valid, pub_key = verify_hello_proof(self.content)
        self.assertTrue(is_valid)
        self.assertIsNotNone(pub_key)

    def test_tampered_content_fails(self):
        tampered = deepcopy(self.content)
        tampered["random"] = "0" * 64
        is_valid, pub_key = verify_hello_proof(tampered)
        self.assertFalse(is_valid)
        self.assertIsNone(pub_key)

    def test_missing_proof_value_fails(self):
        broken = deepcopy(self.content)
        del broken["proof"]["proof_value"]
        is_valid, pub_key = verify_hello_proof(broken)
        self.assertFalse(is_valid)

    def test_missing_public_key_hex_fails(self):
        broken = deepcopy(self.content)
        del broken["verification_method"]["public_key_hex"]
        is_valid, pub_key = verify_hello_proof(broken)
        self.assertFalse(is_valid)


class TestParseSourceHello(unittest.TestCase):

    def test_parse(self):
        priv, pub, pub_hex = generate_ec_key_pair(ec.SECP256R1())
        _, _, eph_pub_hex = generate_ec_key_pair(ec.SECP256R1())
        content = build_source_hello(
            session_id="test123",
            source_did="did:wba:example.com:user:alice",
            destination_did="did:wba:example.com:user:bob",
            random_hex="a" * 64,
            did_private_key=priv,
            did_public_key_hex=pub_hex,
            key_shares=[
                {"group": "secp256r1", "expires": 86400, "key_exchange": eph_pub_hex}
            ],
        )
        parsed = parse_source_hello(content)
        self.assertEqual(parsed.e2ee_type, "source_hello")
        self.assertEqual(parsed.session_id, "test123")


class TestParseFinished(unittest.TestCase):

    def test_parse(self):
        d = {
            "e2ee_type": "finished",
            "session_id": "abc123",
            "verify_data": {"iv": "a", "tag": "b", "ciphertext": "c"},
        }
        parsed = parse_finished(d)
        self.assertEqual(parsed.session_id, "abc123")


class TestParseError(unittest.TestCase):

    def test_parse(self):
        d = {"error_code": "key_not_found", "secret_key_id": "abc"}
        parsed = parse_error(d)
        self.assertEqual(parsed.error_code, "key_not_found")


class TestDecryptMessage(unittest.TestCase):

    def test_decrypt(self):
        key = bytes.fromhex(generate_random_hex(16))
        original_text = "Secret message"
        content = build_encrypted_message(
            secret_key_id="key123",
            original_type="text",
            plaintext=original_text,
            key=key,
        )
        orig_type, plaintext = decrypt_message(content, key)
        self.assertEqual(orig_type, "text")
        self.assertEqual(plaintext, original_text)


if __name__ == "__main__":
    unittest.main()
