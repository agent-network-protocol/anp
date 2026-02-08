"""models.py 单元测试。"""

import unittest

from pydantic import ValidationError

from anp.e2e_encryption_v2.models import (
    DestinationHelloContent,
    E2eeType,
    EncryptedData,
    EncryptedMessageContent,
    ErrorCode,
    ErrorContent,
    FinishedContent,
    KeyShare,
    MessageType,
    Proof,
    SourceHelloContent,
    VerificationMethod,
)


class TestEnums(unittest.TestCase):

    def test_message_type_values(self):
        self.assertEqual(MessageType.E2EE_HELLO.value, "e2ee_hello")
        self.assertEqual(MessageType.E2EE_FINISHED.value, "e2ee_finished")
        self.assertEqual(MessageType.E2EE.value, "e2ee")
        self.assertEqual(MessageType.E2EE_ERROR.value, "e2ee_error")

    def test_e2ee_type_values(self):
        self.assertEqual(E2eeType.SOURCE_HELLO.value, "source_hello")
        self.assertEqual(E2eeType.DESTINATION_HELLO.value, "destination_hello")

    def test_error_code_values(self):
        self.assertEqual(ErrorCode.KEY_EXPIRED.value, "key_expired")
        self.assertEqual(ErrorCode.KEY_NOT_FOUND.value, "key_not_found")


class TestKeyShare(unittest.TestCase):

    def test_valid_key_share(self):
        ks = KeyShare(group="secp256r1", expires=86400, key_exchange="04abcd")
        self.assertEqual(ks.group, "secp256r1")
        self.assertEqual(ks.expires, 86400)
        self.assertEqual(ks.key_exchange, "04abcd")

    def test_model_dump_snake_case(self):
        ks = KeyShare(group="secp256r1", expires=86400, key_exchange="04abcd")
        d = ks.model_dump()
        self.assertIn("key_exchange", d)
        self.assertNotIn("keyExchange", d)

    def test_missing_field_raises(self):
        with self.assertRaises(ValidationError):
            KeyShare(group="secp256r1", expires=86400)


class TestVerificationMethod(unittest.TestCase):

    def test_valid(self):
        vm = VerificationMethod(
            id="did:wba:example.com:user:alice#keys-1",
            type="EcdsaSecp256r1VerificationKey2019",
            public_key_hex="04abcdef",
        )
        d = vm.model_dump()
        self.assertIn("public_key_hex", d)
        self.assertNotIn("publicKeyHex", d)


class TestProof(unittest.TestCase):

    def test_proof_value_optional(self):
        p = Proof(
            type="EcdsaSecp256r1Signature2019",
            created="2024-05-27T10:51:55Z",
            verification_method="did:wba:example.com:user:alice#keys-1",
        )
        self.assertIsNone(p.proof_value)

    def test_proof_with_value(self):
        p = Proof(
            type="EcdsaSecp256r1Signature2019",
            created="2024-05-27T10:51:55Z",
            verification_method="did:wba:example.com:user:alice#keys-1",
            proof_value="abc123",
        )
        self.assertEqual(p.proof_value, "abc123")


class TestEncryptedData(unittest.TestCase):

    def test_valid(self):
        ed = EncryptedData(iv="aaa", tag="bbb", ciphertext="ccc")
        self.assertEqual(ed.iv, "aaa")


class TestSourceHelloContent(unittest.TestCase):

    def _make_source_hello_dict(self):
        return {
            "e2ee_type": "source_hello",
            "version": "1.0",
            "session_id": "abc123session456",
            "source_did": "did:wba:example.com:user:alice",
            "destination_did": "did:wba:example.com:user:bob",
            "random": "a" * 64,
            "supported_versions": ["1.0"],
            "cipher_suites": ["TLS_AES_128_GCM_SHA256"],
            "supported_groups": ["secp256r1"],
            "key_shares": [
                {"group": "secp256r1", "expires": 86400, "key_exchange": "04abcd"}
            ],
            "verification_method": {
                "id": "did:wba:example.com:user:alice#keys-1",
                "type": "EcdsaSecp256r1VerificationKey2019",
                "public_key_hex": "04abcd",
            },
            "proof": {
                "type": "EcdsaSecp256r1Signature2019",
                "created": "2024-05-27T10:51:55Z",
                "verification_method": "did:wba:example.com:user:alice#keys-1",
                "proof_value": "sig123",
            },
        }

    def test_model_validate(self):
        d = self._make_source_hello_dict()
        sh = SourceHelloContent.model_validate(d)
        self.assertEqual(sh.e2ee_type, "source_hello")
        self.assertEqual(sh.session_id, "abc123session456")
        self.assertEqual(len(sh.key_shares), 1)
        self.assertEqual(sh.key_shares[0].group, "secp256r1")

    def test_model_dump_snake_case(self):
        d = self._make_source_hello_dict()
        sh = SourceHelloContent.model_validate(d)
        dumped = sh.model_dump()
        self.assertIn("session_id", dumped)
        self.assertIn("source_did", dumped)
        self.assertIn("key_shares", dumped)
        self.assertNotIn("sessionId", dumped)

    def test_missing_required_field(self):
        d = self._make_source_hello_dict()
        del d["random"]
        with self.assertRaises(ValidationError):
            SourceHelloContent.model_validate(d)


class TestDestinationHelloContent(unittest.TestCase):

    def test_model_validate(self):
        d = {
            "e2ee_type": "destination_hello",
            "version": "1.0",
            "session_id": "abc123session456",
            "source_did": "did:wba:example.com:user:bob",
            "destination_did": "did:wba:example.com:user:alice",
            "random": "b" * 64,
            "selected_version": "1.0",
            "cipher_suite": "TLS_AES_128_GCM_SHA256",
            "key_share": {"group": "secp256r1", "expires": 86400, "key_exchange": "04ef"},
            "verification_method": {
                "id": "did:wba:example.com:user:bob#keys-1",
                "type": "EcdsaSecp256r1VerificationKey2019",
                "public_key_hex": "04ef",
            },
            "proof": {
                "type": "EcdsaSecp256r1Signature2019",
                "created": "2024-05-27T10:52:00Z",
                "verification_method": "did:wba:example.com:user:bob#keys-1",
                "proof_value": "sig456",
            },
        }
        dh = DestinationHelloContent.model_validate(d)
        self.assertEqual(dh.e2ee_type, "destination_hello")
        self.assertEqual(dh.cipher_suite, "TLS_AES_128_GCM_SHA256")
        self.assertEqual(dh.key_share.group, "secp256r1")


class TestFinishedContent(unittest.TestCase):

    def test_model_validate(self):
        d = {
            "e2ee_type": "finished",
            "session_id": "abc123",
            "verify_data": {"iv": "a", "tag": "b", "ciphertext": "c"},
        }
        fc = FinishedContent.model_validate(d)
        self.assertEqual(fc.e2ee_type, "finished")
        self.assertEqual(fc.verify_data.iv, "a")


class TestEncryptedMessageContent(unittest.TestCase):

    def test_model_validate(self):
        d = {
            "secret_key_id": "0123456789abcdef",
            "original_type": "text",
            "encrypted": {"iv": "a", "tag": "b", "ciphertext": "c"},
        }
        em = EncryptedMessageContent.model_validate(d)
        self.assertEqual(em.secret_key_id, "0123456789abcdef")
        self.assertEqual(em.original_type, "text")


class TestErrorContent(unittest.TestCase):

    def test_model_validate(self):
        d = {"error_code": "key_expired", "secret_key_id": "0123456789abcdef"}
        ec_obj = ErrorContent.model_validate(d)
        self.assertEqual(ec_obj.error_code, "key_expired")


if __name__ == "__main__":
    unittest.main()
