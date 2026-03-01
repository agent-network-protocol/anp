"""Tests for E2EE DID document creation (secp256r1 + X25519 keys)."""

import unittest

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

from anp.authentication import (
    create_did_wba_document,
    create_did_wba_document_with_key_binding,
)


class TestE2eeDIDDocument(unittest.TestCase):
    """Test E2EE key generation in DID documents."""

    def test_default_creates_e2ee_keys(self):
        """Default should produce 3 verificationMethods."""
        doc, keys = create_did_wba_document("example.com")
        self.assertEqual(len(doc["verificationMethod"]), 3)
        self.assertIn("key-1", keys)
        self.assertIn("key-2", keys)
        self.assertIn("key-3", keys)

    def test_disable_e2ee_backward_compatible(self):
        """enable_e2ee=False should only produce key-1."""
        doc, keys = create_did_wba_document("example.com", enable_e2ee=False)
        self.assertEqual(len(doc["verificationMethod"]), 1)
        self.assertIn("key-1", keys)
        self.assertNotIn("key-2", keys)
        self.assertNotIn("key-3", keys)
        self.assertNotIn("keyAgreement", doc)

    def test_key_agreement_present(self):
        """keyAgreement should reference #key-3."""
        doc, _ = create_did_wba_document("example.com")
        self.assertIn("keyAgreement", doc)
        ka = doc["keyAgreement"]
        self.assertEqual(len(ka), 1)
        self.assertTrue(ka[0].endswith("#key-3"))

    def test_authentication_only_key_1(self):
        """authentication should only reference #key-1."""
        doc, _ = create_did_wba_document("example.com")
        auth = doc["authentication"]
        self.assertEqual(len(auth), 1)
        self.assertTrue(auth[0].endswith("#key-1"))

    def test_secp256r1_jwk_format(self):
        """key-2 should be EcdsaSecp256r1VerificationKey2019 with P-256 JWK."""
        doc, _ = create_did_wba_document("example.com")
        vm_key2 = doc["verificationMethod"][1]
        self.assertEqual(vm_key2["type"], "EcdsaSecp256r1VerificationKey2019")
        jwk = vm_key2["publicKeyJwk"]
        self.assertEqual(jwk["kty"], "EC")
        self.assertEqual(jwk["crv"], "P-256")
        self.assertIn("x", jwk)
        self.assertIn("y", jwk)

    def test_x25519_multibase_format(self):
        """key-3 should be X25519KeyAgreementKey2019 with z-prefix multibase."""
        doc, _ = create_did_wba_document("example.com")
        vm_key3 = doc["verificationMethod"][2]
        self.assertEqual(vm_key3["type"], "X25519KeyAgreementKey2019")
        multibase = vm_key3["publicKeyMultibase"]
        self.assertTrue(multibase.startswith("z"))

    def test_contexts_include_x25519(self):
        """@context should include x25519-2019/v1 URI."""
        doc, _ = create_did_wba_document("example.com")
        self.assertIn(
            "https://w3id.org/security/suites/x25519-2019/v1",
            doc["@context"],
        )

    def test_contexts_no_x25519_when_disabled(self):
        """@context should not include x25519 URI when e2ee is disabled."""
        doc, _ = create_did_wba_document("example.com", enable_e2ee=False)
        self.assertNotIn(
            "https://w3id.org/security/suites/x25519-2019/v1",
            doc["@context"],
        )

    def test_keys_pem_loadable(self):
        """All returned PEM keys should be loadable as correct types."""
        _, keys = create_did_wba_document("example.com")

        # key-1: secp256k1
        priv1 = load_pem_private_key(keys["key-1"][0], password=None)
        pub1 = load_pem_public_key(keys["key-1"][1])
        self.assertIsInstance(priv1, ec.EllipticCurvePrivateKey)
        self.assertIsInstance(pub1, ec.EllipticCurvePublicKey)

        # key-2: secp256r1
        priv2 = load_pem_private_key(keys["key-2"][0], password=None)
        pub2 = load_pem_public_key(keys["key-2"][1])
        self.assertIsInstance(priv2, ec.EllipticCurvePrivateKey)
        self.assertIsInstance(pub2, ec.EllipticCurvePublicKey)
        self.assertIsInstance(priv2.curve, ec.SECP256R1)

        # key-3: X25519
        priv3 = load_pem_private_key(keys["key-3"][0], password=None)
        pub3 = load_pem_public_key(keys["key-3"][1])
        self.assertIsInstance(priv3, X25519PrivateKey)
        self.assertIsInstance(pub3, X25519PublicKey)

    def test_proof_still_secp256k1(self):
        """proof type should remain EcdsaSecp256k1Signature2019."""
        doc, _ = create_did_wba_document("example.com")
        proof = doc.get("proof", {})
        self.assertEqual(proof.get("type"), "EcdsaSecp256k1Signature2019")
        self.assertTrue(proof.get("verificationMethod", "").endswith("#key-1"))

    def test_key_bound_with_e2ee(self):
        """key-binding + E2EE should produce 3 verificationMethods."""
        doc, keys = create_did_wba_document_with_key_binding("example.com")
        self.assertEqual(len(doc["verificationMethod"]), 3)
        self.assertIn("key-1", keys)
        self.assertIn("key-2", keys)
        self.assertIn("key-3", keys)
        self.assertIn(":k1_", doc["id"])
        self.assertIn("keyAgreement", doc)

    def test_key_bound_disable_e2ee(self):
        """key-binding with enable_e2ee=False should only have key-1."""
        doc, keys = create_did_wba_document_with_key_binding(
            "example.com", enable_e2ee=False
        )
        self.assertEqual(len(doc["verificationMethod"]), 1)
        self.assertNotIn("keyAgreement", doc)

    def test_x25519_key_works_with_hpke(self):
        """Generated X25519 key should be usable with E2eeHpkeSession."""
        doc, keys = create_did_wba_document(
            "example.com", path_segments=["user", "alice"]
        )
        did = doc["id"]

        # Load the X25519 private key from PEM
        x25519_priv = load_pem_private_key(keys["key-3"][0], password=None)
        self.assertIsInstance(x25519_priv, X25519PrivateKey)

        # Load the secp256r1 signing private key from PEM
        signing_priv = load_pem_private_key(keys["key-2"][0], password=None)
        self.assertIsInstance(signing_priv, ec.EllipticCurvePrivateKey)

        # Verify we can construct an E2eeHpkeSession
        from anp.e2e_encryption_hpke import E2eeHpkeSession
        session = E2eeHpkeSession(
            local_did=did,
            peer_did="did:wba:example.com:user:bob",
            local_x25519_private_key=x25519_priv,
            local_x25519_key_id=f"{did}#key-3",
            signing_private_key=signing_priv,
            signing_verification_method=f"{did}#key-2",
        )
        self.assertIsNotNone(session)

    def test_extract_keys_from_generated_doc(self):
        """Should be able to extract X25519/secp256r1 keys from generated doc."""
        from anp.e2e_encryption_hpke.key_pair import (
            extract_signing_public_key_from_did_document,
            extract_x25519_public_key_from_did_document,
        )

        doc, _ = create_did_wba_document("example.com")
        did = doc["id"]

        # Extract X25519 public key
        x25519_pk, key_id = extract_x25519_public_key_from_did_document(doc)
        self.assertIsInstance(x25519_pk, X25519PublicKey)
        self.assertEqual(key_id, f"{did}#key-3")

        # Extract secp256r1 signing key
        signing_pk = extract_signing_public_key_from_did_document(
            doc, f"{did}#key-2"
        )
        self.assertIsInstance(signing_pk, ec.EllipticCurvePublicKey)


if __name__ == "__main__":
    unittest.main()
