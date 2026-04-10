"""Tests for E2EE DID document creation across DID profiles."""

import unittest
import warnings

from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)

from anp.authentication import (
    ANP_MESSAGE_SERVICE_TYPE,
    build_agent_message_service,
    build_group_message_service,
    create_did_wba_document,
    create_did_wba_document_with_key_binding,
)


class TestE2eeDIDDocument(unittest.TestCase):
    """Test E2EE key generation in DID documents."""

    def test_default_creates_e2ee_keys_for_e1(self):
        """The default e1 profile should produce 3 verification methods."""
        doc, keys = create_did_wba_document(
            "example.com",
            path_segments=["user", "alice"],
        )
        self.assertEqual(len(doc["verificationMethod"]), 3)
        self.assertIn(":e1_", doc["id"])
        self.assertEqual(doc["verificationMethod"][0]["type"], "Multikey")
        self.assertIn("key-1", keys)
        self.assertIn("key-2", keys)
        self.assertIn("key-3", keys)

    def test_disable_e2ee_preserves_binding_key_only(self):
        """Disabling E2EE should keep only the binding key."""
        doc, keys = create_did_wba_document(
            "example.com",
            path_segments=["user", "alice"],
            enable_e2ee=False,
        )
        self.assertEqual(len(doc["verificationMethod"]), 1)
        self.assertEqual(set(keys.keys()), {"key-1"})
        self.assertNotIn("keyAgreement", doc)

    def test_key_agreement_present(self):
        """keyAgreement should reference #key-3."""
        doc, _ = create_did_wba_document(
            "example.com",
            path_segments=["user", "alice"],
        )
        self.assertEqual(doc["keyAgreement"], [f"{doc['id']}#key-3"])

    def test_authentication_uses_binding_key(self):
        """authentication should only reference #key-1."""
        doc, _ = create_did_wba_document(
            "example.com",
            path_segments=["user", "alice"],
        )
        self.assertEqual(doc["authentication"], [f"{doc['id']}#key-1"])
        self.assertEqual(doc["assertionMethod"], [f"{doc['id']}#key-1"])

    def test_secp256r1_jwk_format(self):
        """key-2 should remain EcdsaSecp256r1VerificationKey2019."""
        doc, _ = create_did_wba_document(
            "example.com",
            path_segments=["user", "alice"],
        )
        vm_key2 = doc["verificationMethod"][1]
        self.assertEqual(vm_key2["type"], "EcdsaSecp256r1VerificationKey2019")
        jwk = vm_key2["publicKeyJwk"]
        self.assertEqual(jwk["kty"], "EC")
        self.assertEqual(jwk["crv"], "P-256")
        self.assertIn("x", jwk)
        self.assertIn("y", jwk)

    def test_x25519_multibase_format(self):
        """key-3 should remain an X25519 multibase entry."""
        doc, _ = create_did_wba_document(
            "example.com",
            path_segments=["user", "alice"],
        )
        vm_key3 = doc["verificationMethod"][2]
        self.assertEqual(vm_key3["type"], "X25519KeyAgreementKey2019")
        self.assertTrue(vm_key3["publicKeyMultibase"].startswith("z"))

    def test_contexts_include_x25519(self):
        """The x25519 context should be included when E2EE is enabled."""
        doc, _ = create_did_wba_document(
            "example.com",
            path_segments=["user", "alice"],
        )
        self.assertIn(
            "https://w3id.org/security/suites/x25519-2019/v1",
            doc["@context"],
        )

    def test_contexts_no_x25519_when_disabled(self):
        """The x25519 context should be absent when E2EE is disabled."""
        doc, _ = create_did_wba_document(
            "example.com",
            path_segments=["user", "alice"],
            enable_e2ee=False,
        )
        self.assertNotIn(
            "https://w3id.org/security/suites/x25519-2019/v1",
            doc["@context"],
        )

    def test_keys_pem_loadable(self):
        """All generated PEM keys should be loadable."""
        _, keys = create_did_wba_document(
            "example.com",
            path_segments=["user", "alice"],
        )

        priv1 = load_pem_private_key(keys["key-1"][0], password=None)
        pub1 = load_pem_public_key(keys["key-1"][1])
        self.assertIsInstance(priv1, ed25519.Ed25519PrivateKey)
        self.assertIsInstance(pub1, ed25519.Ed25519PublicKey)

        priv2 = load_pem_private_key(keys["key-2"][0], password=None)
        pub2 = load_pem_public_key(keys["key-2"][1])
        self.assertIsInstance(priv2, ec.EllipticCurvePrivateKey)
        self.assertIsInstance(pub2, ec.EllipticCurvePublicKey)
        self.assertIsInstance(priv2.curve, ec.SECP256R1)

        priv3 = load_pem_private_key(keys["key-3"][0], password=None)
        pub3 = load_pem_public_key(keys["key-3"][1])
        self.assertIsInstance(priv3, X25519PrivateKey)
        self.assertIsInstance(pub3, X25519PublicKey)

    def test_default_proof_is_ed25519_data_integrity(self):
        """The default e1 profile should use DataIntegrityProof with EdDSA."""
        doc, _ = create_did_wba_document(
            "example.com",
            path_segments=["user", "alice"],
        )
        proof = doc["proof"]
        self.assertEqual(proof["type"], "DataIntegrityProof")
        self.assertEqual(proof["cryptosuite"], "eddsa-jcs-2022")
        self.assertTrue(proof["verificationMethod"].endswith("#key-1"))

    def test_k1_wrapper_with_e2ee(self):
        """The k1 compatibility wrapper should still support E2EE keys."""
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", DeprecationWarning)
            doc, keys = create_did_wba_document_with_key_binding(
                "example.com",
                path_prefix=["user", "alice"],
            )
        self.assertTrue(caught)
        self.assertIn("deprecated", str(caught[0].message).lower())
        self.assertEqual(len(doc["verificationMethod"]), 3)
        self.assertIn(":k1_", doc["id"])
        self.assertIn("key-2", keys)
        self.assertIn("key-3", keys)

    def test_k1_wrapper_disable_e2ee(self):
        """The k1 compatibility wrapper should still support disabling E2EE."""
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", DeprecationWarning)
            doc, keys = create_did_wba_document_with_key_binding(
                "example.com",
                path_prefix=["user", "alice"],
                enable_e2ee=False,
            )
        self.assertTrue(caught)
        self.assertIn("deprecated", str(caught[0].message).lower())
        self.assertEqual(len(doc["verificationMethod"]), 1)
        self.assertEqual(set(keys.keys()), {"key-1"})
        self.assertNotIn("keyAgreement", doc)

    def test_build_agent_message_service_defaults(self):
        """Agent helper should emit ANPMessageService with agent profiles."""
        service = build_agent_message_service(
            did="did:wba:example.com:user:alice",
            service_endpoint="https://example.com/rpc",
        )
        self.assertEqual(service["type"], ANP_MESSAGE_SERVICE_TYPE)
        self.assertEqual(service["id"], "did:wba:example.com:user:alice#message")
        self.assertEqual(
            service["profiles"],
            [
                "anp.core.binding.v1",
                "anp.direct.base.v1",
                "anp.direct.e2ee.v1",
            ],
        )
        self.assertEqual(
            service["securityProfiles"],
            ["transport-protected", "direct-e2ee"],
        )

    def test_build_group_message_service_defaults(self):
        """Group helper should emit ANPMessageService with group profiles."""
        service = build_group_message_service(
            did="did:wba:example.com:groups:test",
            service_endpoint="https://example.com/rpc",
        )
        self.assertEqual(service["type"], ANP_MESSAGE_SERVICE_TYPE)
        self.assertEqual(service["id"], "did:wba:example.com:groups:test#message")
        self.assertEqual(
            service["profiles"],
            [
                "anp.core.binding.v1",
                "anp.group.base.v1",
                "anp.group.e2ee.v1",
            ],
        )
        self.assertEqual(
            service["securityProfiles"],
            ["transport-protected", "group-e2ee"],
        )


if __name__ == "__main__":
    unittest.main()
