"""Tests for strict did:wba binding proof helpers."""

import copy
import unittest
from datetime import datetime, timezone

from cryptography.hazmat.primitives.serialization import load_pem_private_key

from anp.authentication.did_wba import create_did_wba_document
from anp.proof import generate_did_wba_binding, verify_did_wba_binding


class TestDidWbaBindingProof(unittest.TestCase):
    def setUp(self):
        self.agent_document, self.agent_keys = create_did_wba_document(
            "a.example",
            path_segments=["agents", "alice"],
            did_profile="e1",
        )
        self.private_key = load_pem_private_key(self.agent_keys["key-1"][0], password=None)
        self.binding = generate_did_wba_binding(
            agent_did=self.agent_document["id"],
            verification_method=f"{self.agent_document['id']}#key-1",
            leaf_signature_key_b64u="MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY",
            private_key=self.private_key,
            issued_at="2026-03-29T12:00:00Z",
            expires_at="2026-04-29T12:00:00Z",
            proof_created="2026-03-29T12:00:00Z",
        )

    def test_generate_and_verify_binding(self):
        self.assertEqual(self.binding["proof"]["type"], "DataIntegrityProof")
        self.assertEqual(self.binding["proof"]["cryptosuite"], "eddsa-jcs-2022")
        self.assertTrue(self.binding["proof"]["proofValue"].startswith("z"))
        self.assertTrue(
            verify_did_wba_binding(
                self.binding,
                self.agent_document,
                now=datetime(2026, 3, 30, tzinfo=timezone.utc),
                expected_credential_identity=self.agent_document["id"],
            )
        )

    def test_tampered_leaf_key_fails(self):
        tampered = copy.deepcopy(self.binding)
        tampered["leaf_signature_key_b64u"] = "YWJjZA"
        self.assertFalse(
            verify_did_wba_binding(
                tampered,
                self.agent_document,
                now=datetime(2026, 3, 30, tzinfo=timezone.utc),
            )
        )

    def test_wrong_issuer_document_fails(self):
        other_document, _ = create_did_wba_document(
            "a.example",
            path_segments=["agents", "bob"],
            did_profile="e1",
        )
        self.assertFalse(
            verify_did_wba_binding(
                self.binding,
                other_document,
                now=datetime(2026, 3, 30, tzinfo=timezone.utc),
            )
        )

    def test_expired_binding_fails(self):
        self.assertFalse(
            verify_did_wba_binding(
                self.binding,
                self.agent_document,
                now=datetime(2026, 5, 1, tzinfo=timezone.utc),
            )
        )
