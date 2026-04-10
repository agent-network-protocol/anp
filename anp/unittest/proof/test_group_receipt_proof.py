"""Tests for strict group receipt proof helpers."""

import copy
import unittest

from cryptography.hazmat.primitives.serialization import load_pem_private_key

from anp.authentication.did_wba import create_did_wba_document
from anp.proof import generate_group_receipt_proof, verify_group_receipt_proof


class TestGroupReceiptProof(unittest.TestCase):
    def setUp(self):
        self.group_document, self.group_keys = create_did_wba_document(
            "groups.example",
            path_segments=["team", "dev"],
            did_profile="e1",
        )
        self.private_key = load_pem_private_key(self.group_keys["key-1"][0], password=None)
        self.receipt = {
            "receipt_type": "anp.group_receipt.v1",
            "group_did": self.group_document["id"],
            "group_state_version": "43",
            "group_event_seq": "128",
            "subject_method": "group.send",
            "operation_id": "op-group-send-001",
            "message_id": "msg-group-send-001",
            "actor_did": "did:wba:a.example:agents:alice:e1_alice",
            "accepted_at": "2026-03-29T15:10:01Z",
            "payload_digest": "sha-256=:stub:",
        }

    def test_generate_and_verify_group_receipt_proof(self):
        signed = generate_group_receipt_proof(
            self.receipt,
            self.private_key,
            f"{self.group_document['id']}#key-1",
            created="2026-03-29T15:10:01Z",
        )
        self.assertIn("proof", signed)
        self.assertEqual(signed["proof"]["type"], "DataIntegrityProof")
        self.assertEqual(signed["proof"]["cryptosuite"], "eddsa-jcs-2022")
        self.assertEqual(signed["proof"]["proofPurpose"], "assertionMethod")
        self.assertTrue(signed["proof"]["proofValue"].startswith("z"))
        self.assertTrue(verify_group_receipt_proof(signed, self.group_document))

    def test_tampered_receipt_fails_verification(self):
        signed = generate_group_receipt_proof(
            self.receipt,
            self.private_key,
            f"{self.group_document['id']}#key-1",
        )
        tampered = copy.deepcopy(signed)
        tampered["group_event_seq"] = "129"
        self.assertFalse(verify_group_receipt_proof(tampered, self.group_document))

    def test_wrong_issuer_document_fails_verification(self):
        signed = generate_group_receipt_proof(
            self.receipt,
            self.private_key,
            f"{self.group_document['id']}#key-1",
        )
        other_document, _ = create_did_wba_document(
            "groups.example",
            path_segments=["team", "ops"],
            did_profile="e1",
        )
        self.assertFalse(verify_group_receipt_proof(signed, other_document))

    def test_missing_required_field_raises(self):
        invalid_receipt = dict(self.receipt)
        invalid_receipt.pop("payload_digest")
        with self.assertRaises(ValueError):
            generate_group_receipt_proof(
                invalid_receipt,
                self.private_key,
                f"{self.group_document['id']}#key-1",
            )
