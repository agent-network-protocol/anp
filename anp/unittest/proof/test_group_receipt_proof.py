"""Tests for group receipt proof helpers."""

import copy
import unittest

from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from anp.proof import generate_group_receipt_proof, verify_group_receipt_proof


class TestGroupReceiptProof(unittest.TestCase):
    def setUp(self):
        self.private_key = ec.generate_private_key(ec.SECP256K1())
        self.public_key = self.private_key.public_key()
        self.receipt = {
            "receipt_type": "anp.group_receipt.v1",
            "group_did": "did:wba:groups.example:team:dev:e1_group_dev",
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
            "did:wba:groups.example:team:dev:e1_group_dev#key-1",
        )
        self.assertIn("proof", signed)
        self.assertTrue(verify_group_receipt_proof(signed, self.public_key))

    def test_tampered_receipt_fails_verification(self):
        signed = generate_group_receipt_proof(
            self.receipt,
            self.private_key,
            "did:wba:groups.example:team:dev:e1_group_dev#key-1",
        )
        tampered = copy.deepcopy(signed)
        tampered["group_event_seq"] = "129"
        self.assertFalse(verify_group_receipt_proof(tampered, self.public_key))

    def test_missing_required_field_raises(self):
        invalid_receipt = dict(self.receipt)
        invalid_receipt.pop("payload_digest")
        with self.assertRaises(ValueError):
            generate_group_receipt_proof(
                invalid_receipt,
                self.private_key,
                "did:wba:groups.example:team:dev:e1_group_dev#key-1",
            )


class TestGroupReceiptProofEd25519(unittest.TestCase):
    def setUp(self):
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.receipt = {
            "receipt_type": "anp.group_receipt.v1",
            "group_did": "did:wba:groups.example:team:dev:e1_group_dev",
            "group_state_version": "43",
            "group_event_seq": "128",
            "subject_method": "group.send",
            "operation_id": "op-group-send-001",
            "actor_did": "did:wba:a.example:agents:alice:e1_alice",
            "accepted_at": "2026-03-29T15:10:01Z",
            "payload_digest": "sha-256=:stub:",
        }

    def test_generate_and_verify_group_receipt_proof_ed25519(self):
        signed = generate_group_receipt_proof(
            self.receipt,
            self.private_key,
            "did:wba:groups.example:team:dev:e1_group_dev#key-1",
        )
        self.assertEqual(signed["proof"]["cryptosuite"], "eddsa-jcs-2022")
        self.assertTrue(verify_group_receipt_proof(signed, self.public_key))
