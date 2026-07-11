"""Tests for anp.wns.models — Pydantic model serialization and validation."""

import json
import unittest
from pathlib import Path

from pydantic import ValidationError

from anp.wns import canonicalize_binding_generation, compare_binding_generations
from anp.wns.models import (
    DIDSubjectProfile,
    HandleResolutionDocument,
    HandleServiceEntry,
    HandleStatus,
    ParsedWbaUri,
    SubjectType,
)


_GENERATION_VECTORS = (
    Path(__file__).resolve().parents[3]
    / "testdata"
    / "wns"
    / "binding_generation_vectors.json"
)


class TestHandleStatus(unittest.TestCase):

    def test_values(self):
        self.assertEqual(HandleStatus.ACTIVE.value, "active")
        self.assertEqual(HandleStatus.SUSPENDED.value, "suspended")
        self.assertEqual(HandleStatus.REVOKED.value, "revoked")

    def test_from_string(self):
        self.assertEqual(HandleStatus("active"), HandleStatus.ACTIVE)


class TestHandleResolutionDocument(unittest.TestCase):

    def test_valid_document(self):
        doc = HandleResolutionDocument(
            handle="alice.example.com",
            did="did:wba:example.com:user:alice",
            status=HandleStatus.ACTIVE,
            binding_generation="8",
            updated="2025-01-01T00:00:00Z",
            versionId="42",
            ttl=300,
        )
        self.assertEqual(doc.handle, "alice.example.com")
        self.assertEqual(doc.did, "did:wba:example.com:user:alice")
        self.assertEqual(doc.status, HandleStatus.ACTIVE)
        self.assertEqual(doc.binding_generation, "8")
        self.assertEqual(doc.updated, "2025-01-01T00:00:00Z")
        self.assertEqual(doc.versionId, "42")
        self.assertEqual(doc.ttl, 300)

    def test_optional_updated(self):
        doc = HandleResolutionDocument(
            handle="alice.example.com",
            did="did:wba:example.com:user:alice",
            status=HandleStatus.ACTIVE,
            binding_generation="8",
        )
        self.assertIsNone(doc.updated)

    def test_model_dump(self):
        doc = HandleResolutionDocument(
            handle="alice.example.com",
            did="did:wba:example.com:user:alice",
            status=HandleStatus.ACTIVE,
            binding_generation="8",
        )
        d = doc.model_dump()
        self.assertEqual(d["handle"], "alice.example.com")
        self.assertEqual(d["status"], "active")
        self.assertEqual(d["binding_generation"], "8")

    def test_model_validate(self):
        data = {
            "handle": "alice.example.com",
            "did": "did:wba:example.com:user:alice",
            "status": "active",
            "binding_generation": "8",
            "updated": "2025-01-01T00:00:00Z",
            "profile": {
                "type": "DIDSubjectProfile",
                "subject_did": "did:wba:example.com:user:alice",
                "subject_type": "person",
                "handle": "alice.example.com",
                "display_name": "Alice",
                "avatar_uri": "https://example.com/avatars/alice.png",
                "labels": {"locale": "en-US"},
                "proof": {"type": "DataIntegrityProof"},
            },
        }
        doc = HandleResolutionDocument.model_validate(data)
        self.assertEqual(doc.status, HandleStatus.ACTIVE)
        self.assertIsNotNone(doc.profile)
        self.assertEqual(doc.profile.subject_type, SubjectType.PERSON)
        self.assertEqual(doc.profile.display_name, "Alice")
        self.assertEqual(doc.profile.proof["type"], "DataIntegrityProof")

    def test_profile_subject_did_mismatch_is_ignored(self):
        doc = HandleResolutionDocument.model_validate(
            {
                "handle": "alice.example.com",
                "did": "did:wba:example.com:user:alice",
                "status": "active",
                "binding_generation": "8",
                "profile": {
                    "subject_did": "did:wba:example.com:user:bob",
                    "display_name": "Bob",
                },
            }
        )

        self.assertIsNone(doc.profile)

    def test_profile_handle_mismatch_is_ignored(self):
        doc = HandleResolutionDocument.model_validate(
            {
                "handle": "alice.example.com",
                "did": "did:wba:example.com:user:alice",
                "status": "active",
                "binding_generation": "8",
                "profile": {
                    "subject_did": "did:wba:example.com:user:alice",
                    "handle": "bob.example.com",
                    "display_name": "Bob",
                },
            }
            )

        self.assertIsNone(doc.profile)

    def test_missing_required_field(self):
        with self.assertRaises(ValidationError):
            HandleResolutionDocument(
                handle="alice.example.com",
                # missing did and status
            )

    def test_invalid_status(self):
        with self.assertRaises(ValidationError):
            HandleResolutionDocument(
                handle="alice.example.com",
                did="did:wba:example.com:user:alice",
                status="unknown",
                binding_generation="8",
            )

    def test_missing_binding_generation_is_rejected(self):
        with self.assertRaises(ValidationError):
            HandleResolutionDocument(
                handle="alice.example.com",
                did="did:wba:example.com:user:alice",
                status="active",
            )

    def test_non_canonical_binding_generations_are_rejected(self):
        invalid_values = [
            0,
            1,
            "",
            "0",
            "00",
            "01",
            "-1",
            "+1",
            " 1",
            "1 ",
            "1.0",
            "a",
            "\u0661",
        ]
        for value in invalid_values:
            with self.subTest(value=value), self.assertRaises(ValidationError):
                HandleResolutionDocument(
                    handle="alice.example.com",
                    did="did:wba:example.com:user:alice",
                    status="active",
                    binding_generation=value,
                )

    def test_large_binding_generation_is_preserved_and_compared(self):
        generation = "9" * 10_000
        doc = HandleResolutionDocument(
            handle="alice.example.com",
            did="did:wba:example.com:user:alice",
            status="active",
            binding_generation=generation,
        )

        self.assertEqual(doc.binding_generation, generation)
        self.assertEqual(canonicalize_binding_generation(generation), generation)
        self.assertEqual(
            compare_binding_generations(generation, "1" + "0" * 10_000), -1
        )
        self.assertEqual(compare_binding_generations(generation, generation), 0)
        self.assertEqual(compare_binding_generations("10", "9"), 1)

    def test_generation_helpers_reject_non_canonical_values(self):
        for value in (None, 8, "08", "0", " 8"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                canonicalize_binding_generation(value)

        with self.assertRaises(ValueError):
            compare_binding_generations("8", "09")

    def test_invalid_generation_is_not_hidden_by_profile_tolerance(self):
        with self.assertRaises(ValidationError):
            HandleResolutionDocument.model_validate(
                {
                    "handle": "alice.example.com",
                    "did": "did:wba:example.com:user:alice",
                    "status": "active",
                    "binding_generation": "08",
                    "profile": {
                        "subject_did": "did:wba:example.com:user:bob",
                        "display_name": "Bob",
                    },
                }
            )

    def test_shared_binding_generation_vectors(self):
        vectors = json.loads(_GENERATION_VECTORS.read_text(encoding="utf-8"))

        for case in vectors["validation"]:
            value = case.get("value")
            if case["valid"]:
                with self.subTest(case=case["name"]):
                    self.assertEqual(
                        canonicalize_binding_generation(value), case["canonical"]
                    )
            else:
                with self.subTest(case=case["name"]), self.assertRaises(
                    ValueError
                ):
                    canonicalize_binding_generation(value)

        for transition in vectors["transitions"]:
            with self.subTest(transition=transition["name"]):
                accepted = (
                    compare_binding_generations(
                        transition["current"], transition["previous"]
                    )
                    > 0
                )
                self.assertEqual(accepted, transition["accepted"])


class TestDIDSubjectProfile(unittest.TestCase):

    def test_valid_profile(self):
        profile = DIDSubjectProfile(
            subject_did="did:wba:example.com:user:alice",
            subject_type=SubjectType.PERSON,
            handle="alice.example.com",
            display_name="Alice",
            ttl=300,
        )
        self.assertEqual(profile.type, "DIDSubjectProfile")
        self.assertEqual(profile.subject_type, SubjectType.PERSON)
        self.assertEqual(profile.display_name, "Alice")

    def test_unknown_subject_type_defaults_to_unknown(self):
        missing = DIDSubjectProfile(subject_did="did:wba:example.com:user:alice")
        custom = DIDSubjectProfile(
            subject_did="did:wba:example.com:user:alice",
            subject_type="custom-private-type",
        )

        self.assertEqual(missing.subject_type, SubjectType.UNKNOWN)
        self.assertEqual(custom.subject_type, SubjectType.UNKNOWN)


class TestHandleServiceEntry(unittest.TestCase):

    def test_valid_entry(self):
        entry = HandleServiceEntry(
            id="did:wba:example.com:user:alice#handle",
            type="ANPHandleService",
            serviceEndpoint="https://example.com/.well-known/handle/alice",
        )
        self.assertEqual(entry.type, "ANPHandleService")

    def test_default_type(self):
        entry = HandleServiceEntry(
            id="did:wba:example.com:user:alice#handle",
            serviceEndpoint="https://example.com/.well-known/handle/alice",
        )
        self.assertEqual(entry.type, "ANPHandleService")

    def test_model_dump(self):
        entry = HandleServiceEntry(
            id="did:wba:example.com:user:alice#handle",
            serviceEndpoint="https://example.com/.well-known/handle/alice",
        )
        d = entry.model_dump()
        self.assertIn("serviceEndpoint", d)
        self.assertEqual(d["type"], "ANPHandleService")


class TestParsedWbaUri(unittest.TestCase):

    def test_fields(self):
        uri = ParsedWbaUri(
            local_part="alice",
            domain="example.com",
            handle="alice.example.com",
            original_uri="wba://alice.example.com",
        )
        self.assertEqual(uri.local_part, "alice")
        self.assertEqual(uri.domain, "example.com")


if __name__ == "__main__":
    unittest.main()
