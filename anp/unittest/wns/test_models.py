"""Tests for anp.wns.models — Pydantic model serialization and validation."""

import unittest

from pydantic import ValidationError

from anp.wns.models import (
    DIDSubjectProfile,
    HandleResolutionDocument,
    HandleServiceEntry,
    HandleStatus,
    ParsedWbaUri,
    SubjectType,
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
            updated="2025-01-01T00:00:00Z",
            versionId="42",
            ttl=300,
        )
        self.assertEqual(doc.handle, "alice.example.com")
        self.assertEqual(doc.did, "did:wba:example.com:user:alice")
        self.assertEqual(doc.status, HandleStatus.ACTIVE)
        self.assertEqual(doc.updated, "2025-01-01T00:00:00Z")
        self.assertEqual(doc.versionId, "42")
        self.assertEqual(doc.ttl, 300)

    def test_optional_updated(self):
        doc = HandleResolutionDocument(
            handle="alice.example.com",
            did="did:wba:example.com:user:alice",
            status=HandleStatus.ACTIVE,
        )
        self.assertIsNone(doc.updated)

    def test_model_dump(self):
        doc = HandleResolutionDocument(
            handle="alice.example.com",
            did="did:wba:example.com:user:alice",
            status=HandleStatus.ACTIVE,
        )
        d = doc.model_dump()
        self.assertEqual(d["handle"], "alice.example.com")
        self.assertEqual(d["status"], "active")

    def test_model_validate(self):
        data = {
            "handle": "alice.example.com",
            "did": "did:wba:example.com:user:alice",
            "status": "active",
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
            )


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
