"""Tests for anp.wns.models — Pydantic model serialization and validation."""

import unittest

from pydantic import ValidationError

from anp.wns.models import (
    HandleResolutionDocument,
    HandleServiceEntry,
    HandleStatus,
    ParsedWbaUri,
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
        )
        self.assertEqual(doc.handle, "alice.example.com")
        self.assertEqual(doc.did, "did:wba:example.com:user:alice")
        self.assertEqual(doc.status, HandleStatus.ACTIVE)
        self.assertEqual(doc.updated, "2025-01-01T00:00:00Z")

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
        }
        doc = HandleResolutionDocument.model_validate(data)
        self.assertEqual(doc.status, HandleStatus.ACTIVE)

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


class TestHandleServiceEntry(unittest.TestCase):

    def test_valid_entry(self):
        entry = HandleServiceEntry(
            id="did:wba:example.com:user:alice#handle",
            type="HandleService",
            serviceEndpoint="https://example.com/.well-known/handle/alice",
        )
        self.assertEqual(entry.type, "HandleService")

    def test_default_type(self):
        entry = HandleServiceEntry(
            id="did:wba:example.com:user:alice#handle",
            serviceEndpoint="https://example.com/.well-known/handle/alice",
        )
        self.assertEqual(entry.type, "HandleService")

    def test_model_dump(self):
        entry = HandleServiceEntry(
            id="did:wba:example.com:user:alice#handle",
            serviceEndpoint="https://example.com/.well-known/handle/alice",
        )
        d = entry.model_dump()
        self.assertIn("serviceEndpoint", d)
        self.assertEqual(d["type"], "HandleService")


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
