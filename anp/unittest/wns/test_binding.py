"""Tests for anp.wns.binding — bidirectional binding verification.

Uses a local aiohttp test server for both Handle resolution and DID Document
resolution, avoiding any mocks in production code.
"""

import json
import unittest

from aiohttp import web
from aiohttp.test_utils import AioHTTPTestCase

from anp.wns.binding import (
    BindingVerificationResult,
    build_handle_service_entry,
    extract_handle_service_from_did_document,
    verify_handle_binding,
)
from anp.wns.models import HandleStatus


# ---------------------------------------------------------------------------
# Test DID Document fixtures
# ---------------------------------------------------------------------------

ALICE_DID = "did:wba:example.com:user:alice"
ALICE_HANDLE = "alice.example.com"

ALICE_DID_DOCUMENT = {
    "id": ALICE_DID,
    "verificationMethod": [
        {
            "id": f"{ALICE_DID}#key-1",
            "type": "JsonWebKey2020",
            "controller": ALICE_DID,
        }
    ],
    "service": [
        {
            "id": f"{ALICE_DID}#handle",
            "type": "HandleService",
            "serviceEndpoint": "https://example.com/.well-known/handle/alice",
        }
    ],
}

ALICE_DID_DOCUMENT_NO_HANDLE_SERVICE = {
    "id": ALICE_DID,
    "service": [
        {
            "id": f"{ALICE_DID}#ad",
            "type": "AgentDescription",
            "serviceEndpoint": "https://example.com/agents/alice/ad.json",
        }
    ],
}


# ---------------------------------------------------------------------------
# Test application
# ---------------------------------------------------------------------------


def _make_app():
    async def handle_alice(request):
        return web.json_response(
            {
                "handle": ALICE_HANDLE,
                "did": ALICE_DID,
                "status": "active",
                "updated": "2025-01-01T00:00:00Z",
            }
        )

    async def handle_revoked(request):
        return web.json_response(
            {
                "handle": "revoked.example.com",
                "did": "did:wba:example.com:user:revoked",
                "status": "revoked",
            }
        )

    async def did_doc_alice(request):
        return web.json_response(ALICE_DID_DOCUMENT)

    app = web.Application()
    app.router.add_get("/.well-known/handle/alice", handle_alice)
    app.router.add_get("/.well-known/handle/revoked", handle_revoked)
    app.router.add_get("/user/alice/did.json", did_doc_alice)
    return app


class TestVerifyHandleBinding(AioHTTPTestCase):

    async def get_application(self):
        return _make_app()

    def _patch_urls(self):
        """Redirect resolution URLs to the local test server."""
        import anp.wns.validator as validator_mod
        import anp.wns.resolver as resolver_mod

        server_url = str(self.server.make_url("")).rstrip("/")

        original_build = validator_mod.build_resolution_url

        def patched_build(lp, dm):
            return f"{server_url}/.well-known/handle/{lp}"

        validator_mod.build_resolution_url = patched_build
        resolver_mod.build_resolution_url = patched_build
        return original_build

    def _unpatch_urls(self, original_build):
        import anp.wns.validator as validator_mod
        import anp.wns.resolver as resolver_mod

        validator_mod.build_resolution_url = original_build
        resolver_mod.build_resolution_url = original_build

    async def test_valid_binding_with_did_document(self):
        """Full verification succeeds when DID Document is provided."""
        original = self._patch_urls()
        try:
            result = await verify_handle_binding(
                ALICE_HANDLE,
                did_document=ALICE_DID_DOCUMENT,
                verify_ssl=False,
            )
            self.assertTrue(result.is_valid)
            self.assertTrue(result.forward_verified)
            self.assertTrue(result.reverse_verified)
            self.assertEqual(result.did, ALICE_DID)
            self.assertIsNone(result.error_message)
        finally:
            self._unpatch_urls(original)

    async def test_valid_binding_with_wba_uri_prefix(self):
        """wba://alice.example.com should work the same as alice.example.com."""
        original = self._patch_urls()
        try:
            result = await verify_handle_binding(
                f"wba://{ALICE_HANDLE}",
                did_document=ALICE_DID_DOCUMENT,
                verify_ssl=False,
            )
            self.assertTrue(result.is_valid)
            self.assertTrue(result.forward_verified)
            self.assertTrue(result.reverse_verified)
        finally:
            self._unpatch_urls(original)

    async def test_binding_fails_without_handle_service(self):
        """Verification fails when DID Document lacks HandleService."""
        original = self._patch_urls()
        try:
            result = await verify_handle_binding(
                ALICE_HANDLE,
                did_document=ALICE_DID_DOCUMENT_NO_HANDLE_SERVICE,
                verify_ssl=False,
            )
            self.assertFalse(result.is_valid)
            self.assertTrue(result.forward_verified)
            self.assertFalse(result.reverse_verified)
            self.assertIn("HandleService", result.error_message)
        finally:
            self._unpatch_urls(original)

    async def test_binding_fails_for_revoked_handle(self):
        """Verification fails when handle status is not active."""
        original = self._patch_urls()
        try:
            result = await verify_handle_binding(
                "revoked.example.com",
                verify_ssl=False,
            )
            self.assertFalse(result.is_valid)
            self.assertFalse(result.forward_verified)
            self.assertIn("revoked", result.error_message)
        finally:
            self._unpatch_urls(original)


class TestBuildHandleServiceEntry(unittest.TestCase):

    def test_basic(self):
        entry = build_handle_service_entry(ALICE_DID, "alice", "example.com")
        self.assertEqual(entry["id"], f"{ALICE_DID}#handle")
        self.assertEqual(entry["type"], "HandleService")
        self.assertEqual(
            entry["serviceEndpoint"],
            "https://example.com/.well-known/handle/alice",
        )


class TestExtractHandleService(unittest.TestCase):

    def test_extract(self):
        services = extract_handle_service_from_did_document(ALICE_DID_DOCUMENT)
        self.assertEqual(len(services), 1)
        self.assertEqual(services[0]["type"], "HandleService")

    def test_no_services(self):
        services = extract_handle_service_from_did_document({})
        self.assertEqual(services, [])

    def test_no_handle_service(self):
        services = extract_handle_service_from_did_document(
            ALICE_DID_DOCUMENT_NO_HANDLE_SERVICE
        )
        self.assertEqual(services, [])


if __name__ == "__main__":
    unittest.main()
