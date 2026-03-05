"""Tests for anp.wns.resolver — uses a local aiohttp test server."""

import json
import unittest

from aiohttp import web
from aiohttp.test_utils import AioHTTPTestCase

from anp.wns.exceptions import (
    HandleGoneError,
    HandleMovedError,
    HandleNotFoundError,
    HandleResolutionError,
)
from anp.wns.models import HandleResolutionDocument, HandleStatus
from anp.wns.resolver import resolve_handle, resolve_handle_from_uri


def _make_app():
    """Create a test aiohttp application simulating a Handle Provider."""

    async def handle_alice(request):
        return web.json_response(
            {
                "handle": "alice.example.com",
                "did": "did:wba:example.com:user:alice",
                "status": "active",
                "updated": "2025-01-01T00:00:00Z",
            }
        )

    async def handle_suspended(request):
        return web.json_response(
            {
                "handle": "suspended.example.com",
                "did": "did:wba:example.com:user:suspended",
                "status": "suspended",
            }
        )

    async def handle_not_found(request):
        return web.json_response(
            {"error": "handle_not_found", "message": "Handle does not exist"},
            status=404,
        )

    async def handle_gone(request):
        return web.json_response(
            {"error": "handle_gone", "message": "Handle has been revoked"},
            status=410,
        )

    async def handle_moved(request):
        raise web.HTTPMovedPermanently(
            location="https://new-provider.example.com/.well-known/handle/moved"
        )

    async def handle_mismatched(request):
        return web.json_response(
            {
                "handle": "wrong.example.com",
                "did": "did:wba:example.com:user:wrong",
                "status": "active",
            }
        )

    app = web.Application()
    app.router.add_get("/.well-known/handle/alice", handle_alice)
    app.router.add_get("/.well-known/handle/suspended", handle_suspended)
    app.router.add_get("/.well-known/handle/notfound", handle_not_found)
    app.router.add_get("/.well-known/handle/gone", handle_gone)
    app.router.add_get("/.well-known/handle/moved", handle_moved)
    app.router.add_get("/.well-known/handle/mismatched", handle_mismatched)
    return app


class TestResolveHandle(AioHTTPTestCase):
    """Integration tests using a real local HTTP server."""

    async def get_application(self):
        return _make_app()

    async def _resolve(self, local_part, domain="example.com"):
        """Resolve via the test server by overriding the URL construction."""
        # Build URL pointing to our test server instead of the real domain.
        import anp.wns.validator as validator_mod
        import anp.wns.resolver as resolver_mod

        server_url = str(self.server.make_url("")).rstrip("/")

        original_build = validator_mod.build_resolution_url

        def patched_build(lp, dm):
            return f"{server_url}/.well-known/handle/{lp}"

        validator_mod.build_resolution_url = patched_build
        resolver_mod.build_resolution_url = patched_build
        try:
            return await resolve_handle(
                f"{local_part}.{domain}",
                verify_ssl=False,
            )
        finally:
            validator_mod.build_resolution_url = original_build
            resolver_mod.build_resolution_url = original_build

    async def test_resolve_active(self):
        doc = await self._resolve("alice")
        self.assertIsInstance(doc, HandleResolutionDocument)
        self.assertEqual(doc.did, "did:wba:example.com:user:alice")
        self.assertEqual(doc.status, HandleStatus.ACTIVE)
        self.assertEqual(doc.updated, "2025-01-01T00:00:00Z")

    async def test_resolve_with_wba_uri_prefix(self):
        """wba://alice.example.com should resolve identically to alice.example.com."""
        import anp.wns.validator as validator_mod
        import anp.wns.resolver as resolver_mod

        server_url = str(self.server.make_url("")).rstrip("/")
        original_build = validator_mod.build_resolution_url

        def patched_build(lp, dm):
            return f"{server_url}/.well-known/handle/{lp}"

        validator_mod.build_resolution_url = patched_build
        resolver_mod.build_resolution_url = patched_build
        try:
            doc = await resolve_handle(
                "wba://alice.example.com", verify_ssl=False
            )
            self.assertEqual(doc.did, "did:wba:example.com:user:alice")
            self.assertEqual(doc.status, HandleStatus.ACTIVE)
        finally:
            validator_mod.build_resolution_url = original_build
            resolver_mod.build_resolution_url = original_build

    async def test_resolve_suspended(self):
        doc = await self._resolve("suspended")
        self.assertEqual(doc.status, HandleStatus.SUSPENDED)

    async def test_resolve_not_found(self):
        with self.assertRaises(HandleNotFoundError):
            await self._resolve("notfound")

    async def test_resolve_gone(self):
        with self.assertRaises(HandleGoneError):
            await self._resolve("gone")

    async def test_resolve_moved(self):
        with self.assertRaises(HandleMovedError) as ctx:
            await self._resolve("moved")
        self.assertIn("new-provider.example.com", ctx.exception.redirect_url)

    async def test_resolve_mismatch(self):
        with self.assertRaises(HandleResolutionError) as ctx:
            await self._resolve("mismatched")
        self.assertIn("mismatch", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()
