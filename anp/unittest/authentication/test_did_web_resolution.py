"""Shared DID Web URL and production resolution boundary tests."""

import json
import asyncio
from pathlib import Path

import pytest
from aiohttp import web

from anp.authentication.did_resolver import resolve_did_document
from anp.authentication.did_web import _is_public_address, _PublicResolver

from anp.authentication.did_resolver import build_did_resolution_url

FIXTURE = json.loads(
    (Path(__file__).parents[3] / "fixtures/did-method-lifecycle-v1.json").read_text()
)


@pytest.mark.parametrize("case", FIXTURE["resolution_cases"])
def test_web_resolution_url(case):
    assert build_did_resolution_url(case["did"]) == case["url"]


@pytest.mark.parametrize("did", FIXTURE["invalid_resolution_dids"])
def test_web_resolution_rejects_unsafe_did(did):
    with pytest.raises(ValueError):
        build_did_resolution_url(did)


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["valid", "wrong-id", "oversized", "redirect", "html", "timeout"])
async def test_web_response_boundary(mode):
    document = FIXTURE["documents"]["web_single_device"]
    seen = []

    async def handle(request):
        seen.append(request.path)
        if mode == "timeout":
            await asyncio.sleep(0.15)
        if len(seen) > 1:
            return web.json_response(document)
        if mode == "redirect":
            return web.Response(status=302, headers={"Location": "/redirected"})
        if mode == "oversized":
            return web.Response(body=b" " * (1024 * 1024 + 1))
        if mode == "wrong-id":
            return web.json_response({"id": "did:web:other.example"})
        if mode == "html":
            return web.Response(text="<html>SPA</html>", content_type="text/html")
        return web.json_response(document)

    app = web.Application()
    app.router.add_get("/{path:.*}", handle)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    try:
        port = runner.addresses[0][1]
        operation = resolve_did_document(
            document["id"],
            verify_proof=True,
            base_url_override=f"http://127.0.0.1:{port}",
            timeout_seconds=0.05 if mode == "timeout" else 10,
        )
        if mode == "valid":
            assert await operation == document  # No WBA root proof required.
        else:
            with pytest.raises((ValueError, TimeoutError)):
                await operation
        assert len(seen) == 1
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_production_cannot_disable_tls():
    with pytest.raises(ValueError, match="TLS"):
        await resolve_did_document("did:web:example.com", verify_ssl=False)


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.1",
        "169.254.169.254",
        "100.64.0.1",
        "192.168.0.1",
        "198.18.0.1",
        "224.0.0.1",
        "::1",
        "fc00::1",
        "fe80::1",
        "::ffff:127.0.0.1",
        "2002:7f00:1::",
        "2001:db8::1",
        "3fff::1",
    ],
)
def test_non_public_addresses_are_rejected(address):
    assert not _is_public_address(address)


@pytest.mark.asyncio
async def test_connector_checks_all_dns_answers(monkeypatch):
    answers = [{"host": "8.8.8.8"}, {"host": "127.0.0.1"}]

    async def resolve(*args, **kwargs):
        return answers

    resolver = _PublicResolver()
    monkeypatch.setattr(resolver._resolver, "resolve", resolve)
    try:
        with pytest.raises(ValueError, match="non-public"):
            await resolver.resolve("example.com")
        answers.pop()
        assert await resolver.resolve("example.com") is answers
    finally:
        await resolver.close()
