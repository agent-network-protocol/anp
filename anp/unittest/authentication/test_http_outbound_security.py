"""Offline connector/crawler security tests using only injected transports."""

from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest

from anp.anp_crawler.anp_client import ANPClient
from anp.authentication.did_resolver import resolve_did_document
from anp.authentication.did_web import _PublicResolver
from anp.authentication.outbound import fetch_public_json
from anp.wns.exceptions import HandleGoneError, HandleMovedError, HandleNotFoundError
from anp.wns.resolver import resolve_handle


@pytest.fixture(autouse=True)
def no_network():
    with patch(
        "socket.socket.connect", side_effect=AssertionError("Real network forbidden")
    ):
        yield


class Content:
    def __init__(self, chunks):
        self.chunks = chunks

    async def iter_chunked(self, _size):
        for chunk in self.chunks:
            yield chunk


class Response:
    def __init__(
        self, *, status=200, url="https://public.example/ad.json", chunks=None
    ):
        self.status, self.url = status, url
        self.reason = "fixture"
        self.charset = "utf-8"
        self.content_length = None
        self.headers = {
            "Authorization": "Bearer untrusted-marker",
            "Content-Type": "application/json",
        }
        self.content = Content(chunks or [b'{"id":"did:wba:public.example"}'])

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        pass


class Session:
    def __init__(self, response):
        self.response = response
        self.get = Mock(return_value=response)
        self.head = Mock(return_value=response)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        pass


@pytest.mark.asyncio
async def test_fetch_binds_resolver_disables_proxy_and_redirect_and_bounds_decoded_body():
    response = Response()
    session = Session(response)
    resolver = SimpleNamespace(close=AsyncMock())
    with (
        patch("anp.authentication.outbound._PublicResolver", return_value=resolver),
        patch("aiohttp.TCPConnector") as connector,
        patch("aiohttp.ClientSession", return_value=session) as factory,
    ):
        assert await fetch_public_json(response.url) == {"id": "did:wba:public.example"}
        assert connector.call_args.kwargs["resolver"] is resolver
        assert factory.call_args.kwargs["trust_env"] is False
        assert session.get.call_args.kwargs["allow_redirects"] is False
        response.status = 302
        with pytest.raises(ValueError, match="HTTP 200"):
            await fetch_public_json(response.url)
        response.status = 200
        response.content = Content([b"x" * 65536] * 17)
        with pytest.raises(ValueError, match="size limit"):
            await fetch_public_json(response.url)
    assert resolver.close.await_count == 3


@pytest.mark.asyncio
async def test_actual_connector_dns_rejects_mixed_or_rebound_answers():
    resolver = _PublicResolver()
    try:
        with patch.object(
            resolver._resolver, "resolve", AsyncMock(return_value=[{"host": "8.8.8.8"}])
        ):
            assert (await resolver.resolve("public.example"))[0]["host"] == "8.8.8.8"
        with patch.object(
            resolver._resolver,
            "resolve",
            AsyncMock(return_value=[{"host": "8.8.8.8"}, {"host": "10.0.0.1"}]),
        ):
            with pytest.raises(ValueError, match="non-public"):
                await resolver.resolve("public.example")
    finally:
        await resolver.close()


@pytest.mark.asyncio
async def test_wba_generic_resolver_uses_same_bounded_transport():
    with (
        patch(
            "anp.authentication.did_resolver.fetch_public_json",
            AsyncMock(return_value={"id": "did:wba:public.example"}),
        ) as fetch,
        patch(
            "anp.authentication.did_resolver.validate_did_document_method",
            return_value=True,
        ),
    ):
        assert (await resolve_did_document("did:wba:public.example"))[
            "id"
        ] == "did:wba:public.example"
        assert fetch.call_args.kwargs["trusted_override"] is False
    with patch("aiohttp.ClientSession") as session:
        with pytest.raises(ValueError):
            await resolve_did_document("did:wba:127.0.0.1")
        session.assert_not_called()


def crawler(origins=None):
    with patch.object(ANPClient, "_initialize_auth_client"):
        client = ANPClient("unused", "unused", authenticated_origins=origins)
    client.auth_client = Mock()
    client.auth_client.get_auth_header.return_value = {"Signature": "fixture-signature"}
    return client


@pytest.mark.asyncio
@pytest.mark.parametrize("authenticated", [False, True])
async def test_crawler_discovery_does_not_sign_or_absorb_token_unless_origin_approved(
    authenticated,
):
    client = crawler(["https://public.example/"] if authenticated else [])
    response = Response()
    session = Session(response)

    @asynccontextmanager
    async def transport(_timeout):
        yield session

    with patch("anp.anp_crawler.anp_client.public_client_session", transport):
        result = await client.fetch_url(
            response.url, headers={"Authorization": "Bearer do-not-forward"}
        )
    assert result["success"]
    assert session.get.call_args.kwargs["allow_redirects"] is False
    assert "Authorization" not in session.get.call_args.kwargs["headers"]
    assert client.auth_client.get_auth_header.call_count == int(authenticated)
    assert client.auth_client.update_token.call_count == int(authenticated)


@pytest.mark.asyncio
async def test_crawler_head_rejects_private_before_transport_and_redirect_cannot_pollute_origin():
    client = crawler(["https://public.example"])
    with patch("anp.anp_crawler.anp_client.public_client_session") as transport:
        assert not (await client.get_content_info("https://127.0.0.1/"))["success"]
        transport.assert_not_called()
    result = await client._process_response(
        Response(url="https://other.example/ad.json"), "https://public.example/ad.json"
    )
    assert result["success"]
    client.auth_client.update_token.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status,error",
    [(301, HandleMovedError), (404, HandleNotFoundError), (410, HandleGoneError)],
)
async def test_wns_preserves_status_semantics_without_following_redirects(
    status, error
):
    response = Response(status=status)
    session = Session(response)

    @asynccontextmanager
    async def transport(_timeout):
        yield session

    with patch("anp.wns.resolver.public_client_session", transport):
        with pytest.raises(error):
            await resolve_handle("alice.example.com")
    assert session.get.call_args.kwargs["allow_redirects"] is False


@pytest.mark.asyncio
async def test_process_outbound_budget_bounds_all_python_document_paths_and_recovers():
    from contextlib import ExitStack
    from anp.authentication.outbound import outbound_request_budget, public_client_session
    from anp.authentication.did_web import fetch_did_web_document
    with ExitStack() as held, patch("aiohttp.ClientSession") as session:
        for _ in range(32): held.enter_context(outbound_request_budget())
        with pytest.raises(ValueError, match="concurrency budget"):
            await fetch_public_json("https://public.example/did.json")
        with pytest.raises(ValueError, match="concurrency budget"):
            await fetch_did_web_document("did:web:public.example",timeout_seconds=10,verify_ssl=True,base_url_override=None,headers={})
        with pytest.raises(ValueError, match="concurrency budget"):
            async with public_client_session(None): pass
        session.assert_not_called()
    with outbound_request_budget(): pass  # Every earlier permit was released.


@pytest.mark.asyncio
async def test_approved_origin_with_failed_credentials_never_falls_back_to_anonymous():
    client=crawler(["https://public.example"]);client.auth_client=None
    with patch("anp.anp_crawler.anp_client.public_client_session") as transport:
        with pytest.raises(ValueError,match="credential provider"):
            await client.fetch_url("https://public.example/rpc")
        transport.assert_not_called()
