"""In-process wrapper security units; no ASGI server, socket or database."""
import json
from pathlib import Path
from unittest.mock import AsyncMock, patch
from urllib.parse import urlsplit

import pytest
from fastapi import Request
from fastapi.responses import JSONResponse

from anp.authentication import DidWbaVerifier, DidWbaVerifierConfig
from anp.authentication.http_auth_security import MemoryReplayStore
from anp.fastanp import middleware as fastanp
from anp.openanp import middleware as openanp
from anp.openanp.client.agent import RemoteAgent

CORPUS = json.loads((Path(__file__).resolve().parents[3] / "testdata/authentication/security_vectors_v1.json").read_text())
NOW = CORPUS["now"]
CASE = CORPUS["cases"][0]


@pytest.fixture(autouse=True)
def no_network():
    with patch("socket.socket.connect", side_effect=AssertionError("Unit attempted real network")):
        yield


def request(url=CASE["url"], headers=None, extra=()):
    parsed = urlsplit(url)
    async def receive():
        return {"type":"http.request", "body":b"", "more_body":False}
    raw = [(b"host", parsed.netloc.encode())] + [(key.lower().encode(),value.encode()) for key,value in (headers if headers is not None else CASE["headers"]).items()]
    raw.extend(extra)
    return Request({"type":"http", "method":"GET", "scheme":parsed.scheme, "path":parsed.path, "raw_path":parsed.path.encode(), "query_string":parsed.query.encode(), "headers":raw, "server":(parsed.hostname,parsed.port or 443)}, receive)


def verifier(store=None):
    result = DidWbaVerifier(DidWbaVerifierConfig(clock=lambda:NOW, replay_store=store))
    result._create_access_token = lambda _: "public-unit-token"
    return result


@pytest.mark.parametrize("module", [fastanp, openanp])
@pytest.mark.asyncio
async def test_complete_wrapper_preserves_success_and_refuses_replay(module, caplog):
    call_next = AsyncMock(return_value=JSONResponse({"ok":True}))
    auth = verifier(MemoryReplayStore(clock=lambda:NOW))
    with patch("anp.authentication.did_wba_verifier.resolve_did_document", AsyncMock(return_value=CORPUS["document"])):
        first=request()
        response=await module.auth_middleware(first,call_next,auth,[CASE["url"]])
        assert response.status_code==200
        assert first.state.did==CORPUS["document"]["id"]
        assert response.headers["Authorization"]=="Bearer public-unit-token"
        second=request();second.state.did="unverified injected identity"
        response=await module.auth_middleware(second,call_next,auth,[CASE["url"]])
        assert response.status_code==401 and second.state.did is None
        assert second.state.auth_result is None
    call_next.assert_awaited_once()
    assert "public-unit-token" not in caplog.text


@pytest.mark.parametrize("module", [fastanp, openanp])
@pytest.mark.parametrize("allowed", [None, ["https://foreign.example"], ["https://receiver.example:8443"]])
@pytest.mark.asyncio
async def test_untrusted_or_unconfigured_receiver_never_reaches_verifier(module, allowed):
    auth=AsyncMock();call_next=AsyncMock()
    response=await module.auth_middleware(request(),call_next,auth,allowed)
    assert response.status_code==403
    auth.verify_request.assert_not_awaited();call_next.assert_not_awaited()


@pytest.mark.parametrize("module", [fastanp, openanp])
@pytest.mark.asyncio
async def test_repeated_authentication_header_is_not_lost_in_dict_conversion(module):
    auth=AsyncMock();call_next=AsyncMock()
    incoming=request(extra=[(b"signature", CASE["headers"]["Signature"].encode())])
    response=await module.auth_middleware(incoming,call_next,auth,[CASE["url"]])
    assert response.status_code==400
    auth.verify_request.assert_not_awaited();call_next.assert_not_awaited()


@pytest.mark.parametrize("module", [fastanp, openanp])
@pytest.mark.asyncio
async def test_store_outage_remains_unavailable_not_anonymous(module):
    auth=verifier(AsyncMock(side_effect=RuntimeError("unit unavailable")))
    call_next=AsyncMock();incoming=request()
    with patch("anp.authentication.did_wba_verifier.resolve_did_document", AsyncMock(return_value=CORPUS["document"])):
        response=await module.auth_middleware(incoming,call_next,auth,[CASE["url"]])
    assert response.status_code==503 and incoming.state.did is None
    call_next.assert_not_awaited()


@pytest.mark.parametrize("origins", [(),("https://api.example:8443",)])
@pytest.mark.asyncio
async def test_remote_agent_explicit_credential_policy_survives_discovery_and_calls(origins):
    auth=AsyncMock(did_document_path="public-doc-path", private_key_path="unused-unit-path")
    document={"name":"unit", "description":"Unit discovery", "servers":[{"url":"https://api.example:8443/rpc"}], "interfaces":[{"type":"StructuredInterface", "protocol":"openrpc", "content":{"openrpc":"1.3.2", "methods":[{"name":"unit", "description":"Unit method", "params":[], "result":{"name":"result","schema":{"type":"string"}}}]}}]}
    with patch("anp.openanp.client.agent.ANPClient") as factory:
        factory.return_value.fetch=AsyncMock(return_value={"success":True,"data":document})
        factory.return_value.call_jsonrpc=AsyncMock(return_value={"success":True,"result":"ok"})
        remote=await RemoteAgent.discover("https://api.example/ad.json",auth,authenticated_origins=origins)
        assert await remote.call("unit")=="ok"
        assert all(call.kwargs["authenticated_origins"]==origins for call in factory.call_args_list)
