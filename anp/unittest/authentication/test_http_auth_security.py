"""Offline HTTP auth regression tests. No listener, DNS or database is used."""

import asyncio
import base64
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from anp.authentication import DidWbaVerifier, DidWbaVerifierConfig, DidWbaVerifierError
from anp.authentication.did_resolver import build_did_resolution_url
from anp.authentication.did_wba_authenticator import DIDWbaAuthHeader
from anp.authentication.federation import (
    FederatedVerificationError,
    verify_federated_http_request,
)
from anp.authentication.http_auth_security import (
    HttpSignaturePolicy,
    MemoryReplayStore,
    ReplayContext,
    authentication_origin,
    consume_http_replay,
)
from anp.authentication.http_signatures import (
    _build_signature_base,
    verify_http_message_signature,
)
from anp.authentication.outbound import validate_public_url

CORPUS = json.loads(
    (
        Path(__file__).resolve().parents[3]
        / "testdata/authentication/security_vectors_v1.json"
    ).read_text()
)
NOW = CORPUS["now"]


@pytest.fixture(autouse=True)
def no_network():
    with patch(
        "socket.socket.connect",
        side_effect=AssertionError("Unit test attempted real network"),
    ):
        yield


@pytest.mark.parametrize("case", CORPUS["cases"], ids=lambda case: case["id"])
def test_shared_signature_vectors(case):
    valid, message, _ = verify_http_message_signature(
        CORPUS["document"],
        case["method"],
        case["url"],
        case["headers"],
        case["body"],
        now=NOW,
    )
    assert valid is case["accepted"], message


def test_time_window_is_default_and_offline_mode_is_explicit():
    case = next(c for c in CORPUS["cases"] if c["id"] == "expired_2001")
    args = (CORPUS["document"], case["method"], case["url"], case["headers"])
    assert not verify_http_message_signature(*args)[0]
    assert verify_http_message_signature(
        *args, policy=HttpSignaturePolicy(check_time=False)
    )[0]


def test_duplicate_headers_and_parameters_are_rejected():
    case = CORPUS["cases"][0]
    for update in (
        {"signature-input": case["headers"]["Signature-Input"]},
        {"Signature-Input": case["headers"]["Signature-Input"] + ";created=1"},
        {
            "Signature-Input": case["headers"]["Signature-Input"].replace(
                str(NOW), "?1", 1
            )
        },
        {"Signature-Input": case["headers"]["Signature-Input"] + ';nonce="other"'},
    ):
        assert not verify_http_message_signature(
            CORPUS["document"],
            "GET",
            case["url"],
            {**case["headers"], **update},
            now=NOW,
        )[0]


def test_extensions_remain_in_signed_parameters():
    # Public test key only; unknown signed params cannot be silently discarded.
    key = Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(b"ANP public security fixture only, never production").digest()
    )
    doc = CORPUS["document"]
    case = CORPUS["cases"][0]
    params = (
        case["headers"]["Signature-Input"].split("=", 1)[1]
        + ';alg="ed25519";tag="a;\\"b"'
    )
    base = _build_signature_base(
        ["@method", "@target-uri"],
        "GET",
        case["url"],
        {},
        NOW,
        NOW + 300,
        "security-vector",
        doc["authentication"][0],
        signature_params=params,
    )
    headers = {
        "Signature-Input": "sig1=" + params,
        "Signature": "sig1=:" + base64.b64encode(key.sign(base)).decode() + ":",
    }
    assert verify_http_message_signature(doc, "GET", case["url"], headers, now=NOW)[0]
    # The old signature did not cover the appended tag/algorithm.
    headers["Signature"] = case["headers"]["Signature"]
    assert not verify_http_message_signature(doc, "GET", case["url"], headers, now=NOW)[
        0
    ]


@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1/did.json",
        "https://169.254.169.254/",
        "https://10.0.0.1/",
        "https://[::1]/",
        "https://[::ffff:127.0.0.1]/",
        "https://localhost/",
        "http://example.com/",
        "https://user@example.com/",
        "https://example.com/#fragment",
    ],
)
def test_outbound_policy_rejects_before_connect(url):
    with pytest.raises(ValueError):
        validate_public_url(url)


@pytest.mark.parametrize(
    "did",
    [
        "did:wba:example.com%2fother:user",
        "did:wba:user%40example.com:alice",
        "did:wba:example.com:..",
        "did:wba:example.com:%2fetc",
        "did:wba:example.com:%252fetc",
    ],
)
def test_wba_resolution_rejects_ambiguous_authority_and_path(did):
    with pytest.raises(ValueError):
        build_did_resolution_url(did)


def test_origin_and_challenge_isolation():
    assert authentication_origin("https://EXAMPLE.com/path") == authentication_origin(
        "https://example.com:443/other"
    )
    helper = DIDWbaAuthHeader("unused", "unused")
    helper.update_token(
        "https://example.com:8443/", {"Authorization": "Bearer unit-marker"}
    )
    assert helper._get_domain("https://example.com:8443/") in helper.tokens
    assert helper._get_domain("https://example.com/") not in helper.tokens
    assert helper._get_domain("http://example.com:8443/") not in helper.tokens
    covered = helper._normalize_covered_components(["@method"], {}, b"")
    assert "@target-uri" in covered


def test_replay_store_atomic_capacity_and_expiry():
    clock = [NOW]
    store = MemoryReplayStore(capacity=1, clock=lambda: clock[0])
    context = ReplayContext("did:web:a.example", "receiver", "key", NOW + 60)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: store.consume_once(context), range(20)))
    assert results.count(True) == 1
    with pytest.raises(RuntimeError, match="capacity"):
        store.consume_once(
            ReplayContext(context.signer_did, context.verifier_scope, "other", NOW + 60)
        )
    clock[0] += 60
    assert not store.consume_once(context)  # Boundary is still replay-protected.
    clock[0] += 1
    assert store.consume_once(
        ReplayContext(context.signer_did, context.verifier_scope, "other", NOW + 120)
    )


@pytest.mark.asyncio
async def test_async_store_and_nonboolean_fail_closed():
    context = ReplayContext("did:web:a.example", "receiver", "key", NOW + 60)
    callback = AsyncMock(return_value=True)
    assert await consume_http_replay(callback, context)
    callback.return_value = "true"
    with pytest.raises(ValueError):
        await consume_http_replay(callback, context)


def make_verifier(store=None, **kw):
    config = DidWbaVerifierConfig(clock=lambda: NOW, replay_store=store, **kw)
    verifier = DidWbaVerifier(config)
    verifier._create_access_token = lambda _: "offline-not-a-token"
    return verifier


@pytest.mark.asyncio
async def test_two_verifiers_share_async_replay_store_and_invalid_signature_cannot_poison():
    store = MemoryReplayStore(clock=lambda: NOW)
    first, second = make_verifier(store), make_verifier(store)
    case = CORPUS["cases"][0]
    args = dict(method="GET", url=case["url"], headers=case["headers"])
    resolver = AsyncMock(return_value=CORPUS["document"])
    with patch("anp.authentication.did_wba_verifier.resolve_did_document", resolver):
        bad_headers = {**case["headers"], "Signature": "sig1=:AA==:"}
        with pytest.raises(DidWbaVerifierError):
            await first.verify_request(**{**args, "headers": bad_headers})
        results = await asyncio.gather(
            first.verify_request(**args),
            second.verify_request(**args),
            return_exceptions=True,
        )
    assert sum(isinstance(r, dict) for r in results) == 1
    assert sum(isinstance(r, DidWbaVerifierError) for r in results) == 1


@pytest.mark.asyncio
async def test_no_nonce_profile_is_still_replay_protected_and_storage_failure_never_mints():
    case = next(c for c in CORPUS["cases"] if c["id"] == "no_expires_no_nonce")
    verifier = make_verifier(require_nonce_for_http_signatures=False)
    args = dict(method="GET", url=case["url"], headers=case["headers"])
    with patch(
        "anp.authentication.did_wba_verifier.resolve_did_document",
        AsyncMock(return_value=CORPUS["document"]),
    ):
        assert (await verifier.verify_request(**args))["did"] == CORPUS["document"][
            "id"
        ]
        with pytest.raises(DidWbaVerifierError):
            await verifier.verify_request(**args)
        broken = make_verifier(
            AsyncMock(side_effect=RuntimeError("store offline")),
            require_nonce_for_http_signatures=False,
        )
        with pytest.raises(DidWbaVerifierError) as error:
            await broken.verify_request(**args)
        assert error.value.status_code == 503


@pytest.mark.asyncio
async def test_federation_requires_time_and_shared_replay():
    case = CORPUS["cases"][0]
    sender = {
        "id": "did:web:sender.example:agent",
        "service": [
            {
                "id": "message",
                "type": "ANPMessageService",
                "serviceDid": CORPUS["document"]["id"],
                "serviceEndpoint": "https://receiver.example/rpc",
            }
        ],
    }
    store = MemoryReplayStore(clock=lambda: NOW)
    args = dict(
        sender_did=sender["id"],
        request_method="GET",
        request_url=case["url"],
        headers=case["headers"],
        sender_did_document=sender,
        service_did_document=CORPUS["document"],
        replay_store=store,
        now=NOW,
    )
    assert (await verify_federated_http_request(**args)).service_did == CORPUS[
        "document"
    ]["id"]
    with pytest.raises(FederatedVerificationError, match="replay"):
        await verify_federated_http_request(**args)
    with pytest.raises(FederatedVerificationError, match="time validation"):
        await verify_federated_http_request(
            **args, signature_policy=HttpSignaturePolicy(check_time=False)
        )


def test_frozen_legacy_authority_serializers_and_canonical_replay():
    from anp.authentication.http_auth_security import http_replay_context
    compatibility = json.loads((Path(__file__).resolve().parents[3] / "testdata/authentication/authority_compatibility_v1.json").read_text())
    for case in compatibility["cases"]:
        valid, message, metadata = verify_http_message_signature(
            compatibility["document"], "GET", case["url"], case["headers"], now=compatibility["now"],
        )
        assert valid, (case["id"], message)
        assert http_replay_context(metadata, case["url"]).replay_key == case["replay_key"]
        assert not verify_http_message_signature(compatibility["document"], "GET", case["url"]+"tampered", case["headers"], now=compatibility["now"])[0]


@pytest.mark.asyncio
async def test_custom_window_reaches_primitive_and_legacy_callback_outage_is_closed():
    case = next(c for c in CORPUS["cases"] if c["id"] == "age_exceeded")
    verifier = make_verifier(timestamp_expiration_minutes=10)
    with patch("anp.authentication.did_wba_verifier.resolve_did_document", AsyncMock(return_value=CORPUS["document"])):
        assert (await verifier.verify_request(method="GET", url=case["url"], headers=case["headers"]))["did"] == CORPUS["document"]["id"]
    failed = make_verifier(external_nonce_validator=AsyncMock(side_effect=RuntimeError("synthetic shared storage outage")))
    with pytest.raises(DidWbaVerifierError) as exc:
        await failed._is_valid_server_nonce(CORPUS["document"]["id"], "unit-nonce")
    assert exc.value.status_code == 503


def test_bounded_headers_and_unambiguous_legacy_fields():
    from anp.authentication import extract_auth_header_parts
    legacy = json.loads((Path(__file__).resolve().parents[3] / "testdata/authentication/legacy_compatibility_v1.json").read_text())
    assert extract_auth_header_parts(legacy["header"])[0] == legacy["document"]["id"]
    for tail in [', nonce="duplicate"', ', DID="duplicate"', ', v="1.0"', ' garbage']:
        with pytest.raises(ValueError): extract_auth_header_parts(legacy["header"] + tail)
    case=CORPUS["cases"][0]
    for signature in ["sig1=:"+"A"*20000+":", case["headers"]["Signature"]+"\r\nInjected: value"]:
        assert not verify_http_message_signature(CORPUS["document"],"GET",case["url"],{**case["headers"],"Signature":signature},now=NOW)[0]


@pytest.mark.asyncio
async def test_federation_expiry_precheck_precedes_any_document_resolution():
    expired=next(case for case in CORPUS["cases"] if case["id"]=="expired_2001")
    with patch("anp.authentication.federation.resolve_did_document",AsyncMock(side_effect=AssertionError("Resolution before precheck"))) as resolver:
        with pytest.raises(FederatedVerificationError,match="metadata"):
            await verify_federated_http_request(sender_did="invalid-sender",request_method="GET",request_url=expired["url"],headers=expired["headers"],now=NOW)
        resolver.assert_not_awaited()


def test_origin_ipv6_is_canonical_and_zero_or_ambiguous_ports_are_rejected():
    assert authentication_origin("https://[2001:4860:0000:0000:0000:0000:0000:8888]/")=="https://[2001:4860::8888]:443"
    for value in ["https://api.example:0/","https://api.example/#","https://127.0.0.01/","https://api.example\\evil/","https://[::ffff:8.8.8.8]/"]:
        with pytest.raises(ValueError):authentication_origin(value)
