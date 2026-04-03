"""Tests for the direct_e2ee module."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Tuple

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from anp.authentication.did_wba import create_did_wba_document
from anp.direct_e2ee import (
    DirectE2eeSession,
    FileSessionStore,
    FileSignedPrekeyStore,
    MessageServiceDirectE2eeClient,
    PrekeyManager,
)
from anp.direct_e2ee.models import ApplicationPlaintext, DirectEnvelopeMetadata
from anp.e2e_encryption_hpke.key_pair import extract_x25519_public_key_from_did_document


def _load_identity_keys(keys: Dict[str, Tuple[bytes, bytes]]) -> Tuple[Ed25519PrivateKey, X25519PrivateKey]:
    signing_private_key = serialization.load_pem_private_key(keys["key-1"][0], password=None)
    static_key_private_key = serialization.load_pem_private_key(keys["key-3"][0], password=None)
    assert isinstance(signing_private_key, Ed25519PrivateKey)
    assert isinstance(static_key_private_key, X25519PrivateKey)
    return signing_private_key, static_key_private_key


class FakeRpcClient:
    def __init__(self, prekey_bundle: Dict[str, Any]) -> None:
        self.prekey_bundle = prekey_bundle
        self.calls = []

    def __call__(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        self.calls.append((method, params))
        if method == "direct.e2ee.publish_prekey_bundle":
            bundle = params["body"]["prekey_bundle"]
            return {
                "published": True,
                "owner_did": bundle["owner_did"],
                "bundle_id": bundle["bundle_id"],
                "published_at": "2026-03-31T09:59:01Z",
            }
        if method == "direct.e2ee.get_prekey_bundle":
            return {
                "target_did": params["body"]["target_did"],
                "prekey_bundle": self.prekey_bundle,
            }
        if method == "direct.send":
            return {
                "accepted": True,
                "message_id": params["meta"]["message_id"],
                "operation_id": params["meta"]["operation_id"],
                "target_did": params["meta"]["target"]["did"],
                "body": params["body"],
            }
        raise AssertionError(f"Unexpected RPC method: {method}")


def _build_identity(hostname: str, path_segments: list[str]) -> Tuple[Dict[str, Any], Dict[str, Tuple[bytes, bytes]]]:
    return create_did_wba_document(
        hostname=hostname,
        path_segments=path_segments,
        enable_e2ee=True,
    )


def test_prekey_bundle_round_trip(tmp_path: Path) -> None:
    bob_doc, bob_keys = _build_identity("b.example", ["agents", "bob"])
    bob_did = bob_doc["id"]
    bob_signing_key, _ = _load_identity_keys(bob_keys)
    store = FileSignedPrekeyStore(tmp_path / "spk")
    manager = PrekeyManager(
        local_did=bob_did,
        static_key_agreement_id=f"{bob_did}#key-3",
        signing_private_key=bob_signing_key,
        signing_verification_method=f"{bob_did}#key-1",
        signed_prekey_store=store,
    )
    _, signed_prekey = manager.generate_signed_prekey("spk-bob-001", "2026-04-07T00:00:00Z")
    bundle = manager.build_prekey_bundle(
        signed_prekey,
        bundle_id="bundle-bob-001",
        created="2026-03-31T09:58:58Z",
    )

    PrekeyManager.verify_prekey_bundle(bundle, bob_doc)


def test_session_init_and_follow_up_round_trip(tmp_path: Path) -> None:
    alice_doc, alice_keys = _build_identity("a.example", ["agents", "alice"])
    bob_doc, bob_keys = _build_identity("b.example", ["agents", "bob"])
    alice_did = alice_doc["id"]
    bob_did = bob_doc["id"]
    alice_signing_key, alice_static_key = _load_identity_keys(alice_keys)
    bob_signing_key, bob_static_key = _load_identity_keys(bob_keys)
    bob_store = FileSignedPrekeyStore(tmp_path / "spk")
    bob_manager = PrekeyManager(
        local_did=bob_did,
        static_key_agreement_id=f"{bob_did}#key-3",
        signing_private_key=bob_signing_key,
        signing_verification_method=f"{bob_did}#key-1",
        signed_prekey_store=bob_store,
    )
    bob_spk_private, bob_spk = bob_manager.generate_signed_prekey(
        "spk-bob-001",
        "2026-04-07T00:00:00Z",
    )
    bundle = bob_manager.build_prekey_bundle(bob_spk, bundle_id="bundle-bob-001")
    metadata = DirectEnvelopeMetadata(
        sender_did=alice_did,
        recipient_did=bob_did,
        message_id="msg-init",
        profile="anp.direct.e2ee.v1",
        security_profile="direct-e2ee",
    )
    bob_metadata = DirectEnvelopeMetadata(
        sender_did=alice_did,
        recipient_did=bob_did,
        message_id="msg-init",
        profile="anp.direct.e2ee.v1",
        security_profile="direct-e2ee",
    )
    bob_static_public, _ = extract_x25519_public_key_from_did_document(
        bob_doc,
        f"{bob_did}#key-3",
    )
    session, _, init_body = DirectE2eeSession.initiate_session(
        metadata,
        "op-init",
        f"{alice_did}#key-3",
        alice_static_key,
        bundle,
        bob_static_public,
        bob_spk_private.public_key(),
        ApplicationPlaintext.new_text("text/plain", "hello bob"),
    )
    bob_session, plaintext = DirectE2eeSession.accept_incoming_init(
        bob_metadata,
        f"{bob_did}#key-3",
        bob_static_key,
        bob_spk_private,
        extract_x25519_public_key_from_did_document(alice_doc, f"{alice_did}#key-3")[0],
        init_body,
    )
    assert plaintext.text == "hello bob"

    follow_up_metadata = DirectEnvelopeMetadata(
        sender_did=alice_did,
        recipient_did=bob_did,
        message_id="msg-2",
        profile="anp.direct.e2ee.v1",
        security_profile="direct-e2ee",
    )
    _, cipher_body = DirectE2eeSession.encrypt_follow_up(
        session,
        follow_up_metadata,
        "op-2",
        ApplicationPlaintext.new_json("application/json", {"event": "wave"}),
    )
    decrypted = DirectE2eeSession.decrypt_follow_up(
        bob_session,
        follow_up_metadata,
        cipher_body,
        "application/json",
    )
    assert decrypted.payload == {"event": "wave"}


def test_client_send_and_pending_history_processing(tmp_path: Path) -> None:
    alice_doc, alice_keys = _build_identity("a.example", ["agents", "alice"])
    bob_doc, bob_keys = _build_identity("b.example", ["agents", "bob"])
    alice_did = alice_doc["id"]
    bob_did = bob_doc["id"]
    alice_signing_key, alice_static_key = _load_identity_keys(alice_keys)
    bob_signing_key, bob_static_key = _load_identity_keys(bob_keys)

    bob_signed_prekeys = FileSignedPrekeyStore(tmp_path / "bob-spk")
    bob_prekey_manager = PrekeyManager(
        local_did=bob_did,
        static_key_agreement_id=f"{bob_did}#key-3",
        signing_private_key=bob_signing_key,
        signing_verification_method=f"{bob_did}#key-1",
        signed_prekey_store=bob_signed_prekeys,
    )
    bob_spk_private, bob_spk = bob_prekey_manager.generate_signed_prekey(
        "spk-bob-001",
        "2026-04-07T00:00:00Z",
    )
    bundle = bob_prekey_manager.build_prekey_bundle(bob_spk, bundle_id="bundle-bob-001")

    rpc = FakeRpcClient(bundle.to_dict())
    alice_client = MessageServiceDirectE2eeClient(
        local_did=alice_did,
        signing_private_key=alice_signing_key,
        signing_verification_method=f"{alice_did}#key-1",
        static_key_agreement_private_key=alice_static_key,
        static_key_agreement_id=f"{alice_did}#key-3",
        rpc_client=rpc,
        did_document_resolver=lambda did: alice_doc if did == alice_did else bob_doc,
        session_store=FileSessionStore(tmp_path / "alice-sessions"),
        signed_prekey_store=FileSignedPrekeyStore(tmp_path / "alice-spk"),
    )
    init_response = alice_client.send_text(
        bob_did,
        "hello bob",
        operation_id="op-init",
        message_id="msg-init",
    )
    assert init_response["body"]["session_id"]

    follow_up_response = alice_client.send_json(
        bob_did,
        {"event": "wave"},
        operation_id="op-2",
        message_id="msg-2",
    )
    assert follow_up_response["body"]["ratchet_header"]["n"] == "0"

    bob_client = MessageServiceDirectE2eeClient(
        local_did=bob_did,
        signing_private_key=bob_signing_key,
        signing_verification_method=f"{bob_did}#key-1",
        static_key_agreement_private_key=bob_static_key,
        static_key_agreement_id=f"{bob_did}#key-3",
        rpc_client=rpc,
        did_document_resolver=lambda did: alice_doc if did == alice_did else bob_doc,
        session_store=FileSessionStore(tmp_path / "bob-sessions"),
        signed_prekey_store=bob_signed_prekeys,
    )

    pending = bob_client.process_incoming(
        {
            "meta": {
                "sender_did": alice_did,
                "target": {"kind": "agent", "did": bob_did},
                "message_id": "msg-2",
                "profile": "anp.direct.e2ee.v1",
                "security_profile": "direct-e2ee",
                "content_type": "application/anp-direct-cipher+json",
            },
            "body": follow_up_response["body"],
            "server_seq": 2,
        }
    )
    assert pending["state"] == "pending"

    decrypted = bob_client.process_incoming(
        {
            "meta": {
                "sender_did": alice_did,
                "target": {"kind": "agent", "did": bob_did},
                "message_id": "msg-init",
                "profile": "anp.direct.e2ee.v1",
                "security_profile": "direct-e2ee",
                "content_type": "application/anp-direct-init+json",
            },
            "body": init_response["body"],
            "server_seq": 1,
        }
    )
    assert decrypted["state"] == "decrypted"
    assert decrypted["plaintext"]["text"] == "hello bob"
    assert decrypted["pending_results"][0]["state"] == "decrypted"
