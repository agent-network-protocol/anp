import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from anp.authentication.did_wba import create_did_wba_document
from anp.direct_e2ee import DirectE2eeSession, PrekeyManager
from anp.direct_e2ee.models import ApplicationPlaintext, DirectEnvelopeMetadata
from anp.direct_e2ee.store import FileSignedPrekeyStore
from anp.e2e_encryption_hpke.key_pair import extract_x25519_public_key_from_did_document


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def load_x25519_private_key(pem_bytes: bytes) -> X25519PrivateKey:
    key = serialization.load_pem_private_key(pem_bytes, password=None)
    assert isinstance(key, X25519PrivateKey)
    return key


def main() -> None:
    alice_doc, alice_keys = create_did_wba_document(
        "a.example",
        path_segments=["agents", "alice"],
        enable_e2ee=True,
    )
    bob_doc, bob_keys = create_did_wba_document(
        "b.example",
        path_segments=["agents", "bob"],
        enable_e2ee=True,
    )
    alice_did = alice_doc["id"]
    bob_did = bob_doc["id"]
    alice_static = load_x25519_private_key(alice_keys["key-3"][0])
    bob_static = load_x25519_private_key(bob_keys["key-3"][0])
    bob_signing = serialization.load_pem_private_key(bob_keys["key-1"][0], password=None)
    store = FileSignedPrekeyStore(Path("/tmp") / "anp_py_direct_e2ee_fixture")
    manager = PrekeyManager(
        local_did=bob_did,
        static_key_agreement_id=f"{bob_did}#key-3",
        signing_private_key=bob_signing,
        signing_verification_method=f"{bob_did}#key-1",
        signed_prekey_store=store,
    )
    bob_spk_private, bob_spk = manager.generate_signed_prekey(
        "spk-bob-001",
        "2026-04-07T00:00:00Z",
    )
    bundle = manager.build_prekey_bundle(
        bob_spk,
        bundle_id="bundle-bob-001",
        created="2026-03-31T09:58:58Z",
    )
    init_metadata = DirectEnvelopeMetadata(
        sender_did=alice_did,
        recipient_did=bob_did,
        message_id="msg-init",
        profile="anp.direct.e2ee.v1",
        security_profile="direct-e2ee",
    )
    alice_session, _pending, init_body = DirectE2eeSession.initiate_session(
        init_metadata,
        "op-init",
        f"{alice_did}#key-3",
        alice_static,
        bundle,
        extract_x25519_public_key_from_did_document(bob_doc, f"{bob_did}#key-3")[0],
        bob_spk_private.public_key(),
        ApplicationPlaintext.new_text("text/plain", "hello bob"),
    )
    follow_up_metadata = DirectEnvelopeMetadata(
        sender_did=alice_did,
        recipient_did=bob_did,
        message_id="msg-2",
        profile="anp.direct.e2ee.v1",
        security_profile="direct-e2ee",
    )
    _pending, cipher_body = DirectE2eeSession.encrypt_follow_up(
        alice_session,
        follow_up_metadata,
        "op-2",
        ApplicationPlaintext.new_json("application/json", {"event": "wave"}),
    )
    print(
        json.dumps(
            {
                "alice_did_document": alice_doc,
                "bob_did_document": bob_doc,
                "bundle": bundle.to_dict(),
                "bob_static_private_key_b64u": b64u(
                    bob_static.private_bytes_raw()
                ),
                "bob_signed_prekey_private_key_b64u": b64u(
                    bob_spk_private.private_bytes_raw()
                ),
                "init_metadata": init_metadata.__dict__,
                "follow_up_metadata": follow_up_metadata.__dict__,
                "init_body": init_body.to_dict(),
                "cipher_body": cipher_body.to_dict(),
                "init_plaintext": ApplicationPlaintext.new_text(
                    "text/plain", "hello bob"
                ).to_dict(),
                "follow_up_plaintext": ApplicationPlaintext.new_json(
                    "application/json", {"event": "wave"}
                ).to_dict(),
            }
        )
    )


if __name__ == "__main__":
    main()
