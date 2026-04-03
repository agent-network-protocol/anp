"""Reference message-service client for Direct E2EE."""

from __future__ import annotations

import base64
from typing import Any, Callable, Dict, Iterable, List

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from anp.e2e_encryption_hpke.key_pair import extract_x25519_public_key_from_did_document

from .errors import DirectE2eeError
from .models import (
    ApplicationPlaintext,
    DirectCipherBody,
    DirectEnvelopeMetadata,
    DirectInitBody,
    PrekeyBundle,
    RatchetHeader,
)
from .prekey_manager import PrekeyManager
from .session import DirectE2eeSession
from .store import FileSessionStore, FileSignedPrekeyStore

RPCClient = Callable[[str, Dict[str, Any]], Dict[str, Any]]
DIDResolver = Callable[[str], Dict[str, Any]]


class MessageServiceDirectE2eeClient:
    """Reference Direct E2EE client over the message-service RPC boundary."""

    def __init__(
        self,
        *,
        local_did: str,
        signing_private_key: Ed25519PrivateKey,
        signing_verification_method: str,
        static_key_agreement_private_key: X25519PrivateKey,
        static_key_agreement_id: str,
        rpc_client: RPCClient,
        did_document_resolver: DIDResolver,
        session_store: FileSessionStore,
        signed_prekey_store: FileSignedPrekeyStore,
    ) -> None:
        self._local_did = local_did
        self._rpc_client = rpc_client
        self._did_document_resolver = did_document_resolver
        self._session_store = session_store
        self._signed_prekey_store = signed_prekey_store
        self._static_key_agreement_private_key = static_key_agreement_private_key
        self._static_key_agreement_id = static_key_agreement_id
        self._prekey_manager = PrekeyManager(
            local_did=local_did,
            static_key_agreement_id=static_key_agreement_id,
            signing_private_key=signing_private_key,
            signing_verification_method=signing_verification_method,
            signed_prekey_store=signed_prekey_store,
            rpc_client=rpc_client,
        )
        self._pending_by_peer: Dict[str, List[Dict[str, Any]]] = {}

    def publish_prekey_bundle(self) -> Dict[str, Any]:
        bundle = self._prekey_manager.ensure_fresh_prekey_bundle()
        return self._prekey_manager.publish_prekey_bundle(bundle)

    def ensure_fresh_prekey_bundle(self) -> PrekeyBundle:
        return self._prekey_manager.ensure_fresh_prekey_bundle()

    def get_verified_prekey_bundle(self, target_did: str) -> PrekeyBundle:
        response = self._rpc_client(
            "direct.e2ee.get_prekey_bundle",
            {
                "meta": {
                    "anp_version": "1.0",
                    "profile": "anp.direct.e2ee.v1",
                    "security_profile": "transport-protected",
                    "sender_did": self._local_did,
                    "operation_id": f"op-get-prekey-{target_did}",
                },
                "body": {
                    "target_did": target_did,
                    "require_opk": False,
                },
            },
        )
        bundle = PrekeyBundle.from_dict(response["prekey_bundle"])
        did_document = self._did_document_resolver(target_did)
        self._prekey_manager.verify_prekey_bundle(bundle, did_document)
        return bundle

    def send_text(
        self,
        peer_did: str,
        text: str,
        *,
        operation_id: str,
        message_id: str,
    ) -> Dict[str, Any]:
        plaintext = ApplicationPlaintext.new_text("text/plain", text)
        return self._send_application_plaintext(peer_did, plaintext, operation_id, message_id)

    def send_json(
        self,
        peer_did: str,
        payload: Dict[str, Any],
        *,
        operation_id: str,
        message_id: str,
    ) -> Dict[str, Any]:
        plaintext = ApplicationPlaintext.new_json("application/json", payload)
        return self._send_application_plaintext(peer_did, plaintext, operation_id, message_id)

    def _send_application_plaintext(
        self,
        peer_did: str,
        plaintext: ApplicationPlaintext,
        operation_id: str,
        message_id: str,
    ) -> Dict[str, Any]:
        session = self._session_store.find_by_peer_did(peer_did)
        metadata = DirectEnvelopeMetadata(
            sender_did=self._local_did,
            recipient_did=peer_did,
            message_id=message_id,
            profile="anp.direct.e2ee.v1",
            security_profile="direct-e2ee",
        )
        if session is None:
            bundle = self.get_verified_prekey_bundle(peer_did)
            did_document = self._did_document_resolver(peer_did)
            recipient_static_public_key, _ = extract_x25519_public_key_from_did_document(
                did_document,
                bundle.static_key_agreement_id,
            )
            spk_bytes = base64.urlsafe_b64decode(
                bundle.signed_prekey.public_key_b64u
                + "=" * (-len(bundle.signed_prekey.public_key_b64u) % 4)
            )
            recipient_signed_prekey_public_key = X25519PublicKey.from_public_bytes(spk_bytes)
            session, _pending, body = DirectE2eeSession.initiate_session(
                metadata,
                operation_id,
                self._static_key_agreement_id,
                self._static_key_agreement_private_key,
                bundle,
                recipient_static_public_key,
                recipient_signed_prekey_public_key,
                plaintext,
            )
            self._session_store.save_session(session)
            return self._rpc_client(
                "direct.send",
                {
                    "meta": {
                        "anp_version": "1.0",
                        "profile": "anp.direct.e2ee.v1",
                        "security_profile": "direct-e2ee",
                        "sender_did": self._local_did,
                        "target": {"kind": "agent", "did": peer_did},
                        "operation_id": operation_id,
                        "message_id": message_id,
                        "content_type": "application/anp-direct-init+json",
                    },
                    "body": body.to_dict(),
                },
            )

        pending, body = DirectE2eeSession.encrypt_follow_up(
            session,
            metadata,
            operation_id,
            plaintext,
        )
        self._session_store.save_session(session)
        return self._rpc_client(
            "direct.send",
            {
                "meta": {
                    "anp_version": "1.0",
                    "profile": "anp.direct.e2ee.v1",
                    "security_profile": "direct-e2ee",
                    "sender_did": self._local_did,
                    "target": {"kind": "agent", "did": peer_did},
                    "operation_id": operation_id,
                    "message_id": message_id,
                    "content_type": "application/anp-direct-cipher+json",
                },
                "body": body.to_dict(),
            },
        )

    def process_incoming(self, notification_or_message_view: Dict[str, Any]) -> Dict[str, Any]:
        meta = notification_or_message_view["meta"]
        body = notification_or_message_view["body"]
        sender_did = meta["sender_did"]
        recipient_did = meta["target"]["did"]
        content_type = meta["content_type"]
        metadata = DirectEnvelopeMetadata(
            sender_did=sender_did,
            recipient_did=recipient_did,
            message_id=meta["message_id"],
            profile=meta["profile"],
            security_profile=meta["security_profile"],
        )
        if content_type == "application/anp-direct-init+json":
            init_body = DirectInitBody(**body)
            sender_document = self._did_document_resolver(sender_did)
            sender_static_public_key, _ = extract_x25519_public_key_from_did_document(
                sender_document,
                init_body.sender_static_key_agreement_id,
            )
            signed_prekey_private_key, _ = self._signed_prekey_store.load_signed_prekey(
                init_body.recipient_signed_prekey_id
            )
            session, plaintext = DirectE2eeSession.accept_incoming_init(
                metadata,
                self._static_key_agreement_id,
                self._static_key_agreement_private_key,
                signed_prekey_private_key,
                sender_static_public_key,
                init_body,
            )
            self._session_store.save_session(session)
            results = [{"state": "decrypted", "plaintext": plaintext.to_dict()}]
            for pending_message in self._pending_by_peer.pop(sender_did, []):
                results.append(self.process_incoming(pending_message))
            return {"state": "decrypted", "plaintext": plaintext.to_dict(), "pending_results": results[1:]}

        if content_type != "application/anp-direct-cipher+json":
            raise DirectE2eeError(f"Unsupported content type: {content_type}", "unsupported")

        cipher_body = DirectCipherBody(
            session_id=body["session_id"],
            suite=body["suite"],
            ratchet_header=RatchetHeader(**body["ratchet_header"]),
            ciphertext_b64u=body["ciphertext_b64u"],
        )
        try:
            session = self._session_store.load_session(cipher_body.session_id)
        except DirectE2eeError:
            self._pending_by_peer.setdefault(sender_did, []).append(notification_or_message_view)
            return {"state": "pending"}

        for content_type_guess in ("text/plain", "application/json"):
            try:
                plaintext = DirectE2eeSession.decrypt_follow_up(
                    session,
                    metadata,
                    cipher_body,
                    content_type_guess,
                )
                self._session_store.save_session(session)
                return {"state": "decrypted", "plaintext": plaintext.to_dict()}
            except Exception:
                continue
        return {"state": "undecryptable"}

    def decrypt_history_page(self, messages: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        ordered = sorted(
            list(messages),
            key=lambda item: (item.get("server_seq", 0), item.get("meta", {}).get("message_id", "")),
        )
        return [self.process_incoming(message) for message in ordered]
