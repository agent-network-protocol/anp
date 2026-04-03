"""Direct E2EE session state machine."""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Dict, Iterable, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .errors import DirectE2eeError
from .models import (
    ApplicationPlaintext,
    DirectCipherBody,
    DirectEnvelopeMetadata,
    DirectInitBody,
    DirectSessionState,
    PendingOutboundRecord,
    PrekeyBundle,
    RatchetHeader,
    MTI_DIRECT_E2EE_SUITE,
)

MAX_SKIP = 1000


def _b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64u_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _canonical_json(data: Dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _hkdf(ikm: bytes, info: bytes, length: int) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=b"\x00" * 32,
        info=info,
    ).derive(ikm)


def _chain_step(chain_key: bytes) -> Tuple[bytes, bytes, bytes]:
    message_key = hashlib.sha256(b"ANP Direct E2EE v1 Message Key" + chain_key).digest()
    nonce = hashlib.sha256(b"ANP Direct E2EE v1 Message Nonce" + chain_key).digest()[:12]
    next_chain_key = hashlib.sha256(b"ANP Direct E2EE v1 Next Chain Key" + chain_key).digest()
    return message_key, nonce, next_chain_key


def _encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    return ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)


def _decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)


class DirectE2eeSession:
    """Build and process direct E2EE init / cipher messages."""

    @staticmethod
    def build_init_aad(
        metadata: DirectEnvelopeMetadata,
        body: DirectInitBody,
    ) -> bytes:
        return _canonical_json(
            {
                "sender_did": metadata.sender_did,
                "recipient_did": metadata.recipient_did,
                "suite": body.suite,
                "bundle_id": body.recipient_bundle_id,
                "sender_static_key_agreement_id": body.sender_static_key_agreement_id,
                "recipient_static_key_agreement_id": body.recipient_static_key_agreement_id,
                "recipient_signed_prekey_id": body.recipient_signed_prekey_id,
                "recipient_one_time_prekey_id": body.recipient_one_time_prekey_id,
                "session_id": body.session_id,
                "message_id": metadata.message_id,
                "profile": metadata.profile,
                "security_profile": metadata.security_profile,
            }
        )

    @staticmethod
    def build_message_aad(
        metadata: DirectEnvelopeMetadata,
        body: DirectCipherBody,
        application_content_type: str,
    ) -> bytes:
        return _canonical_json(
            {
                "sender_did": metadata.sender_did,
                "recipient_did": metadata.recipient_did,
                "session_id": body.session_id,
                "message_id": metadata.message_id,
                "profile": metadata.profile,
                "security_profile": metadata.security_profile,
                "application_content_type": application_content_type,
                "ratchet_header": body.ratchet_header.to_dict(),
            }
        )

    @staticmethod
    def initiate_session(
        metadata: DirectEnvelopeMetadata,
        operation_id: str,
        local_static_key_id: str,
        local_static_private_key: X25519PrivateKey,
        recipient_bundle: PrekeyBundle,
        recipient_static_public_key: X25519PublicKey,
        recipient_signed_prekey_public_key: X25519PublicKey,
        plaintext: ApplicationPlaintext,
    ) -> tuple[DirectSessionState, PendingOutboundRecord, DirectInitBody]:
        sender_ephemeral_private_key = X25519PrivateKey.generate()
        sender_ephemeral_public_key = sender_ephemeral_private_key.public_key()
        dh1 = local_static_private_key.exchange(recipient_signed_prekey_public_key)
        dh2 = sender_ephemeral_private_key.exchange(recipient_static_public_key)
        dh3 = sender_ephemeral_private_key.exchange(recipient_signed_prekey_public_key)
        initial_secret = _hkdf(dh1 + dh2 + dh3, b"ANP Direct E2EE v1 Initial Secret", 32)
        session_id = _b64u_encode(_hkdf(initial_secret, b"ANP Direct E2EE v1 Session ID", 16))
        body = DirectInitBody(
            session_id=session_id,
            suite=MTI_DIRECT_E2EE_SUITE,
            sender_static_key_agreement_id=local_static_key_id,
            recipient_bundle_id=recipient_bundle.bundle_id,
            recipient_static_key_agreement_id=recipient_bundle.static_key_agreement_id,
            recipient_signed_prekey_id=recipient_bundle.signed_prekey.key_id,
            recipient_one_time_prekey_id=None,
            sender_ephemeral_pub_b64u=_b64u_encode(
                sender_ephemeral_public_key.public_bytes_raw()
            ),
            ciphertext_b64u="",
        )
        aad = DirectE2eeSession.build_init_aad(metadata, body)
        init_key = _hkdf(initial_secret, b"ANP Direct E2EE v1 Init AEAD Key", 32)
        init_nonce = _hkdf(initial_secret, b"ANP Direct E2EE v1 Init AEAD Nonce", 12)
        ciphertext = _encrypt(
            init_key,
            init_nonce,
            json.dumps(plaintext.to_dict(), separators=(",", ":"), sort_keys=True).encode(
                "utf-8"
            ),
            aad,
        )
        body.ciphertext_b64u = _b64u_encode(ciphertext)
        session = DirectSessionState(
            session_id=session_id,
            suite=MTI_DIRECT_E2EE_SUITE,
            peer_did=metadata.recipient_did,
            local_key_agreement_id=local_static_key_id,
            peer_key_agreement_id=recipient_bundle.static_key_agreement_id,
            root_key_b64u=_b64u_encode(
                _hkdf(initial_secret, b"ANP Direct E2EE v1 Root Key", 32)
            ),
            send_chain_key_b64u=_b64u_encode(
                _hkdf(initial_secret, b"ANP Direct E2EE v1 Initiator Chain Key", 32)
            ),
            recv_chain_key_b64u=_b64u_encode(
                _hkdf(initial_secret, b"ANP Direct E2EE v1 Responder Chain Key", 32)
            ),
            ratchet_public_key_b64u=_b64u_encode(X25519PrivateKey.generate().public_key().public_bytes_raw()),
            peer_ratchet_public_key_b64u=None,
            send_n=0,
            recv_n=0,
            previous_send_chain_length=0,
            is_initiator=True,
        )
        pending = PendingOutboundRecord(
            operation_id=operation_id,
            message_id=metadata.message_id,
            wire_content_type="application/anp-direct-init+json",
            body_json=body.to_dict(),
        )
        return session, pending, body

    @staticmethod
    def accept_incoming_init(
        metadata: DirectEnvelopeMetadata,
        local_static_key_id: str,
        local_static_private_key: X25519PrivateKey,
        local_signed_prekey_private_key: X25519PrivateKey,
        sender_static_public_key: X25519PublicKey,
        body: DirectInitBody,
    ) -> tuple[DirectSessionState, ApplicationPlaintext]:
        sender_ephemeral_public_key = X25519PublicKey.from_public_bytes(
            _b64u_decode(body.sender_ephemeral_pub_b64u)
        )
        dh1 = local_signed_prekey_private_key.exchange(sender_static_public_key)
        dh2 = local_static_private_key.exchange(sender_ephemeral_public_key)
        dh3 = local_signed_prekey_private_key.exchange(sender_ephemeral_public_key)
        initial_secret = _hkdf(dh1 + dh2 + dh3, b"ANP Direct E2EE v1 Initial Secret", 32)
        aad = DirectE2eeSession.build_init_aad(metadata, body)
        init_key = _hkdf(initial_secret, b"ANP Direct E2EE v1 Init AEAD Key", 32)
        init_nonce = _hkdf(initial_secret, b"ANP Direct E2EE v1 Init AEAD Nonce", 12)
        plaintext = ApplicationPlaintext.from_dict(
            json.loads(
                _decrypt(
                    init_key,
                    init_nonce,
                    _b64u_decode(body.ciphertext_b64u),
                    aad,
                ).decode("utf-8")
            )
        )
        session = DirectSessionState(
            session_id=body.session_id,
            suite=MTI_DIRECT_E2EE_SUITE,
            peer_did=metadata.sender_did,
            local_key_agreement_id=local_static_key_id,
            peer_key_agreement_id=body.sender_static_key_agreement_id,
            root_key_b64u=_b64u_encode(
                _hkdf(initial_secret, b"ANP Direct E2EE v1 Root Key", 32)
            ),
            send_chain_key_b64u=_b64u_encode(
                _hkdf(initial_secret, b"ANP Direct E2EE v1 Responder Chain Key", 32)
            ),
            recv_chain_key_b64u=_b64u_encode(
                _hkdf(initial_secret, b"ANP Direct E2EE v1 Initiator Chain Key", 32)
            ),
            ratchet_public_key_b64u=_b64u_encode(X25519PrivateKey.generate().public_key().public_bytes_raw()),
            peer_ratchet_public_key_b64u=None,
            send_n=0,
            recv_n=0,
            previous_send_chain_length=0,
            is_initiator=False,
        )
        return session, plaintext

    @staticmethod
    def encrypt_follow_up(
        session: DirectSessionState,
        metadata: DirectEnvelopeMetadata,
        operation_id: str,
        plaintext: ApplicationPlaintext,
    ) -> tuple[PendingOutboundRecord, DirectCipherBody]:
        chain_key = _b64u_decode(session.send_chain_key_b64u)
        message_key, nonce, next_chain_key = _chain_step(chain_key)
        body = DirectCipherBody(
            session_id=session.session_id,
            suite=MTI_DIRECT_E2EE_SUITE,
            ratchet_header=RatchetHeader(
                dh_pub_b64u=session.ratchet_public_key_b64u,
                pn=str(session.previous_send_chain_length),
                n=str(session.send_n),
            ),
            ciphertext_b64u="",
        )
        aad = DirectE2eeSession.build_message_aad(
            metadata,
            body,
            plaintext.application_content_type,
        )
        ciphertext = _encrypt(
            message_key,
            nonce,
            json.dumps(plaintext.to_dict(), separators=(",", ":"), sort_keys=True).encode(
                "utf-8"
            ),
            aad,
        )
        body.ciphertext_b64u = _b64u_encode(ciphertext)
        session.send_chain_key_b64u = _b64u_encode(next_chain_key)
        session.send_n += 1
        pending = PendingOutboundRecord(
            operation_id=operation_id,
            message_id=metadata.message_id,
            wire_content_type="application/anp-direct-cipher+json",
            body_json=body.to_dict(),
        )
        return pending, body

    @staticmethod
    def decrypt_follow_up(
        session: DirectSessionState,
        metadata: DirectEnvelopeMetadata,
        body: DirectCipherBody,
        application_content_type: str,
    ) -> ApplicationPlaintext:
        n = int(body.ratchet_header.n)
        if n < session.recv_n:
            raise DirectE2eeError(
                "Duplicate direct-e2ee message number",
                "replay_detected",
            )
        if n - session.recv_n > MAX_SKIP:
            raise DirectE2eeError("MAX_SKIP exceeded", "replay_detected")
        chain_key = _b64u_decode(session.recv_chain_key_b64u)
        for _ in range(session.recv_n, n):
            _, _, chain_key = _chain_step(chain_key)
        message_key, nonce, next_chain_key = _chain_step(chain_key)
        aad = DirectE2eeSession.build_message_aad(
            metadata,
            body,
            application_content_type,
        )
        plaintext = ApplicationPlaintext.from_dict(
            json.loads(
                _decrypt(
                    message_key,
                    nonce,
                    _b64u_decode(body.ciphertext_b64u),
                    aad,
                ).decode("utf-8")
            )
        )
        session.recv_chain_key_b64u = _b64u_encode(next_chain_key)
        session.recv_n = n + 1
        session.peer_ratchet_public_key_b64u = body.ratchet_header.dh_pub_b64u
        return plaintext
