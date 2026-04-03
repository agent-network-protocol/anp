"""Data models for Direct E2EE."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

MTI_DIRECT_E2EE_SUITE = "ANP-DIRECT-E2EE-X3DH-25519-CHACHA20POLY1305-SHA256-V1"


@dataclass
class SignedPrekey:
    key_id: str
    public_key_b64u: str
    expires_at: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PrekeyBundle:
    bundle_id: str
    owner_did: str
    suite: str
    static_key_agreement_id: str
    signed_prekey: SignedPrekey
    proof: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["signed_prekey"] = self.signed_prekey.to_dict()
        return payload

    @classmethod
    def from_dict(cls, value: Dict[str, Any]) -> "PrekeyBundle":
        return cls(
            bundle_id=value["bundle_id"],
            owner_did=value["owner_did"],
            suite=value["suite"],
            static_key_agreement_id=value["static_key_agreement_id"],
            signed_prekey=SignedPrekey(**value["signed_prekey"]),
            proof=value["proof"],
        )


@dataclass
class DirectEnvelopeMetadata:
    sender_did: str
    recipient_did: str
    message_id: str
    profile: str
    security_profile: str


@dataclass
class RatchetHeader:
    dh_pub_b64u: str
    pn: str
    n: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DirectInitBody:
    session_id: str
    suite: str
    sender_static_key_agreement_id: str
    recipient_bundle_id: str
    recipient_static_key_agreement_id: str
    recipient_signed_prekey_id: str
    sender_ephemeral_pub_b64u: str
    ciphertext_b64u: str
    recipient_one_time_prekey_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        if payload["recipient_one_time_prekey_id"] is None:
            payload.pop("recipient_one_time_prekey_id")
        return payload


@dataclass
class DirectCipherBody:
    session_id: str
    suite: str
    ratchet_header: RatchetHeader
    ciphertext_b64u: str

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["ratchet_header"] = self.ratchet_header.to_dict()
        return payload


@dataclass
class ApplicationPlaintext:
    application_content_type: str
    conversation_id: Optional[str] = None
    reply_to_message_id: Optional[str] = None
    annotations: Optional[Dict[str, Any]] = None
    text: Optional[str] = None
    payload: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        return {key: value for key, value in payload.items() if value is not None}

    @classmethod
    def new_text(cls, application_content_type: str, text: str) -> "ApplicationPlaintext":
        return cls(application_content_type=application_content_type, text=text)

    @classmethod
    def new_json(
        cls,
        application_content_type: str,
        payload: Dict[str, Any],
    ) -> "ApplicationPlaintext":
        return cls(application_content_type=application_content_type, payload=payload)

    @classmethod
    def from_dict(cls, value: Dict[str, Any]) -> "ApplicationPlaintext":
        return cls(**value)


@dataclass
class SkippedMessageKey:
    n: int
    message_key_b64u: str
    nonce_b64u: str


@dataclass
class DirectSessionState:
    session_id: str
    suite: str
    peer_did: str
    local_key_agreement_id: str
    peer_key_agreement_id: str
    root_key_b64u: str
    send_chain_key_b64u: str
    recv_chain_key_b64u: str
    ratchet_public_key_b64u: str
    peer_ratchet_public_key_b64u: Optional[str]
    send_n: int
    recv_n: int
    previous_send_chain_length: int
    skipped_message_keys: List[SkippedMessageKey] = field(default_factory=list)
    is_initiator: bool = True

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        return payload

    @classmethod
    def from_dict(cls, value: Dict[str, Any]) -> "DirectSessionState":
        skipped = [SkippedMessageKey(**item) for item in value.get("skipped_message_keys", [])]
        return cls(
            session_id=value["session_id"],
            suite=value["suite"],
            peer_did=value["peer_did"],
            local_key_agreement_id=value["local_key_agreement_id"],
            peer_key_agreement_id=value["peer_key_agreement_id"],
            root_key_b64u=value["root_key_b64u"],
            send_chain_key_b64u=value["send_chain_key_b64u"],
            recv_chain_key_b64u=value["recv_chain_key_b64u"],
            ratchet_public_key_b64u=value["ratchet_public_key_b64u"],
            peer_ratchet_public_key_b64u=value.get("peer_ratchet_public_key_b64u"),
            send_n=value["send_n"],
            recv_n=value["recv_n"],
            previous_send_chain_length=value["previous_send_chain_length"],
            skipped_message_keys=skipped,
            is_initiator=value["is_initiator"],
        )


@dataclass
class PendingOutboundRecord:
    operation_id: str
    message_id: str
    wire_content_type: str
    body_json: Dict[str, Any]
