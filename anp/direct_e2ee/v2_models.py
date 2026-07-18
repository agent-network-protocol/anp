"""Side-by-side wire models for ``anp.direct.e2ee.v2``.

These types do not alter or implicitly upgrade the existing P5 v1 session API.
"""

from __future__ import annotations

import base64
import re
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Mapping, Optional

from .v2_errors import DirectE2eeV2Error

DIRECT_E2EE_PROFILE_V2 = "anp.direct.e2ee.v2"
DIRECT_E2EE_SECURITY_PROFILE = "direct-e2ee"
TRANSPORT_PROTECTED_SECURITY_PROFILE = "transport-protected"
CONTENT_TYPE_DIRECT_INIT_V2 = "application/anp-direct-init+json"
CONTENT_TYPE_DIRECT_CIPHER_V2 = "application/anp-direct-cipher+json"
MTI_DIRECT_E2EE_SUITE_V2 = "ANP-DIRECT-E2EE-X3DH-25519-CHACHA20POLY1305-SHA256-V1"


def _strict(value: Mapping[str, Any], fields: set[str], subject: str) -> None:
    if set(value) != fields:
        raise DirectE2eeV2Error(
            f"{subject} must contain exactly {', '.join(sorted(fields))}"
        )


def _optional_fields(
    value: Mapping[str, Any], required: set[str], optional: set[str], subject: str
) -> None:
    if not required.issubset(value) or not set(value).issubset(required | optional):
        raise DirectE2eeV2Error(f"invalid fields in {subject}")
    for field in optional.intersection(value):
        if value[field] is None:
            raise DirectE2eeV2Error(
                f"{subject}.{field} must be omitted rather than null"
            )


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise DirectE2eeV2Error(f"{field} must be a non-empty string")
    return value


def _x25519_b64u(value: Any, field: str) -> None:
    _fixed_b64u(value, field, 32)


def _fixed_b64u(value: Any, field: str, expected_length: int) -> None:
    decoded = _decode_b64u(value, field)
    if len(decoded) != expected_length:
        raise DirectE2eeV2Error(f"{field} must encode {expected_length} bytes")


def _b64u(value: Any, field: str) -> None:
    _decode_b64u(value, field)


def _decode_b64u(value: Any, field: str) -> bytes:
    text = _text(value, field)
    if "=" in text or re.fullmatch(r"[A-Za-z0-9_-]+", text) is None:
        raise DirectE2eeV2Error(f"{field} must be unpadded base64url")
    try:
        decoded = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except Exception as exc:
        raise DirectE2eeV2Error(f"{field} must be base64url") from exc
    return decoded


def _rfc3339(value: Any, field: str) -> None:
    text = _text(value, field)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise DirectE2eeV2Error(f"{field} must be RFC3339") from exc
    if "T" not in text or parsed.tzinfo is None:
        raise DirectE2eeV2Error(f"{field} must be RFC3339")


@dataclass(frozen=True)
class V2SignedPrekey:
    key_id: str
    public_key_b64u: str
    expires_at: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def validate(self) -> None:
        _text(self.key_id, "signed_prekey.key_id")
        _x25519_b64u(self.public_key_b64u, "signed_prekey.public_key_b64u")
        _rfc3339(self.expires_at, "signed_prekey.expires_at")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "V2SignedPrekey":
        _strict(value, {"key_id", "public_key_b64u", "expires_at"}, "signed_prekey")
        result = cls(**value)
        result.validate()
        return result


@dataclass(frozen=True)
class V2OneTimePrekey:
    key_id: str
    public_key_b64u: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def validate(self) -> None:
        _text(self.key_id, "one_time_prekey.key_id")
        _x25519_b64u(self.public_key_b64u, "one_time_prekey.public_key_b64u")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "V2OneTimePrekey":
        _strict(value, {"key_id", "public_key_b64u"}, "one_time_prekey")
        result = cls(**value)
        result.validate()
        return result


@dataclass(frozen=True)
class V2PrekeyBundle:
    bundle_id: str
    owner_did: str
    owner_device_id: str
    suite: str
    static_key_agreement_id: str
    signed_prekey: V2SignedPrekey
    proof: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["signed_prekey"] = self.signed_prekey.to_dict()
        return result

    def validate_structure(self) -> None:
        for name in (
            "bundle_id",
            "owner_did",
            "owner_device_id",
            "static_key_agreement_id",
        ):
            _text(getattr(self, name), f"prekey_bundle.{name}")
        if self.suite != MTI_DIRECT_E2EE_SUITE_V2:
            raise DirectE2eeV2Error("unsupported P5 v2 suite")
        self.signed_prekey.validate()
        for field in (
            "type",
            "cryptosuite",
            "verificationMethod",
            "proofPurpose",
            "created",
            "proofValue",
        ):
            _text(self.proof.get(field), f"prekey_bundle.proof.{field}")
        if (
            self.proof["type"] != "DataIntegrityProof"
            or self.proof["cryptosuite"] != "eddsa-jcs-2022"
            or self.proof["proofPurpose"] != "assertionMethod"
        ):
            raise DirectE2eeV2Error("invalid Appendix-B Object Proof profile")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "V2PrekeyBundle":
        _strict(
            value,
            {
                "bundle_id",
                "owner_did",
                "owner_device_id",
                "suite",
                "static_key_agreement_id",
                "signed_prekey",
                "proof",
            },
            "prekey_bundle",
        )
        if not isinstance(value["proof"], dict):
            raise DirectE2eeV2Error("prekey_bundle.proof must be an object")
        result = cls(
            bundle_id=value["bundle_id"],
            owner_did=value["owner_did"],
            owner_device_id=value["owner_device_id"],
            suite=value["suite"],
            static_key_agreement_id=value["static_key_agreement_id"],
            signed_prekey=V2SignedPrekey.from_dict(value["signed_prekey"]),
            proof=dict(value["proof"]),
        )
        result.validate_structure()
        return result


@dataclass(frozen=True)
class V2Target:
    kind: str
    did: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "V2Target":
        _strict(value, {"kind", "did"}, "meta.target")
        return cls(
            kind=_text(value["kind"], "meta.target.kind"),
            did=_text(value["did"], "meta.target.did"),
        )


@dataclass(frozen=True)
class V2KeyServiceMetadata:
    profile: str
    security_profile: str
    sender_did: str
    sender_device_id: str
    target: V2Target
    operation_id: str
    anp_version: Optional[str] = None
    created_at: Optional[str] = None

    def validate(self) -> None:
        if self.profile != DIRECT_E2EE_PROFILE_V2:
            raise DirectE2eeV2Error("meta.profile must equal anp.direct.e2ee.v2")
        if self.security_profile != TRANSPORT_PROTECTED_SECURITY_PROFILE:
            raise DirectE2eeV2Error(
                "key service security_profile must be transport-protected"
            )
        if self.target.kind != "service":
            raise DirectE2eeV2Error("key service target.kind must be service")
        for name, value in (
            ("sender_did", self.sender_did),
            ("sender_device_id", self.sender_device_id),
            ("operation_id", self.operation_id),
        ):
            _text(value, f"meta.{name}")
        _text(self.target.did, "meta.target.did")
        if self.anp_version is not None:
            _text(self.anp_version, "meta.anp_version")
        if self.created_at is not None:
            _rfc3339(self.created_at, "meta.created_at")

    def to_dict(self) -> dict[str, Any]:
        result = {
            "profile": self.profile,
            "security_profile": self.security_profile,
            "sender_did": self.sender_did,
            "sender_device_id": self.sender_device_id,
            "target": self.target.to_dict(),
            "operation_id": self.operation_id,
        }
        if self.anp_version is not None:
            result["anp_version"] = _text(self.anp_version, "meta.anp_version")
        if self.created_at is not None:
            result["created_at"] = _text(self.created_at, "meta.created_at")
        return result

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "V2KeyServiceMetadata":
        required = {
            "profile",
            "security_profile",
            "sender_did",
            "sender_device_id",
            "target",
            "operation_id",
        }
        _optional_fields(
            value, required, {"anp_version", "created_at"}, "key service meta"
        )
        result = cls(
            profile=value["profile"],
            security_profile=value["security_profile"],
            sender_did=value["sender_did"],
            sender_device_id=value["sender_device_id"],
            target=V2Target.from_dict(value["target"]),
            operation_id=value["operation_id"],
            anp_version=value.get("anp_version"),
            created_at=value.get("created_at"),
        )
        result.validate()
        return result


@dataclass(frozen=True)
class V2DirectMetadata:
    profile: str
    security_profile: str
    sender_did: str
    sender_device_id: str
    target: V2Target
    recipient_device_id: str
    operation_id: str
    message_id: str
    content_type: str
    anp_version: Optional[str] = None
    created_at: Optional[str] = None

    def validate(self) -> None:
        if (
            self.profile != DIRECT_E2EE_PROFILE_V2
            or self.security_profile != DIRECT_E2EE_SECURITY_PROFILE
        ):
            raise DirectE2eeV2Error("invalid direct.send profile binding")
        if self.target.kind != "agent":
            raise DirectE2eeV2Error("direct.send target.kind must be agent")
        if self.content_type not in {
            CONTENT_TYPE_DIRECT_INIT_V2,
            CONTENT_TYPE_DIRECT_CIPHER_V2,
        }:
            raise DirectE2eeV2Error("content_type is not a P5 v2 MTI wire object")
        for name, value in (
            ("sender_did", self.sender_did),
            ("sender_device_id", self.sender_device_id),
            ("recipient_device_id", self.recipient_device_id),
            ("operation_id", self.operation_id),
            ("message_id", self.message_id),
        ):
            _text(value, f"meta.{name}")
        _text(self.target.did, "meta.target.did")
        if self.operation_id != self.message_id:
            raise DirectE2eeV2Error("meta.operation_id must equal meta.message_id")
        if self.anp_version is not None:
            _text(self.anp_version, "meta.anp_version")
        if self.created_at is not None:
            _rfc3339(self.created_at, "meta.created_at")

    def to_dict(self) -> dict[str, Any]:
        result = {
            "profile": self.profile,
            "security_profile": self.security_profile,
            "sender_did": self.sender_did,
            "sender_device_id": self.sender_device_id,
            "target": self.target.to_dict(),
            "recipient_device_id": self.recipient_device_id,
            "operation_id": self.operation_id,
            "message_id": self.message_id,
            "content_type": self.content_type,
        }
        if self.anp_version is not None:
            result["anp_version"] = _text(self.anp_version, "meta.anp_version")
        if self.created_at is not None:
            result["created_at"] = _text(self.created_at, "meta.created_at")
        return result

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "V2DirectMetadata":
        required = {
            "profile",
            "security_profile",
            "sender_did",
            "sender_device_id",
            "target",
            "recipient_device_id",
            "operation_id",
            "message_id",
            "content_type",
        }
        _optional_fields(value, required, {"anp_version", "created_at"}, "direct meta")
        result = cls(
            profile=value["profile"],
            security_profile=value["security_profile"],
            sender_did=value["sender_did"],
            sender_device_id=value["sender_device_id"],
            target=V2Target.from_dict(value["target"]),
            recipient_device_id=value["recipient_device_id"],
            operation_id=value["operation_id"],
            message_id=value["message_id"],
            content_type=value["content_type"],
            anp_version=value.get("anp_version"),
            created_at=value.get("created_at"),
        )
        result.validate()
        return result


@dataclass(frozen=True)
class V2RatchetHeader:
    dh_pub_b64u: str
    pn: str
    n: str

    def validate(self) -> None:
        _x25519_b64u(self.dh_pub_b64u, "ratchet_header.dh_pub_b64u")
        if not self.pn.isdecimal() or not self.n.isdecimal():
            raise DirectE2eeV2Error("ratchet counters must be decimal strings")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class V2DirectInitBody:
    session_id: str
    suite: str
    sender_static_key_agreement_id: str
    recipient_bundle_id: str
    recipient_signed_prekey_id: str
    sender_ephemeral_pub_b64u: str
    ciphertext_b64u: str
    recipient_one_time_prekey_id: Optional[str] = None

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "V2DirectInitBody":
        required = {
            "session_id",
            "suite",
            "sender_static_key_agreement_id",
            "recipient_bundle_id",
            "recipient_signed_prekey_id",
            "sender_ephemeral_pub_b64u",
            "ciphertext_b64u",
        }
        _optional_fields(
            value, required, {"recipient_one_time_prekey_id"}, "direct init body"
        )
        result = cls(**value)
        result.validate()
        return result

    def validate(self) -> None:
        if self.suite != MTI_DIRECT_E2EE_SUITE_V2:
            raise DirectE2eeV2Error("unsupported P5 v2 suite")
        _fixed_b64u(self.session_id, "body.session_id", 16)
        _x25519_b64u(self.sender_ephemeral_pub_b64u, "body.sender_ephemeral_pub_b64u")
        _b64u(self.ciphertext_b64u, "body.ciphertext_b64u")
        for name in (
            "sender_static_key_agreement_id",
            "recipient_bundle_id",
            "recipient_signed_prekey_id",
        ):
            _text(getattr(self, name), f"body.{name}")
        if self.recipient_one_time_prekey_id is not None:
            _text(
                self.recipient_one_time_prekey_id, "body.recipient_one_time_prekey_id"
            )

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        if self.recipient_one_time_prekey_id is None:
            result.pop("recipient_one_time_prekey_id")
        return result


@dataclass(frozen=True)
class V2DirectCipherBody:
    session_id: str
    ratchet_header: V2RatchetHeader
    ciphertext_b64u: str
    suite: Optional[str] = None

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "V2DirectCipherBody":
        required = {"session_id", "ratchet_header", "ciphertext_b64u"}
        _optional_fields(value, required, {"suite"}, "direct cipher body")
        raw_header = value["ratchet_header"]
        _strict(raw_header, {"dh_pub_b64u", "pn", "n"}, "ratchet_header")
        result = cls(
            session_id=value["session_id"],
            ratchet_header=V2RatchetHeader(**raw_header),
            ciphertext_b64u=value["ciphertext_b64u"],
            suite=value.get("suite"),
        )
        result.validate()
        return result

    def validate(self) -> None:
        _fixed_b64u(self.session_id, "body.session_id", 16)
        _b64u(self.ciphertext_b64u, "body.ciphertext_b64u")
        if self.suite is not None and self.suite != MTI_DIRECT_E2EE_SUITE_V2:
            raise DirectE2eeV2Error("cipher suite does not match the P5 v2 MTI suite")
        self.ratchet_header.validate()

    def to_dict(self) -> dict[str, Any]:
        result = {
            "session_id": self.session_id,
            "ratchet_header": self.ratchet_header.to_dict(),
            "ciphertext_b64u": self.ciphertext_b64u,
        }
        if self.suite is not None:
            result["suite"] = self.suite
        return result


@dataclass(frozen=True)
class V2ApplicationPlaintext:
    application_content_type: str
    logical_message_id: Optional[str] = None
    conversation_id: Optional[str] = None
    reply_to_message_id: Optional[str] = None
    annotations: Optional[dict[str, Any]] = None
    text: Optional[str] = None
    payload: Optional[dict[str, Any]] = None
    payload_b64u: Optional[str] = None

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "V2ApplicationPlaintext":
        required = {"application_content_type"}
        optional = {
            "logical_message_id",
            "conversation_id",
            "reply_to_message_id",
            "annotations",
            "text",
            "payload",
            "payload_b64u",
        }
        _optional_fields(value, required, optional, "ApplicationPlaintext")
        result = cls(**value)
        result.validate()
        return result

    def validate(self) -> None:
        _text(self.application_content_type, "application_content_type")
        for name in ("logical_message_id", "conversation_id", "reply_to_message_id"):
            value = getattr(self, name)
            if value is not None:
                _text(value, name)
        if (
            sum(
                value is not None
                for value in (self.text, self.payload, self.payload_b64u)
            )
            != 1
        ):
            raise DirectE2eeV2Error("exactly one plaintext bearer must be present")
        if self.text is not None:
            _text(self.text, "text")
        if self.payload is not None and not isinstance(self.payload, dict):
            raise DirectE2eeV2Error("payload must be an object")
        if self.annotations is not None and not isinstance(self.annotations, dict):
            raise DirectE2eeV2Error("annotations must be an object")
        if self.application_content_type == "text/plain" and self.text is None:
            raise DirectE2eeV2Error("text/plain requires the text bearer")
        if self.application_content_type in {
            "application/json",
            "application/anp-attachment-manifest+json",
        } and self.payload is None:
            raise DirectE2eeV2Error(
                f"{self.application_content_type} requires the payload bearer"
            )
        if self.payload_b64u is not None:
            _b64u(self.payload_b64u, "payload_b64u")

    def to_dict(self) -> dict[str, Any]:
        return {key: value for key, value in asdict(self).items() if value is not None}
