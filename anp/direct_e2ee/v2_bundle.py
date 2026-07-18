"""P5 v2 PreKey Bundle proof and device-binding helpers."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping, Optional

import jcs
from cryptography.hazmat.primitives.asymmetric import ed25519

from anp.authentication import PROFILE_DIRECT_E2EE_V2, find_eligible_device
from anp.proof import generate_object_proof, verify_object_proof

from .v2_errors import DirectE2eeV2Error
from .v2_models import (
    DIRECT_E2EE_PROFILE_V2,
    MTI_DIRECT_E2EE_SUITE_V2,
    TRANSPORT_PROTECTED_SECURITY_PROFILE,
    V2KeyServiceMetadata,
    V2OneTimePrekey,
    V2PrekeyBundle,
    V2SignedPrekey,
    V2Target,
)


def build_prekey_bundle_v2(
    bundle_id: str,
    owner_did: str,
    owner_device_id: str,
    static_key_agreement_id: str,
    signed_prekey: V2SignedPrekey,
    signing_private_key: ed25519.Ed25519PrivateKey,
    verification_method: str,
    created: Optional[str] = None,
) -> V2PrekeyBundle:
    signed_prekey.validate()
    unsigned = {
        "bundle_id": bundle_id,
        "owner_did": owner_did,
        "owner_device_id": owner_device_id,
        "suite": MTI_DIRECT_E2EE_SUITE_V2,
        "static_key_agreement_id": static_key_agreement_id,
        "signed_prekey": signed_prekey.to_dict(),
    }
    signed = generate_object_proof(
        unsigned,
        signing_private_key,
        verification_method,
        issuer_did=owner_did,
        created=created,
    )
    result = V2PrekeyBundle(
        bundle_id=bundle_id,
        owner_did=owner_did,
        owner_device_id=owner_device_id,
        suite=MTI_DIRECT_E2EE_SUITE_V2,
        static_key_agreement_id=static_key_agreement_id,
        signed_prekey=signed_prekey,
        proof=signed["proof"],
    )
    result.validate_structure()
    return result


def signed_bundle_object_jcs_v2(bundle: V2PrekeyBundle) -> bytes:
    value = bundle.to_dict()
    value.pop("proof")
    return jcs.canonicalize(value)


def verify_prekey_bundle_v2(
    bundle: V2PrekeyBundle,
    did_document: Mapping[str, Any],
    now: datetime,
) -> None:
    bundle.validate_structure()
    if did_document.get("id") != bundle.owner_did:
        raise DirectE2eeV2Error("owner_did must match the issuer DID document")
    try:
        device = find_eligible_device(
            dict(did_document), bundle.owner_device_id, PROFILE_DIRECT_E2EE_V2
        )
    except Exception as exc:
        raise DirectE2eeV2Error("invalid owner Device Manifest") from exc
    if device is None:
        raise DirectE2eeV2Error("owner device is not P5 v2 eligible")
    if device.e2ee_key_id != bundle.static_key_agreement_id:
        raise DirectE2eeV2Error(
            "static_key_agreement_id must equal the device e2ee_key_id"
        )
    if bundle.proof.get("verificationMethod") != device.signing_key_id:
        raise DirectE2eeV2Error(
            "proof.verificationMethod must equal the device signing_key_id"
        )
    try:
        expires_at = datetime.fromisoformat(
            bundle.signed_prekey.expires_at.replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise DirectE2eeV2Error("signed_prekey.expires_at must be RFC3339") from exc
    effective_now = now if now.tzinfo is not None else now.replace(tzinfo=timezone.utc)
    if expires_at <= effective_now:
        raise DirectE2eeV2Error("signed prekey is expired")
    try:
        verify_object_proof(
            bundle.to_dict(),
            issuer_did=bundle.owner_did,
            issuer_did_document=dict(did_document),
        )
    except Exception as exc:
        raise DirectE2eeV2Error("bundle Object Proof is invalid") from exc


def key_service_metadata_v2(
    sender_did: str,
    sender_device_id: str,
    service_did: str,
    operation_id: str,
) -> V2KeyServiceMetadata:
    return V2KeyServiceMetadata(
        profile=DIRECT_E2EE_PROFILE_V2,
        security_profile=TRANSPORT_PROTECTED_SECURITY_PROFILE,
        sender_did=sender_did,
        sender_device_id=sender_device_id,
        target=V2Target(kind="service", did=service_did),
        operation_id=operation_id,
    )


def parse_one_time_prekeys(value: Any) -> tuple[V2OneTimePrekey, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not value:
        raise DirectE2eeV2Error("one_time_prekeys must be omitted or non-empty")
    return tuple(V2OneTimePrekey.from_dict(entry) for entry in value)
