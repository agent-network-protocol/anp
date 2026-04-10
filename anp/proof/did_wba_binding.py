"""did:wba binding proof helpers.

[INPUT]: did_wba_binding objects, issuer DID documents, Ed25519 signing keys,
and binding metadata such as ``agent_did``, ``verification_method``,
``leaf_signature_key_b64u``, ``issued_at``, and ``expires_at``.
[OUTPUT]: Strict Appendix-B compliant did:wba binding objects and verification
results for MLS-related binding flows.
[POS]: This module provides the profile-specific P6 helper built on the shared
Appendix-B object proof core.

[PROTOCOL]:
1. Keep ``agent_did`` as the issuer DID for every binding proof.
2. Validate binding timestamps and DID authorization before accepting the
   binding object.
3. Reuse the shared object-proof verifier for all proof-field checks.
"""

from __future__ import annotations

import base64
import logging
from datetime import datetime, timezone
from typing import Any, Dict

from cryptography.hazmat.primitives.asymmetric import ed25519

from .object_proof import generate_object_proof, verify_object_proof

DID_WBA_BINDING_REQUIRED_FIELDS = (
    "agent_did",
    "verification_method",
    "leaf_signature_key_b64u",
    "issued_at",
    "expires_at",
)


def generate_did_wba_binding(
    *,
    agent_did: str,
    verification_method: str,
    leaf_signature_key_b64u: str,
    private_key: ed25519.Ed25519PrivateKey,
    issued_at: str | None = None,
    expires_at: str | None = None,
    proof_created: str | None = None,
) -> Dict[str, Any]:
    """Generate a strict did:wba binding object and proof."""
    issued_at_value = issued_at or _current_timestamp()
    expires_at_value = expires_at or issued_at_value
    binding = {
        "agent_did": agent_did,
        "verification_method": verification_method,
        "leaf_signature_key_b64u": leaf_signature_key_b64u,
        "issued_at": issued_at_value,
        "expires_at": expires_at_value,
    }
    _validate_binding_fields(binding)
    return generate_object_proof(
        binding,
        private_key,
        verification_method,
        issuer_did=agent_did,
        created=proof_created or issued_at_value,
    )


def verify_did_wba_binding(
    binding: Dict[str, Any],
    issuer_did_document: Dict[str, Any],
    *,
    now: datetime | None = None,
    expected_leaf_signature_key_b64u: str | None = None,
    expected_credential_identity: str | None = None,
) -> bool:
    """Verify a did:wba binding object against its issuer DID document."""
    try:
        _validate_binding_fields(binding)
        agent_did = binding["agent_did"]
        verification_method = binding["verification_method"]
        if verification_method.split("#", 1)[0] != agent_did:
            raise ValueError("verification_method must belong to agent_did")

        did_wba = _load_did_wba_helpers()
        if not did_wba["is_assertion_authorized"](issuer_did_document, verification_method):
            raise ValueError("verification_method is not authorized for assertionMethod")
        if not did_wba["find_verification_method"](issuer_did_document, verification_method):
            raise ValueError("verification_method was not found in the issuer DID document")

        if expected_leaf_signature_key_b64u is not None and (
            binding["leaf_signature_key_b64u"] != expected_leaf_signature_key_b64u
        ):
            raise ValueError("leaf_signature_key_b64u does not match the expected MLS leaf key")
        if expected_credential_identity is not None and expected_credential_identity != agent_did:
            raise ValueError("credential.identity does not match agent_did")

        current_time = now or datetime.now(timezone.utc)
        issued_at = _parse_rfc3339_timestamp(binding["issued_at"])
        expires_at = _parse_rfc3339_timestamp(binding["expires_at"])
        if issued_at > expires_at:
            raise ValueError("issued_at must not be later than expires_at")
        if current_time < issued_at or current_time > expires_at:
            raise ValueError("binding is outside the accepted validity window")

        verify_object_proof(
            binding,
            issuer_did=agent_did,
            issuer_did_document=issuer_did_document,
        )
        return True
    except Exception as exc:
        logging.error("did_wba_binding verification failed: %s", exc)
        return False


def _validate_binding_fields(binding: Dict[str, Any]) -> None:
    if not isinstance(binding, dict):
        raise ValueError("did_wba_binding must be a JSON object")
    missing_fields = [field for field in DID_WBA_BINDING_REQUIRED_FIELDS if field not in binding]
    if missing_fields:
        raise ValueError(
            "did_wba_binding is missing required fields: " + ", ".join(missing_fields)
        )
    _parse_rfc3339_timestamp(binding["issued_at"])
    _parse_rfc3339_timestamp(binding["expires_at"])
    _decode_base64url(binding["leaf_signature_key_b64u"])


def _decode_base64url(value: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError("leaf_signature_key_b64u must be a non-empty base64url string")
    padding = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding)
    except Exception as exc:
        raise ValueError("leaf_signature_key_b64u is not valid base64url data") from exc


def _parse_rfc3339_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"invalid RFC3339 timestamp: {value}") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"invalid RFC3339 timestamp: {value}")
    return parsed


def _current_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_did_wba_helpers() -> Dict[str, Any]:
    from anp.authentication.did_wba import (
        _find_verification_method,
        _is_assertion_method_authorized_in_document,
    )

    return {
        "find_verification_method": _find_verification_method,
        "is_assertion_authorized": _is_assertion_method_authorized_in_document,
    }


__all__ = [
    "DID_WBA_BINDING_REQUIRED_FIELDS",
    "generate_did_wba_binding",
    "verify_did_wba_binding",
]
