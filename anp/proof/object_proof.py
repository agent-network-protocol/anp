"""Strict Appendix-B object proof helpers.

[INPUT]: JSON objects that carry top-level ``proof`` members, issuer DID values,
issuer DID documents, Ed25519 signing keys, and proof metadata such as
``verificationMethod`` and ``created`` timestamps.
[OUTPUT]: Appendix-B compliant object-proof documents and structured verification
results for profile-specific helpers such as group receipts, prekey bundles,
and did:wba bindings.
[POS]: This module is the strict shared proof core for ANP object-level proofs
that follow Appendix B of the core binding specification.

[PROTOCOL]:
1. Keep proof generation and verification aligned with Appendix B.
2. Remove only the top-level ``proof`` member when rebuilding the protected
   document.
3. Check issuer DID ownership and ``assertionMethod`` authorization during
   verification.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict

import base58
from cryptography.hazmat.primitives.asymmetric import ed25519

from .proof import CRYPTOSUITE_EDDSA_JCS_2022, PROOF_TYPE_DATA_INTEGRITY, _compute_signing_input

OBJECT_PROOF_PURPOSE = "assertionMethod"
OBJECT_PROOF_SIGNATURE_MULTIBASE_PREFIX = "z"
OBJECT_PROOF_REQUIRED_FIELDS = (
    "type",
    "cryptosuite",
    "verificationMethod",
    "proofPurpose",
    "created",
    "proofValue",
)


class ObjectProofError(ValueError):
    """Raised when Appendix-B object proof validation fails."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ObjectProofVerificationResult:
    """Successful Appendix-B object proof verification output."""

    issuer_did: str
    verification_method_id: str
    verification_method: Dict[str, Any]


def generate_object_proof(
    document: Dict[str, Any],
    private_key: ed25519.Ed25519PrivateKey,
    verification_method: str,
    *,
    issuer_did: str,
    created: str | None = None,
) -> Dict[str, Any]:
    """Generate an Appendix-B compliant object proof."""
    _ensure_json_object(document, code="document_invalid")
    _ensure_ed25519_private_key(private_key)
    _ensure_verification_method_matches_issuer(verification_method, issuer_did)
    created_value = _normalize_rfc3339_timestamp(created)

    proof_options = {
        "type": PROOF_TYPE_DATA_INTEGRITY,
        "cryptosuite": CRYPTOSUITE_EDDSA_JCS_2022,
        "verificationMethod": verification_method,
        "proofPurpose": OBJECT_PROOF_PURPOSE,
        "created": created_value,
    }
    signing_input = _compute_signing_input(_document_without_top_level_proof(document), proof_options)
    signature = private_key.sign(signing_input)

    result = copy.deepcopy(document)
    result["proof"] = {
        **proof_options,
        "proofValue": _encode_signature_multibase(signature),
    }
    return result


def verify_object_proof(
    document: Dict[str, Any],
    *,
    issuer_did: str,
    issuer_did_document: Dict[str, Any],
) -> ObjectProofVerificationResult:
    """Verify an Appendix-B object proof against the issuer DID document."""
    _ensure_json_object(document, code="document_invalid")
    _ensure_json_object(issuer_did_document, code="issuer_document_invalid")
    if issuer_did_document.get("id") != issuer_did:
        raise ObjectProofError(
            "issuer_document_mismatch",
            "issuer DID document id does not match issuer DID",
        )

    did_wba = _load_did_wba_helpers()
    if issuer_did.startswith("did:wba:") and not did_wba["validate_did_document_binding"](
        issuer_did_document,
        verify_proof=False,
    ):
        raise ObjectProofError(
            "issuer_document_binding_invalid",
            "issuer DID document binding validation failed",
        )

    proof = document.get("proof")
    if not isinstance(proof, dict):
        raise ObjectProofError("proof_missing", "document has no top-level proof object")
    for field in OBJECT_PROOF_REQUIRED_FIELDS:
        value = proof.get(field)
        if not isinstance(value, str) or not value:
            raise ObjectProofError(
                "proof_field_missing",
                f"proof field is required: {field}",
            )

    if proof["type"] != PROOF_TYPE_DATA_INTEGRITY:
        raise ObjectProofError("proof_type_invalid", "proof.type must be DataIntegrityProof")
    if proof["cryptosuite"] != CRYPTOSUITE_EDDSA_JCS_2022:
        raise ObjectProofError(
            "proof_cryptosuite_invalid",
            "proof.cryptosuite must be eddsa-jcs-2022",
        )
    if proof["proofPurpose"] != OBJECT_PROOF_PURPOSE:
        raise ObjectProofError(
            "proof_purpose_invalid",
            "proof.proofPurpose must be assertionMethod",
        )

    verification_method_id = proof["verificationMethod"]
    _ensure_verification_method_matches_issuer(verification_method_id, issuer_did)
    _parse_rfc3339_timestamp(proof["created"])

    if not did_wba["is_assertion_authorized"](issuer_did_document, verification_method_id):
        raise ObjectProofError(
            "verification_method_unauthorized",
            "proof.verificationMethod is not authorized for assertionMethod",
        )
    method = did_wba["find_verification_method"](issuer_did_document, verification_method_id)
    if not method:
        raise ObjectProofError(
            "verification_method_missing",
            "proof.verificationMethod was not found in the issuer DID document",
        )

    from anp.authentication.verification_methods import create_verification_method

    verifier = create_verification_method(method)
    public_key = getattr(verifier, "public_key", None)
    if not isinstance(public_key, ed25519.Ed25519PublicKey):
        raise ObjectProofError(
            "verification_method_key_invalid",
            "Appendix-B object proof requires an Ed25519 verification method",
        )

    signature = _decode_signature_multibase(proof["proofValue"])
    proof_options = {key: value for key, value in proof.items() if key != "proofValue"}
    signing_input = _compute_signing_input(
        _document_without_top_level_proof(document),
        proof_options,
    )
    try:
        public_key.verify(signature, signing_input)
    except Exception as exc:
        raise ObjectProofError(
            "proof_signature_invalid",
            "object proof signature verification failed",
        ) from exc

    return ObjectProofVerificationResult(
        issuer_did=issuer_did,
        verification_method_id=verification_method_id,
        verification_method=copy.deepcopy(method),
    )


def _document_without_top_level_proof(document: Dict[str, Any]) -> Dict[str, Any]:
    return {key: copy.deepcopy(value) for key, value in document.items() if key != "proof"}


def _encode_signature_multibase(signature: bytes) -> str:
    return OBJECT_PROOF_SIGNATURE_MULTIBASE_PREFIX + base58.b58encode(signature).decode("ascii")


def _decode_signature_multibase(value: str) -> bytes:
    if not isinstance(value, str) or not value.startswith(OBJECT_PROOF_SIGNATURE_MULTIBASE_PREFIX):
        raise ObjectProofError(
            "proof_value_invalid",
            "proof.proofValue must use base58-btc multibase encoding",
        )
    try:
        signature = base58.b58decode(value[1:])
    except Exception as exc:
        raise ObjectProofError(
            "proof_value_invalid",
            "proof.proofValue is not valid base58-btc multibase data",
        ) from exc
    if len(signature) != 64:
        raise ObjectProofError(
            "proof_value_invalid",
            "proof.proofValue must decode to a 64-byte Ed25519 signature",
        )
    return signature


def _ensure_ed25519_private_key(private_key: Any) -> None:
    if not isinstance(private_key, ed25519.Ed25519PrivateKey):
        raise ObjectProofError(
            "private_key_invalid",
            "Appendix-B object proof requires an Ed25519 private key",
        )


def _ensure_json_object(value: Any, *, code: str) -> None:
    if not isinstance(value, dict):
        raise ObjectProofError(code, "value must be a JSON object")


def _ensure_verification_method_matches_issuer(
    verification_method: str,
    issuer_did: str,
) -> None:
    if not isinstance(verification_method, str) or not verification_method:
        raise ObjectProofError(
            "verification_method_invalid",
            "verification method must be a non-empty DID URL",
        )
    did = _did_from_verification_method(verification_method)
    if did != issuer_did:
        raise ObjectProofError(
            "issuer_did_mismatch",
            "verification method DID does not match the profile issuer DID",
        )


def _did_from_verification_method(verification_method: str) -> str:
    if not verification_method.startswith("did:") or "#" not in verification_method:
        raise ObjectProofError(
            "verification_method_invalid",
            "verification method must be a full DID URL",
        )
    did, fragment = verification_method.split("#", 1)
    if not did or not fragment:
        raise ObjectProofError(
            "verification_method_invalid",
            "verification method must be a full DID URL",
        )
    return did


def _normalize_rfc3339_timestamp(value: str | None) -> str:
    if value is None:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    _parse_rfc3339_timestamp(value)
    return value


def _parse_rfc3339_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ObjectProofError(
            "timestamp_invalid",
            f"invalid RFC3339 timestamp: {value}",
        ) from exc
    if parsed.tzinfo is None:
        raise ObjectProofError(
            "timestamp_invalid",
            f"invalid RFC3339 timestamp: {value}",
        )
    return parsed


def _load_did_wba_helpers() -> Dict[str, Any]:
    from anp.authentication.did_wba import (
        _find_verification_method,
        _is_assertion_method_authorized_in_document,
        validate_did_document_binding,
    )

    return {
        "find_verification_method": _find_verification_method,
        "is_assertion_authorized": _is_assertion_method_authorized_in_document,
        "validate_did_document_binding": validate_did_document_binding,
    }


__all__ = [
    "OBJECT_PROOF_PURPOSE",
    "OBJECT_PROOF_REQUIRED_FIELDS",
    "OBJECT_PROOF_SIGNATURE_MULTIBASE_PREFIX",
    "ObjectProofError",
    "ObjectProofVerificationResult",
    "generate_object_proof",
    "verify_object_proof",
]
