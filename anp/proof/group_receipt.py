"""Group receipt proof helpers.

This module provides convenience helpers for signing and verifying ANP group
receipt objects. A group receipt is a result witness emitted by the Group Host
for ordered group operations such as ``group.create`` and ``group.send``.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Union

from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from .proof import (
    CRYPTOSUITE_DIDWBA_SECP256K1_2025,
    CRYPTOSUITE_EDDSA_JCS_2022,
    PROOF_TYPE_DATA_INTEGRITY,
    generate_w3c_proof,
    verify_w3c_proof,
)

GROUP_RECEIPT_PROOF_PURPOSE = "assertionMethod"
GROUP_RECEIPT_REQUIRED_FIELDS = (
    "receipt_type",
    "group_did",
    "group_state_version",
    "subject_method",
    "operation_id",
    "actor_did",
    "accepted_at",
    "payload_digest",
)


def generate_group_receipt_proof(
    receipt: Dict[str, Any],
    private_key: Union[ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey],
    verification_method: str,
    *,
    created: Optional[str] = None,
    domain: Optional[str] = None,
    challenge: Optional[str] = None,
) -> Dict[str, Any]:
    """Generate a W3C Data Integrity proof for a group receipt."""
    _validate_group_receipt(receipt)
    cryptosuite = _select_group_receipt_cryptosuite(private_key)
    return generate_w3c_proof(
        document=receipt,
        private_key=private_key,
        verification_method=verification_method,
        proof_purpose=GROUP_RECEIPT_PROOF_PURPOSE,
        proof_type=PROOF_TYPE_DATA_INTEGRITY,
        cryptosuite=cryptosuite,
        created=created,
        domain=domain,
        challenge=challenge,
    )


def verify_group_receipt_proof(
    receipt: Dict[str, Any],
    public_key: Union[ec.EllipticCurvePublicKey, ed25519.Ed25519PublicKey],
    *,
    expected_domain: Optional[str] = None,
    expected_challenge: Optional[str] = None,
) -> bool:
    """Verify a W3C Data Integrity proof on a group receipt."""
    _validate_group_receipt(receipt)
    return verify_w3c_proof(
        receipt,
        public_key,
        expected_purpose=GROUP_RECEIPT_PROOF_PURPOSE,
        expected_domain=expected_domain,
        expected_challenge=expected_challenge,
    )


def _validate_group_receipt(receipt: Dict[str, Any]) -> None:
    if not isinstance(receipt, dict):
        raise ValueError("group receipt must be a JSON object")
    missing_fields = [field for field in GROUP_RECEIPT_REQUIRED_FIELDS if field not in receipt]
    if missing_fields:
        raise ValueError(
            f"group receipt is missing required fields: {', '.join(missing_fields)}"
        )


def _select_group_receipt_cryptosuite(
    private_key: Union[ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey],
) -> str:
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        return CRYPTOSUITE_EDDSA_JCS_2022
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        return CRYPTOSUITE_DIDWBA_SECP256K1_2025
    raise ValueError(f"unsupported group receipt signing key type: {type(private_key).__name__}")
