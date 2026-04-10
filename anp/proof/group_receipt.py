"""Group receipt proof helpers.

[INPUT]: Group receipt JSON objects, issuer DID documents, Ed25519 signing
keys, and group receipt proof metadata such as ``verificationMethod`` and
``created`` timestamps.
[OUTPUT]: Appendix-B compliant group receipt proof documents and verification
results expressed as boolean success values for Python callers.
[POS]: This module provides the P4 object-proof adapter built on the shared
Appendix-B object proof core.

[PROTOCOL]:
1. Treat ``group_did`` as the issuer DID for every group receipt proof.
2. Rebuild the protected document from the entire receipt without its top-level
   ``proof`` field.
3. Require Appendix-B proof semantics during generation and verification.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives.asymmetric import ed25519

from .object_proof import generate_object_proof, verify_object_proof

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
    private_key: ed25519.Ed25519PrivateKey,
    verification_method: str,
    *,
    created: Optional[str] = None,
) -> Dict[str, Any]:
    """Generate an Appendix-B object proof for a group receipt."""
    _validate_group_receipt(receipt)
    return generate_object_proof(
        receipt,
        private_key,
        verification_method,
        issuer_did=receipt["group_did"],
        created=created,
    )


def verify_group_receipt_proof(
    receipt: Dict[str, Any],
    issuer_did_document: Dict[str, Any],
) -> bool:
    """Verify an Appendix-B object proof on a group receipt."""
    try:
        _validate_group_receipt(receipt)
        verify_object_proof(
            receipt,
            issuer_did=receipt["group_did"],
            issuer_did_document=issuer_did_document,
        )
        return True
    except Exception as exc:
        logging.error("group receipt verification failed: %s", exc)
        return False


def _validate_group_receipt(receipt: Dict[str, Any]) -> None:
    if not isinstance(receipt, dict):
        raise ValueError("group receipt must be a JSON object")
    missing_fields = [field for field in GROUP_RECEIPT_REQUIRED_FIELDS if field not in receipt]
    if missing_fields:
        raise ValueError(
            f"group receipt is missing required fields: {', '.join(missing_fields)}"
        )


__all__ = [
    "GROUP_RECEIPT_PROOF_PURPOSE",
    "GROUP_RECEIPT_REQUIRED_FIELDS",
    "generate_group_receipt_proof",
    "verify_group_receipt_proof",
]
