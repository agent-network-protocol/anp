"""Bidirectional binding verification between Handle and DID Document.

Implements the verification flow from WNS spec section 6.
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .exceptions import HandleBindingError, HandleResolutionError
from .models import HandleResolutionDocument, HandleStatus
from .resolver import resolve_handle
from .validator import build_resolution_url, validate_handle


@dataclass
class BindingVerificationResult:
    """Result of a bidirectional binding verification."""

    is_valid: bool
    handle: str
    did: str
    forward_verified: bool
    reverse_verified: bool
    error_message: Optional[str] = None


async def verify_handle_binding(
    handle: str,
    *,
    did_document: Optional[Dict[str, Any]] = None,
    timeout_seconds: float = 10,
    verify_ssl: bool = True,
) -> BindingVerificationResult:
    """Verify bidirectional binding between *handle* and its DID.

    Verification steps (spec section 6.3):
      1. **Forward**: resolve the handle to obtain a DID; check status is active.
      2. **Domain consistency**: Handle domain must match DID domain.
      3. **Reverse**: fetch/use the DID Document and check that it contains a
         ``HandleService`` entry whose ``serviceEndpoint`` points back to the
         same Handle Resolution Endpoint.

    Args:
        handle: The handle to verify.  Accepts both bare handles
            (``alice.example.com``) and ``wba://`` URIs
            (``wba://alice.example.com``).
        did_document: If provided, skip fetching the DID Document and use this
            dict directly.  Useful when the caller already has it.
        timeout_seconds: HTTP timeout for resolution requests.
        verify_ssl: Whether to verify TLS certificates.

    Returns:
        A :class:`BindingVerificationResult` describing the outcome.
    """
    # Strip wba:// prefix if present for compatibility.
    bare_handle = handle[len("wba://"):] if handle.startswith("wba://") else handle
    local_part, domain = validate_handle(bare_handle)
    normalized_handle = f"{local_part}.{domain}"
    expected_endpoint = build_resolution_url(local_part, domain)

    # -- Step 1: Forward resolution ----------------------------------------
    forward_verified = False
    did = ""
    try:
        doc: HandleResolutionDocument = await resolve_handle(
            handle, timeout_seconds=timeout_seconds, verify_ssl=verify_ssl
        )
        did = doc.did
        if doc.status != HandleStatus.ACTIVE:
            return BindingVerificationResult(
                is_valid=False,
                handle=normalized_handle,
                did=did,
                forward_verified=False,
                reverse_verified=False,
                error_message=(
                    f"Handle status is '{doc.status.value}', expected 'active'"
                ),
            )
        forward_verified = True
    except Exception as exc:
        return BindingVerificationResult(
            is_valid=False,
            handle=normalized_handle,
            did="",
            forward_verified=False,
            reverse_verified=False,
            error_message=f"Forward resolution failed: {exc}",
        )

    # -- Step 2: Domain consistency ----------------------------------------
    if not did.startswith("did:wba:"):
        return BindingVerificationResult(
            is_valid=False,
            handle=normalized_handle,
            did=did,
            forward_verified=True,
            reverse_verified=False,
            error_message=f"DID does not use did:wba method: '{did}'",
        )

    did_parts = did.split(":", 3)
    did_domain = did_parts[2] if len(did_parts) > 2 else ""
    if did_domain.lower() != domain.lower():
        return BindingVerificationResult(
            is_valid=False,
            handle=normalized_handle,
            did=did,
            forward_verified=True,
            reverse_verified=False,
            error_message=(
                f"Domain mismatch: handle domain '{domain}' "
                f"!= DID domain '{did_domain}'"
            ),
        )

    # -- Step 3: Reverse verification --------------------------------------
    if did_document is None:
        try:
            from anp.authentication.did_wba import resolve_did_wba_document

            did_document = await resolve_did_wba_document(did)
        except Exception as exc:
            return BindingVerificationResult(
                is_valid=False,
                handle=normalized_handle,
                did=did,
                forward_verified=True,
                reverse_verified=False,
                error_message=f"Failed to resolve DID Document: {exc}",
            )

    if did_document is None:
        return BindingVerificationResult(
            is_valid=False,
            handle=normalized_handle,
            did=did,
            forward_verified=True,
            reverse_verified=False,
            error_message="DID Document resolved to None",
        )

    handle_services = extract_handle_service_from_did_document(did_document)
    reverse_verified = any(
        svc.get("serviceEndpoint", "").rstrip("/") == expected_endpoint.rstrip("/")
        for svc in handle_services
    )

    if not reverse_verified:
        return BindingVerificationResult(
            is_valid=False,
            handle=normalized_handle,
            did=did,
            forward_verified=True,
            reverse_verified=False,
            error_message=(
                "DID Document does not contain a HandleService entry "
                f"pointing to '{expected_endpoint}'"
            ),
        )

    logging.info(
        "Bidirectional binding verified: %s ↔ %s", normalized_handle, did
    )
    return BindingVerificationResult(
        is_valid=True,
        handle=normalized_handle,
        did=did,
        forward_verified=True,
        reverse_verified=True,
    )


def build_handle_service_entry(
    did: str, local_part: str, domain: str
) -> Dict[str, str]:
    """Build a HandleService entry for inclusion in a DID Document.

    Returns a dict matching the structure in WNS spec section 6.2::

        {
            "id": "did:wba:example.com:user:alice#handle",
            "type": "HandleService",
            "serviceEndpoint": "https://example.com/.well-known/handle/alice"
        }
    """
    return {
        "id": f"{did}#handle",
        "type": "HandleService",
        "serviceEndpoint": build_resolution_url(local_part, domain),
    }


def extract_handle_service_from_did_document(
    did_document: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Extract all HandleService entries from a DID Document."""
    services = did_document.get("service", [])
    return [svc for svc in services if svc.get("type") == "HandleService"]
