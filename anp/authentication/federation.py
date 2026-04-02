"""Federated service-to-service DID verification helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from .did_resolver import resolve_did_document
from .did_wba import ANP_MESSAGE_SERVICE_TYPE, _is_authentication_authorized_in_document
from .http_signatures import extract_signature_metadata, verify_http_message_signature


class FederatedVerificationError(ValueError):
    """Raised when federated HTTP request verification fails."""


@dataclass
class FederatedVerificationResult:
    """Successful federated verification details."""

    sender_did: str
    service_did: str
    service_id: str
    signature_metadata: Dict[str, Any]


async def verify_federated_http_request(
    *,
    sender_did: str,
    request_method: str,
    request_url: str,
    headers: Dict[str, str],
    body: Any = None,
    sender_did_document: Optional[Dict[str, Any]] = None,
    service_did_document: Optional[Dict[str, Any]] = None,
    service_id: Optional[str] = None,
    service_endpoint: Optional[str] = None,
    verify_sender_did_proof: bool = False,
    verify_service_did_proof: bool = False,
) -> FederatedVerificationResult:
    """Verify a federated HTTP request using `ANPMessageService.serviceDid`."""
    sender_document = sender_did_document or await resolve_did_document(
        sender_did,
        verify_proof=verify_sender_did_proof,
    )
    if sender_document.get("id") != sender_did:
        raise FederatedVerificationError("Sender DID document ID mismatch")

    service = _select_anp_message_service(
        sender_document,
        service_id=service_id,
        service_endpoint=service_endpoint,
    )
    service_did = service.get("serviceDid")
    if not isinstance(service_did, str) or not service_did:
        raise FederatedVerificationError("Selected ANPMessageService is missing serviceDid")

    metadata = extract_signature_metadata(headers)
    keyid = metadata.get("params", {}).get("keyid")
    if not isinstance(keyid, str) or "#" not in keyid:
        raise FederatedVerificationError("Invalid Signature-Input keyid")

    keyid_did = keyid.split("#", 1)[0]
    if keyid_did != service_did:
        raise FederatedVerificationError("Signature keyid DID does not match serviceDid")

    service_document = service_did_document or await resolve_did_document(
        service_did,
        verify_proof=verify_service_did_proof,
    )
    if service_document.get("id") != service_did:
        raise FederatedVerificationError("serviceDid document ID mismatch")
    if not _is_authentication_authorized_in_document(service_document, keyid):
        raise FederatedVerificationError(
            "Verification method is not authorized for authentication"
        )

    is_valid, message, verification_metadata = verify_http_message_signature(
        did_document=service_document,
        request_method=request_method,
        request_url=request_url,
        headers=headers,
        body=body,
    )
    if not is_valid:
        raise FederatedVerificationError(message)

    return FederatedVerificationResult(
        sender_did=sender_did,
        service_did=service_did,
        service_id=str(service.get("id", "")),
        signature_metadata=verification_metadata,
    )


def _select_anp_message_service(
    did_document: Dict[str, Any],
    *,
    service_id: Optional[str] = None,
    service_endpoint: Optional[str] = None,
) -> Dict[str, Any]:
    """Select a single ANPMessageService from a DID document."""
    services = did_document.get("service", [])
    candidates = [
        service
        for service in services
        if isinstance(service, dict) and service.get("type") == ANP_MESSAGE_SERVICE_TYPE
    ]
    if not candidates:
        raise FederatedVerificationError("No ANPMessageService found in DID document")

    if service_id:
        for service in candidates:
            if service.get("id") == service_id:
                return service
        raise FederatedVerificationError(
            f"ANPMessageService not found for service_id={service_id}"
        )

    if service_endpoint:
        for service in candidates:
            if service.get("serviceEndpoint") == service_endpoint:
                return service
        raise FederatedVerificationError(
            "ANPMessageService not found for serviceEndpoint"
        )

    if len(candidates) == 1:
        return candidates[0]

    raise FederatedVerificationError(
        "Multiple ANPMessageService entries found; service_id or service_endpoint is required"
    )
