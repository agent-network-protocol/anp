"""RFC 9421 origin proof helpers for ANP requests.

This module implements the high-level origin-proof flow defined by
ANP P1 Appendix A. It builds the shared signed request object,
canonicalizes it with RFC 8785 JCS, maps protocol fields into the
RFC 9421 signature base, and reuses the lower-level IM proof
primitives for signing and verification.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Dict, Mapping, TypedDict
from urllib.parse import quote

import jcs

from .im import (
    IM_PROOF_DEFAULT_COMPONENTS,
    IM_PROOF_RELATION_AUTHENTICATION,
    ImProofError,
    ImProofVerificationResult,
    build_im_content_digest,
    generate_im_proof,
    parse_im_signature_input,
    verify_im_proof,
)

RFC9421_ORIGIN_PROOF_DEFAULT_LABEL = "sig1"
RFC9421_ORIGIN_PROOF_DEFAULT_COMPONENTS = IM_PROOF_DEFAULT_COMPONENTS
TARGET_KIND_AGENT = "agent"
TARGET_KIND_GROUP = "group"
TARGET_KIND_SERVICE = "service"
_ALLOWED_TARGET_KINDS = {
    TARGET_KIND_AGENT,
    TARGET_KIND_GROUP,
    TARGET_KIND_SERVICE,
}


class Rfc9421OriginProofError(ImProofError):
    """Raised when RFC 9421 origin proof generation or verification fails."""


class SignedRequestObject(TypedDict):
    """Shared signed request object defined by P1 Appendix A."""

    method: str
    meta: Dict[str, Any]
    body: Dict[str, Any]


class Rfc9421OriginProof(TypedDict):
    """Serialized RFC 9421 origin proof payload."""

    contentDigest: str
    signatureInput: str
    signature: str


@dataclass(frozen=True)
class Rfc9421OriginProofGenerationOptions:
    """Generation options for RFC 9421 origin proof helpers."""

    created: int | None = None
    expires: int | None = None
    nonce: str | None = None
    label: str = RFC9421_ORIGIN_PROOF_DEFAULT_LABEL


@dataclass(frozen=True)
class Rfc9421OriginProofVerificationOptions:
    """Verification options for RFC 9421 origin proof helpers."""

    expected_signer_did: str | None = None


def build_signed_request_object(
    method: str,
    meta: Mapping[str, Any],
    body: Mapping[str, Any],
) -> SignedRequestObject:
    """Build the shared signed request object.

    Args:
        method: JSON-RPC method name.
        meta: Request meta object.
        body: Request body object.

    Returns:
        The normalized signed request object.
    """
    if not isinstance(method, str) or not method.strip():
        raise Rfc9421OriginProofError("method is required")
    if not isinstance(meta, Mapping):
        raise Rfc9421OriginProofError("meta must be an object")
    if not isinstance(body, Mapping):
        raise Rfc9421OriginProofError("body must be an object")
    return {
        "method": method,
        "meta": deepcopy(dict(meta)),
        "body": deepcopy(dict(body)),
    }


def canonicalize_signed_request_object(
    signed_request_object: Mapping[str, Any],
) -> bytes:
    """Canonicalize the shared signed request object using RFC 8785 JCS."""
    required_keys = {"method", "meta", "body"}
    if set(signed_request_object.keys()) != required_keys:
        raise Rfc9421OriginProofError(
            "signed request object must contain only method, meta, and body"
        )
    return jcs.canonicalize(dict(signed_request_object))


def build_logical_target_uri(target_kind: str, target_did: str) -> str:
    """Build the protocol-level logical target URI for origin proof."""
    normalized_kind = str(target_kind).strip()
    if normalized_kind not in _ALLOWED_TARGET_KINDS:
        raise Rfc9421OriginProofError(f"unsupported target kind: {target_kind}")
    normalized_did = str(target_did).strip()
    if not normalized_did:
        raise Rfc9421OriginProofError("target did is required")
    return f"anp://{normalized_kind}/{quote(normalized_did, safe='-._~')}"


def build_rfc9421_origin_signature_base(
    method: str,
    logical_target_uri: str,
    content_digest: str,
    signature_input: str,
) -> bytes:
    """Build the RFC 9421 application-layer signature base for origin proof."""
    if not isinstance(method, str) or not method.strip():
        raise Rfc9421OriginProofError("method is required")
    if not isinstance(logical_target_uri, str) or not logical_target_uri.strip():
        raise Rfc9421OriginProofError("logical_target_uri is required")
    if not isinstance(content_digest, str) or not content_digest.strip():
        raise Rfc9421OriginProofError("content_digest is required")
    parsed = parse_im_signature_input(signature_input)
    _validate_parsed_signature_input(parsed.label, parsed.components)
    component_values = {
        "@method": method,
        "@target-uri": logical_target_uri,
        "content-digest": content_digest,
    }
    lines = [
        f'"{component}": {component_values[component]}'
        for component in parsed.components
    ]
    lines.append(f'"@signature-params": {parsed.signature_params}')
    return "\n".join(lines).encode("utf-8")


def generate_rfc9421_origin_proof(
    method: str,
    meta: Mapping[str, Any],
    body: Mapping[str, Any],
    private_key: Any,
    keyid: str,
    *,
    options: Rfc9421OriginProofGenerationOptions | None = None,
) -> Rfc9421OriginProof:
    """Generate an RFC 9421 origin proof from protocol fields."""
    generation_options = options or Rfc9421OriginProofGenerationOptions()
    _validate_label(generation_options.label)
    signed_request_object = build_signed_request_object(method, meta, body)
    canonical_request = canonicalize_signed_request_object(signed_request_object)
    logical_target_uri = _build_logical_target_uri_from_meta(signed_request_object["meta"])
    content_digest = build_im_content_digest(canonical_request)
    signature_input = _build_rfc9421_signature_input(
        keyid,
        generation_options,
    )
    signature_base = build_rfc9421_origin_signature_base(
        method,
        logical_target_uri,
        content_digest,
        signature_input,
    )
    proof = generate_im_proof(
        canonical_request,
        signature_base,
        private_key,
        keyid,
        components=RFC9421_ORIGIN_PROOF_DEFAULT_COMPONENTS,
        label=generation_options.label,
        created=generation_options.created,
        expires=generation_options.expires,
        nonce=generation_options.nonce,
    )
    parsed = parse_im_signature_input(proof["signatureInput"])
    _validate_parsed_signature_input(parsed.label, parsed.components)
    return proof


def verify_rfc9421_origin_proof(
    origin_proof: Mapping[str, str],
    method: str,
    meta: Mapping[str, Any],
    body: Mapping[str, Any],
    *,
    did_document: Dict[str, Any] | None = None,
    verification_method: Dict[str, Any] | None = None,
    options: Rfc9421OriginProofVerificationOptions | None = None,
) -> ImProofVerificationResult:
    """Verify an RFC 9421 origin proof against protocol fields."""
    verification_options = options or Rfc9421OriginProofVerificationOptions()
    signed_request_object = build_signed_request_object(method, meta, body)
    canonical_request = canonicalize_signed_request_object(signed_request_object)
    logical_target_uri = _build_logical_target_uri_from_meta(signed_request_object["meta"])
    signature_input = _require_proof_field(origin_proof, "signatureInput")
    parsed = parse_im_signature_input(signature_input)
    _validate_parsed_signature_input(parsed.label, parsed.components)
    signature_base = build_rfc9421_origin_signature_base(
        method,
        logical_target_uri,
        _require_proof_field(origin_proof, "contentDigest"),
        signature_input,
    )
    return verify_im_proof(
        origin_proof,
        canonical_request,
        signature_base,
        did_document=did_document,
        verification_method=verification_method,
        expected_signer_did=verification_options.expected_signer_did,
        verification_relationship=IM_PROOF_RELATION_AUTHENTICATION,
    )


def _build_rfc9421_signature_input(
    keyid: str,
    options: Rfc9421OriginProofGenerationOptions,
) -> str:
    from .im import build_im_signature_input

    return build_im_signature_input(
        keyid,
        components=RFC9421_ORIGIN_PROOF_DEFAULT_COMPONENTS,
        label=options.label,
        created=options.created,
        expires=options.expires,
        nonce=options.nonce,
    )


def _build_logical_target_uri_from_meta(meta: Mapping[str, Any]) -> str:
    target = meta.get("target")
    if not isinstance(target, Mapping):
        raise Rfc9421OriginProofError("meta.target is required")
    target_kind = target.get("kind")
    target_did = target.get("did")
    return build_logical_target_uri(str(target_kind), str(target_did))


def _validate_label(label: str) -> None:
    if label != RFC9421_ORIGIN_PROOF_DEFAULT_LABEL:
        raise Rfc9421OriginProofError(
            "RFC 9421 origin proof requires signature label sig1"
        )


def _validate_parsed_signature_input(label: str, components: tuple[str, ...]) -> None:
    _validate_label(label)
    if tuple(components) != tuple(RFC9421_ORIGIN_PROOF_DEFAULT_COMPONENTS):
        raise Rfc9421OriginProofError(
            "RFC 9421 origin proof requires covered components (\"@method\" \"@target-uri\" \"content-digest\")"
        )


def _require_proof_field(proof: Mapping[str, str], field: str) -> str:
    value = proof.get(field)
    if not value:
        raise Rfc9421OriginProofError(f"missing proof field: {field}")
    return value


__all__ = [
    "RFC9421_ORIGIN_PROOF_DEFAULT_LABEL",
    "RFC9421_ORIGIN_PROOF_DEFAULT_COMPONENTS",
    "TARGET_KIND_AGENT",
    "TARGET_KIND_GROUP",
    "TARGET_KIND_SERVICE",
    "SignedRequestObject",
    "Rfc9421OriginProof",
    "Rfc9421OriginProofError",
    "Rfc9421OriginProofGenerationOptions",
    "Rfc9421OriginProofVerificationOptions",
    "build_signed_request_object",
    "canonicalize_signed_request_object",
    "build_logical_target_uri",
    "build_rfc9421_origin_signature_base",
    "generate_rfc9421_origin_proof",
    "verify_rfc9421_origin_proof",
]
