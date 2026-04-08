"""ANP IM business proof generation and verification helpers.

This module implements proof helpers for ANP IM business-layer proofs such as
``sender_proof`` and ``actor_proof``. Unlike W3C DID document proofs, these
proofs sign a protocol-specific signature base assembled by the business layer.

The SDK is responsible for:
- Content-Digest generation and verification
- Signature-Input parsing and serialization
- Signature encoding / decoding
- DID document + verification method lookup
- Public key verification

The business layer is responsible for assembling the protocol-specific
signature base bytes and passing them into ``generate_im_proof`` /
``verify_im_proof``.

When verification is performed with a DID document, request-level IM proofs
default to DID ``authentication`` authorization. Assertion-style business
objects should explicitly opt into ``assertionMethod`` verification.
"""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Mapping, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils

from anp.authentication.verification_methods import create_verification_method

IM_PROOF_DEFAULT_COMPONENTS = ("@method", "@target-uri", "content-digest")
IM_PROOF_RELATION_AUTHENTICATION = "authentication"
IM_PROOF_RELATION_ASSERTION_METHOD = "assertionMethod"

_SIGNATURE_INPUT_RE = re.compile(
    r'^\s*(?P<label>[a-zA-Z0-9_-]+)=\((?P<components>[^)]*)\)(?P<params>.*)$'
)
_SIGNATURE_VALUE_RE = re.compile(
    r"^\s*(?:(?P<label>[a-zA-Z0-9_-]+)=)?:(?P<value>[A-Za-z0-9+/=_-]+):\s*$"
)


class ImProofError(ValueError):
    """Raised when ANP IM proof generation or verification fails."""


@dataclass(frozen=True)
class ParsedImSignatureInput:
    """Parsed representation of the RFC 9421-style signatureInput string."""

    label: str
    components: tuple[str, ...]
    signature_params: str
    keyid: str
    nonce: str | None
    created: int | None
    expires: int | None


@dataclass(frozen=True)
class ImProofVerificationResult:
    """Successful IM proof verification output."""

    parsed_signature_input: ParsedImSignatureInput
    verification_method: Dict[str, Any]


def build_im_content_digest(payload: bytes | bytearray | str) -> str:
    """Build the ANP IM contentDigest string."""
    digest = hashlib.sha256(_ensure_bytes(payload)).digest()
    return f"sha-256=:{base64.b64encode(digest).decode('ascii')}:"


def verify_im_content_digest(payload: bytes | bytearray | str, content_digest: str) -> bool:
    """Verify the ANP IM contentDigest string."""
    return build_im_content_digest(payload) == content_digest.strip()


def build_im_signature_input(
    keyid: str,
    *,
    components: Optional[Iterable[str]] = None,
    label: str = "sig1",
    created: int | None = None,
    expires: int | None = None,
    nonce: str | None = None,
) -> str:
    """Build the ANP IM signatureInput field value."""
    normalized_components = tuple(components or IM_PROOF_DEFAULT_COMPONENTS)
    if not normalized_components:
        raise ImProofError("signatureInput must include covered components")
    created_value = created if created is not None else int(datetime.now(timezone.utc).timestamp())
    nonce_value = nonce or secrets.token_urlsafe(12)
    quoted_components = " ".join(f'"{component}"' for component in normalized_components)
    params = [f"created={created_value}"]
    if expires is not None:
        params.append(f"expires={expires}")
    if nonce_value:
        params.append(f'nonce="{nonce_value}"')
    params.append(f'keyid="{keyid}"')
    return f"{label}=({quoted_components});" + ";".join(params)


def parse_im_signature_input(signature_input: str) -> ParsedImSignatureInput:
    """Parse the ANP IM signatureInput field."""
    match = _SIGNATURE_INPUT_RE.match(signature_input.strip())
    if not match:
        raise ImProofError("invalid proof.signatureInput format")

    label = match.group("label")
    components = tuple(
        component
        for component in re.findall(r'"([^"]+)"', match.group("components").strip())
        if component
    )
    if not components:
        raise ImProofError("proof.signatureInput must include covered components")

    params_raw = match.group("params")
    keyid: str | None = None
    nonce: str | None = None
    created: int | None = None
    expires: int | None = None
    for raw_param in params_raw.split(";"):
        raw_param = raw_param.strip()
        if not raw_param:
            continue
        if "=" not in raw_param:
            continue
        name, raw_value = raw_param.split("=", 1)
        value = raw_value.strip()
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        if name == "keyid":
            keyid = value
        elif name == "nonce":
            nonce = value
        elif name == "created":
            created = _parse_int(value)
        elif name == "expires":
            expires = _parse_int(value)

    if not keyid:
        raise ImProofError("proof.signatureInput must include keyid")

    params = signature_input.split("=", 1)[1].strip()
    return ParsedImSignatureInput(
        label=label,
        components=components,
        signature_params=params,
        keyid=keyid,
        nonce=nonce,
        created=created,
        expires=expires,
    )


def encode_im_signature(signature_bytes: bytes, *, label: str = "sig1") -> str:
    """Encode raw signature bytes into the ANP IM signature field."""
    return f"{label}=:{base64.b64encode(signature_bytes).decode('ascii')}:"


def decode_im_signature(signature: str) -> tuple[str | None, bytes]:
    """Decode the ANP IM signature field into raw bytes."""
    match = _SIGNATURE_VALUE_RE.match(signature.strip())
    if not match:
        raise ImProofError("invalid proof.signature encoding")
    encoded = match.group("value")
    try:
        return match.group("label"), base64.b64decode(encoded, validate=True)
    except Exception:
        try:
            padding = "=" * (-len(encoded) % 4)
            return match.group("label"), base64.urlsafe_b64decode(encoded + padding)
        except Exception as exc:
            raise ImProofError("invalid proof.signature encoding") from exc


def generate_im_proof(
    payload: bytes | bytearray | str,
    signature_base: bytes | bytearray | str,
    private_key: ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey,
    keyid: str,
    *,
    components: Optional[Iterable[str]] = None,
    label: str = "sig1",
    created: int | None = None,
    expires: int | None = None,
    nonce: str | None = None,
) -> Dict[str, str]:
    """Generate an ANP IM proof object."""
    payload_bytes = _ensure_bytes(payload)
    signature_base_bytes = _ensure_bytes(signature_base)
    signature_input = build_im_signature_input(
        keyid,
        components=components,
        label=label,
        created=created,
        expires=expires,
        nonce=nonce,
    )
    signature_bytes = _sign_business_bytes(private_key, signature_base_bytes)
    return {
        "contentDigest": build_im_content_digest(payload_bytes),
        "signatureInput": signature_input,
        "signature": encode_im_signature(signature_bytes, label=label),
    }


def verify_im_proof(
    proof: Mapping[str, str],
    payload: bytes | bytearray | str,
    signature_base: bytes | bytearray | str,
    *,
    did_document: Optional[Dict[str, Any]] = None,
    verification_method: Optional[Dict[str, Any]] = None,
    expected_signer_did: str | None = None,
    verification_relationship: str = IM_PROOF_RELATION_AUTHENTICATION,
) -> ImProofVerificationResult:
    """Verify an ANP IM proof object.

    When ``did_document`` is provided, the verification method is additionally
    checked against the requested DID verification relationship. The default
    relationship follows ANP request-level origin-proof semantics and uses
    ``authentication``.
    """
    content_digest = _require_field(proof, "contentDigest")
    signature_input = _require_field(proof, "signatureInput")
    signature = _require_field(proof, "signature")

    payload_bytes = _ensure_bytes(payload)
    if not verify_im_content_digest(payload_bytes, content_digest):
        raise ImProofError("proof contentDigest does not match request payload")

    parsed = parse_im_signature_input(signature_input)
    if expected_signer_did and not _keyid_belongs_to_expected_did(
        parsed.keyid,
        expected_signer_did,
    ):
        raise ImProofError("proof keyid must belong to expected signer DID")
    if did_document is not None:
        relationship = _normalize_verification_relationship(verification_relationship)
        if not _is_verification_method_authorized(
            did_document,
            parsed.keyid,
            relationship,
        ):
            raise ImProofError(
                f"verification method is not authorized for {relationship}"
            )

    method_dict = verification_method or _resolve_verification_method(did_document, parsed.keyid)
    verifier = create_verification_method(method_dict)
    _, signature_bytes = decode_im_signature(signature)
    _verify_signature_bytes(verifier.public_key, _ensure_bytes(signature_base), signature_bytes)
    return ImProofVerificationResult(
        parsed_signature_input=parsed,
        verification_method=method_dict,
    )


def _resolve_verification_method(
    did_document: Optional[Dict[str, Any]],
    verification_method_id: str,
) -> Dict[str, Any]:
    if did_document is None:
        raise ImProofError("did_document or verification_method is required")
    method = _find_verification_method_in_document(did_document, verification_method_id)
    if not method:
        raise ImProofError("verification method not found in DID document")
    return method


def _find_verification_method_in_document(
    did_document: Dict[str, Any],
    verification_method_id: str,
) -> Optional[Dict[str, Any]]:
    for method in did_document.get("verificationMethod", []):
        if isinstance(method, dict) and method.get("id") == verification_method_id:
            return method
    for relation in ("authentication", "assertionMethod"):
        for entry in did_document.get(relation, []):
            if isinstance(entry, dict) and entry.get("id") == verification_method_id:
                return entry
            if isinstance(entry, str) and entry == verification_method_id:
                for method in did_document.get("verificationMethod", []):
                    if isinstance(method, dict) and method.get("id") == verification_method_id:
                        return method
    return None


def _normalize_verification_relationship(verification_relationship: str) -> str:
    if verification_relationship in {
        IM_PROOF_RELATION_AUTHENTICATION,
        IM_PROOF_RELATION_ASSERTION_METHOD,
    }:
        return verification_relationship
    raise ImProofError(
        f"unsupported verification relationship: {verification_relationship}"
    )


def _is_verification_method_authorized(
    did_document: Dict[str, Any],
    verification_method_id: str,
    verification_relationship: str,
) -> bool:
    from anp.authentication.did_wba import (
        _is_assertion_method_authorized_in_document,
        _is_authentication_authorized_in_document,
    )

    if verification_relationship == IM_PROOF_RELATION_AUTHENTICATION:
        return _is_authentication_authorized_in_document(
            did_document,
            verification_method_id,
        )
    if verification_relationship == IM_PROOF_RELATION_ASSERTION_METHOD:
        return _is_assertion_method_authorized_in_document(
            did_document,
            verification_method_id,
        )
    raise ImProofError(
        f"unsupported verification relationship: {verification_relationship}"
    )


def _verify_signature_bytes(public_key: Any, content: bytes, signature_bytes: bytes) -> None:
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        public_key.verify(signature_bytes, content)
        return
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        key_size = (public_key.key_size + 7) // 8
        if len(signature_bytes) == key_size * 2:
            r = int.from_bytes(signature_bytes[:key_size], "big")
            s = int.from_bytes(signature_bytes[key_size:], "big")
            der_signature = utils.encode_dss_signature(r, s)
        else:
            der_signature = signature_bytes
        public_key.verify(der_signature, content, ec.ECDSA(hashes.SHA256()))
        return
    raise ImProofError("unsupported verification method public key type")


def _sign_business_bytes(
    private_key: ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey,
    content: bytes,
) -> bytes:
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        return private_key.sign(content)
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        der_signature = private_key.sign(content, ec.ECDSA(hashes.SHA256()))
        r, s = utils.decode_dss_signature(der_signature)
        key_size = (private_key.key_size + 7) // 8
        return r.to_bytes(key_size, "big") + s.to_bytes(key_size, "big")
    raise ImProofError(f"unsupported private key type: {type(private_key).__name__}")


def _ensure_bytes(value: bytes | bytearray | str) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8")
    raise TypeError(f"Unsupported value type: {type(value).__name__}")


def _parse_int(value: str) -> int | None:
    try:
        return int(value)
    except ValueError:
        return None


def _keyid_belongs_to_expected_did(keyid: str, expected_signer_did: str) -> bool:
    return keyid.split("#", 1)[0] == expected_signer_did


def _require_field(proof: Mapping[str, str], field: str) -> str:
    value = proof.get(field)
    if not value:
        raise ImProofError(f"missing proof field: {field}")
    return value


__all__ = [
    "IM_PROOF_DEFAULT_COMPONENTS",
    "IM_PROOF_RELATION_AUTHENTICATION",
    "IM_PROOF_RELATION_ASSERTION_METHOD",
    "ImProofError",
    "ImProofVerificationResult",
    "ParsedImSignatureInput",
    "build_im_content_digest",
    "verify_im_content_digest",
    "build_im_signature_input",
    "parse_im_signature_input",
    "encode_im_signature",
    "decode_im_signature",
    "generate_im_proof",
    "verify_im_proof",
]
