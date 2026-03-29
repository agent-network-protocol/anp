"""HTTP Message Signatures helpers for DID-WBA authentication."""

from __future__ import annotations

import base64
import hashlib
import logging
import re
import secrets
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, Optional, Tuple
from urllib.parse import urlparse

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils

from .verification_methods import create_verification_method

logger = logging.getLogger(__name__)

_SIGNATURE_HEADER_BINARY_RE = re.compile(
    r"^\s*(?P<label>[a-zA-Z0-9_-]+)=:(?P<value>[A-Za-z0-9+/=]+):\s*$"
)
_SIGNATURE_INPUT_RE = re.compile(
    r'^\s*(?P<label>[a-zA-Z0-9_-]+)=\((?P<components>[^)]*)\)(?P<params>.*)$'
)


def _ensure_body_bytes(body: Any) -> bytes:
    """Convert request body to bytes."""
    if body is None:
        return b""
    if isinstance(body, bytes):
        return body
    if isinstance(body, bytearray):
        return bytes(body)
    if isinstance(body, str):
        return body.encode("utf-8")
    raise TypeError(f"Unsupported body type: {type(body).__name__}")


def build_content_digest(body: bytes) -> str:
    """Build RFC 9530 Content-Digest header value."""
    digest = hashlib.sha256(body).digest()
    return f"sha-256=:{base64.b64encode(digest).decode('ascii')}:"


def verify_content_digest(body: bytes, content_digest: str) -> bool:
    """Verify RFC 9530 Content-Digest header value."""
    if not content_digest:
        return False
    return build_content_digest(body) == content_digest.strip()


def _get_header_case_insensitive(headers: Dict[str, str], name: str) -> Optional[str]:
    lower_name = name.lower()
    for key, value in headers.items():
        if key.lower() == lower_name:
            return value
    return None


def _quote_component(component: str) -> str:
    return f'"{component}"'


def _serialize_signature_params(
    components: Iterable[str],
    created: int,
    expires: Optional[int],
    nonce: Optional[str],
    keyid: str,
) -> str:
    quoted_components = " ".join(_quote_component(component) for component in components)
    params = [f"created={created}"]
    if expires is not None:
        params.append(f"expires={expires}")
    if nonce is not None:
        params.append(f'nonce="{nonce}"')
    params.append(f'keyid="{keyid}"')
    return f"({quoted_components});" + ";".join(params)


def _component_value(
    component: str,
    method: str,
    url: str,
    headers: Dict[str, str],
) -> str:
    parsed_url = urlparse(url)
    if component == "@method":
        return method.upper()
    if component == "@target-uri":
        return url
    if component == "@authority":
        return parsed_url.netloc

    value = _get_header_case_insensitive(headers, component)
    if value is None:
        raise ValueError(f"Missing covered header component: {component}")
    return value


def _build_signature_base(
    components: Iterable[str],
    method: str,
    url: str,
    headers: Dict[str, str],
    created: int,
    expires: Optional[int],
    nonce: Optional[str],
    keyid: str,
) -> bytes:
    components = list(components)
    signature_params = _serialize_signature_params(
        components=components,
        created=created,
        expires=expires,
        nonce=nonce,
        keyid=keyid,
    )
    lines = []
    for component in components:
        lines.append(
            f'{_quote_component(component)}: '
            f'{_component_value(component, method, url, headers)}'
        )
    lines.append(f'"@signature-params": {signature_params}')
    return "\n".join(lines).encode("utf-8")


def _parse_signature_input(signature_input: str) -> Tuple[str, list[str], dict[str, Any]]:
    match = _SIGNATURE_INPUT_RE.match(signature_input.strip())
    if not match:
        raise ValueError("Invalid Signature-Input header format")

    label = match.group("label")
    components_raw = match.group("components").strip()
    params_raw = match.group("params")

    components = re.findall(r'"([^"]+)"', components_raw)
    if not components:
        raise ValueError("Signature-Input must include covered components")

    params: dict[str, Any] = {}
    for raw_param in params_raw.split(";"):
        raw_param = raw_param.strip()
        if not raw_param:
            continue
        if "=" not in raw_param:
            params[raw_param] = True
            continue
        name, raw_value = raw_param.split("=", 1)
        name = name.strip()
        raw_value = raw_value.strip()
        if raw_value.startswith('"') and raw_value.endswith('"'):
            params[name] = raw_value[1:-1]
        else:
            try:
                params[name] = int(raw_value)
            except ValueError:
                params[name] = raw_value

    return label, components, params


def extract_signature_metadata(headers: Dict[str, str]) -> Dict[str, Any]:
    """Extract key signature metadata from request headers."""
    signature_input = _get_header_case_insensitive(headers, "Signature-Input")
    signature_header = _get_header_case_insensitive(headers, "Signature")
    if not signature_input or not signature_header:
        raise ValueError("Missing Signature-Input or Signature header")
    label_input, components, params = _parse_signature_input(signature_input)
    label_signature, _ = _parse_signature_header(signature_header)
    if label_input != label_signature:
        raise ValueError("Signature label mismatch")
    return {
        "label": label_input,
        "components": components,
        "params": params,
    }


def _parse_signature_header(signature_header: str) -> Tuple[str, bytes]:
    match = _SIGNATURE_HEADER_BINARY_RE.match(signature_header.strip())
    if not match:
        raise ValueError("Invalid Signature header format")
    label = match.group("label")
    signature = base64.b64decode(match.group("value"))
    return label, signature


def _find_verification_method(did_document: Dict[str, Any], verification_method_id: str) -> Optional[Dict[str, Any]]:
    verification_methods = did_document.get("verificationMethod", [])
    for method in verification_methods:
        if isinstance(method, dict) and method.get("id") == verification_method_id:
            return method

    for auth in did_document.get("authentication", []):
        if isinstance(auth, dict) and auth.get("id") == verification_method_id:
            return auth
        if isinstance(auth, str) and auth == verification_method_id:
            for method in verification_methods:
                if isinstance(method, dict) and method.get("id") == verification_method_id:
                    return method
    return None


def _normalize_signature_bytes(method_dict: Dict[str, Any], signature_bytes: bytes) -> bytes:
    method_type = method_dict.get("type")
    verifier = create_verification_method(method_dict)
    public_key = getattr(verifier, "public_key", None)
    if method_type in (
        "EcdsaSecp256k1VerificationKey2019",
        "EcdsaSecp256r1VerificationKey2019",
    ):
        key_size = (public_key.key_size + 7) // 8 if public_key is not None else 32
        expected_len = key_size * 2
        if len(signature_bytes) == expected_len:
            return signature_bytes
        r, s = utils.decode_dss_signature(signature_bytes)
        return r.to_bytes(key_size, "big") + s.to_bytes(key_size, "big")
    return signature_bytes


def _verify_signature_bytes(method_dict: Dict[str, Any], content: bytes, signature_bytes: bytes) -> bool:
    verifier = create_verification_method(method_dict)
    public_key = getattr(verifier, "public_key", None)
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        public_key.verify(signature_bytes, content)
        return True
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        key_size = (public_key.key_size + 7) // 8
        if len(signature_bytes) != key_size * 2:
            raise ValueError("Invalid ECDSA signature length")
        r = int.from_bytes(signature_bytes[:key_size], "big")
        s = int.from_bytes(signature_bytes[key_size:], "big")
        der_signature = utils.encode_dss_signature(r, s)
        public_key.verify(der_signature, content, ec.ECDSA(hashes.SHA256()))
        return True
    raise ValueError("Unsupported verification method public key type")


def generate_http_signature_headers(
    did_document: Dict[str, Any],
    request_url: str,
    request_method: str,
    sign_callback: Callable[[bytes, str], bytes],
    headers: Optional[Dict[str, str]] = None,
    body: Any = None,
    keyid: Optional[str] = None,
    nonce: Optional[str] = None,
    created: Optional[int] = None,
    expires: Optional[int] = None,
    covered_components: Optional[Iterable[str]] = None,
) -> Dict[str, str]:
    """Generate HTTP Message Signatures headers for a request."""
    if not did_document.get("id"):
        raise ValueError("DID document is missing the id field")

    if keyid is None:
        authentication = did_document.get("authentication", [])
        if not authentication:
            raise ValueError("DID document has no authentication methods")
        auth_method = authentication[0]
        if isinstance(auth_method, str):
            keyid = auth_method
        elif isinstance(auth_method, dict) and auth_method.get("id"):
            keyid = auth_method["id"]
        else:
            raise ValueError("Unsupported authentication method shape")

    method_dict = _find_verification_method(did_document, keyid)
    if method_dict is None:
        raise ValueError(f"Verification method not found: {keyid}")

    headers_to_sign = dict(headers or {})
    body_bytes = _ensure_body_bytes(body)
    components = list(covered_components) if covered_components is not None else [
        "@method",
        "@target-uri",
        "@authority",
    ]

    if body_bytes:
        headers_to_sign.setdefault("Content-Digest", build_content_digest(body_bytes))
        if "content-digest" not in [component.lower() for component in components]:
            components.append("content-digest")
        headers_to_sign.setdefault("Content-Length", str(len(body_bytes)))

    created_ts = created or int(datetime.now(timezone.utc).timestamp())
    expires_ts = expires or (created_ts + 300)
    nonce_value = nonce or secrets.token_hex(16)
    signature_base = _build_signature_base(
        components=components,
        method=request_method,
        url=request_url,
        headers=headers_to_sign,
        created=created_ts,
        expires=expires_ts,
        nonce=nonce_value,
        keyid=keyid,
    )
    signature_fragment = keyid.split("#")[-1]
    raw_signature = sign_callback(signature_base, signature_fragment)
    normalized_signature = _normalize_signature_bytes(method_dict, raw_signature)

    signature_input = (
        f'sig1={_serialize_signature_params(components, created_ts, expires_ts, nonce_value, keyid)}'
    )
    signature_header = (
        f"sig1=:{base64.b64encode(normalized_signature).decode('ascii')}:"
    )

    result_headers = {
        "Signature-Input": signature_input,
        "Signature": signature_header,
    }
    if body_bytes:
        result_headers["Content-Digest"] = headers_to_sign["Content-Digest"]
    return result_headers


def verify_http_message_signature(
    did_document: Dict[str, Any],
    request_method: str,
    request_url: str,
    headers: Dict[str, str],
    body: Any = None,
) -> Tuple[bool, str, Dict[str, Any]]:
    """Verify an RFC 9421-style HTTP Message Signature for DID-WBA."""
    try:
        signature_input = _get_header_case_insensitive(headers, "Signature-Input")
        signature_header = _get_header_case_insensitive(headers, "Signature")
        if not signature_input or not signature_header:
            return False, "Missing Signature-Input or Signature header", {}

        label_input, components, params = _parse_signature_input(signature_input)
        label_signature, signature_bytes = _parse_signature_header(signature_header)
        if label_input != label_signature:
            return False, "Signature label mismatch", {}

        keyid = params.get("keyid")
        if not isinstance(keyid, str) or not keyid:
            return False, "Signature-Input missing keyid", {}

        method_dict = _find_verification_method(did_document, keyid)
        if method_dict is None:
            return False, "Verification method not found", {}

        body_bytes = _ensure_body_bytes(body)
        if body_bytes or "content-digest" in [component.lower() for component in components]:
            content_digest = _get_header_case_insensitive(headers, "Content-Digest")
            if not content_digest:
                return False, "Missing Content-Digest header", {}
            if not verify_content_digest(body_bytes, content_digest):
                return False, "Content-Digest verification failed", {}

        created = params.get("created")
        expires = params.get("expires")
        nonce = params.get("nonce")
        if not isinstance(created, int):
            return False, "Signature-Input missing created parameter", {}
        if expires is not None and not isinstance(expires, int):
            return False, "Invalid expires parameter", {}

        signature_base = _build_signature_base(
            components=components,
            method=request_method,
            url=request_url,
            headers=headers,
            created=created,
            expires=expires,
            nonce=nonce,
            keyid=keyid,
        )
        _verify_signature_bytes(method_dict, signature_base, signature_bytes)
        return True, "Verification successful", {
            "keyid": keyid,
            "nonce": nonce,
            "created": created,
            "expires": expires,
            "components": components,
        }
    except Exception as exc:
        logger.error("HTTP message signature verification failed: %s", exc)
        return False, f"Verification error: {exc}", {}
