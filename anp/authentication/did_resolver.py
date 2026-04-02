"""Generic DID document resolution helpers for ANP authentication."""

from __future__ import annotations

import asyncio
import logging
import urllib.parse
from typing import Any, Dict, Optional

import aiohttp

from anp.proof import verify_w3c_proof

from .did_wba import (
    _extract_public_key,
    _find_verification_method,
    validate_did_document_binding,
)

logger = logging.getLogger(__name__)


def build_did_resolution_url(did: str, base_url_override: Optional[str] = None) -> str:
    """Build the HTTPS resolution URL for a DID document."""
    parts = did.split(":")
    if len(parts) < 3 or parts[0] != "did":
        raise ValueError("Invalid DID format")

    method = parts[1]
    if method not in {"wba", "web"}:
        raise ValueError(f"Unsupported DID method: {method}")

    domain = urllib.parse.unquote(parts[2])
    path_segments = parts[3:]
    base_url = (base_url_override or f"https://{domain}").rstrip("/")
    if path_segments:
        encoded_path = "/".join(
            urllib.parse.unquote(segment) for segment in path_segments
        )
        return f"{base_url}/{encoded_path}/did.json"
    return f"{base_url}/.well-known/did.json"


async def resolve_did_document(
    did: str,
    *,
    verify_proof: bool = False,
    timeout_seconds: float = 10,
    verify_ssl: bool = True,
    base_url_override: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Resolve a DID document for supported DID methods."""
    if not did.startswith("did:"):
        raise ValueError("Invalid DID format")

    url = build_did_resolution_url(did, base_url_override=base_url_override)
    timeout = aiohttp.ClientTimeout(total=timeout_seconds)
    request_headers = {"Accept": "application/json", **(headers or {})}

    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.get(url, headers=request_headers, ssl=verify_ssl) as response:
            response.raise_for_status()
            did_document = await response.json()

    if did_document.get("id") != did:
        raise ValueError(
            f"DID document ID mismatch. Expected: {did}, got: {did_document.get('id')}"
        )

    method = did.split(":", 2)[1]
    if method == "wba" and not validate_did_document_binding(
        did_document, verify_proof=verify_proof
    ):
        raise ValueError("DID document binding verification failed")

    if verify_proof and "proof" in did_document:
        proof = did_document["proof"]
        verification_method_id = proof.get("verificationMethod")
        if not isinstance(verification_method_id, str) or not verification_method_id:
            raise ValueError("Proof missing verificationMethod field")

        method_dict = _find_verification_method(did_document, verification_method_id)
        if not method_dict:
            raise ValueError(f"Verification method not found: {verification_method_id}")

        public_key = _extract_public_key(method_dict)
        if not verify_w3c_proof(did_document, public_key):
            raise ValueError("Verification failed")

    logger.info("Successfully resolved DID document for: %s", did)
    return did_document


def resolve_did_document_sync(
    did: str,
    *,
    verify_proof: bool = False,
    timeout_seconds: float = 10,
    verify_ssl: bool = True,
    base_url_override: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Synchronous wrapper for DID document resolution."""
    return asyncio.run(
        resolve_did_document(
            did,
            verify_proof=verify_proof,
            timeout_seconds=timeout_seconds,
            verify_ssl=verify_ssl,
            base_url_override=base_url_override,
            headers=headers,
        )
    )
