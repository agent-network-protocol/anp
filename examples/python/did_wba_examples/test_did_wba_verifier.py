#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Example: Test DidWbaVerifier with local DID doc and JWT RS256 keys.

Requirements:
- DID document: docs/did_public/public-did-doc.json
- DID private key: docs/did_public/public-private-key.pem
- JWT private key (RS256): docs/jwt_rs256/RS256-private.pem
- JWT public key (RS256): docs/jwt_rs256/RS256-public.pem

This script:
1) Loads the DID doc and keys from docs/
2) Generates a DIDWba Authorization header locally
3) Monkey patches resolver to return the local DID doc
4) Verifies the header and receives a JWT access token
5) Verifies the issued JWT using the same verifier
"""

import asyncio
import json
import logging
from pathlib import Path

import agent_connect.authentication.did_wba_verifier as verifier_module
from agent_connect.authentication import DIDWbaAuthHeader
from agent_connect.authentication.did_wba_verifier import (
    DidWbaVerifier,
    DidWbaVerifierConfig,
)
from agent_connect.utils.log_base import set_log_color_level

TEST_SERVICE_DOMAIN = "service.agent-network-protocol.com"


def _require_file(path: Path, name: str):
    if not path.exists():
        raise FileNotFoundError(f"{name} not found: {path}")


async def main() -> None:
    set_log_color_level(logging.INFO)

    current_dir = Path(__file__).parent.absolute()
    project_root = current_dir.parent.parent.parent

    did_doc_path = project_root / "docs" / "did_public" / "public-did-doc.json"
    did_private_key_path = project_root / "docs" / "did_public" / "public-private-key.pem"

    jwt_priv_path = project_root / "docs" / "jwt_rs256" / "RS256-private.pem"
    jwt_pub_path = project_root / "docs" / "jwt_rs256" / "RS256-public.pem"

    # Validate required files
    _require_file(did_doc_path, "DID document")
    _require_file(did_private_key_path, "DID private key")
    _require_file(jwt_priv_path, "JWT RS256 private key")
    _require_file(jwt_pub_path, "JWT RS256 public key")

    # Load DID document JSON
    with open(did_doc_path, "r", encoding="utf-8") as f:
        did_document = json.load(f)
    logging.info("Loaded DID document: %s", did_document.get("id"))

    # Prepare DID header generator
    auth_client = DIDWbaAuthHeader(
        did_document_path=str(did_doc_path),
        private_key_path=str(did_private_key_path),
    )

    # Generate DIDWba Authorization header for the service domain
    test_url = f"https://{TEST_SERVICE_DOMAIN}/wba/test"
    headers = auth_client.get_auth_header(test_url, force_new=True)
    authorization = headers.get("Authorization", "")
    if not authorization:
        raise RuntimeError("Failed to generate DIDWba Authorization header")

    # Monkey patch resolver in verifier to use local DID document
    async def _fake_resolve_did_wba_document(_did: str):
        return did_document

    verifier_module.resolve_did_wba_document = _fake_resolve_did_wba_document  # type: ignore

    # Load JWT key contents
    jwt_private_key = jwt_priv_path.read_text(encoding="utf-8")
    jwt_public_key = jwt_pub_path.read_text(encoding="utf-8")

    # Configure and create verifier
    config = DidWbaVerifierConfig(
        jwt_private_key=jwt_private_key,
        jwt_public_key=jwt_public_key,
        jwt_algorithm="RS256",
        access_token_expire_minutes=60,
        nonce_expiration_minutes=6,
        timestamp_expiration_minutes=5,
    )
    verifier = DidWbaVerifier(config)

    # Step 1: Verify DIDWba header and get JWT
    logging.info("Verifying DIDWba Authorization header...")
    result = await verifier.verify_auth_header(authorization, TEST_SERVICE_DOMAIN)
    if "access_token" not in result:
        raise RuntimeError(f"Verification failed or no token issued: {result}")

    access_token = result["access_token"]
    did = result.get("did")
    logging.info("DIDWba verified. DID: %s", did)
    logging.info("Issued JWT (prefix): %s...", access_token[:40])

    # Step 2: Verify issued JWT using Bearer header
    bearer_header = f"Bearer {access_token}"
    logging.info("Verifying issued JWT token...")
    verify_token_result = await verifier.verify_auth_header(bearer_header, TEST_SERVICE_DOMAIN)
    logging.info("JWT verified. Result: %s", verify_token_result)


if __name__ == "__main__":
    asyncio.run(main())
