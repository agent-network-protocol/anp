"""End-to-end DID WBA authentication demo without network transport."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Dict
from urllib.parse import urlparse

from agent_connect.authentication import DIDWbaAuthHeader
from agent_connect.authentication import did_wba_verifier as verifier_module
from agent_connect.authentication.did_wba_verifier import (
    DidWbaVerifier,
    DidWbaVerifierConfig,
)


def project_root() -> Path:
    """Return repository root inferred from this file location."""
    return Path(__file__).resolve().parents[3]


def load_text(path: Path) -> str:
    """Read a UTF-8 text file."""
    return path.read_text(encoding="utf-8")


def load_json(path: Path) -> Dict[str, Any]:
    """Load JSON content as a dictionary."""
    return json.loads(load_text(path))


async def run_demo() -> None:
    """Generate a DID WBA header and verify it offline."""
    root = project_root()
    did_document_path = root / "docs/did_public/public-did-doc.json"
    did_private_key_path = root / "docs/did_public/public-private-key.pem"
    jwt_private_key_path = root / "docs/jwt_rs256/RS256-private.pem"
    jwt_public_key_path = root / "docs/jwt_rs256/RS256-public.pem"

    did_document = load_json(did_document_path)

    async def local_resolver(did: str) -> Dict[str, Any]:
        """Return the static DID document used by this example."""
        if did != did_document["id"]:
            raise ValueError(f"Unsupported DID: {did}")
        return did_document

    original_resolver = verifier_module.resolve_did_wba_document
    verifier_module.resolve_did_wba_document = local_resolver  # type: ignore

    try:
        authenticator = DIDWbaAuthHeader(
            did_document_path=str(did_document_path),
            private_key_path=str(did_private_key_path),
        )

        server_url = "https://didhost.cc/public/resource"
        domain = urlparse(server_url).hostname or "didhost.cc"
        did_headers = authenticator.get_auth_header(server_url, force_new=True)
        did_authorization = did_headers["Authorization"]

        verifier = DidWbaVerifier(
            DidWbaVerifierConfig(
                jwt_private_key=load_text(jwt_private_key_path),
                jwt_public_key=load_text(jwt_public_key_path),
                jwt_algorithm="RS256",
                access_token_expire_minutes=5,
            )
        )

        verification_result = await verifier.verify_auth_header(
            authorization=did_authorization,
            domain=domain,
        )
        access_token = verification_result["access_token"]
        print("DID header verified. Issued bearer token.")

        authenticator.update_token(
            server_url,
            {"Authorization": f"Bearer {access_token}"},
        )
        bearer_headers = authenticator.get_auth_header(server_url)
        bearer_authorization = bearer_headers["Authorization"]

        bearer_result = await verifier.verify_auth_header(
            authorization=bearer_authorization,
            domain=domain,
        )
        print("Bearer token verified. Associated DID:", bearer_result["did"])
    finally:
        verifier_module.resolve_did_wba_document = original_resolver


def main() -> None:
    """Run the async demo."""
    asyncio.run(run_demo())


if __name__ == "__main__":
    main()
