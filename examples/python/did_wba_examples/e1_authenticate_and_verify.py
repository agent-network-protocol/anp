"""Create an e1 DID and run the complete DID-WBA authentication flow.

This self-contained example uses the current DID-WBA defaults:

1. Create a strongly bound ``e1_`` DID document and Ed25519 keys.
2. Sign a request with HTTP Message Signatures.
3. Verify the DID binding, document proof, and request signature.
4. Issue, cache, and verify a Bearer access token.

The example uses a local resolver so it can run without publishing the generated
DID document. Production deployments should publish the document at the HTTPS
URL derived from the DID and use the SDK's normal network resolver.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
import tempfile
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from anp.authentication import (
    DIDWbaAuthHeader,
    DidWbaVerifier,
    DidWbaVerifierConfig,
    create_did_wba_document,
)
from anp.authentication import did_wba_verifier as verifier_module


REQUEST_URL = "https://api.example.com/orders/42"
REQUEST_METHOD = "POST"
REQUEST_BODY = b'{"action":"confirm"}'
REQUEST_HEADERS = {"Content-Type": "application/json"}


def create_e1_identity(output_dir: Path) -> tuple[dict[str, Any], Path, Path]:
    """Create an e1 DID document and persist its authentication key.

    Args:
        output_dir: Temporary or permanent directory for the generated files.

    Returns:
        A tuple containing the DID document, document path, and authentication
        private-key path.
    """
    did_document, keys = create_did_wba_document(
        hostname="example.com",
        path_segments=["agents", "alice"],
        agent_description_url="https://example.com/agents/alice/ad.json",
        did_profile="e1",
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    did_document_path = output_dir / "did.json"
    private_key_path = output_dir / "key-1_private.pem"
    did_document_path.write_text(
        json.dumps(did_document, indent=2),
        encoding="utf-8",
    )
    private_key_path.write_bytes(keys["key-1"][0])
    return did_document, did_document_path, private_key_path


def create_jwt_key_pair() -> tuple[str, str]:
    """Create a temporary RSA key pair for issuing demo access tokens."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_pem, public_pem


async def run_demo(verbose: bool = True) -> dict[str, Any]:
    """Run e1 DID creation, request authentication, and token reuse.

    Args:
        verbose: Whether to print the individual authentication steps.

    Returns:
        Authentication artifacts useful for tests and further exploration.
    """
    with tempfile.TemporaryDirectory(prefix="anp-e1-auth-") as temp_dir:
        did_document, did_document_path, private_key_path = create_e1_identity(
            Path(temp_dir)
        )
        did = did_document["id"]

        authenticator = DIDWbaAuthHeader(
            did_document_path=str(did_document_path),
            private_key_path=str(private_key_path),
        )
        signature_headers = authenticator.get_auth_header(
            REQUEST_URL,
            force_new=True,
            method=REQUEST_METHOD,
            headers=REQUEST_HEADERS,
            body=REQUEST_BODY,
        )

        jwt_private_key, jwt_public_key = create_jwt_key_pair()
        verifier = DidWbaVerifier(
            DidWbaVerifierConfig(
                jwt_private_key=jwt_private_key,
                jwt_public_key=jwt_public_key,
                access_token_expire_minutes=5,
                allow_legacy_didwba=False,
            )
        )

        async def local_resolver(requested_did: str) -> dict[str, Any]:
            """Resolve only the generated document for this offline demo."""
            if requested_did != did:
                raise ValueError(f"Unsupported DID: {requested_did}")
            return did_document

        original_resolver = verifier_module.resolve_did_wba_document
        verifier_module.resolve_did_wba_document = local_resolver  # type: ignore[assignment]
        try:
            first_result = await verifier.verify_request(
                method=REQUEST_METHOD,
                url=REQUEST_URL,
                headers={**REQUEST_HEADERS, **signature_headers},
                body=REQUEST_BODY,
            )
        finally:
            verifier_module.resolve_did_wba_document = original_resolver

        access_token = authenticator.update_token(
            REQUEST_URL,
            first_result["response_headers"],
        )
        bearer_headers = authenticator.get_auth_header(REQUEST_URL)
        bearer_result = await verifier.verify_request(
            method=REQUEST_METHOD,
            url=REQUEST_URL,
            headers=bearer_headers,
            body=REQUEST_BODY,
        )

        if verbose:
            print("Created e1 DID:", did)
            print("DID document proof:", did_document["proof"]["cryptosuite"])
            print("Request authentication:", first_result["auth_scheme"])
            print("Issued and cached Bearer token:", bool(access_token))
            print("Bearer token authentication:", bearer_result["auth_scheme"])
            print("Authenticated DID:", bearer_result["did"])

        return {
            "did": did,
            "did_document": did_document,
            "signature_headers": signature_headers,
            "first_result": first_result,
            "bearer_headers": bearer_headers,
            "bearer_result": bearer_result,
        }


def main() -> None:
    """Run the complete e1 authentication example."""
    asyncio.run(run_demo())


if __name__ == "__main__":
    main()
