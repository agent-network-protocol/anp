"""DID WBA HTTP Client Example.

This example demonstrates how to use DIDWbaAuthHeader to authenticate
with a DID WBA protected HTTP server.

Usage:
    1. Start the server in a terminal:
       uv run python examples/python/did_wba_examples/http_server.py

    2. Run this client in another terminal:
       uv run python examples/python/did_wba_examples/http_client.py

The client demonstrates:
- First request: DID authentication → receives Bearer token
- Second request: Uses cached Bearer token
- Third request: Access exempt endpoint (no auth required)
"""

from __future__ import annotations

import logging
from pathlib import Path

import httpx

from anp.authentication import DIDWbaAuthHeader

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

SERVER_URL = "http://localhost:8080"


def project_root() -> Path:
    """Return repository root inferred from this file location."""
    return Path(__file__).resolve().parents[3]


def main() -> None:
    """Run the HTTP client demonstration."""
    root = project_root()
    did_document_path = root / "docs/did_public/public-did-doc.json"
    did_private_key_path = root / "docs/did_public/public-private-key.pem"

    logger.info("Initializing DID WBA authentication client...")
    authenticator = DIDWbaAuthHeader(
        did_document_path=str(did_document_path),
        private_key_path=str(did_private_key_path),
    )

    with httpx.Client(timeout=30.0) as client:
        protected_url = f"{SERVER_URL}/api/protected"
        user_info_url = f"{SERVER_URL}/api/user-info"

        print("\n" + "=" * 60)
        print("Step 1: Access health endpoint (no authentication required)")
        print("=" * 60)
        response = client.get(f"{SERVER_URL}/health")
        print(f"Status: {response.status_code}")
        print(f"Response: {response.json()}")

        print("\n" + "=" * 60)
        print("Step 2: Access protected endpoint with DID authentication")
        print("=" * 60)
        headers = authenticator.get_auth_header(
            protected_url,
            force_new=True,
            method="GET",
        )
        if "Signature-Input" in headers:
            print("Auth header type: HTTP Message Signatures")
            print(f"Signature-Input: {headers['Signature-Input'][:80]}...")
        else:
            print("Auth header type: Legacy DIDWba")
            print(f"Authorization: {headers['Authorization'][:80]}...")

        response = client.get(protected_url, headers=headers)

        if response.status_code == 401:
            print("Received 401, retrying DID authentication with challenge headers...")
            authenticator.clear_token(protected_url)
            headers = authenticator.get_challenge_auth_header(
                protected_url,
                dict(response.headers),
                method="GET",
            )
            response = client.get(protected_url, headers=headers)

        print(f"Status: {response.status_code}")
        print(f"Response: {response.json()}")

        token = authenticator.update_token(protected_url, dict(response.headers))
        if token:
            print(f"Received Bearer token: {token[:50]}...")
        else:
            print("No Bearer token received")

        print("\n" + "=" * 60)
        print("Step 3: Access protected endpoint with cached Bearer token")
        print("=" * 60)
        headers = authenticator.get_auth_header(protected_url)
        print(f"Auth header type: Bearer")
        print(f"Authorization: {headers['Authorization'][:80]}...")

        response = client.get(protected_url, headers=headers)
        if response.status_code == 401:
            print("Received 401 for Bearer token, retrying with challenge-aware DID auth...")
            authenticator.clear_token(protected_url)
            headers = authenticator.get_challenge_auth_header(
                protected_url,
                dict(response.headers),
                method="GET",
            )
            response = client.get(protected_url, headers=headers)
            token = authenticator.update_token(protected_url, dict(response.headers))
            if token:
                headers = authenticator.get_auth_header(protected_url)
        print(f"Status: {response.status_code}")
        print(f"Response: {response.json()}")

        print("\n" + "=" * 60)
        print("Step 4: Access user-info endpoint with Bearer token")
        print("=" * 60)
        headers = authenticator.get_auth_header(user_info_url)
        response = client.get(user_info_url, headers=headers)
        if response.status_code == 401:
            print("Received 401 for Bearer token, retrying with challenge-aware DID auth...")
            authenticator.clear_token(user_info_url)
            headers = authenticator.get_challenge_auth_header(
                user_info_url,
                dict(response.headers),
                method="GET",
            )
            response = client.get(user_info_url, headers=headers)
        print(f"Status: {response.status_code}")
        print(f"Response: {response.json()}")

        print("\n" + "=" * 60)
        print("Demo completed successfully!")
        print("=" * 60)


if __name__ == "__main__":
    main()
