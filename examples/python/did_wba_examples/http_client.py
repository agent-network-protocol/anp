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
        print("\n" + "=" * 60)
        print("Step 1: Access health endpoint (no authentication required)")
        print("=" * 60)
        response = client.get(f"{SERVER_URL}/health")
        print(f"Status: {response.status_code}")
        print(f"Response: {response.json()}")

        print("\n" + "=" * 60)
        print("Step 2: Access protected endpoint with DID authentication")
        print("=" * 60)
        headers = authenticator.get_auth_header(SERVER_URL, force_new=True)
        print(f"Auth header type: DID WBA")
        print(f"Authorization: {headers['Authorization'][:80]}...")

        response = client.get(f"{SERVER_URL}/api/protected", headers=headers)
        print(f"Status: {response.status_code}")
        print(f"Response: {response.json()}")

        auth_header = response.headers.get("authorization")
        if auth_header:
            token = authenticator.update_token(
                SERVER_URL, {"Authorization": auth_header}
            )
            if token:
                print(f"Received Bearer token: {token[:50]}...")
            else:
                print("No Bearer token received")
        else:
            print("No authorization header in response")

        print("\n" + "=" * 60)
        print("Step 3: Access protected endpoint with cached Bearer token")
        print("=" * 60)
        headers = authenticator.get_auth_header(SERVER_URL)
        print(f"Auth header type: Bearer")
        print(f"Authorization: {headers['Authorization'][:80]}...")

        response = client.get(f"{SERVER_URL}/api/protected", headers=headers)
        print(f"Status: {response.status_code}")
        print(f"Response: {response.json()}")

        print("\n" + "=" * 60)
        print("Step 4: Access user-info endpoint with Bearer token")
        print("=" * 60)
        headers = authenticator.get_auth_header(SERVER_URL)
        response = client.get(f"{SERVER_URL}/api/user-info", headers=headers)
        print(f"Status: {response.status_code}")
        print(f"Response: {response.json()}")

        print("\n" + "=" * 60)
        print("Demo completed successfully!")
        print("=" * 60)


if __name__ == "__main__":
    main()
