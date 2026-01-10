#!/usr/bin/env python3
"""OpenANP Minimal Client Example.

Call a remote ANP agent with minimal code.

Prerequisites:
    Start minimal_server.py first:
    uvicorn examples.python.openanp_examples.minimal_server:app --port 8000

Run:
    uv run python examples/python/openanp_examples/minimal_client.py
"""

import asyncio
from pathlib import Path

from anp.authentication import DIDWbaAuthHeader
from anp.openanp import RemoteAgent


# DID document and private key paths
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
DID_DOC = PROJECT_ROOT / "docs/did_public/public-did-doc.json"
PRIVATE_KEY = PROJECT_ROOT / "docs/did_public/public-private-key.pem"


async def main() -> None:
    """Minimal client demo."""
    # 1. Create authentication
    auth = DIDWbaAuthHeader(
        did_document_path=str(DID_DOC),
        private_key_path=str(PRIVATE_KEY),
    )

    # 2. Discover agent
    print("Discovering agent...")
    try:
        agent = await RemoteAgent.discover(
            "http://localhost:8000/agent/ad.json",
            auth,
        )
    except Exception as e:
        print(f"Connection failed: {e}")
        print("\nPlease start the server first:")
        print("  uvicorn examples.python.openanp_examples.minimal_server:app --port 8000")
        return

    print(f"Connected: {agent.name}")

    # 3. Call methods
    result = await agent.add(a=10, b=20)
    print(f"10 + 20 = {result}")

    result = await agent.multiply(a=6, b=7)
    print(f"6 × 7 = {result}")

    print("\nDemo completed!")


if __name__ == "__main__":
    asyncio.run(main())
