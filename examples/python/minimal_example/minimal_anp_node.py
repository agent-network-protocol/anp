#!/usr/bin/env python3
"""
Minimal ANPNode Example

This script demonstrates the simplest way to run an ANP node that can act as both
server and client:

1. Define an ANP server using FastANP (FastAPI app is created for you).
2. Wrap the FastANP instance with ANPNode to add client capabilities.
3. Start the node, exercise JSON-RPC and information endpoints, then stop it.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Dict

# ---------------------------------------------------------------------------
# Add project root to sys.path so the example works when run directly
# ---------------------------------------------------------------------------
project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from anp.fastanp import FastANP  # noqa: E402
from anp.node import ANPNode  # noqa: E402

# ---------------------------------------------------------------------------
# Demo configuration
# ---------------------------------------------------------------------------
DID_DOC_PATH = project_root / "docs" / "did_public" / "public-did-doc.json"
PRIVATE_KEY_PATH = project_root / "docs" / "did_public" / "public-private-key.pem"
KEY_PATH = PRIVATE_KEY_PATH if PRIVATE_KEY_PATH.exists() else DID_DOC_PATH
BASE_URL = "http://localhost:8010"

# ---------------------------------------------------------------------------
# Step 1. Define the ANP server using FastANP
# ---------------------------------------------------------------------------
anp = FastANP(
    name="Minimal ANPNode",
    description="Single-file ANP node example (server + client)",
    did="did:wba:didhost.cc:public",
    agent_domain=BASE_URL,
    enable_auth_middleware=False,  # keep things simple for the demo
)


@anp.interface("/info/calculate.json", description="Evaluate a simple expression")
def calculate(expression: str) -> Dict[str, float]:
    """Basic calculator interface exposed via JSON-RPC."""
    try:
        # WARNING: eval is for demo only. Replace with a safe parser in real apps.
        result = eval(expression, {"__builtins__": {}})  # noqa: S307
        return {"result": result, "expression": expression}
    except Exception as exc:  # pylint: disable=broad-except
        return {"error": str(exc), "expression": expression}


@anp.information("/info/hello.json", description="Simple JSON greeting")
async def get_hello():
    """Information endpoint automatically included in ad.json."""
    return {"message": "Hello from ANPNode!"}


# ---------------------------------------------------------------------------
# Step 2. Wrap FastANP with ANPNode to add client capabilities
# ---------------------------------------------------------------------------
node = ANPNode(
    fastanp=anp,
    did_document_path=str(DID_DOC_PATH),
    private_key_path=str(KEY_PATH),
    host="0.0.0.0",
    port=8010,
)


# ---------------------------------------------------------------------------
# Demo flow
# ---------------------------------------------------------------------------
async def main():
    """Start the node, call its APIs via the built-in client, then stop."""
    print("=" * 60)
    print("Minimal ANPNode Example")
    print("=" * 60)
    print(f"- Agent Description: {BASE_URL}/ad.json")
    print(f"- Hello JSON:       {BASE_URL}/info/hello.json")
    print(f"- JSON-RPC endpoint:{BASE_URL}/rpc")
    print("")

    await node.start()
    print("✓ Node started\n")

    try:
        # Fetch ad.json using the built-in client helper
        ad = await node.fetch(f"{BASE_URL}/ad.json")
        print("Agent Description:")
        print(f"  name: {ad.get('name')}")
        print(f"  did:  {ad.get('did')}")
        print(f"  interfaces: {len(ad.get('interfaces', []))}")
        print(f"  informations: {len(ad.get('Infomations', []))}\n")

        # Call the calculator RPC through the same node client
        calc_result = await node.call_jsonrpc(
            f"{BASE_URL}/rpc",
            method="calculate",
            params={"expression": "2 + 3 * 4"},
        )
        print("JSON-RPC result:")
        print(f"  calculate -> {calc_result}\n")

        # Call the information endpoint
        hello = await node.fetch(f"{BASE_URL}/info/hello.json")
        print("Information endpoint:")
        print(f"  {hello}\n")

        print("Done! Press Ctrl+C to exit.")
        await asyncio.sleep(1)
    finally:
        await node.stop()
        print("\n✓ Node stopped")
        print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())

