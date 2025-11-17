#!/usr/bin/env python3
"""
Minimal ANPNode Example

This script shows how to:
1. Stand up a combined ANP server+client via ANPNode
2. Register both JSON-RPC interfaces and plain information endpoints
3. Use the built-in client helpers to call the node (or any remote peer)
"""

import asyncio
import sys
from pathlib import Path
from typing import Dict

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from anp.node import ANPNode  # noqa: E402

DID_DOC_PATH = project_root / "docs" / "did_public" / "public-did-doc.json"
PRIVATE_KEY_PATH = project_root / "docs" / "did_public" / "public-private-key.pem"
BASE_URL = "http://localhost:8010"


# ---------------------------------------------------------------------------
# Configure the node
# ---------------------------------------------------------------------------
node = ANPNode(
    name="Minimal ANPNode",
    description="Single-file ANP node example (server + client)",
    did="did:wba:didhost.cc:public",
    did_document_path=str(DID_DOC_PATH),
    private_key_path=str(PRIVATE_KEY_PATH if PRIVATE_KEY_PATH.exists() else DID_DOC_PATH),
    agent_domain=BASE_URL,
    host="0.0.0.0",
    port=8010,
    enable_auth_middleware=False,  # keep things simple for local demo
)


@node.interface("/info/calculate.json", description="Evaluate a simple expression")
def calculate(expression: str) -> Dict[str, float]:
    """Basic calculator interface exposed via JSON-RPC."""
    try:
        # WARNING: eval is for demo only. Replace with a safe parser in real apps.
        result = eval(expression, {"__builtins__": {}})  # noqa: S307
        return {"result": result, "expression": expression}
    except Exception as exc:  # pylint: disable=broad-except
        return {"error": str(exc), "expression": expression}


@node.information("/info/hello.json", description="Simple JSON greeting")
async def get_hello():
    """Information endpoint automatically included in ad.json."""
    return {"message": "Hello from ANPNode!"}


# ---------------------------------------------------------------------------
# Demo flow
# ---------------------------------------------------------------------------
async def main():
    """Start the node, exercise both client and server APIs, then stop."""
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
        ad = await node.fetch_agent_description(BASE_URL)
        print("Agent Description:")
        print(f"  name: {ad.get('name')}")
        print(f"  did:  {ad.get('did')}")
        print(f"  interfaces: {len(ad.get('interfaces', []))}")
        print(f"  informations: {len(ad.get('Infomations', []))}\n")

        # Call the calculator RPC through the same node client
        calc_result = await node.call_remote_method(
            BASE_URL,
            method="calculate",
            params={"expression": "2 + 3 * 4"},
        )
        print("JSON-RPC result:")
        print(f"  calculate -> {calc_result}\n")

        # Call the information endpoint
        hello = await node.fetch_information_endpoint(BASE_URL, "/info/hello.json")
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

