#!/usr/bin/env python3
"""
Minimal ANP Client Example

This example demonstrates a minimal ANP client that interacts with the minimal ANP server.
It uses the unified fetch() API in ANPClient for simple, clean code.
"""

import asyncio
import json
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from anp import ANPClient

SERVER_URL = "http://localhost:8000"
DID_DOC_PATH = project_root / "docs" / "did_public" / "public-did-doc.json"
PRIVATE_KEY_PATH = project_root / "docs" / "did_public" / "public-private-key.pem"


async def main():
    """Main client function."""
    print("=" * 60)
    print("Minimal ANP Client")
    print("=" * 60)
    
    # Initialize client
    if not DID_DOC_PATH.exists():
        print(f"Error: DID document not found at {DID_DOC_PATH}")
        return
    
    private_key = PRIVATE_KEY_PATH if PRIVATE_KEY_PATH.exists() else DID_DOC_PATH
    client = ANPClient(
        did_document_path=str(DID_DOC_PATH),
        private_key_path=str(private_key)
    )
    print("\n1. Client initialized")
    
    # Fetch agent description
    ad_url = f"{SERVER_URL}/ad.json"
    print(f"\n2. Fetching agent description from {ad_url}...")
    agent_result = await client.fetch(ad_url)
    if agent_result ["success"]:
        agent = agent_result["data"]
        print(f"   ✓ Agent: {agent.get('name', 'N/A')} (DID: {agent.get('did', 'N/A')})")
        print(f"   ✓ Interfaces: {len(agent.get('interfaces', []))}")
        # Print list of interfaces with summary
        for iface in agent.get("interfaces", []):
            print(f"      - {iface.get('url', '')} : {iface.get('description', '')}")

        print(f"   ✓ Informations: {len(agent.get('Infomations', []))}")
        # Print list of information endpoints
        for info in agent.get("Infomations", []):
            print(f"      - {info.get('url', '')} : {info.get('description', 'No description')}")
    else:
        print(f"   ✗ Agent error: {agent_result.get('error')}")
        return
    
    
    # Call server methods
    print("\n3. Calling server methods...")
    
    # Hello - fetch the hello endpoint
    hello_result = await client.fetch(f"{SERVER_URL}/info/hello.json")
    if hello_result["success"]:
        print(f"   ✓ Hello: {json.dumps(hello_result['data'], indent=2)}")
    else:
        print(f"   ✗ Hello error: {hello_result.get('error')}")
    
    # Calculator
    calc_result = await client.call_jsonrpc(
        server_url=f"{SERVER_URL}/rpc",
        method="calculate",
        params={"expression": "2 + 3"}
    )
    if calc_result["success"]:
        print(f"   ✓ Calculator: {json.dumps(calc_result['result'], indent=2)}")
    else:
        print(f"   ✗ Calculator error: {calc_result.get('error', {})}")
    
    # DeepSeek
    deepseek_result = await client.call_jsonrpc(
        server_url=f"{SERVER_URL}/rpc",
        method="call_openai",
        params={"prompt": "Say hello in one sentence"}
    )
    if deepseek_result["success"]:
        print(f"   ✓ DeepSeek: {json.dumps(deepseek_result['result'], indent=2)}")
    else:
        print(f"   ✗ DeepSeek error: {deepseek_result.get('error', {})}")
        print("   (Note: This may fail if DEEPSEEK_API_KEY is not set on the server)")
    
    print("\n" + "=" * 60)
    print("Complete!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
