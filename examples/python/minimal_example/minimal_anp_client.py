#!/usr/bin/env python3
"""
Minimal ANP Client Example

This example demonstrates a minimal ANP client that interacts with the minimal ANP server.
It uses the new high-level APIs in ANPClient for clean, readable code.
"""

import asyncio
import json
import sys
import traceback
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from anp.anp_crawler.anp_client import ANPClient

# ============================================================================
# Configuration
# ============================================================================

SERVER_URL = "http://localhost:8000"
DID_DOC_PATH = project_root / "docs" / "did_public" / "public-did-doc.json"
PRIVATE_KEY_PATH = project_root / "docs" / "did_public" / "public-private-key.pem"

# ============================================================================
# Helper Functions
# ============================================================================

def print_result(label: str, result: dict, data_key: str = "result"):
    """Print result or error in a consistent format."""
    if result["success"]:
        data = result.get(data_key, {})
        print(f"   ✓ {label}: {json.dumps(data, indent=2)}")
    else:
        error = result.get("error", {})
        if isinstance(error, dict):
            error_msg = error.get("message", "Unknown error")
        else:
            error_msg = str(error)
        print(f"   ✗ Error: {error_msg}")


def list_items(items: list, item_type: str):
    """List items in a formatted way."""
    if not items:
        return
    
    print(f"\n{len(items)} {item_type}(s):")
    for i, item in enumerate(items, 1):
        desc = item.get("description", "No description")
        url = item.get("url", "N/A")
        print(f"   {i}. {desc} - {url}")


def list_discovered_items(items: list, item_type: str):
    """List discovered items (with fetched data)."""
    if not items:
        return
    
    print(f"\n{len(items)} {item_type}(s) discovered:")
    for i, item in enumerate(items, 1):
        desc = item.get("description", "No description")
        url = item.get("url", "N/A")
        print(f"   {i}. {desc}")
        print(f"      URL: {url}")


# ============================================================================
# Main Function
# ============================================================================

async def main():
    """Main client function."""
    print("=" * 60)
    print("Minimal ANP Client")
    print("=" * 60)
    
    # Validate DID document exists
    if not DID_DOC_PATH.exists():
        print(f"Error: DID document not found at {DID_DOC_PATH}")
        print("Please ensure the DID document exists in docs/did_public/")
        return
    
    # Use DID doc as placeholder if private key doesn't exist (auth disabled on server)
    private_key = PRIVATE_KEY_PATH if PRIVATE_KEY_PATH.exists() else DID_DOC_PATH
    if not PRIVATE_KEY_PATH.exists():
        print(f"Warning: Private key not found, using placeholder (server has auth disabled)")
    
    # Initialize client
    print("\n1. Initializing ANP Client...")
    client = ANPClient(
        did_document_path=str(DID_DOC_PATH),
        private_key_path=str(private_key)
    )
    print("   ✓ Client initialized")
    
    # Discover agent (fetches agent description, interfaces, and information endpoints)
    ad_url = f"{SERVER_URL}/ad.json"
    print(f"\n2. Discovering agent from {ad_url}...")
    
    try:
        discovery = await client.discover_agent(ad_url)
        
        if not discovery["success"]:
            print(f"   ✗ Failed: {discovery['error']}")
            return
        
        agent_data = discovery["agent"]
        print("   ✓ Agent discovered")
        print(f"   - Name: {agent_data.get('name', 'N/A')}")
        print(f"   - DID: {agent_data.get('did', 'N/A')}")
        
        # List discovered resources (with fetched data)
        list_discovered_items(discovery["interfaces"], "interface")
        list_discovered_items(discovery["informations"], "information endpoint")
        
        # Call server methods
        print("\n3. Calling server methods...")
        
        # Calculator
        print("\n   a) Calculator...")
        calc_result = await client.call_jsonrpc(
            server_url=f"{SERVER_URL}/rpc",
            method="calculate",
            params={"expression": "2 + 3"}
        )
        print_result("Result", calc_result)
        
        # Hello JSON
        print("\n   b) Hello JSON...")
        hello_result = await client.get_information(f"{SERVER_URL}/info/hello.json")
        print_result("Hello message", hello_result, "data")
        
        # OpenAI
        print("\n   c) OpenAI API...")
        openai_result = await client.call_jsonrpc(
            server_url=f"{SERVER_URL}/rpc",
            method="call_openai",
            params={"prompt": "Say hello in one sentence"}
        )
        print_result("OpenAI response", openai_result)
        if not openai_result["success"]:
            print("   (Note: This may fail if OPENAI_API_KEY is not set on the server)")
        
        print("\n" + "=" * 60)
        print("Client interaction complete!")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n✗ Error: {str(e)}")
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
