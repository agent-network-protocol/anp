#!/usr/bin/env python3
"""
Minimal ANP Client Example

This example demonstrates a minimal ANP client that interacts with the minimal ANP server.
It uses the DID documents from docs/did_public folder.
"""

import asyncio
import json
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from anp.anp_crawler.anp_client import ANPClient
from anp.anp_crawler.anp_parser import ANPDocumentParser


async def main():
    """Main client function."""
    print("=" * 60)
    print("Minimal ANP Client")
    print("=" * 60)
    
    # Paths to DID documents (assuming they exist in docs/did_public)
    did_doc_path = project_root / "docs" / "did_public" / "public-did-doc.json"
    
    # Check if DID document exists
    if not did_doc_path.exists():
        print(f"Error: DID document not found at {did_doc_path}")
        print("Please ensure the DID document exists in docs/did_public/")
        return
    
    # For this example, we'll use a placeholder private key path
    # In a real scenario, you would have the actual private key
    private_key_path = project_root / "docs" / "did_public" / "public-private-key.pem"
    
    # If private key doesn't exist, we'll still try to connect (server has auth disabled)
    if not private_key_path.exists():
        print(f"Warning: Private key not found at {private_key_path}")
        print("Using placeholder - server has auth disabled, so this should work")
        # Create a dummy path for initialization
        private_key_path = did_doc_path  # Use DID doc as placeholder
    
    # Initialize ANP client
    print("\n1. Initializing ANP Client...")
    client = ANPClient(
        did_document_path=str(did_doc_path),
        private_key_path=str(private_key_path)
    )
    print("   ✓ Client initialized")
    
    # Server URL
    server_url = "http://localhost:8000"
    ad_url = f"{server_url}/ad.json"
    
    print(f"\n2. Fetching Agent Description from {ad_url}...")
    
    try:
        # Fetch agent description
        response = await client.fetch_url(ad_url)
        
        if not response.get("success", False):
            print(f"   ✗ Failed to fetch agent description: {response.get('error', 'Unknown error')}")
            return
        
        print("   ✓ Agent description fetched")
        
        # Parse the agent description
        parser = ANPDocumentParser()
        content = parser.parse_document(
            content=response.get("text", ""),
            content_type=response.get("content_type", "application/json"),
            source_url=ad_url
        )
        
        print("\n3. Parsed Agent Description:")
        print(json.dumps(content, indent=2, ensure_ascii=False))
        
        # Get interfaces
        interfaces = content.get("interfaces", [])
        print(f"\n4. Found {len(interfaces)} interface(s)")
        
        # List available interfaces
        for i, interface in enumerate(interfaces, 1):
            if interface.get("type") == "StructuredInterface":
                interface_url = interface.get("url", "N/A")
                print(f"   {i}. {interface.get('description', 'No description')} - {interface_url}")
        
        # Now let's call the methods directly using JSON-RPC
        print("\n6. Calling server methods via JSON-RPC...")
        
        # Call calculator
        print("\n   a) Calling calculate('2 + 3')...")
        calc_response = await client.fetch_url(
            url=f"{server_url}/rpc",
            method="POST",
            headers={"Content-Type": "application/json"},
            body={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "calculate",
                "params": {"expression": "2 + 3"}
            }
        )
        
        if calc_response.get("success"):
            result = json.loads(calc_response.get("text", "{}"))
            print(f"   ✓ Result: {json.dumps(result, indent=2)}")
        else:
            print(f"   ✗ Error: {calc_response.get('error', 'Unknown error')}")
        
        # Get hello JSON
        print("\n   b) Fetching hello.json...")
        hello_response = await client.fetch_url(f"{server_url}/info/hello.json")
        
        if hello_response.get("success"):
            hello_data = json.loads(hello_response.get("text", "{}"))
            print(f"   ✓ Hello message: {json.dumps(hello_data, indent=2)}")
        else:
            print(f"   ✗ Error: {hello_response.get('error', 'Unknown error')}")
        
        # Call OpenAI (if API key is set)
        print("\n   c) Calling OpenAI API...")
        openai_response = await client.fetch_url(
            url=f"{server_url}/rpc",
            method="POST",
            headers={"Content-Type": "application/json"},
            body={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "call_openai",
                "params": {"prompt": "Say hello in one sentence"}
            }
        )
        
        if openai_response.get("success"):
            openai_result = json.loads(openai_response.get("text", "{}"))
            print(f"   ✓ OpenAI response: {json.dumps(openai_result, indent=2)}")
        else:
            print(f"   ✗ Error: {openai_response.get('error', 'Unknown error')}")
            print("   (Note: This may fail if OPENAI_API_KEY is not set on the server)")
        
        print("\n" + "=" * 60)
        print("Client interaction complete!")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n✗ Error: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())

