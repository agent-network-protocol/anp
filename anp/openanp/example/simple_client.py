"""OpenANP client example - discovering and calling remote agents.

This example demonstrates:
1. Agent discovery via AD URL
2. Method calling via dynamic attribute access
3. Method calling via explicit call() method
4. Accessing OpenAI Tools format for LLM integration

Prerequisites:
- Start the server first: uvicorn anp.openanp.example.simple_server:app --port 8000
- Update paths to your DID document and private key

Run with:
    uv run python -m anp.openanp.example.simple_client
"""

import asyncio
from pathlib import Path

from anp.authentication import DIDWbaAuthHeader
from anp.openanp import RemoteAgent


# Default paths - update for your environment
DEFAULT_DID_DOC = Path(__file__).parent.parent.parent.parent.parent / "docs/did_public/public-did-doc.json"
DEFAULT_PRIVATE_KEY = Path(__file__).parent.parent.parent.parent.parent / "docs/did_public/public-private-key.pem"


async def main() -> None:
    """Demonstrate OpenANP client capabilities."""

    # Setup authentication
    auth = DIDWbaAuthHeader(
        did_document_path=str(DEFAULT_DID_DOC),
        private_key_path=str(DEFAULT_PRIVATE_KEY),
    )

    # Discover agent from AD URL
    # This fetches ad.json, parses interfaces, and loads OpenRPC documents
    print("Discovering agent...")
    try:
        agent = await RemoteAgent.discover(
            "http://localhost:8000/hotel/ad.json",
            auth
        )
    except Exception as e:
        print(f"Failed to discover agent: {e}")
        print("\nMake sure the server is running:")
        print("  uvicorn anp.openanp.example.simple_server:app --port 8000")
        return

    # Print agent info
    print(f"\n{'='*60}")
    print(f"Agent: {agent.name}")
    print(f"Description: {agent.description}")
    print(f"URL: {agent.url}")
    print(f"{'='*60}")

    # List available methods
    print(f"\nAvailable methods ({len(agent.methods)}):")
    for i, method in enumerate(agent.methods, 1):
        print(f"\n  {i}. {method.name}")
        print(f"     Description: {method.description}")
        print(f"     RPC URL: {method.rpc_url}")
        if method.params:
            print(f"     Parameters: {len(method.params)}")
            for param in method.params:
                print(f"       - {param.get('name')}: {param.get('schema', {}).get('type', 'any')}")

    # Get OpenAI Tools format for LLM integration
    print(f"\n{'='*60}")
    print("OpenAI Tools format (for LLM integration):")
    print(f"{'='*60}")
    tools = agent.tools
    for tool in tools:
        func = tool["function"]
        print(f"\n  Tool: {func['name']}")
        print(f"  Description: {func['description']}")
        params = func["parameters"]
        if params.get("properties"):
            print(f"  Parameters:")
            for name, schema in params["properties"].items():
                required = name in params.get("required", [])
                req_str = " (required)" if required else ""
                print(f"    - {name}: {schema.get('type', 'any')}{req_str}")

    # Call methods
    print(f"\n{'='*60}")
    print("Calling methods:")
    print(f"{'='*60}")

    # Method 1: Dynamic attribute access
    print("\n1. Search via dynamic access (agent.search()):")
    try:
        result = await agent.search(query="Tokyo")
        print(f"   Result: {result}")
    except Exception as e:
        print(f"   Error: {e}")

    # Method 2: Explicit call() method
    print("\n2. Book via explicit call (agent.call('book', ...)):")
    try:
        result = await agent.call(
            "book",
            hotel_id="tokyo-001",
            check_in="2024-06-01",
            check_out="2024-06-03",
        )
        print(f"   Result: {result}")
    except Exception as e:
        print(f"   Error: {e}")

    # Method 3: Context-aware method
    print("\n3. Search with context (session tracking):")
    try:
        result = await agent.search_with_context(query="Kyoto")
        print(f"   Result: {result}")
    except Exception as e:
        print(f"   Error: {e}")

    print(f"\n{'='*60}")
    print("Done!")


if __name__ == "__main__":
    asyncio.run(main())
