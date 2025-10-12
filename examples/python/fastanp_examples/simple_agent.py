#!/usr/bin/env python3
"""
Simple Agent Example

This is the minimal FastANP agent example showing the basic usage.
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from fastapi import FastAPI

from anp.fastanp import FastANP

# Initialize FastAPI app
app = FastAPI(
    title="Simple Agent",
    description="A simple ANP agent example",
    version="1.0.0"
)

# Initialize FastANP plugin
anp = FastANP(
    app=app,
    name="Simple Agent",
    description="A simple ANP agent built with FastANP",
    base_url="https://example.com",
    did="did:wba:example.com:agent:simple",
    enable_auth_middleware=False,  # Disable middleware for simplicity
)


# Define ad.json route
@app.get("/ad.json", tags=["agent"])
def get_agent_description():
    """Get Agent Description."""
    # Get common header
    ad = anp.get_common_header()
    
    # Add interfaces
    ad["interfaces"] = [
        anp.interfaces[hello].link_summary,
    ]
    
    return ad


# Register a simple interface
@anp.interface("/info/hello.json", description="Say hello")
def hello(name: str) -> dict:
    """
    Greet someone by name.
    
    Args:
        name: The name to greet
        
    Returns:
        Greeting message
    """
    return {"message": f"Hello, {name}!"}


def main():
    """Run the simple agent server."""
    import uvicorn
    
    print("Starting Simple Agent...")
    print("- Agent Description: http://localhost:8000/ad.json")
    print("- OpenRPC document: http://localhost:8000/info/hello.json")
    print("- JSON-RPC endpoint: http://localhost:8000/rpc")
    print("")
    print("Try calling the hello method:")
    print('  curl -X POST http://localhost:8000/rpc \\')
    print('    -H "Content-Type: application/json" \\')
    print('    -d \'{"jsonrpc": "2.0", "id": 1, "method": "hello", "params": {"name": "World"}}\'')
    
    uvicorn.run(app, host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()
