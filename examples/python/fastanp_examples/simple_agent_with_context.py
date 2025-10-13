#!/usr/bin/env python3
"""
Simple Agent with Context Example

This example demonstrates Context injection for session management.
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from fastapi import FastAPI

from anp.fastanp import Context, FastANP

# Initialize FastAPI app
app = FastAPI(
    title="Simple Agent with Context",
    description="A simple ANP agent with Context injection",
    version="1.0.0"
)

# Initialize FastANP plugin
anp = FastANP(
    app=app,
    name="Simple Agent with Context",
    description="Demonstrates Context injection and session management",
    agent_domain="https://example.com",
    agent_description_path="/ad.json",
    did="did:wba:example.com:agent:simple-context",
    enable_auth_middleware=False,  # Disable auth for demo
)


# Define ad.json route
@app.get("/ad.json", tags=["agent"])
def get_agent_description():
    """Get Agent Description."""
    ad = anp.get_common_header()
    ad["interfaces"] = [
        anp.interfaces[counter].link_summary,
    ]
    return ad


# Register interface with Context injection
@anp.interface("/info/counter.json", description="Counter with session")
def counter(ctx: Context) -> dict:
    """
    A counter that tracks calls per session.
    
    Args:
        ctx: Automatically injected context with session management
        
    Returns:
        Counter result with session info
    """
    # Get current count from session
    count = ctx.session.get("count", 0)
    count += 1
    ctx.session.set("count", count)
    
    return {
        "count": count,
        "session_id": ctx.session.id,
        "did": ctx.did,
        "message": f"This is call #{count} in this session"
    }


def main():
    """Run the agent server."""
    import uvicorn
    
    print("Starting Simple Agent with Context...")
    print("- Agent Description: http://localhost:8000/ad.json")
    print("- JSON-RPC endpoint: http://localhost:8000/rpc")
    print("")
    print("Try calling the counter method multiple times:")
    print('  curl -X POST http://localhost:8000/rpc \\')
    print('    -H "Content-Type: application/json" \\')
    print('    -d \'{"jsonrpc": "2.0", "id": 1, "method": "counter", "params": {}}\'')
    print("")
    print("Note: Each call will increment the counter in the session!")
    
    uvicorn.run(app, host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()

