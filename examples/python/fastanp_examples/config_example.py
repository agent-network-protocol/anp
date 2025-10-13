#!/usr/bin/env python3
"""
FastANP with DidWbaVerifierConfig Example

This example demonstrates using DidWbaVerifierConfig for authentication.
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from fastapi import FastAPI

from anp.authentication.did_wba_verifier import DidWbaVerifierConfig
from anp.fastanp import FastANP
from anp.fastanp.utils import load_private_key

# Initialize FastAPI app
app = FastAPI(
    title="Config Example",
    description="Example using DidWbaVerifierConfig",
    version="1.0.0"
)

# Load JWT keys
jwt_private_key = load_private_key(
    str(project_root / "docs" / "jwt_rs256" / "private_key.pem")
).decode('utf-8')
jwt_public_key = load_private_key(
    str(project_root / "docs" / "jwt_rs256" / "public_key.pem")
).decode('utf-8')

# Create custom auth config with allowed domains
auth_config = DidWbaVerifierConfig(
    jwt_private_key=jwt_private_key,
    jwt_public_key=jwt_public_key,
    jwt_algorithm="RS256",
    access_token_expire_minutes=120,  # 2 hours
    nonce_expiration_minutes=10,
    timestamp_expiration_minutes=5,
    allowed_domains=["example.com", "*.example.com"]  # Domain whitelist in config
)

# Initialize FastANP with auth config
anp = FastANP(
    app=app,
    name="Config Example Agent",
    description="Demonstrates custom authentication configuration",
    agent_domain="https://example.com",
    agent_description_path="/ad.json",
    did="did:wba:example.com:agent:config-example",
    auth_config=auth_config,  # Pass the config directly (includes allowed_domains)
    enable_auth_middleware=True,
)


# Define ad.json route
@app.get("/ad.json", tags=["agent"])
def get_agent_description():
    """Get Agent Description."""
    ad = anp.get_common_header()
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
        name: Name to greet

    Returns:
        Greeting message
    """
    return {"message": f"Hello, {name}!"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
