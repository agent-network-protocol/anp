#!/usr/bin/env python3
"""
Minimal ANP Server Example

This example demonstrates a minimal ANP server with:
1. A basic one-line calculator function
2. A JSON endpoint that returns "hello"
3. A basic DeepSeek API call
"""

import sys
import os
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from anp.fastanp import FastANP
from openai import OpenAI
from typing import Optional
from dotenv import load_dotenv

# Load environment variables from .env if present
load_dotenv()


# Initialize FastANP plugin (without auth for simplicity)
anp = FastANP(
    name="Minimal ANP Server",
    description="A minimal ANP server with calculator, hello JSON, and DeepSeek API",
    agent_domain="http://localhost:8000",
    did="did:wba:didhost.cc:public",
    enable_auth_middleware=False,  # Disable auth for simplicity
)

# Initialize DeepSeek client (optional, will work if DEEPSEEK_API_KEY is set)
deepseek_client = None
if os.getenv("DEEPSEEK_API_KEY"):
    deepseek_client = OpenAI(
        api_key=os.getenv("DEEPSEEK_API_KEY"),
        base_url="https://api.deepseek.com"
    )


# Define ad.json route
@anp.information("/ad.json", type="AgentDescription", description="Agent Description", tags=["agent"])
def get_agent_description():
    """Get Agent Description."""
    ad = anp.get_common_header(agent_description_path="/ad.json")
    
    # Add interfaces
    ad["interfaces"] = [
        anp.interfaces[calculate].link_summary,
        anp.interfaces[call_openai].link_summary,
    ]
    
    # Add Information endpoints (automatically includes all registered information, excluding ad.json)
    ad["Infomations"] = anp.get_information_list(exclude_paths=["/ad.json"])
    
    return ad


# 1. Basic one-line calculator function
@anp.interface("/info/calculate.json", description="Basic calculator, parameters: expression: str")
def calculate(expression: str) -> dict:
    """
    Evaluate a simple mathematical expression.
    
    Args:
        expression: A simple mathematical expression (e.g., "2 + 3", "10 * 5")
        
    Returns:
        Dictionary with the result
    """
    try:
        # Simple one-line calculator - evaluate the expression
        result = eval(expression)
        return {"result": result, "expression": expression}
    except Exception as e:
        return {"error": str(e), "expression": expression}


# 2. JSON endpoint that returns "hello"
@anp.information(
    "/info/hello.json",
    type="Information",
    description="Hello message",
    tags=["information"]
)
def get_hello():
    """Return a hello message as JSON."""
    return {"message": "hello"}


# 3. Basic DeepSeek API call
@anp.interface("/info/openai_call.json", description="Call DeepSeek API, parameters: prompt: str, model: str = 'deepseek-chat'")
def call_openai(prompt: str, model: Optional[str] = "deepseek-chat") -> dict:
    """
    Make a basic DeepSeek API call.
    
    Args:
        prompt: The prompt to send to the API
        model: The model to use (default: deepseek-chat)
        
    Returns:
        Dictionary with the API response
    """
    if not deepseek_client:
        return {
            "error": "DeepSeek client not initialized. Please set DEEPSEEK_API_KEY environment variable."
        }
    
    try:
        response = deepseek_client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are a helpful assistant"},
                {"role": "user", "content": prompt}
            ],
            stream=False
        )
        
        return {
            "response": response.choices[0].message.content,
            "model": model,
            "prompt": prompt
        }
    except Exception as e:
        return {
            "error": str(e),
            "prompt": prompt
        }


def main():
    """Run the minimal ANP server."""
    import uvicorn
    
    print("=" * 60)
    print("Minimal ANP Server")
    print("=" * 60)
    print(f"- Agent Description: http://localhost:8000/ad.json")
    print(f"- Hello JSON: http://localhost:8000/info/hello.json")
    print(f"- Calculator OpenRPC: http://localhost:8000/info/calculate.json")
    print(f"- DeepSeek OpenRPC: http://localhost:8000/info/openai_call.json")
    print(f"- JSON-RPC endpoint: http://localhost:8000/rpc")
    print("")
    print("Example JSON-RPC calls:")
    print('  Calculator: curl -X POST http://localhost:8000/rpc \\')
    print('    -H "Content-Type: application/json" \\')
    print('    -d \'{"jsonrpc": "2.0", "id": 1, "method": "calculate", "params": {"expression": "2 + 3"}}\'')
    print("")
    print('  DeepSeek: curl -X POST http://localhost:8000/rpc \\')
    print('    -H "Content-Type: application/json" \\')
    print('    -d \'{"jsonrpc": "2.0", "id": 2, "method": "call_openai", "params": {"prompt": "Say hello"}}\'')
    print("")
    if deepseek_client:
        print("  ✓ DeepSeek client initialized")
    else:
        print("  ⚠ DeepSeek client not initialized (set DEEPSEEK_API_KEY)")
    print("=" * 60)
    
    uvicorn.run(anp.app, host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()

