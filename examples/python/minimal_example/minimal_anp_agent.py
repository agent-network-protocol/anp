#!/usr/bin/env python3
"""
Minimal ANP Agent Example

This example demonstrates a pydantic_ai-based agent that interacts with a FastANP server
using ANPClient methods as tools. The agent accepts queries from CLI and responds in CLI.
"""

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Optional

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from pydantic_ai import Agent, RunContext
from anp import ANPClient
from dotenv import load_dotenv

# Load environment variables from .env if present
load_dotenv()

# Configuration
SERVER_URL = "http://localhost:8000"
DID_DOC_PATH = project_root / "docs" / "did_public" / "public-did-doc.json"
PRIVATE_KEY_PATH = project_root / "docs" / "did_public" / "public-private-key.pem"

# Global ANPClient instance (will be initialized in main)
anp_client: Optional[ANPClient] = None


# Configure DeepSeek model
os.environ['OPENAI_API_KEY'] = os.getenv("DEEPSEEK_API_KEY")
os.environ['OPENAI_BASE_URL'] = 'https://api.deepseek.com'

# Initialize the Pydantic AI agent with DeepSeek
anp_agent = Agent(
    'openai:deepseek-chat',
    system_prompt=(
        "You are an intelligent assistant that helps users interact with ANP (Agent Network Protocol) servers. "
        "You have access to tools that can fetch agent descriptions, call JSON-RPC methods, and retrieve information "
        "from ANP servers. Use these tools to help users accomplish their tasks. Always provide clear, helpful responses "
        "and explain what you're doing when using the tools."
    ),
)


@anp_agent.tool
async def fetch_agent_description(ctx: RunContext, server_url: Optional[str] = None) -> str:
    """
    Fetch the agent description (ad.json) from an ANP server.
    
    Args:
        server_url: The base URL of the ANP server (defaults to http://localhost:8000)
    
    Returns:
        A formatted string containing the agent description information
    """
    global anp_client
    
    if server_url is None:
        server_url = SERVER_URL
    
    ad_url = f"{server_url}/ad.json"
    
    try:
        result = await anp_client.fetch(ad_url)
        
        if result["success"]:
            agent = result["data"]
            interfaces = agent.get("interfaces", [])
            informations = agent.get("Infomations", [])
            
            response = f"Agent: {agent.get('name', 'N/A')}\n"
            response += f"DID: {agent.get('did', 'N/A')}\n"
            response += f"Description: {agent.get('description', 'N/A')}\n\n"
            
            response += f"Available Interfaces ({len(interfaces)}):\n"
            for iface in interfaces:
                response += f"  - {iface.get('url', '')}: {iface.get('description', 'No description')}\n"
            
            response += f"\nAvailable Information Endpoints ({len(informations)}):\n"
            for info in informations:
                response += f"  - {info.get('url', '')}: {info.get('description', 'No description')}\n"
            
            return response
        else:
            return f"Error fetching agent description: {result.get('error', 'Unknown error')}"
    except Exception as e:
        return f"Exception while fetching agent description: {str(e)}"


@anp_agent.tool
async def call_jsonrpc_method(
    ctx: RunContext,
    method: str,
    params: dict,
    server_url: Optional[str] = None
) -> str:
    """
    Call a JSON-RPC method on an ANP server.
    
    Args:
        method: The name of the JSON-RPC method to call
        params: A dictionary of parameters to pass to the method
        server_url: The base URL of the ANP server (defaults to http://localhost:8000)
    
    Returns:
        A formatted string containing the result or error
    """
    global anp_client
    
    if server_url is None:
        server_url = SERVER_URL
    
    rpc_url = f"{server_url}/rpc"
    
    try:
        result = await anp_client.call_jsonrpc(
            server_url=rpc_url,
            method=method,
            params=params
        )
        
        if result["success"]:
            return f"Success: {json.dumps(result['result'], indent=2, ensure_ascii=False)}"
        else:
            error = result.get("error", {})
            error_msg = error.get("message", "Unknown error") if isinstance(error, dict) else str(error)
            return f"Error: {error_msg}"
    except Exception as e:
        return f"Exception while calling JSON-RPC method: {str(e)}"


@anp_agent.tool
async def fetch_information(
    ctx: RunContext,
    endpoint_path: str,
    server_url: Optional[str] = None
) -> str:
    """
    Fetch information from an ANP server information endpoint.
    
    Args:
        endpoint_path: The path to the information endpoint (e.g., "/info/hello.json")
        server_url: The base URL of the ANP server (defaults to http://localhost:8000)
    
    Returns:
        A formatted string containing the information data
    """
    global anp_client
    
    if server_url is None:
        server_url = SERVER_URL
    
    # Ensure endpoint_path starts with /
    if not endpoint_path.startswith("/"):
        endpoint_path = "/" + endpoint_path
    
    info_url = f"{server_url}{endpoint_path}"
    
    try:
        result = await anp_client.fetch(info_url)
        
        if result["success"]:
            return f"Information from {endpoint_path}:\n{json.dumps(result['data'], indent=2, ensure_ascii=False)}"
        else:
            return f"Error fetching information: {result.get('error', 'Unknown error')}"
    except Exception as e:
        return f"Exception while fetching information: {str(e)}"


async def main():
    """Main function to run the agent in CLI mode."""
    global anp_client
    
    print("=" * 60)
    print("Minimal ANP Agent (Pydantic AI)")
    print("=" * 60)
    print(f"Model: DeepSeek Chat")
    print(f"Server URL: {SERVER_URL}")
    print(f"DID Document: {DID_DOC_PATH}")
    print(f"Private Key: {PRIVATE_KEY_PATH}")
    print("")
    
    # Initialize ANPClient
    if not DID_DOC_PATH.exists():
        print(f"Error: DID document not found at {DID_DOC_PATH}")
        print("Please ensure the DID document exists before running the agent.")
        return
    
    private_key = PRIVATE_KEY_PATH if PRIVATE_KEY_PATH.exists() else DID_DOC_PATH
    anp_client = ANPClient(
        did_document_path=str(DID_DOC_PATH),
        private_key_path=str(private_key)
    )
    print("✓ ANPClient initialized")
    print("")
    print("You can now interact with the ANP server through this agent.")
    print("Try asking questions like:")
    print("  - 'What services does this agent provide?'")
    print("  - 'Calculate 2 + 3 * 4'")
    print("  - 'Call the hello endpoint'")
    print("  - 'What information endpoints are available?'")
    print("")
    print("Type 'exit' or 'quit' to exit.")
    print("=" * 60)
    print("")
    
    # Run the agent in CLI mode
    # Use a simple interactive loop that works with async tools
    print("Entering interactive mode. Type 'exit' or 'quit' to exit.\n")
    
    try:
        while True:
            try:
                user_input = input("You: ").strip()
                if user_input.lower() in ['exit', 'quit', 'q']:
                    print("Goodbye!")
                    break
                
                if not user_input:
                    continue
                
                # Run the agent with the user's query
                result = await anp_agent.run(user_input)
                
                # Print tool calls and results using official pydantic_ai approach
                messages = result.all_messages()
                if messages:
                    print("\n--- Tool Calls & Results ---")
                    for msg in messages:
                        if hasattr(msg, 'role'):
                            if msg.role == 'tool_call':
                                print(f"  🔧 Tool Call: {msg.name}")
                                if hasattr(msg, 'args') and msg.args:
                                    print(f"     Args: {json.dumps(msg.args, indent=6, ensure_ascii=False)}")
                            elif msg.role == 'tool_return':
                                content = str(msg.content)
                                if len(content) > 500:
                                    content = content[:500] + "..."
                                print(f"  ✓ Tool Return ({msg.name}): {content}")
                    print("--- End Tool Calls & Results ---\n")
                
                print(f"\nAgent: {result.output}\n")
            except KeyboardInterrupt:
                print("\n\nExiting...")
                break
            except Exception as e:
                print(f"\nError: {str(e)}\n")
                import traceback
                traceback.print_exc()
    except Exception as e:
        print(f"\n\nFatal error: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())

