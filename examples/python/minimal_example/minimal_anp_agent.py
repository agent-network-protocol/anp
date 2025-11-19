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
                
                # Print intermediate steps (tool calls)
                # Check various possible attributes for tool call information
                tool_calls_found = False
                
                # Try to access all_messages (common in pydantic_ai)
                # Check if it's a method or property
                all_messages = None
                if hasattr(result, 'all_messages'):
                    if callable(result.all_messages):
                        try:
                            all_messages = result.all_messages()
                        except:
                            pass
                    else:
                        all_messages = result.all_messages
                
                if all_messages:
                    print("\n--- Tool Calls & Results ---")
                    tool_call_count = 0
                    for i, msg in enumerate(all_messages):
                        # Check for tool calls in message
                        if hasattr(msg, 'tool_calls') and msg.tool_calls:
                            for tool_call in msg.tool_calls:
                                tool_calls_found = True
                                tool_call_count += 1
                                tool_name = getattr(tool_call, 'function_name', getattr(tool_call, 'name', str(tool_call)))
                                print(f"\n  🔧 Tool Call #{tool_call_count}: {tool_name}")
                                
                                # Display arguments
                                if hasattr(tool_call, 'args'):
                                    args = tool_call.args
                                    if args:
                                        print(f"     Args: {json.dumps(args, indent=8, ensure_ascii=False)}")
                                elif hasattr(tool_call, 'arguments'):
                                    args = tool_call.arguments
                                    if isinstance(args, str):
                                        try:
                                            args = json.loads(args)
                                        except:
                                            pass
                                    if args:
                                        print(f"     Args: {json.dumps(args, indent=8, ensure_ascii=False)}")
                        
                        # Check for tool results in the same message
                        if hasattr(msg, 'tool_results') and msg.tool_results:
                            for j, tool_result in enumerate(msg.tool_results):
                                result_str = str(tool_result)
                                if len(result_str) > 500:
                                    result_str = result_str[:500] + "..."
                                print(f"  ✓ Result: {result_str}")
                        
                        # Check if message is a tool result message (role='tool')
                        if hasattr(msg, 'role') and msg.role == 'tool':
                            content = getattr(msg, 'content', None)
                            if content:
                                content_str = str(content)
                                if len(content_str) > 500:
                                    content_str = content_str[:500] + "..."
                                print(f"  ✓ Tool Result: {content_str}")
                        
                        # Check for content in tool messages
                        if hasattr(msg, 'role') and getattr(msg, 'role', None) in ['tool', 'assistant']:
                            if hasattr(msg, 'content') and msg.content:
                                # Check if this is a tool result
                                if hasattr(msg, 'tool_call_id') or (hasattr(msg, 'role') and msg.role == 'tool'):
                                    content_str = str(msg.content)
                                    if len(content_str) > 500:
                                        content_str = content_str[:500] + "..."
                                    print(f"  ✓ Tool Result: {content_str}")
                    
                    if tool_calls_found or tool_call_count > 0:
                        print("\n--- End Tool Calls & Results ---\n")
                
                # Also check result object directly for tool calls and results
                if not tool_calls_found:
                    if hasattr(result, 'tool_calls') and result.tool_calls:
                        print("\n--- Tool Calls & Results ---")
                        for tool_call in result.tool_calls:
                            print(f"  🔧 Tool: {tool_call}")
                        print("--- End Tool Calls & Results ---\n")
                        tool_calls_found = True
                    
                    # Check for tool results directly on result object
                    if hasattr(result, 'tool_results') and result.tool_results:
                        if not tool_calls_found:
                            print("\n--- Tool Results ---")
                        for tool_result in result.tool_results:
                            result_str = str(tool_result)
                            if len(result_str) > 500:
                                result_str = result_str[:500] + "..."
                            print(f"  ✓ Result: {result_str}")
                        if not tool_calls_found:
                            print("--- End Tool Results ---\n")
                    
                    # Check for data that might contain tool results
                    if hasattr(result, 'data') and result.data:
                        # Check if data contains tool-related information
                        data_str = str(result.data)
                        if 'tool' in data_str.lower() or 'result' in data_str.lower():
                            print(f"\n  📊 Additional Data: {data_str[:300]}...")
                
                # Check for steps
                if not tool_calls_found and hasattr(result, 'steps') and result.steps:
                    print("\n--- Steps ---")
                    for step_num, step in enumerate(result.steps, 1):
                        print(f"\n  Step #{step_num}:")
                        if hasattr(step, 'tool_calls') and step.tool_calls:
                            for tool_call in step.tool_calls:
                                tool_name = getattr(tool_call, 'function_name', getattr(tool_call, 'name', str(tool_call)))
                                print(f"    🔧 Tool: {tool_name}")
                                if hasattr(tool_call, 'args') and tool_call.args:
                                    print(f"       Args: {json.dumps(tool_call.args, indent=10, ensure_ascii=False)}")
                        
                        # Check for tool results in step
                        if hasattr(step, 'tool_results') and step.tool_results:
                            for tool_result in step.tool_results:
                                result_str = str(tool_result)
                                if len(result_str) > 500:
                                    result_str = result_str[:500] + "..."
                                print(f"    ✓ Result: {result_str}")
                        
                        # Check for result/response in step
                        if hasattr(step, 'result'):
                            result_str = str(step.result)
                            if len(result_str) > 500:
                                result_str = result_str[:500] + "..."
                            print(f"    ✓ Step Result: {result_str}")
                    print("\n--- End Steps ---\n")
                    tool_calls_found = True
                
                # If no tool calls found, print debug info (can be removed later)
                if not tool_calls_found and hasattr(result, '__dict__'):
                    # Debug: print available attributes
                    attrs = [attr for attr in dir(result) if not attr.startswith('_')]
                    if 'all_messages' not in attrs and 'tool_calls' not in attrs:
                        # Only print debug if we really can't find tool calls
                        pass  # Comment out this pass to enable debug mode
                        # print(f"\n[Debug] Result attributes: {', '.join(attrs)}")
                
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

