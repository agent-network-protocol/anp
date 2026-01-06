"""
OpenANP Client - ANP protocol client operations.

Uses anp_crawler module for HTTP operations.

Two layers:
- High-level: RemoteAgent class for discovery and calling
- Low-level: Pure functions for parsing

Example:

    from anp.openanp import RemoteAgent

    agent = await RemoteAgent.discover(ad_url, auth)
    result = await agent.search(query="Tokyo")

    # Or low-level parsing:
    from anp.openanp.client import parse_agent_document
    import json
    text = ...  # fetched from URL
    ad = json.loads(text)
    _, methods = parse_agent_document(ad)
"""

from .agent import HttpError, Method, RemoteAgent, RpcError
from .openrpc import convert_to_openai_tool, parse_agent_document, parse_openrpc

__all__ = [
    # High-level
    "RemoteAgent",
    "Method",
    # Errors
    "HttpError",
    "RpcError",
    # Parsing
    "parse_openrpc",
    "parse_agent_document",
    "convert_to_openai_tool",
]
