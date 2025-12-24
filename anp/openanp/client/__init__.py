"""
OpenANP Client - ANP protocol client operations.

Two layers:
- High-level: RemoteAgent class for discovery and calling
- Low-level: Pure functions for HTTP and parsing

Example:

    from anp.openanp import RemoteAgent

    agent = await RemoteAgent.discover(ad_url, auth)
    result = await agent.search(query="Tokyo")

    # Or low-level:
    from anp.openanp.client import fetch, call_rpc, parse_agent_document
    import json
    text = await fetch(url, auth)
    ad = json.loads(text)
    _, methods = parse_agent_document(ad)
"""

from .agent import Method, RemoteAgent
from .http import (
    HttpError,
    RpcError,
    call_rpc,
    call_rpc_batch,
    call_rpc_concurrent,
    call_rpc_stream,
    fetch,
)
from .openrpc import convert_to_openai_tool, parse_agent_document, parse_openrpc

__all__ = [
    # High-level
    "RemoteAgent",
    "Method",
    # HTTP - Single call
    "fetch",
    "call_rpc",
    "call_rpc_stream",
    # HTTP - Concurrent calls (对齐 MCP 并发模型)
    "call_rpc_batch",  # 批量请求，服务端并发执行
    "call_rpc_concurrent",  # 并行 HTTP 请求
    # Errors
    "HttpError",
    "RpcError",
    # Parsing
    "parse_openrpc",
    "parse_agent_document",
    "convert_to_openai_tool",
]
