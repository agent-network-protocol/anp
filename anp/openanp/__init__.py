"""OpenANP - Modern ANP Agent SDK

Python SDK for Agent Network Protocol (ANP). Build P2P agents that are both
client and server.

Quick Start - Server:

    from fastapi import FastAPI
    from anp.openanp import anp_agent, interface, AgentConfig

    @anp_agent(AgentConfig(name="Hotel", did="did:wba:example.com:hotel"))
    class HotelAgent:
        @interface
        async def search(self, query: str) -> dict:
            return {"results": [{"name": "Tokyo Hotel", "price": 100}]}

    app = FastAPI()
    app.include_router(HotelAgent.router())

Quick Start - Client:

    from anp.openanp import RemoteAgent
    from anp.authentication import DIDWbaAuthHeader

    auth = DIDWbaAuthHeader(
        did_document_path="/path/to/did-doc.json",
        private_key_path="/path/to/private-key.pem",
    )

    # Discover agent (fetches ad.json + interface.json)
    agent = await RemoteAgent.discover("https://hotel.example.com/ad.json", auth)

    # Call methods
    result = await agent.search(query="Tokyo")

Quick Start - P2P (Both):

    @anp_agent(AgentConfig(name="Travel", did="..."))
    class TravelAgent:
        def __init__(self, auth: DIDWbaAuthHeader):
            self.auth = auth

        @interface
        async def plan_trip(self, destination: str) -> dict:
            # I'm a server - expose this method
            # I'm also a client - call other agents
            hotel = await RemoteAgent.discover("https://hotel.example.com/ad.json", self.auth)
            return await hotel.search(query=destination)

See README.md for complete documentation.
"""

__version__ = "0.0.2"

# =============================================================================
# Client SDK (ANP protocol client capabilities)
# =============================================================================
from . import client

# =============================================================================
# 自动生成路由（可选）
# =============================================================================
from .autogen import create_agent_router
from .client import Method, RemoteAgent

# =============================================================================
# 装饰器（可选）
# =============================================================================
from .decorators import (
    anp_agent,
    extract_rpc_methods,
    interface,
)

# =============================================================================
# Schema 自动生成（核心）
# WHY: Auto-generate JSON Schema from Python type hints to reduce boilerplate.
# ADR: docs/adr/0001-auto-schema-generation.md
# =============================================================================
from .schema_gen import (
    extract_method_schemas,
    type_to_json_schema,
)
from .types import (
    AgentConfig,
    AgentProtocol,
    ConfigurationError,
    OpenANPError,
    FrozenRPCMethodCollection,
    IHealthCheck,
    InternalError,
    InvalidParamsError,
    InvalidRequestError,
    IRPCAgent,
    IRPCMiddleware,
    MethodNotFoundError,
    ParseError,
    RPCError,
    RPCMethodCollection,
    RPCMethodInfo,
    RPCProtocol,
)

# =============================================================================
# 纯函数工具
# =============================================================================
from .utils import (
    RPCErrorCodes,
    create_rpc_error,
    create_rpc_response,
    generate_ad_document,
    generate_rpc_interface,
    resolve_base_url,
    validate_rpc_request,
)

# =============================================================================
# 公共 API
# =============================================================================

__all__ = [
    # Version
    "__version__",
    # Client SDK (high-level)
    "RemoteAgent",
    "Method",
    "client",
    # Core types (always needed)
    "AgentConfig",
    "RPCMethodInfo",
    "RPCMethodCollection",
    "FrozenRPCMethodCollection",
    # Protocols (extension points)
    "IRPCAgent",
    "AgentProtocol",
    "RPCProtocol",
    "IRPCMiddleware",
    "IHealthCheck",
    # Errors (structured error handling)
    "OpenANPError",
    "ConfigurationError",
    "RPCError",
    "ParseError",
    "InvalidRequestError",
    "MethodNotFoundError",
    "InvalidParamsError",
    "InternalError",
    # Pure functions (core only)
    "generate_ad_document",
    "generate_rpc_interface",
    "resolve_base_url",
    "validate_rpc_request",
    "create_rpc_response",
    "create_rpc_error",
    "RPCErrorCodes",
    # Decorators (optional, for quick start)
    "interface",
    "anp_agent",
    "extract_rpc_methods",
    # Router generation (optional)
    "create_agent_router",
    # Schema generation (advanced)
    "type_to_json_schema",
    "extract_method_schemas",
]
