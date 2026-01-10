"""OpenANP SDK - Pure Function Utilities

This module provides pure functions for generating ANP protocol documents.
All functions are pure: the same input always produces the same output,
with no side effects.

Design principles:
- Pure functions: no side effects, predictable
- Stateless: no external state dependency
- Composable: can be combined
- Type-safe: complete type hints
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Literal

from .types import AgentConfig, RPCMethodInfo

if TYPE_CHECKING:
    from fastapi import Request

__all__ = [
    "generate_ad_document",
    "generate_rpc_interface",
    "resolve_base_url",
]


# =============================================================================
# Core Document Generation Functions
# =============================================================================


def generate_ad_document(
    config: AgentConfig,
    base_url: str,
    interfaces: list[dict[str, Any]] | None = None,
    inline_methods: list[RPCMethodInfo] | None = None,
) -> dict[str, Any]:
    """Generate Agent Description (ad.json) document.

    The new format uses product-style description instead of JSON-LD,
    retaining ANP protocol info and security declarations for easy
    consumption by directories/clients.

    Args:
        config: Agent configuration.
        base_url: Base URL (protocol + hostname).
        interfaces: Optional list of interface references.
        inline_methods: If provided, generates OpenRPC document from these
            methods and inlines it into ad.json.

    Returns:
        ad.json document dictionary.

    Example:
        config = AgentConfig(name="Hotel", did="did:wba:example.com:hotel")
        # Method 1: Reference external interface
        doc = generate_ad_document(config, "https://api.example.com")

        # Method 2: Inline interface
        methods = [...]
        doc = generate_ad_document(config, "https://api.example.com", inline_methods=methods)
    """

    # Build full path
    full_path = f"{config.prefix}/ad.json" if config.prefix else "/ad.json"

    # Build interface list
    interface_refs = interfaces or []

    # Process interface references from URL config
    if config.url_config and "interface_url" in config.url_config:
        interface_refs.append(
            {
                "type": "StructuredInterface",
                "protocol": "openrpc",
                "url": config.url_config["interface_url"],
                "description": f"{config.name} JSON-RPC interface",
            }
        )

    # Process inline RPC methods
    if inline_methods:
        # Generate OpenRPC document
        openrpc_doc = generate_rpc_interface(config, base_url, inline_methods)
        interface_refs.append(
            {
                "type": "InlineOpenRPC",
                "protocol": "openrpc",
                "definition": openrpc_doc,
                "description": f"{config.name} Inline JSON-RPC interface",
            }
        )

    # Generate product-style Agent Description (non JSON-LD)
    doc: dict[str, Any] = {
        "protocolType": "ANP",
        "protocolVersion": "1.0.0",
        "type": "Product",
        "url": f"{base_url}{full_path}",
        "identifier": config.did,
        "name": config.name,
        "description": config.description or config.name,
        "security": {
            "didwba": {"scheme": "didwba", "in": "header", "name": "Authorization"}
        },
        "brand": {"type": "Brand", "name": config.name},
        "category": "Agent Service",
        "sku": config.did,
        # UTC timestamp in ISO 8601 second precision
        "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    if interface_refs:
        doc["interfaces"] = interface_refs

    return doc


def _convert_schema_to_openrpc_params(schema: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert JSON Schema to OpenRPC params array (ContentDescriptor format).

    Trust upstream: schema must have properties, no fallback.
    """
    properties = schema["properties"]
    required_fields = set(schema.get("required", []))

    return [
        {
            "name": param_name,
            "schema": param_schema,
            "required": True,
        }
        if param_name in required_fields
        else {
            "name": param_name,
            "schema": param_schema,
        }
        for param_name, param_schema in properties.items()
    ]


def _convert_schema_to_openrpc_result(schema: dict[str, Any]) -> dict[str, Any]:
    """Convert JSON Schema to OpenRPC result ContentDescriptor."""
    return {"name": "result", "schema": schema}


def generate_rpc_interface(
    config: AgentConfig,
    base_url: str,
    methods: list[RPCMethodInfo],
    protocol_version: Literal["1.0", "2.0"] = "1.0",
) -> dict[str, Any]:
    """Generate RPC interface document (interface.json).

    Generates an OpenRPC-compliant interface document describing all
    available RPC methods. If a method specifies a protocol field
    (e.g., "AP2/ANP"), an x-protocol extension field is added.

    Args:
        config: Agent configuration.
        base_url: Base URL.
        methods: List of RPC method information.
        protocol_version: Protocol version, defaults to "1.0".

    Returns:
        OpenRPC format interface document.

    Example:
        methods = [
            RPCMethodInfo(
                name="search",
                description="Search for hotels",
                params_schema={...},
                result_schema={...}
            ),
            RPCMethodInfo(
                name="cart_mandate",
                description="Create cart mandate",
                protocol="AP2/ANP",  # AP2 method
                params_schema={...},
                result_schema={...}
            )
        ]
        doc = generate_rpc_interface(config, "https://api.example.com", methods)
        # Returns OpenRPC interface document, AP2 methods include x-protocol field
    """
    # Convert to OpenRPC methods (trust upstream data)
    rpc_methods = []
    for m in methods:
        method = {
            "name": m.name,
            "description": m.description,
            "params": _convert_schema_to_openrpc_params(m.params_schema),
            "result": _convert_schema_to_openrpc_result(m.result_schema),
        }
        if m.protocol:
            method["x-protocol"] = m.protocol
        rpc_methods.append(method)

    # Build RPC URL
    rpc_url = f"{base_url}{config.prefix}/rpc" if config.prefix else f"{base_url}/rpc"

    # Generate interface document
    doc = {
        "openrpc": "1.3.2",
        "info": {
            "title": f"{config.name} API",
            "version": "1.0.0",
            "description": config.description or config.name,
        },
        "methods": rpc_methods,
        "servers": [
            {
                "name": f"{config.name} Server",
                "url": rpc_url,
            }
        ],
        "securityDefinitions": {
            "didwba_sc": {"scheme": "didwba", "in": "header", "name": "Authorization"}
        },
        "security": "didwba_sc",
    }

    return doc


# =============================================================================
# URL Utility Functions
# =============================================================================


def resolve_base_url(request: Request) -> str:
    """Resolve base URL from FastAPI Request.

    Extracts protocol, hostname and port from the request object
    to construct a standard base URL.

    Note:
        On macOS, 0.0.0.0 causes CORS issues, so it is automatically
        replaced with 127.0.0.1. On Windows and Linux, 0.0.0.0 is also
        replaced with 127.0.0.1 for consistency.

    Args:
        request: FastAPI Request object.

    Returns:
        Base URL string, format: https://example.com

    Example:
        request = Request(...)
        base_url = resolve_base_url(request)
        # Returns: "https://api.example.com"
    """
    import platform

    # Extract base URL from request
    base_url = str(request.base_url).rstrip("/")

    # Detect operating system
    system = platform.system().lower()

    # On macOS (darwin), 0.0.0.0 causes CORS issues
    # On all platforms, uniformly replace 0.0.0.0 with 127.0.0.1 for consistency
    # and to avoid potential issues. Server still listens on 0.0.0.0 (all interfaces),
    # but generated URLs use 127.0.0.1
    if "0.0.0.0" in base_url:
        if system == "darwin":
            # macOS: must replace to avoid CORS issues
            base_url = base_url.replace("://0.0.0.0:", "://127.0.0.1:")
            base_url = base_url.replace("://0.0.0.0/", "://127.0.0.1/")
            if base_url.endswith("://0.0.0.0"):
                base_url = base_url.replace("://0.0.0.0", "://127.0.0.1")
        elif system in ("linux", "windows"):
            # Linux/Windows: also replace for consistency
            base_url = base_url.replace("://0.0.0.0:", "://127.0.0.1:")
            base_url = base_url.replace("://0.0.0.0/", "://127.0.0.1/")
            if base_url.endswith("://0.0.0.0"):
                base_url = base_url.replace("://0.0.0.0", "://127.0.0.1")

    return base_url


# =============================================================================
# Validation Utility Functions
# =============================================================================


def validate_rpc_request(request_body: dict[str, Any]) -> tuple[str, dict, Any]:
    """Validate and parse RPC request.

    Args:
        request_body: Request body dictionary.

    Returns:
        Tuple of (method, params, request_id).

    Raises:
        ValueError: When request format is invalid.
    """
    # Check JSON-RPC 2.0 format
    if "jsonrpc" not in request_body:
        raise ValueError("Missing 'jsonrpc' field")

    if request_body["jsonrpc"] != "2.0":
        raise ValueError("Only JSON-RPC 2.0 is supported")

    if "method" not in request_body:
        raise ValueError("Missing 'method' field")

    method = request_body["method"]
    params = request_body.get("params", {})
    req_id = request_body.get("id")

    return method, params, req_id


def create_rpc_response(
    result: Any,
    request_id: Any = None,
) -> dict[str, Any]:
    """Create RPC response.

    Args:
        result: Response result.
        request_id: Request ID.

    Returns:
        Response dictionary conforming to JSON-RPC 2.0 format.

    Example:
        response = create_rpc_response({"data": "value"}, 1)
        # Returns: {"jsonrpc": "2.0", "result": {"data": "value"}, "id": 1}
    """
    response = {
        "jsonrpc": "2.0",
        "result": result,
    }

    if request_id is not None:
        response["id"] = request_id

    return response


def create_rpc_error(
    code: int,
    message: str,
    request_id: Any = None,
    data: Any = None,
) -> dict[str, Any]:
    """Create RPC error response.

    Args:
        code: Error code (JSON-RPC standard error codes).
        message: Error message.
        request_id: Request ID.
        data: Additional error data.

    Returns:
        Error response dictionary conforming to JSON-RPC 2.0 format.

    Example:
        response = create_rpc_error(-32601, "Method not found", 1)
        # Returns: {"jsonrpc": "2.0", "error": {"code": -32601, "message": "Method not found"}, "id": 1}
    """
    error = {
        "code": code,
        "message": message,
    }

    if data is not None:
        error["data"] = data

    response = {
        "jsonrpc": "2.0",
        "error": error,
    }

    if request_id is not None:
        response["id"] = request_id

    return response


# =============================================================================
# Constants Definition
# =============================================================================


# JSON-RPC Error Codes (Standard Definition)
class RPCErrorCodes:
    """JSON-RPC standard error codes."""

    PARSE_ERROR = -32700
    INVALID_REQUEST = -32600
    METHOD_NOT_FOUND = -32601
    INVALID_PARAMS = -32602
    INTERNAL_ERROR = -32603
