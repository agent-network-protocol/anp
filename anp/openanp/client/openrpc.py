"""
OpenRPC parsing and conversion functions.

Pure functions for parsing OpenRPC documents and converting to OpenAI Tools format.
"""

from __future__ import annotations

import re
from typing import Any


def _require_non_empty_str(value: Any, *, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field} must be a string, got {type(value).__name__}")
    if not value.strip():
        raise ValueError(f"{field} cannot be empty")
    return value


def _require_dict(value: Any, *, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TypeError(f"{field} must be a dict, got {type(value).__name__}")
    return value


def _require_list(value: Any, *, field: str) -> list[Any]:
    if not isinstance(value, list):
        raise TypeError(f"{field} must be a list, got {type(value).__name__}")
    return value


def parse_openrpc(data: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Parse OpenRPC document and extract method definitions.

    Args:
        data: OpenRPC document as dict

    Returns:
        List of method definitions with resolved $refs
    """
    if not _is_openrpc(data):
        raise ValueError("Invalid OpenRPC document: missing 'openrpc' or 'methods'")

    methods = _require_list(data.get("methods"), field="openrpc.methods")
    components = _require_dict(data.get("components", {}), field="openrpc.components")
    servers = _require_list(data.get("servers", []), field="openrpc.servers")

    parsed: list[dict[str, Any]] = []
    for idx, raw in enumerate(methods):
        method = _require_dict(raw, field=f"openrpc.methods[{idx}]")
        name = _require_non_empty_str(method.get("name"), field="method.name")
        description = _require_non_empty_str(
            method.get("description"), field=f"openrpc.methods[{idx}].description"
        )
        params = _require_list(
            method.get("params", []), field=f"openrpc.methods[{idx}].params"
        )
        result = _require_dict(
            method.get("result"), field=f"openrpc.methods[{idx}].result"
        )
        parsed.append(
            {
                "name": name,
                "description": description,
                "params": params,
                "result": result,
                "components": components,
                "servers": servers,
            }
        )
    return parsed


def parse_agent_document(
    data: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """
    Parse Agent Description document.

    Args:
        data: Agent Description document as dict

    Returns:
        (agent_data, embedded_methods) - Agent data and any embedded OpenRPC methods
    """
    if not isinstance(data, dict):
        raise TypeError("Agent Description document must be a dict")

    methods = []
    servers = _require_list(data.get("servers", []), field="ad.servers")

    interfaces = _require_list(data.get("interfaces", []), field="ad.interfaces")
    for idx, raw_interface in enumerate(interfaces):
        interface = _require_dict(raw_interface, field=f"ad.interfaces[{idx}]")
        if (
            interface.get("type") == "StructuredInterface"
            and interface.get("protocol") == "openrpc"
            and "content" in interface
        ):
            embedded = interface["content"]
            embedded_doc = _require_dict(embedded, field="ad.interfaces[].content")
            if _is_openrpc(embedded_doc):
                for m in parse_openrpc(embedded_doc):
                    has_servers = bool(m.get("servers"))
                    merged = m if has_servers else {**m, "servers": servers}
                    methods.append(merged)

    return data, methods


def convert_to_openai_tool(method: dict[str, Any]) -> dict[str, Any]:
    """
    Convert OpenRPC method to OpenAI Tools format.

    Args:
        method: Method definition from parse_openrpc()

    Returns:
        OpenAI Tools format dictionary
    """
    name = _sanitize_name(
        _require_non_empty_str(method.get("name"), field="method.name")
    )
    description = _require_non_empty_str(
        method.get("description"), field="method.description"
    )
    params = _require_list(method.get("params"), field="method.params")
    components = _require_dict(method.get("components", {}), field="method.components")

    properties = {}
    required = []

    for idx, raw_param in enumerate(params):
        p = _require_dict(raw_param, field=f"method.params[{idx}]")
        pname = _require_non_empty_str(
            p.get("name"), field=f"method.params[{idx}].name"
        )
        schema = _require_dict(p.get("schema"), field=f"method.params[{idx}].schema")
        resolved = resolve_refs(schema, components)

        if p.get("description") and "description" not in resolved:
            resolved["description"] = p["description"]

        properties[pname] = resolved

        if p.get("required"):
            required.append(pname)

    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required,
            },
        },
    }


def resolve_refs(schema: Any, components: dict[str, Any]) -> dict[str, Any]:
    """Recursively resolve $ref in JSON Schema."""
    if not isinstance(schema, dict):
        raise TypeError(f"schema must be a dict, got {type(schema).__name__}")

    if "$ref" in schema:
        ref = _require_non_empty_str(schema.get("$ref"), field="schema.$ref")
        resolved = _resolve_ref(ref, components)
        if resolved is None:
            raise ValueError(f"Unresolvable $ref: {ref}")
        return resolve_refs(resolved, components)

    result = {}
    for k, v in schema.items():
        if k == "properties" and isinstance(v, dict):
            result[k] = {pk: resolve_refs(pv, components) for pk, pv in v.items()}
        elif k == "items" and isinstance(v, dict):
            result[k] = resolve_refs(v, components)
        elif isinstance(v, dict):
            result[k] = resolve_refs(v, components)
        elif isinstance(v, list):
            result[k] = [
                resolve_refs(i, components) if isinstance(i, dict) else i for i in v
            ]
        else:
            result[k] = v

    return result


def _is_openrpc(data: dict) -> bool:
    return (
        isinstance(data, dict)
        and "openrpc" in data
        and "methods" in data
        and isinstance(data["methods"], list)
    )


def _resolve_ref(ref: str, components: dict) -> dict | None:
    if not ref.startswith("#/components/"):
        return None

    parts = ref[13:].split("/")  # Skip "#/components/"
    current = components

    for part in parts:
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None

    return current if isinstance(current, dict) else None


def _sanitize_name(name: str) -> str:
    sanitized = re.sub(r"[^a-zA-Z0-9_]", "_", name)
    if not sanitized:
        raise ValueError("method.name cannot be sanitized to a non-empty string")

    if sanitized and not sanitized[0].isalpha() and sanitized[0] != "_":
        sanitized = f"fn_{sanitized}"

    return sanitized[:64]
