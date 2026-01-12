"""OpenANP SDK - Agent Definition (ad.json) utilities.

This module provides utility functions for generating ANP Agent Definition documents.
ADR: See docs/adr/0001-auto-schema-generation.md

Functions:
- interface_ref: Generate interface reference for ad.json
- _extract_domain: Extract domain from DID string
- _normalize_url: Normalize domain to full URL
"""

from __future__ import annotations

from typing import Literal

__all__ = [
    "interface_ref",
    "_extract_domain",
    "_normalize_url",
    "PROTOCOL_TYPE",
    "PROTOCOL_VERSION",
    "SECURITY_DEFINITIONS",
]

# Protocol constants
PROTOCOL_TYPE = "ANP"
PROTOCOL_VERSION = "1.0.0"
SECURITY_DEFINITIONS = {
    "didwba_sc": {"scheme": "didwba", "in": "header", "name": "Authorization"}
}


def interface_ref(
    url: str,
    description: str,
    protocol: Literal["openrpc", "openapi", "yaml", "mcp"] = "openrpc",
) -> dict[str, str]:
    """Generate an interface reference for ad.json.

    Creates a structured interface reference that can be included
    in the ad.json document's interfaces array.

    Args:
        url: Full URL to the interface document
        description: Human-readable description of the interface
        protocol: Protocol type (openrpc, openapi, yaml, mcp)

    Returns:
        Interface reference dictionary

    Example:
        >>> ref = interface_ref(
        ...     url="https://api.example.com/hotel/interface.json",
        ...     description="Hotel booking API",
        ...     protocol="openrpc"
        ... )
        >>> ref
        {
            "type": "StructuredInterface",
            "url": "https://api.example.com/hotel/interface.json",
            "description": "Hotel booking API",
            "protocol": "openrpc"
        }
    """
    return {
        "type": "StructuredInterface",
        "url": url,
        "description": description,
        "protocol": protocol,
    }


def _extract_domain(did: str) -> str:
    """Extract domain from a DID string.

    Parses DID strings in various formats and extracts the domain
    portion (which may include a port number).

    Supported formats:
    - did:wba:example.com:service:hotel -> example.com
    - did:wba:127.0.0.1:8080:service:hotel -> 127.0.0.1:8080
    - did:wba:localhost:3000:service:hotel -> localhost:3000

    Args:
        did: DID string to parse

    Returns:
        Domain string (may include port)

    Example:
        >>> _extract_domain("did:wba:example.com:service:hotel")
        'example.com'
        >>> _extract_domain("did:wba:localhost:8080:service:hotel")
        'localhost:8080'
    """
    if not did.startswith("did:wba:"):
        # Return as-is if not a valid DID format
        return did

    # Remove the "did:wba:" prefix
    rest = did[8:]  # len("did:wba:") == 8

    # Split by ":"
    parts = rest.split(":")

    if not parts:
        return did

    # First part is the host
    host = parts[0]

    # Check if second part looks like a port number
    if len(parts) > 1 and parts[1].isdigit():
        # Include port in domain
        return f"{host}:{parts[1]}"

    return host


def _normalize_url(domain: str) -> str:
    """Normalize a domain to a full URL.

    Determines the appropriate protocol (http or https) based on
    the domain characteristics:
    - localhost/127.0.0.1 -> http://
    - Custom port (non-443) -> http://
    - Production domains -> https://

    Note:
        0.0.0.0 is automatically replaced with 127.0.0.1 on macOS (darwin)
        to avoid CORS issues. On other platforms, it's also replaced for consistency.

    Args:
        domain: Domain string (may include port)

    Returns:
        Full URL with protocol

    Example:
        >>> _normalize_url("localhost:8080")
        'http://localhost:8080'
        >>> _normalize_url("api.example.com")
        'https://api.example.com'
        >>> _normalize_url("127.0.0.1:3000")
        'http://127.0.0.1:3000'
        >>> _normalize_url("0.0.0.0:8000")
        'http://127.0.0.1:8000'
    """
    import platform

    # 检测操作系统并替换 0.0.0.0
    system = platform.system().lower()

    # 在 macOS 上，0.0.0.0 会导致 CORS 问题，必须替换
    # 在其他平台上也统一替换以保持一致性
    if "0.0.0.0" in domain:
        if system == "darwin":
            # macOS: 替换以避免 CORS 问题
            domain = domain.replace("0.0.0.0", "127.0.0.1")
        elif system in ("linux", "windows"):
            # Linux/Windows: 也可以替换以保持一致性
            domain = domain.replace("0.0.0.0", "127.0.0.1")

    # Already has protocol
    if domain.startswith("http://") or domain.startswith("https://"):
        return domain

    # Local development indicators
    local_hosts = {"localhost", "127.0.0.1"}

    # Check if it's a local host
    host = domain.split(":")[0] if ":" in domain else domain

    if host in local_hosts:
        return f"http://{domain}"

    # Check if it has a non-standard port
    if ":" in domain:
        port = domain.split(":")[-1]
        if port.isdigit() and port not in ("80", "443"):
            # Non-standard port, likely development
            return f"http://{domain}"

    # Default to HTTPS for production domains
    return f"https://{domain}"
