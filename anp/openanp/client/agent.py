"""
RemoteAgent - Handle to a discovered remote ANP agent.

Uses anp_crawler module for HTTP operations and interface conversion.

Example:

    from anp.openanp import RemoteAgent
    from anp.authentication import DIDWbaAuthHeader

    auth = DIDWbaAuthHeader(
        did_document_path="/path/to/did-doc.json",
        private_key_path="/path/to/private-key.pem",
    )
    agent = await RemoteAgent.discover(ad_url, auth)
    result = await agent.search(query="Tokyo")
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ...authentication import DIDWbaAuthHeader
from ...anp_crawler.anp_client import ANPClient
from .openrpc import convert_to_openai_tool, parse_agent_document, parse_openrpc


def _require_non_empty_str(value: Any, *, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field} must be a string, got {type(value).__name__}")
    if not value.strip():
        raise ValueError(f"{field} cannot be empty")
    return value


def _is_openrpc(data: dict) -> bool:
    """Check if data is a valid OpenRPC document."""
    return (
        isinstance(data, dict)
        and "openrpc" in data
        and "methods" in data
        and isinstance(data["methods"], list)
    )


class HttpError(Exception):
    """HTTP request failed."""

    def __init__(self, status: int, message: str, url: str):
        self.status = status
        self.url = url
        super().__init__(f"HTTP {status}: {message} ({url})")


class RpcError(Exception):
    """JSON-RPC error response."""

    def __init__(self, code: int, message: str, data: Any = None):
        self.code = code
        self.data = data
        super().__init__(f"RPC {code}: {message}")


@dataclass(frozen=True)
class Method:
    """Immutable method definition."""

    name: str
    description: str
    params: tuple[dict[str, Any], ...]
    rpc_url: str


@dataclass(frozen=True)
class RemoteAgent:
    """
    Handle to a discovered remote ANP agent.

    Immutable. Created via RemoteAgent.discover().
    Uses anp_crawler.ANPClient for HTTP operations.
    """

    url: str
    name: str
    description: str
    methods: tuple[Method, ...]
    _auth: DIDWbaAuthHeader

    @classmethod
    async def discover(cls, ad_url: str, auth: DIDWbaAuthHeader) -> RemoteAgent:
        """
        Discover agent from AD URL.

        Uses anp_crawler.ANPClient for authenticated HTTP requests.
        Fail Fast: Raises if no methods found.
        """
        # Create ANPClient from auth header
        client = ANPClient(
            did_document_path=auth.did_document_path,
            private_key_path=auth.private_key_path,
        )

        # Fetch AD document
        response = await client.fetch(ad_url)
        if not response.get("success"):
            raise HttpError(500, response.get("error", "Failed to fetch"), ad_url)

        ad = response.get("data", {})
        _, raw_methods = parse_agent_document(ad)

        # If no embedded methods, fetch from interface URLs (fail fast with context).
        if not raw_methods:
            interfaces = ad.get("interfaces")
            if not isinstance(interfaces, list):
                raise TypeError("ad.interfaces must be a list")

            interface_urls: list[str] = []
            for idx, raw_interface in enumerate(interfaces):
                if not isinstance(raw_interface, dict):
                    raise TypeError(f"ad.interfaces[{idx}] must be a dict")
                if (
                    raw_interface.get("type") == "StructuredInterface"
                    and raw_interface.get("protocol") == "openrpc"
                    and "url" in raw_interface
                ):
                    interface_urls.append(
                        _require_non_empty_str(
                            raw_interface.get("url"), field=f"ad.interfaces[{idx}].url"
                        )
                    )

            if not interface_urls:
                raise ValueError(f"No OpenRPC interface URLs found at {ad_url}")

            errors: list[str] = []
            for interface_url in interface_urls:
                try:
                    interface_response = await client.fetch(interface_url)
                    if not interface_response.get("success"):
                        errors.append(
                            f"{interface_url}: Failed to fetch: {interface_response.get('error')}"
                        )
                        continue
                    interface_data = interface_response.get("data", {})
                    if not _is_openrpc(interface_data):
                        errors.append(f"{interface_url}: Invalid OpenRPC document")
                        continue
                    raw_methods.extend(parse_openrpc(interface_data))
                except Exception as exc:
                    errors.append(f"{interface_url}: {type(exc).__name__}: {exc}")

            if not raw_methods:
                raise ValueError(
                    f"Failed to load OpenRPC methods for {ad_url}. Errors: {errors}"
                )

        if not raw_methods:
            raise ValueError(f"No methods found at {ad_url}")

        methods = tuple(
            Method(
                name=m["name"],
                description=m["description"],
                params=tuple(m["params"]),
                rpc_url=_extract_rpc_url(m),
            )
            for m in raw_methods
        )

        if not methods:
            raise ValueError(f"No callable methods at {ad_url}")

        return cls(
            url=ad_url,
            name=_require_non_empty_str(ad.get("name"), field="ad.name"),
            description=_require_non_empty_str(
                ad.get("description"), field="ad.description"
            ),
            methods=methods,
            _auth=auth,
        )

    @property
    def method_names(self) -> tuple[str, ...]:
        """Available method names."""
        return tuple(m.name for m in self.methods)

    @property
    def tools(self) -> list[dict[str, Any]]:
        """OpenAI Tools format.

        Uses ANPInterfaceConverter for conversion when available,
        falls back to local convert_to_openai_tool.
        """
        return [
            convert_to_openai_tool(
                {
                    "name": m.name,
                    "description": m.description,
                    "params": list(m.params),
                }
            )
            for m in self.methods
        ]

    def get_method(self, name: str) -> Method:
        """Get method by name. Raises KeyError if not found."""
        for m in self.methods:
            if m.name == name:
                return m
        raise KeyError(f"Method not found: {name}")

    async def call(self, method: str, **params: Any) -> Any:
        """Call method with standard JSON-RPC.

        Uses anp_crawler.ANPClient for authenticated HTTP requests.

        Args:
            method: Method name to call
            **params: Method parameters

        Returns:
            The result from the JSON-RPC response

        Raises:
            KeyError: If method not found
            RpcError: On JSON-RPC error
            HttpError: On HTTP errors
        """
        m = self.get_method(method)

        # Create ANPClient for this call
        client = ANPClient(
            did_document_path=self._auth.did_document_path,
            private_key_path=self._auth.private_key_path,
        )

        # Use ANPClient's call_jsonrpc method
        response = await client.call_jsonrpc(
            server_url=m.rpc_url,
            method=method,
            params=params,
        )

        if not response.get("success"):
            error = response.get("error", {})
            if isinstance(error, dict):
                raise RpcError(
                    code=error.get("code", -1),
                    message=error.get("message", "Unknown error"),
                    data=error.get("data"),
                )
            else:
                raise RpcError(
                    code=-1,
                    message=str(error),
                )

        return response.get("result")

    def __getattr__(self, name: str) -> Any:
        """Dynamic method access: agent.search(query="...")"""
        if name.startswith("_"):
            raise AttributeError(name)

        try:
            method = self.get_method(name)
        except KeyError:
            raise AttributeError(f"No method: {name}") from None

        async def caller(**params: Any) -> Any:
            return await self.call(method.name, **params)

        return caller

    def __repr__(self) -> str:
        return f"RemoteAgent({self.name!r}, methods={self.method_names})"


def _extract_rpc_url(method: dict[str, Any]) -> str:
    """Extract RPC URL from method. Raises if not found."""
    servers = method.get("servers", [])
    if not servers:
        raise ValueError(f"No servers for method: {method.get('name')}")
    url = servers[0].get("url")
    if not url:
        raise ValueError(f"No URL in server for method: {method.get('name')}")
    return url
