"""OpenANP SDK - Type Definitions and Protocols.

This module defines all core types, following:
- High cohesion: All type definitions are closely related
- Immutability: Use frozen dataclass to prevent accidental modification
- Type safety: Protocol ensures interface consistency
"""

from __future__ import annotations

from abc import abstractmethod
from dataclasses import dataclass, field
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Generic,
    Literal,
    Protocol,
    TypeVar,
    runtime_checkable,
)

if TYPE_CHECKING:
    from fastapi import Request

__all__ = [
    "AgentConfig",
    "RPCMethodInfo",
    "Information",
    "RPCMethodCollection",
    "FrozenRPCMethodCollection",
    "IRPCAgent",
    "AgentProtocol",
    "RPCProtocol",
    "IRPCMiddleware",
    "IHealthCheck",
    "OpenANPError",
    "ConfigurationError",
    "RPCError",
    "ParseError",
    "InvalidRequestError",
    "MethodNotFoundError",
    "InvalidParamsError",
    "InternalError",
    "AuthenticationError",
    "AuthorizationError",
    "RateLimitError",
    "ValidationError",
    "ResourceNotFoundError",
    "ConflictError",
    "ServiceUnavailableError",
]

T = TypeVar("T")


# =============================================================================
# Core Configuration Types
# =============================================================================


@dataclass(frozen=True)
class AgentConfig:
    """Immutable agent configuration.

    All fields are read-only to ensure configuration is not accidentally modified.
    This is important for concurrent access and debugging.

    Attributes:
        name: Human-readable agent identifier
        did: Decentralized identifier (must start with 'did:')
        description: Optional description, defaults to name
        prefix: FastAPI router prefix, defaults to empty
        tags: FastAPI tags, defaults to ["ANP"]
        url_config: Custom URL configuration
        auth_config: DID WBA authentication configuration

    Note:
        OpenANP focuses on ANP protocol, not infrastructure.
        For caching, use cachetools/redis.
        For health checks, implement your own endpoint.
        For retry, use tenacity.
        For logging, use loguru/structlog.

    Example:
        config = AgentConfig(
            name="Hotel Agent",
            did="did:wba:example.com:hotel",
            description="Hotel booking service",
            prefix="/hotel",
            tags=["Hotel", "Booking"],
        )
    """

    name: str
    did: str
    description: str = ""
    prefix: str = ""
    tags: list[str] | None = None
    url_config: dict[str, str] | None = None
    auth_config: Any = None  # DidWbaVerifierConfig, optional to avoid circular import

    def __post_init__(self):
        """Validate configuration."""
        if not self.name or not self.name.strip():
            raise ValueError("Agent name cannot be empty")

        if not self.did.startswith("did:"):
            raise ValueError(
                f"Invalid DID format: {self.did}. DID must start with 'did:'"
            )

        object.__setattr__(self, "name", self.name.strip())
        object.__setattr__(self, "did", self.did.strip())


@dataclass(frozen=True)
class Information:
    """Information document definition.

    Supports both URL mode (link to external resource) and Content mode (embedded content).

    Attributes:
        type: Information type (Product, VideoObject, ImageObject, etc.)
        description: Description of this information
        mode: Output mode - "url" for link, "content" for embedded
        path: Relative path (URL mode, hosted by OpenANP)
        url: External URL (URL mode)
        file: Static file path (URL mode, for hosting)
        content: Embedded content (Content mode)

    Example:
        # URL mode - hosted file
        Information(
            type="Product",
            description="Room catalog",
            path="/products/rooms.json",
            file="data/rooms.json"
        )

        # URL mode - external link
        Information(
            type="VideoObject",
            description="Hotel tour",
            url="https://cdn.hotel.com/tour.mp4"
        )

        # Content mode - embedded
        Information(
            type="Organization",
            description="Contact info",
            mode="content",
            content={"name": "Hotel", "phone": "+1-234-567"}
        )
    """

    type: str
    description: str
    mode: Literal["url", "content"] = "url"
    path: str | None = None
    url: str | None = None
    file: str | None = None
    content: dict[str, Any] | None = None

    def __post_init__(self):
        """Validate information configuration."""
        if self.mode == "url" and not self.path and not self.url:
            raise ValueError("URL mode Information must have either 'path' or 'url'")
        if self.mode == "content" and self.content is None:
            raise ValueError("Content mode Information must have 'content'")

    def to_dict(self, base_url: str = "") -> dict[str, Any]:
        """Convert to dictionary for ad.json.

        Args:
            base_url: Base URL for constructing full URLs

        Returns:
            Dictionary representation
        """
        result: dict[str, Any] = {
            "type": self.type,
            "description": self.description,
        }

        if self.mode == "content":
            result["content"] = self.content
        else:
            if self.url:
                result["url"] = self.url
            elif self.path:
                if base_url:
                    result["url"] = f"{base_url.rstrip('/')}{self.path}"
                else:
                    result["url"] = self.path

        return result


@dataclass(frozen=True)
class RPCMethodInfo:
    """RPC method information.

    Stores RPC method metadata, including name, description, and schemas for
    parameters and return values. All fields are read-only to ensure metadata
    consistency.

    Example:
        method = RPCMethodInfo(
            name="search_hotels",
            description="Search for hotels by city",
            params_schema={
                "type": "object",
                "properties": {"city": {"type": "string"}},
                "required": ["city"]
            },
            result_schema={
                "type": "array",
                "items": {"type": "object"}
            }
        )

        # AP2 method example
        ap2_method = RPCMethodInfo(
            name="cart_mandate",
            description="Create cart mandate",
            protocol="AP2/ANP",  # Marks as AP2 protocol method
            ...
        )

        # Link mode example
        link_method = RPCMethodInfo(
            name="book",
            description="Book a hotel",
            mode="link",  # Uses URL instead of embedded content in ad.json
            ...
        )
    """

    name: str
    """RPC method name - The 'method' field in JSON-RPC"""

    description: str
    """Method description - Used for generating interface documentation"""

    params_schema: dict[str, Any] | None = None
    """Parameter schema - Used for parameter validation and documentation"""

    result_schema: dict[str, Any] | None = None
    """Result schema - Used for return value validation and documentation"""

    handler: Callable | None = None
    """Optional: Handler function reference - Used for automatic invocation"""

    protocol: str | None = None
    """Optional: Protocol type marker - e.g., "AP2/ANP" for AP2 payment protocol methods, adds x-protocol field when generated"""

    mode: Literal["content", "link"] = "content"
    """Optional: Interface mode - "content" embeds OpenRPC document, "link" provides URL only"""

    has_context: bool = False
    """Optional: Marks whether the method requires Context parameter injection"""

    def __post_init__(self):
        object.__setattr__(self, "name", self.name.strip())
        object.__setattr__(self, "description", self.description.strip())


# =============================================================================
# Protocol Definitions
# =============================================================================


@runtime_checkable
class IRPCAgent(Protocol):
    """RPC agent protocol.

    User-implemented agent classes must conform to this protocol.
    This ensures all agents have a consistent interface.

    Example:
        class HotelAgent(IRPCAgent):
            config = AgentConfig(name="Hotel", did="...")

            async def setup(self) -> None:
                self.db = await create_db()

            async def handle_rpc(self, request: Request, method: str, params: dict) -> Any:
                if method == "search":
                    return await self.search(request, **params)
                else:
                    raise ValueError(f"Unknown method: {method}")

            async def search(self, request: Request, query: str) -> dict:
                return {"results": []}
    """

    config: AgentConfig
    """Agent configuration - Must be provided"""

    async def setup(self) -> None:
        """Initialize the agent.

        Called before the agent starts processing requests.
        Used for establishing database connections, loading configurations,
        and other preparatory work.
        """
        ...

    async def handle_rpc(self, request: Request, method: str, params: dict) -> Any:
        """Handle RPC request.

        This is the core method of the RPC agent, responsible for dispatching
        RPC requests to the corresponding handler methods.

        Args:
            request: FastAPI Request object
            method: RPC method name
            params: RPC parameters (dictionary)

        Returns:
            Result of the RPC call

        Raises:
            ValueError: When the method does not exist
            RPCError: When processing fails
        """
        ...


@runtime_checkable
class AgentProtocol(Protocol):
    """Agent protocol (broader definition).

    Suitable for agents that do not depend on specific implementations.
    """

    config: AgentConfig
    """Agent configuration"""

    async def setup(self) -> None:
        """Initialize the agent."""
        ...


@runtime_checkable
class RPCProtocol(Protocol):
    """RPC protocol.

    Marks a class that implements RPC functionality.
    """

    async def handle_rpc(self, request: Request, method: str, params: dict) -> Any:
        """Handle RPC request."""
        ...


@runtime_checkable
class IRPCMiddleware(Protocol):
    """RPC middleware protocol.

    Implement this protocol to create reusable middleware for RPC processing.
    Middleware can intercept requests before/after handler execution.

    Example:
        class LoggingMiddleware:
            async def before_call(
                self,
                method: str,
                params: dict[str, Any],
                context: dict[str, Any],
            ) -> dict[str, Any]:
                context["start_time"] = time.time()
                logger.info(f"Calling {method} with {params}")
                return params

            async def after_call(
                self,
                method: str,
                result: Any,
                context: dict[str, Any],
            ) -> Any:
                duration = time.time() - context["start_time"]
                logger.info(f"{method} completed in {duration:.2f}s")
                return result

            async def on_error(
                self,
                method: str,
                error: Exception,
                context: dict[str, Any],
            ) -> RPCError:
                logger.error(f"{method} failed: {error}")
                return InternalError(str(error), cause=error)
    """

    async def before_call(
        self,
        method: str,
        params: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        """Called before RPC method execution.

        Args:
            method: RPC method name
            params: Request parameters
            context: Mutable context dict for passing data between hooks

        Returns:
            Modified params (or original if unchanged)
        """
        ...

    async def after_call(
        self,
        method: str,
        result: Any,
        context: dict[str, Any],
    ) -> Any:
        """Called after successful RPC method execution.

        Args:
            method: RPC method name
            result: Handler return value
            context: Context dict from before_call

        Returns:
            Modified result (or original if unchanged)
        """
        ...

    async def on_error(
        self,
        method: str,
        error: Exception,
        context: dict[str, Any],
    ) -> "RPCError":
        """Called when RPC method raises an exception.

        Args:
            method: RPC method name
            error: Raised exception
            context: Context dict from before_call

        Returns:
            RPCError to return to client
        """
        ...


@runtime_checkable
class IHealthCheck(Protocol):
    """Health check protocol.

    Implement this to provide custom health check logic.

    Example:
        class DatabaseHealthCheck:
            def __init__(self, db):
                self.db = db

            async def check(self) -> dict[str, Any]:
                try:
                    await self.db.ping()
                    return {"status": "healthy", "db": "connected"}
                except Exception as e:
                    return {"status": "unhealthy", "db": str(e)}
    """

    async def check(self) -> dict[str, Any]:
        """Perform health check.

        Returns:
            Dict with at least "status" key ("healthy" or "unhealthy")
        """
        ...


class RPCMethodCollection(dict[str, RPCMethodInfo]):
    """RPC method collection.

    A specialized dict for storing RPC method information.
    Provides convenient methods for building and accessing methods.

    For immutable access, use the `freeze()` method to get a read-only view.

    Example:
        # Building phase (mutable)
        methods = RPCMethodCollection()
        methods.add("search", "Search for hotels", schema)
        methods.add("book", "Book a hotel", schema)

        # Frozen phase (immutable)
        frozen = methods.freeze()
        # frozen["new"] = ...  # Raises TypeError

        for method in methods:
            print(method.name)
    """

    def add(
        self,
        name: str,
        description: str,
        params_schema: dict[str, Any] | None = None,
        result_schema: dict[str, Any] | None = None,
        handler: Callable | None = None,
        protocol: str | None = None,
    ) -> "RPCMethodCollection":
        """Add an RPC method.

        Args:
            name: Method name
            description: Method description
            params_schema: Parameter schema
            result_schema: Return value schema
            handler: Handler function
            protocol: Protocol type (e.g., "AP2/ANP" for AP2 payment methods)

        Returns:
            self for method chaining
        """
        self[name] = RPCMethodInfo(
            name=name,
            description=description,
            params_schema=params_schema,
            result_schema=result_schema,
            handler=handler,
            protocol=protocol,
        )
        return self

    def get_methods(self) -> list[RPCMethodInfo]:
        """Get all RPC method info.

        Returns:
            List of RPCMethodInfo objects
        """
        return list(self.values())

    def freeze(self) -> "FrozenRPCMethodCollection":
        """Create an immutable snapshot of this collection.

        Returns:
            FrozenRPCMethodCollection with read-only access
        """
        return FrozenRPCMethodCollection(self)


class FrozenRPCMethodCollection:
    """Immutable RPC method collection.

    A read-only view of RPC methods that cannot be modified after creation.
    Thread-safe for concurrent access.

    Example:
        frozen = FrozenRPCMethodCollection(methods_dict)
        method = frozen.get("search")  # OK
        frozen["new"] = ...  # Raises TypeError
    """

    __slots__ = ("_methods",)

    def __init__(self, methods: dict[str, RPCMethodInfo]):
        """Initialize from a dict of methods.

        Args:
            methods: Dict mapping method names to RPCMethodInfo
        """
        from types import MappingProxyType

        object.__setattr__(self, "_methods", MappingProxyType(dict(methods)))

    def __setattr__(self, name: str, value: Any) -> None:
        raise TypeError("FrozenRPCMethodCollection is immutable")

    def __getitem__(self, key: str) -> RPCMethodInfo:
        return self._methods[key]

    def __contains__(self, key: object) -> bool:
        return key in self._methods

    def __iter__(self):
        return iter(self._methods)

    def __len__(self) -> int:
        return len(self._methods)

    def get(self, name: str) -> RPCMethodInfo | None:
        """Get method by name.

        Args:
            name: Method name

        Returns:
            RPCMethodInfo or None if not found
        """
        return self._methods.get(name)

    def keys(self):
        """Return method names."""
        return self._methods.keys()

    def values(self):
        """Return method info objects."""
        return self._methods.values()

    def items(self):
        """Return (name, info) pairs."""
        return self._methods.items()

    def get_methods(self) -> tuple[RPCMethodInfo, ...]:
        """Get all RPC method info as an immutable tuple.

        Returns:
            Tuple of RPCMethodInfo objects
        """
        return tuple(self._methods.values())


# =============================================================================
# Error Types
# =============================================================================


class OpenANPError(Exception):
    """OpenANP base exception class.

    All OpenANP-related exceptions should inherit from this class.
    """

    pass


class ConfigurationError(OpenANPError):
    """Configuration error.

    Raised when the AgentConfig configuration is incorrect.
    """

    pass


class RPCError(OpenANPError):
    """RPC processing error base class.

    Raised when an RPC method execution fails.
    Supports error chain tracking and structured error data.

    Attributes:
        code: JSON-RPC error code
        message: Error message
        data: Additional error data
        cause: Original exception (error chain tracking)
        trace_id: Optional trace ID

    Example:
        try:
            result = await some_operation()
        except SomeError as e:
            raise RPCError(
                code=-32603,
                message="Internal error",
                cause=e,
            ) from e
    """

    code: int
    message: str
    data: Any | None
    cause: Exception | None
    trace_id: str | None

    def __init__(
        self,
        code: int,
        message: str,
        data: Any | None = None,
        cause: Exception | None = None,
        trace_id: str | None = None,
    ):
        self.code = code
        self.message = message
        self.data = data
        self.cause = cause
        self.trace_id = trace_id
        super().__init__(f"RPC Error {code}: {message}")

    def to_dict(self) -> dict[str, Any]:
        """Convert to JSON-RPC error format.

        Returns:
            Error dictionary conforming to JSON-RPC 2.0 specification
        """
        error = {
            "code": self.code,
            "message": self.message,
        }
        if self.data is not None:
            error["data"] = self.data
        if self.trace_id is not None:
            error["trace_id"] = self.trace_id
        return error


# =============================================================================
# Specific Error Types (JSON-RPC 2.0 Standard Errors)
# =============================================================================


class ParseError(RPCError):
    """Parse error (-32700).

    Raised when the request is not valid JSON.
    """

    def __init__(
        self,
        message: str = "Parse error",
        data: Any | None = None,
        cause: Exception | None = None,
    ):
        super().__init__(code=-32700, message=message, data=data, cause=cause)


class InvalidRequestError(RPCError):
    """Invalid request error (-32600).

    Raised when the request does not conform to JSON-RPC 2.0 specification.
    """

    def __init__(
        self,
        message: str = "Invalid Request",
        data: Any | None = None,
        cause: Exception | None = None,
    ):
        super().__init__(code=-32600, message=message, data=data, cause=cause)


class MethodNotFoundError(RPCError):
    """Method not found error (-32601).

    Raised when the requested method does not exist.
    """

    def __init__(
        self,
        method: str,
        data: Any | None = None,
    ):
        super().__init__(
            code=-32601,
            message=f"Method not found: {method}",
            data=data,
        )


class InvalidParamsError(RPCError):
    """Invalid params error (-32602).

    Raised when method parameters are incorrect.
    """

    def __init__(
        self,
        message: str = "Invalid params",
        data: Any | None = None,
        cause: Exception | None = None,
    ):
        super().__init__(code=-32602, message=message, data=data, cause=cause)


class InternalError(RPCError):
    """Internal error (-32603).

    Raised when an internal JSON-RPC error occurs.
    """

    def __init__(
        self,
        message: str = "Internal error",
        data: Any | None = None,
        cause: Exception | None = None,
        trace_id: str | None = None,
    ):
        super().__init__(
            code=-32603,
            message=message,
            data=data,
            cause=cause,
            trace_id=trace_id,
        )


# =============================================================================
# Custom Error Types (-32000 to -32099 reserved for implementation)
# =============================================================================


class AuthenticationError(RPCError):
    """Authentication error (-32001).

    Raised when authentication fails.
    """

    def __init__(
        self,
        message: str = "Authentication failed",
        data: Any | None = None,
    ):
        super().__init__(code=-32001, message=message, data=data)


class AuthorizationError(RPCError):
    """Authorization error (-32002).

    Raised when the user does not have permission to perform the operation.
    """

    def __init__(
        self,
        message: str = "Authorization denied",
        data: Any | None = None,
    ):
        super().__init__(code=-32002, message=message, data=data)


class RateLimitError(RPCError):
    """Rate limit error (-32003).

    Raised when the request is rate-limited.
    """

    def __init__(
        self,
        message: str = "Rate limit exceeded",
        retry_after: int | None = None,
    ):
        data = {"retry_after": retry_after} if retry_after else None
        super().__init__(code=-32003, message=message, data=data)


class ValidationError(RPCError):
    """Validation error (-32004).

    Raised when business logic validation fails (distinct from parameter
    format errors).
    """

    def __init__(
        self,
        message: str = "Validation failed",
        fields: dict[str, str] | None = None,
    ):
        data = {"fields": fields} if fields else None
        super().__init__(code=-32004, message=message, data=data)


class ResourceNotFoundError(RPCError):
    """Resource not found error (-32005).

    Raised when the requested resource does not exist.
    """

    def __init__(
        self,
        resource_type: str,
        resource_id: str,
    ):
        super().__init__(
            code=-32005,
            message=f"{resource_type} not found: {resource_id}",
            data={"resource_type": resource_type, "resource_id": resource_id},
        )


class ConflictError(RPCError):
    """Conflict error (-32006).

    Raised when an operation conflicts with the current resource state.
    """

    def __init__(
        self,
        message: str = "Conflict",
        data: Any | None = None,
    ):
        super().__init__(code=-32006, message=message, data=data)


class ServiceUnavailableError(RPCError):
    """Service unavailable error (-32007).

    Raised when a dependent service is unavailable.
    """

    def __init__(
        self,
        service: str,
        message: str | None = None,
        retry_after: int | None = None,
    ):
        msg = f"Service unavailable: {service}" if message is None else message
        data = {"service": service}
        if retry_after is not None:
            data["retry_after"] = retry_after
        super().__init__(code=-32007, message=msg, data=data)
