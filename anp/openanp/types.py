"""OpenANP SDK - 类型定义和协议

这个模块定义了所有核心类型，遵循：
- 高内聚：所有类型定义紧密相关
- 不可变：使用 frozen dataclass 防止意外修改
- 类型安全：Protocol 确保接口一致性
"""

from __future__ import annotations

from abc import abstractmethod
from dataclasses import dataclass, field
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Generic,
    Protocol,
    TypeVar,
    runtime_checkable,
)

if TYPE_CHECKING:
    from fastapi import Request

__all__ = [
    "AgentConfig",
    "RPCMethodInfo",
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
# 核心配置类型
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
class RPCMethodInfo:
    """RPC 方法信息。

    存储 RPC 方法的元数据，包括名称、描述、参数和返回值的 schema。
    所有字段都是只读的，确保元数据的一致性。

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

        # AP2 方法示例
        ap2_method = RPCMethodInfo(
            name="cart_mandate",
            description="Create cart mandate",
            protocol="AP2/ANP",  # 标记为 AP2 协议方法
            ...
        )
    """

    name: str
    """RPC 方法名称 - JSON-RPC 中的 method 字段"""

    description: str
    """方法描述 - 用于生成接口文档"""

    params_schema: dict[str, Any] | None = None
    """参数 schema - 用于参数验证和文档生成"""

    result_schema: dict[str, Any] | None = None
    """返回值 schema - 用于返回值验证和文档生成"""

    handler: Callable | None = None
    """可选：处理器函数的引用 - 用于自动调用"""

    protocol: str | None = None
    """可选：协议类型标记 - 如 "AP2/ANP" 表示 AP2 支付协议方法，生成时会添加 x-protocol 字段"""

    streaming: bool = False
    """可选：标记为流式方法 - 返回 AsyncIterator，/rpc 端点会返回 SSE 流"""

    def __post_init__(self):
        object.__setattr__(self, "name", self.name.strip())
        object.__setattr__(self, "description", self.description.strip())


# =============================================================================
# 协议定义
# =============================================================================


@runtime_checkable
class IRPCAgent(Protocol):
    """RPC 代理协议。

    用户实现的代理类必须遵守这个协议。
    这确保了所有代理都有一致的接口。

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
    """代理配置 - 必须提供"""

    async def setup(self) -> None:
        """初始化代理。

        在代理开始处理请求之前调用。
        用于建立数据库连接、加载配置等准备工作。
        """
        ...

    async def handle_rpc(self, request: Request, method: str, params: dict) -> Any:
        """处理 RPC 请求。

        这是 RPC 代理的核心方法，负责将 RPC 请求分派到相应的处理方法。

        Args:
            request: FastAPI Request 对象
            method: RPC 方法名称
            params: RPC 参数（字典）

        Returns:
            RPC 调用的结果

        Raises:
            ValueError: 当 method 不存在时
            RPCError: 当处理失败时
        """
        ...


@runtime_checkable
class AgentProtocol(Protocol):
    """代理协议（更宽泛的定义）。

    适用于不依赖具体实现的代理。
    """

    config: AgentConfig
    """代理配置"""

    async def setup(self) -> None:
        """初始化代理"""
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
# 错误类型
# =============================================================================


class OpenANPError(Exception):
    """OpenANP 基础异常类。

    所有 OpenANP 相关的异常都应该继承自这个类。
    """

    pass


class ConfigurationError(OpenANPError):
    """配置错误。

    当 AgentConfig 的配置不正确时抛出。
    """

    pass


class RPCError(OpenANPError):
    """RPC 处理错误基类。

    当 RPC 方法执行失败时抛出。
    支持错误链追踪和结构化错误数据。

    Attributes:
        code: JSON-RPC 错误码
        message: 错误消息
        data: 额外错误数据
        cause: 原始异常（错误链追踪）
        trace_id: 可选的追踪 ID

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
        """转换为 JSON-RPC 错误格式。

        Returns:
            符合 JSON-RPC 2.0 规范的错误字典
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
# 具体错误类型（JSON-RPC 2.0 标准错误）
# =============================================================================


class ParseError(RPCError):
    """解析错误 (-32700)。

    当请求不是有效的 JSON 时抛出。
    """

    def __init__(
        self,
        message: str = "Parse error",
        data: Any | None = None,
        cause: Exception | None = None,
    ):
        super().__init__(code=-32700, message=message, data=data, cause=cause)


class InvalidRequestError(RPCError):
    """无效请求错误 (-32600)。

    当请求不符合 JSON-RPC 2.0 规范时抛出。
    """

    def __init__(
        self,
        message: str = "Invalid Request",
        data: Any | None = None,
        cause: Exception | None = None,
    ):
        super().__init__(code=-32600, message=message, data=data, cause=cause)


class MethodNotFoundError(RPCError):
    """方法未找到错误 (-32601)。

    当请求的方法不存在时抛出。
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
    """无效参数错误 (-32602)。

    当方法参数不正确时抛出。
    """

    def __init__(
        self,
        message: str = "Invalid params",
        data: Any | None = None,
        cause: Exception | None = None,
    ):
        super().__init__(code=-32602, message=message, data=data, cause=cause)


class InternalError(RPCError):
    """内部错误 (-32603)。

    当发生内部 JSON-RPC 错误时抛出。
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
# 自定义错误类型（-32000 到 -32099 保留给实现）
# =============================================================================


class AuthenticationError(RPCError):
    """认证错误 (-32001)。

    当认证失败时抛出。
    """

    def __init__(
        self,
        message: str = "Authentication failed",
        data: Any | None = None,
    ):
        super().__init__(code=-32001, message=message, data=data)


class AuthorizationError(RPCError):
    """授权错误 (-32002)。

    当用户没有权限执行操作时抛出。
    """

    def __init__(
        self,
        message: str = "Authorization denied",
        data: Any | None = None,
    ):
        super().__init__(code=-32002, message=message, data=data)


class RateLimitError(RPCError):
    """速率限制错误 (-32003)。

    当请求被限流时抛出。
    """

    def __init__(
        self,
        message: str = "Rate limit exceeded",
        retry_after: int | None = None,
    ):
        data = {"retry_after": retry_after} if retry_after else None
        super().__init__(code=-32003, message=message, data=data)


class ValidationError(RPCError):
    """验证错误 (-32004)。

    当业务逻辑验证失败时抛出（区别于参数格式错误）。
    """

    def __init__(
        self,
        message: str = "Validation failed",
        fields: dict[str, str] | None = None,
    ):
        data = {"fields": fields} if fields else None
        super().__init__(code=-32004, message=message, data=data)


class ResourceNotFoundError(RPCError):
    """资源未找到错误 (-32005)。

    当请求的资源不存在时抛出。
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
    """冲突错误 (-32006)。

    当操作与当前资源状态冲突时抛出。
    """

    def __init__(
        self,
        message: str = "Conflict",
        data: Any | None = None,
    ):
        super().__init__(code=-32006, message=message, data=data)


class ServiceUnavailableError(RPCError):
    """服务不可用错误 (-32007)。

    当依赖的服务不可用时抛出。
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
