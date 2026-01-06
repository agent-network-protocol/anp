# pyright: reportMissingImports=false

"""OpenANP SDK - 装饰器模块

Usage:
    @anp_agent(config)
    class HotelAgent:
        @interface
        async def search(self, query: str) -> dict: ...

    # Class method (tries no-arg instantiation)
    router = HotelAgent.router()

    # Instance method (uses bound methods) - recommended for complex agents
    agent = HotelAgent(api_key="...", ...)
    await agent.setup()
    router = agent.router()
"""

from __future__ import annotations

from typing import Any, Callable, Literal, TypeVar, cast

from .types import AgentConfig, RPCMethodInfo, Information  # pyright: ignore[reportMissingImports]

APIRouter = Any

__all__ = [
    "anp_agent",
    "interface",
    "information",
    "extract_rpc_methods",
]

T = TypeVar("T")


# =============================================================================
# Router 描述符 - 支持类方法和实例方法调用
# =============================================================================


class _RouterDescriptor:
    """Router 描述符，实现 Pythonic 的双模式调用。

    使用 Python 描述符协议，让 router() 同时支持：
    - 类方法调用：HotelAgent.router()
    - 实例方法调用：agent.router()

    Example:
        @anp_agent(config)
        class HotelAgent:
            @interface
            async def search(self, query: str) -> dict: ...

        # 方式 1：类方法（尝试无参实例化）
        router = HotelAgent.router()

        # 方式 2：实例方法（推荐，使用绑定方法）
        agent = HotelAgent(api_key="...", ...)
        await agent.setup()
        router = agent.router()
    """

    def __get__(
        self, obj: T | None, objtype: type[T] | None = None
    ) -> Callable[[], APIRouter]:
        """描述符协议实现。

        Args:
            obj: 实例（如果从实例访问）或 None（如果从类访问）
            objtype: 类类型

        Returns:
            返回一个无参函数，调用后返回 APIRouter
        """
        if objtype is None:
            raise RuntimeError("RouterDescriptor requires a class type")

        if obj is None:
            # 类方法调用：HotelAgent.router()
            def class_router() -> APIRouter:
                return _generate_router_from_class(objtype)

            return class_router
        else:
            # 实例方法调用：agent.router()
            def instance_router() -> APIRouter:
                return _generate_router_from_instance(objtype, obj)

            return instance_router


# =============================================================================
# 装饰器
# =============================================================================


def interface(
    func: T | None = None,
    *,
    name: str | None = None,
    description: str | None = None,
    protocol: str | None = None,
    streaming: bool = False,
    mode: Literal["content", "link"] = "content",
    params_schema: dict[str, Any] | None = None,
    result_schema: dict[str, Any] | None = None,
) -> T | Callable[[T], T]:
    """标记一个方法为接口端点。

    这是最小心智负担的装饰器，只需要一行代码就能标记一个方法为接口端点。

    Args:
        func: 被装饰的函数
        name: 接口名称，默认使用函数名
        description: 方法描述，默认使用函数文档的第一行
        protocol: 协议类型，如 "AP2/ANP" 表示 AP2 支付协议方法
        streaming: 标记为流式方法，返回 AsyncIterator，/rpc 端点会返回 SSE 流
        mode: 接口模式，"content" 嵌入 OpenRPC 文档，"link" 仅提供 URL 链接
        params_schema: 自定义参数 schema
        result_schema: 自定义返回值 schema

    Returns:
        装饰后的函数

    Example:
        最简单的用法：
            @interface
            async def search(self, query: str) -> dict:
                return {"results": []}

        Link 模式（生成独立的 OpenRPC 文档端点）：
            @interface(mode="link")
            async def book(self, hotel_id: str) -> dict:
                return {"status": "booked"}

        AP2 协议方法：
            @interface(protocol="AP2/ANP")
            async def cart_mandate(self, cart_mandate_id: str, items: list) -> dict:
                return {"cart_mandate_id": cart_mandate_id, "status": "CREATED"}

        流式方法（SSE）：
            @interface(streaming=True)
            async def ask_stream(self, content: str) -> AsyncIterator[dict]:
                async for chunk in upstream.stream(content):
                    yield chunk
    """
    # 如果直接调用装饰器（没有参数）
    if func is not None:
        resolved_name = cast(Any, func).__name__ if name is None else name
        resolved_description = (
            _extract_first_line(func.__doc__) if description is None else description
        )
        return _rpc_decorator(
            func,
            name=resolved_name,
            description=resolved_description,
            protocol=protocol,
            streaming=streaming,
            mode=mode,
            params_schema=params_schema,
            result_schema=result_schema,
        )

    # 如果用参数调用装饰器
    def decorator(f: T) -> T:
        resolved_name = cast(Any, f).__name__ if name is None else name
        resolved_description = (
            _extract_first_line(f.__doc__) if description is None else description
        )
        return _rpc_decorator(
            f,
            name=resolved_name,
            description=resolved_description,
            protocol=protocol,
            streaming=streaming,
            mode=mode,
            params_schema=params_schema,
            result_schema=result_schema,
        )

    return decorator


def _rpc_decorator(
    func: T,
    name: str,
    description: str,
    protocol: str | None = None,
    streaming: bool = False,
    mode: Literal["content", "link"] = "content",
    params_schema: dict[str, Any] | None = None,
    result_schema: dict[str, Any] | None = None,
) -> T:
    """实际的 RPC 装饰器实现。

    Args:
        func: 被装饰的函数
        name: 方法名称
        description: 方法描述
        protocol: 协议类型（如 "AP2/ANP"）
        streaming: 标记为流式方法
        mode: 接口模式
        params_schema: 参数 schema
        result_schema: 返回值 schema

    Returns:
        装饰后的函数
    """
    # WHY: Use schema_gen module for consistent schema generation.
    # ADR: docs/adr/0001-auto-schema-generation.md
    if params_schema is None or result_schema is None:
        from .schema_gen import (
            extract_method_schemas,  # pyright: ignore[reportMissingImports]
        )

        extracted_params, extracted_result = extract_method_schemas(func)

        if params_schema is None:
            params_schema = extracted_params
        if result_schema is None:
            result_schema = extracted_result

    # 检测是否有 Context 参数
    has_context = _check_has_context(func)

    # 设置元数据属性（使用 object.__setattr__ 因为函数默认是不可变的）
    object.__setattr__(func, "_rpc_name", name)
    object.__setattr__(func, "_rpc_description", description)
    object.__setattr__(func, "_protocol", protocol)
    object.__setattr__(func, "_streaming", streaming)
    object.__setattr__(func, "_mode", mode)
    object.__setattr__(func, "_has_context", has_context)
    object.__setattr__(func, "_rpc_params_schema", params_schema)
    object.__setattr__(func, "_rpc_result_schema", result_schema)

    return func


def _check_has_context(func: Callable) -> bool:
    """检查函数是否有 Context 参数。

    Args:
        func: 要检查的函数

    Returns:
        True 如果函数有 Context 参数
    """
    import inspect
    try:
        sig = inspect.signature(func)
        for param_name, param in sig.parameters.items():
            if param_name == "ctx" or param_name == "context":
                return True
            # 检查类型注解
            if param.annotation != inspect.Parameter.empty:
                ann = param.annotation
                if hasattr(ann, "__name__") and ann.__name__ == "Context":
                    return True
                if isinstance(ann, str) and ann == "Context":
                    return True
    except (ValueError, TypeError):
        pass
    return False


def information(
    type: str,
    description: str,
    path: str | None = None,
    mode: Literal["url", "content"] = "url",
) -> Callable[[T], T]:
    """标记一个方法为 Information 端点。

    将方法注册为动态 Information 端点，方法返回值将作为 Information 内容。

    Args:
        type: Information 类型（Product, VideoObject, ImageObject 等）
        description: 描述
        path: URL 路径（URL 模式必需）
        mode: "url"（托管并返回 URL）或 "content"（内嵌到 ad.json）

    Returns:
        装饰后的函数

    Example:
        # URL 模式 - 生成独立端点
        @information(type="Product", description="Room list", path="/products/rooms.json")
        def get_rooms(self) -> dict:
            return {"rooms": [...]}

        # Content 模式 - 内嵌到 ad.json
        @information(type="Service", description="Menu", mode="content")
        def get_menu(self) -> dict:
            return {"menu": [...]}
    """
    if mode == "url" and not path:
        raise ValueError("URL mode @information requires 'path' parameter")

    def decorator(func: T) -> T:
        object.__setattr__(func, "_info_type", type)
        object.__setattr__(func, "_info_description", description)
        object.__setattr__(func, "_info_path", path)
        object.__setattr__(func, "_info_mode", mode)
        return func

    return decorator


def anp_agent(config: AgentConfig) -> Callable[[type[T]], type[T]]:
    """自动生成 FastAPI 路由的装饰器。

    使用描述符协议，router() 同时支持类方法和实例方法调用。
    这是最 Pythonic 的方式，单一接口自动适配不同场景。

    Args:
        config: Agent 配置

    Returns:
        装饰器函数

    Example:
        @anp_agent(AgentConfig(name="Hotel", did="..."))
        class HotelAgent:
            def __init__(self, api_key: str):
                self.api_key = api_key

            @interface
            async def search(self, query: str) -> dict:
                return {"results": []}

        # 方式 1：类方法（适用于无参构造函数）
        app.include_router(HotelAgent.router())

        # 方式 2：实例方法（推荐，适用于有参构造函数）
        agent = HotelAgent(api_key="...")
        await agent.setup()  # 如果需要初始化
        app.include_router(agent.router())

    Note:
        - 类方法调用会尝试无参实例化，失败则使用未绑定方法（可能导致 RPC 调用失败）
        - 实例方法调用使用绑定方法，确保 self 正确绑定
        - 对于有参数的构造函数，推荐使用实例方法调用
    """

    def decorator(cls: type[T]) -> type[T]:
        # 收集类中所有被 @interface 标记的方法
        rpc_method_names: list[str] = []
        # 收集类中所有被 @information 标记的方法
        info_method_names: list[str] = []

        for attr_name in dir(cls):
            attr = getattr(cls, attr_name)
            if hasattr(attr, "_rpc_name"):
                rpc_method_names.append(attr_name)
            if hasattr(attr, "_info_type"):
                info_method_names.append(attr_name)

        # 将配置附加到类（不可变）
        cls._anp_config = config  # type: ignore[attr-defined]
        cls._anp_rpc_method_names = tuple(rpc_method_names)  # type: ignore[attr-defined]
        cls._anp_info_method_names = tuple(info_method_names)  # type: ignore[attr-defined]

        # 使用描述符实现 router
        cls.router = _RouterDescriptor()  # type: ignore[attr-defined]

        return cls

    return decorator


# =============================================================================
# 辅助函数
# =============================================================================


def _extract_first_line(doc: str | None) -> str:
    """提取文档字符串的第一行。

    Args:
        doc: 文档字符串

    Returns:
        第一行文本（去除空白）
    """
    if not doc:
        return ""
    return doc.strip().split("\n")[0].strip()


def extract_rpc_methods(obj: object) -> list[RPCMethodInfo]:
    """从对象中提取接口信息。

    这是一个通用的工具函数，支持从类或实例中提取被 @interface 装饰的方法。

    Args:
        obj: 类或实例对象

    Returns:
        RPCMethodInfo 列表，包含所有被标记的方法信息

    Example:
        # 从类提取
        methods = extract_rpc_methods(HotelAgent)

        # 从实例提取
        agent = HotelAgent()
        methods = extract_rpc_methods(agent)
    """
    methods = []
    seen_methods = set()

    # 检查对象是否有 _rpc_name 属性
    for attr_name in dir(obj):
        # 跳过私有属性（除非明确是 rpc 方法）
        if attr_name.startswith("_") and not attr_name.startswith("__"):
            # 简单跳过私有方法，避免意外暴露内部方法
            continue

        try:
            attr = getattr(obj, attr_name)
        except Exception:
            # 某些属性访问可能抛出异常
            continue

        if hasattr(attr, "_rpc_name"):
            if attr._rpc_name in seen_methods:
                continue
            seen_methods.add(attr._rpc_name)

            method_info = RPCMethodInfo(
                name=attr._rpc_name,
                description=attr._rpc_description,
                params_schema=attr._rpc_params_schema,
                result_schema=attr._rpc_result_schema,
                handler=attr,
                protocol=getattr(attr, "_protocol", None),
                streaming=getattr(attr, "_streaming", False),
                mode=getattr(attr, "_mode", "content"),
                has_context=getattr(attr, "_has_context", False),
            )
            methods.append(method_info)

    return methods


def _generate_router_from_class(cls: type) -> Any:
    """从类生成 FastAPI 路由。

    尝试无参实例化类，如果失败则使用未绑定方法。

    Args:
        cls: @anp_agent 装饰的类

    Returns:
        FastAPI APIRouter
    """
    # 尝试无参实例化
    try:
        instance = cls()
        return _generate_router_from_instance(cls, instance)
    except TypeError:
        # 类需要参数，使用未绑定方法（ad.json/interface.json 可用，rpc 可能失败）
        from .autogen import (
            create_agent_router,  # pyright: ignore[reportMissingImports]
        )

        config: AgentConfig = cls._anp_config  # type: ignore[attr-defined]
        methods = _extract_unbound_methods(cls)
        return create_agent_router(config, methods)


def _generate_router_from_instance(cls: type, instance: Any) -> Any:
    """从实例生成 FastAPI 路由。

    使用实例的绑定方法，确保 RPC 调用时 self 正确绑定。

    Args:
        cls: @anp_agent 装饰的类
        instance: agent 实例

    Returns:
        FastAPI APIRouter
    """
    from .autogen import create_agent_router  # pyright: ignore[reportMissingImports]

    config: AgentConfig = cls._anp_config  # type: ignore[attr-defined]
    methods = _extract_bound_methods(instance)
    return create_agent_router(config, methods, instance)


def _extract_unbound_methods(cls: type) -> list[RPCMethodInfo]:
    """从类中提取未绑定的 RPC 方法信息。"""
    methods: list[RPCMethodInfo] = []
    method_names: tuple[str, ...] = getattr(cls, "_anp_rpc_method_names", ())

    for attr_name in method_names:
        attr = getattr(cls, attr_name, None)
        if attr is not None and hasattr(attr, "_rpc_name"):
            methods.append(
                RPCMethodInfo(
                    name=attr._rpc_name,
                    description=attr._rpc_description,
                    params_schema=attr._rpc_params_schema,
                    result_schema=attr._rpc_result_schema,
                    handler=attr,
                    protocol=getattr(attr, "_protocol", None),
                    streaming=getattr(attr, "_streaming", False),
                    mode=getattr(attr, "_mode", "content"),
                    has_context=getattr(attr, "_has_context", False),
                )
            )

    return methods


def _extract_bound_methods(instance: Any) -> list[RPCMethodInfo]:
    """从实例中提取绑定的 RPC 方法信息。"""
    methods: list[RPCMethodInfo] = []
    cls = type(instance)
    method_names: tuple[str, ...] = getattr(cls, "_anp_rpc_method_names", ())

    for attr_name in method_names:
        attr = getattr(instance, attr_name, None)
        if attr is not None and hasattr(attr, "_rpc_name"):
            methods.append(
                RPCMethodInfo(
                    name=attr._rpc_name,
                    description=attr._rpc_description,
                    params_schema=attr._rpc_params_schema,
                    result_schema=attr._rpc_result_schema,
                    handler=attr,  # 绑定方法
                    protocol=getattr(attr, "_protocol", None),
                    streaming=getattr(attr, "_streaming", False),
                    mode=getattr(attr, "_mode", "content"),
                    has_context=getattr(attr, "_has_context", False),
                )
            )

    return methods


# =============================================================================
# 类型检查工具
# =============================================================================


def is_rpc_method(func: Callable) -> bool:
    """检查一个函数是否被 @interface 装饰。

    Args:
        func: 要检查的函数

    Returns:
        True 如果函数被 @interface 装饰
    """
    return hasattr(func, "_rpc_name")


def get_rpc_method_info(func: Callable) -> RPCMethodInfo | None:
    """获取接口信息。

    Args:
        func: 被 @interface 装饰的函数

    Returns:
        RPCMethodInfo 对象，如果函数没有被装饰则返回 None
    """
    if not is_rpc_method(func):
        return None

    f = cast(Any, func)
    return RPCMethodInfo(
        name=f._rpc_name,
        description=f._rpc_description,
        params_schema=f._rpc_params_schema,
        result_schema=f._rpc_result_schema,
        handler=func,
        protocol=getattr(f, "_protocol", None),
        streaming=getattr(f, "_streaming", False),
        mode=getattr(f, "_mode", "content"),
        has_context=getattr(f, "_has_context", False),
    )


# =============================================================================
# 便捷函数
# =============================================================================


def create_agent(config: AgentConfig, cls: type) -> object:
    """创建一个代理实例。

    这是一个便捷函数，用于创建符合 IRPCAgent 协议的实例。

    Args:
        config: Agent 配置
        cls: 代理类

    Returns:
        代理实例

    Example:
        class HotelAgent:
            async def handle_rpc(self, request, method, params):
                ...

        agent = create_agent(config, HotelAgent)
        await agent.setup()
    """
    # 创建实例（假设类接受 config 参数）
    try:
        instance = cls(config)
    except TypeError:
        # 如果类不接受参数，创建空实例
        instance = cls()

    # 设置配置
    instance.config = config

    return instance
