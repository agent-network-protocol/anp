# pyright: reportMissingImports=false

"""OpenANP SDK - Decorators Module

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
# Router Descriptor - Supports class method and instance method calls
# =============================================================================


class _RouterDescriptor:
    """Router descriptor implementing Pythonic dual-mode calling.

    Uses Python descriptor protocol to support router() for both:
    - Class method call: HotelAgent.router()
    - Instance method call: agent.router()

    Example:
        @anp_agent(config)
        class HotelAgent:
            @interface
            async def search(self, query: str) -> dict: ...

        # Method 1: Class method (tries no-arg instantiation)
        router = HotelAgent.router()

        # Method 2: Instance method (recommended, uses bound methods)
        agent = HotelAgent(api_key="...", ...)
        await agent.setup()
        router = agent.router()
    """

    def __get__(
        self, obj: T | None, objtype: type[T] | None = None
    ) -> Callable[[], APIRouter]:
        """Descriptor protocol implementation.

        Args:
            obj: Instance (if accessed from instance) or None (if from class)
            objtype: Class type

        Returns:
            A no-arg function that returns APIRouter when called
        """
        if objtype is None:
            raise RuntimeError("RouterDescriptor requires a class type")

        if obj is None:
            # Class method call: HotelAgent.router()
            def class_router() -> APIRouter:
                return _generate_router_from_class(objtype)

            return class_router
        else:
            # Instance method call: agent.router()
            def instance_router() -> APIRouter:
                return _generate_router_from_instance(objtype, obj)

            return instance_router


# =============================================================================
# Decorators
# =============================================================================


def interface(
    func: T | None = None,
    *,
    name: str | None = None,
    description: str | None = None,
    protocol: str | None = None,
    mode: Literal["content", "link"] = "content",
    params_schema: dict[str, Any] | None = None,
    result_schema: dict[str, Any] | None = None,
) -> T | Callable[[T], T]:
    """Mark a method as an interface endpoint.

    This is a minimal cognitive overhead decorator that marks a method as an
    interface endpoint with just one line of code.

    Args:
        func: The decorated function.
        name: Interface name, defaults to the function name.
        description: Method description, defaults to the first line of the docstring.
        protocol: Protocol type, e.g., "AP2/ANP" for AP2 payment protocol methods.
        mode: Interface mode, "content" embeds OpenRPC document, "link" provides
            URL reference only.
        params_schema: Custom parameters schema.
        result_schema: Custom return value schema.

    Returns:
        The decorated function.

    Example:
        Simplest usage:
            @interface
            async def search(self, query: str) -> dict:
                return {"results": []}

        Link mode (generates a separate OpenRPC document endpoint):
            @interface(mode="link")
            async def book(self, hotel_id: str) -> dict:
                return {"status": "booked"}

        AP2 protocol method:
            @interface(protocol="AP2/ANP")
            async def cart_mandate(self, cart_mandate_id: str, items: list) -> dict:
                return {"cart_mandate_id": cart_mandate_id, "status": "CREATED"}
    """
    # If decorator is called directly (without arguments)
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
            mode=mode,
            params_schema=params_schema,
            result_schema=result_schema,
        )

    # If decorator is called with arguments
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
    mode: Literal["content", "link"] = "content",
    params_schema: dict[str, Any] | None = None,
    result_schema: dict[str, Any] | None = None,
) -> T:
    """Internal RPC decorator implementation.

    Args:
        func: The decorated function.
        name: Method name.
        description: Method description.
        protocol: Protocol type (e.g., "AP2/ANP").
        mode: Interface mode.
        params_schema: Parameters schema.
        result_schema: Return value schema.

    Returns:
        The decorated function.
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

    # Check if the function has a Context parameter
    has_context = _check_has_context(func)

    # Set metadata attributes (using object.__setattr__ because functions are immutable by default)
    object.__setattr__(func, "_rpc_name", name)
    object.__setattr__(func, "_rpc_description", description)
    object.__setattr__(func, "_protocol", protocol)
    object.__setattr__(func, "_mode", mode)
    object.__setattr__(func, "_has_context", has_context)
    object.__setattr__(func, "_rpc_params_schema", params_schema)
    object.__setattr__(func, "_rpc_result_schema", result_schema)

    return func


def _check_has_context(func: Callable) -> bool:
    """Check if the function has a Context parameter.

    Args:
        func: The function to check.

    Returns:
        True if the function has a Context parameter.
    """
    import inspect
    try:
        sig = inspect.signature(func)
        for param_name, param in sig.parameters.items():
            if param_name == "ctx" or param_name == "context":
                return True
            # Check type annotation
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
    """Mark a method as an Information endpoint.

    Register the method as a dynamic Information endpoint, where the method's
    return value serves as the Information content.

    Args:
        type: Information type (Product, VideoObject, ImageObject, etc.).
        description: Description.
        path: URL path (required for URL mode).
        mode: "url" (host and return URL) or "content" (embed in ad.json).

    Returns:
        The decorated function.

    Example:
        # URL mode - generates a separate endpoint
        @information(type="Product", description="Room list", path="/products/rooms.json")
        def get_rooms(self) -> dict:
            return {"rooms": [...]}

        # Content mode - embed in ad.json
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
    """Decorator that automatically generates FastAPI routes.

    Uses the descriptor protocol so that router() supports both class method
    and instance method calls. This is the most Pythonic approach, with a
    single interface that automatically adapts to different scenarios.

    Args:
        config: Agent configuration.

    Returns:
        The decorator function.

    Example:
        @anp_agent(AgentConfig(name="Hotel", did="..."))
        class HotelAgent:
            def __init__(self, api_key: str):
                self.api_key = api_key

            @interface
            async def search(self, query: str) -> dict:
                return {"results": []}

        # Method 1: Class method (for no-argument constructors)
        app.include_router(HotelAgent.router())

        # Method 2: Instance method (recommended for constructors with arguments)
        agent = HotelAgent(api_key="...")
        await agent.setup()  # If initialization is needed
        app.include_router(agent.router())

    Note:
        - Class method call attempts no-argument instantiation; if it fails,
          unbound methods are used (which may cause RPC calls to fail).
        - Instance method call uses bound methods, ensuring self is correctly bound.
        - For constructors with arguments, instance method call is recommended.
    """

    def decorator(cls: type[T]) -> type[T]:
        # Collect all methods marked with @interface in the class
        rpc_method_names: list[str] = []
        # Collect all methods marked with @information in the class
        info_method_names: list[str] = []

        for attr_name in dir(cls):
            attr = getattr(cls, attr_name)
            if hasattr(attr, "_rpc_name"):
                rpc_method_names.append(attr_name)
            if hasattr(attr, "_info_type"):
                info_method_names.append(attr_name)

        # Attach configuration to the class (immutable)
        cls._anp_config = config  # type: ignore[attr-defined]
        cls._anp_rpc_method_names = tuple(rpc_method_names)  # type: ignore[attr-defined]
        cls._anp_info_method_names = tuple(info_method_names)  # type: ignore[attr-defined]

        # Implement router using descriptor
        cls.router = _RouterDescriptor()  # type: ignore[attr-defined]

        return cls

    return decorator


# =============================================================================
# Helper Functions
# =============================================================================


def _extract_first_line(doc: str | None) -> str:
    """Extract the first line of a docstring.

    Args:
        doc: The docstring.

    Returns:
        The first line of text (whitespace stripped).
    """
    if not doc:
        return ""
    return doc.strip().split("\n")[0].strip()


def extract_rpc_methods(obj: object) -> list[RPCMethodInfo]:
    """Extract interface information from an object.

    This is a general utility function that extracts methods decorated with
    @interface from a class or instance.

    Args:
        obj: A class or instance object.

    Returns:
        A list of RPCMethodInfo containing information about all marked methods.

    Example:
        # Extract from class
        methods = extract_rpc_methods(HotelAgent)

        # Extract from instance
        agent = HotelAgent()
        methods = extract_rpc_methods(agent)
    """
    methods = []
    seen_methods = set()

    # Check if the object has the _rpc_name attribute
    for attr_name in dir(obj):
        # Skip private attributes (unless explicitly an rpc method)
        if attr_name.startswith("_") and not attr_name.startswith("__"):
            # Simply skip private methods to avoid accidentally exposing internal methods
            continue

        try:
            attr = getattr(obj, attr_name)
        except Exception:
            # Some attribute accesses may raise exceptions
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
                mode=getattr(attr, "_mode", "content"),
                has_context=getattr(attr, "_has_context", False),
            )
            methods.append(method_info)

    return methods


def _generate_router_from_class(cls: type) -> Any:
    """Generate FastAPI router from a class.

    Attempts no-argument instantiation of the class; if it fails, uses unbound methods.

    Args:
        cls: Class decorated with @anp_agent.

    Returns:
        FastAPI APIRouter.
    """
    # Attempt no-argument instantiation
    try:
        instance = cls()
        return _generate_router_from_instance(cls, instance)
    except TypeError:
        # Class requires arguments, use unbound methods (ad.json/interface.json available, rpc may fail)
        from .autogen import (
            create_agent_router,  # pyright: ignore[reportMissingImports]
        )

        config: AgentConfig = cls._anp_config  # type: ignore[attr-defined]
        methods = _extract_unbound_methods(cls)
        return create_agent_router(config, methods)


def _generate_router_from_instance(cls: type, instance: Any) -> Any:
    """Generate FastAPI router from an instance.

    Uses the instance's bound methods, ensuring self is correctly bound during RPC calls.

    Args:
        cls: Class decorated with @anp_agent.
        instance: Agent instance.

    Returns:
        FastAPI APIRouter.
    """
    from .autogen import create_agent_router  # pyright: ignore[reportMissingImports]

    config: AgentConfig = cls._anp_config  # type: ignore[attr-defined]
    methods = _extract_bound_methods(instance)
    return create_agent_router(config, methods, instance)


def _extract_unbound_methods(cls: type) -> list[RPCMethodInfo]:
    """Extract unbound RPC method information from a class."""
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
                    mode=getattr(attr, "_mode", "content"),
                    has_context=getattr(attr, "_has_context", False),
                )
            )

    return methods


def _extract_bound_methods(instance: Any) -> list[RPCMethodInfo]:
    """Extract bound RPC method information from an instance."""
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
                    handler=attr,  # Bound method
                    protocol=getattr(attr, "_protocol", None),
                    mode=getattr(attr, "_mode", "content"),
                    has_context=getattr(attr, "_has_context", False),
                )
            )

    return methods


# =============================================================================
# Type Checking Utilities
# =============================================================================


def is_rpc_method(func: Callable) -> bool:
    """Check if a function is decorated with @interface.

    Args:
        func: The function to check.

    Returns:
        True if the function is decorated with @interface.
    """
    return hasattr(func, "_rpc_name")


def get_rpc_method_info(func: Callable) -> RPCMethodInfo | None:
    """Get interface information.

    Args:
        func: A function decorated with @interface.

    Returns:
        RPCMethodInfo object, or None if the function is not decorated.
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
        mode=getattr(f, "_mode", "content"),
        has_context=getattr(f, "_has_context", False),
    )


# =============================================================================
# Convenience Functions
# =============================================================================


def create_agent(config: AgentConfig, cls: type) -> object:
    """Create an agent instance.

    This is a convenience function for creating instances that conform to
    the IRPCAgent protocol.

    Args:
        config: Agent configuration.
        cls: Agent class.

    Returns:
        Agent instance.

    Example:
        class HotelAgent:
            async def handle_rpc(self, request, method, params):
                ...

        agent = create_agent(config, HotelAgent)
        await agent.setup()
    """
    # Create instance (assuming the class accepts a config parameter)
    try:
        instance = cls(config)
    except TypeError:
        # If the class doesn't accept parameters, create an empty instance
        instance = cls()

    # Set configuration
    instance.config = config

    return instance
