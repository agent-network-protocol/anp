"""OpenANP SDK - Auto-generated Routes

This module provides automatic FastAPI route generation.
Users can choose to use this module or implement their own.

Design Principles:
- Optional: Not required, users can implement their own
- Transparent: Generated routes are standard FastAPI routes
- Customizable: Users can customize part or all routes
- JSON-RPC 2.0: Full support for single and batch requests
- Context Injection: Automatic Context parameter injection to handlers

Usage:
1. Use @anp_agent decorator for auto-generation (simplest)
2. Manually call create_agent_router() function
3. Fully implement yourself (most flexible)
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
from typing import (
    TYPE_CHECKING,
    Annotated,
    Any,
    Callable,
    get_args,
    get_origin,
    get_type_hints,
)

# Import Request and JSONResponse for runtime use
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from .context import Context, SessionManager
from .types import AgentConfig, Information, RPCMethodInfo
from .utils import (
    RPCErrorCodes,
    create_rpc_error,
    create_rpc_response,
    generate_ad_document,
    generate_rpc_interface,
    resolve_base_url,
    validate_rpc_request,
)

if TYPE_CHECKING:
    pass  # All types imported above

logger = logging.getLogger(__name__)

__all__ = [
    "create_agent_router",
    "coerce_params",
    "process_single_rpc_request",
    "process_batch_rpc_request",
    "generate_ad",
]


# =============================================================================
# Global Session Manager
# =============================================================================

_session_manager = SessionManager()


def get_session_manager() -> SessionManager:
    """Get the global session manager."""
    return _session_manager


# =============================================================================
# Parameter Type Coercion
# =============================================================================


def _is_pydantic_model(cls: Any) -> bool:
    """Check if a class is a Pydantic BaseModel."""
    return hasattr(cls, "model_validate") and hasattr(cls, "model_fields")


def _unwrap_annotated(tp: Any) -> Any:
    """Unwrap Annotated[T, ...] to get the underlying type T."""
    if get_origin(tp) is Annotated:
        return get_args(tp)[0]
    return tp


def coerce_params(handler: Callable, params: dict[str, Any]) -> dict[str, Any]:
    """Coerce dict parameters to Pydantic models based on handler type hints.

    This function enables "hybrid mode" where JSON-RPC dict params are
    automatically converted to Pydantic models when the handler expects them.

    Args:
        handler: The RPC method handler function
        params: Raw JSON-RPC params dictionary

    Returns:
        Coerced params with dicts converted to Pydantic models where applicable

    Example:
        @interface
        async def search(self, criteria: HotelSearchCriteria) -> dict:
            # criteria is automatically converted from dict to HotelSearchCriteria
            ...

        # Before: {"criteria": {"city": "Tokyo"}}
        # After:  {"criteria": HotelSearchCriteria(city="Tokyo")}
    """
    if not params:
        return params

    try:
        hints = get_type_hints(handler, include_extras=True)
    except Exception:
        # If type hints cannot be resolved, return params unchanged
        return params

    coerced = {}
    for param_name, param_value in params.items():
        param_type = hints.get(param_name)

        if param_type is not None and isinstance(param_value, dict):
            # Unwrap Annotated[T, ...] to get actual type
            actual_type = _unwrap_annotated(param_type)

            # Convert dict to Pydantic model if applicable
            if _is_pydantic_model(actual_type):
                try:
                    param_value = actual_type.model_validate(param_value)
                except Exception:
                    # If validation fails, pass through the raw dict
                    # and let the handler raise appropriate errors
                    pass

        coerced[param_name] = param_value

    return coerced


# =============================================================================
# Context Injection
# =============================================================================


def _create_context(request: Request) -> Context:
    """Create Context from request.

    Extracts authentication info from request.state (set by middleware)
    and creates/retrieves session.

    Args:
        request: FastAPI Request object

    Returns:
        Context object with session and authentication info
    """
    auth_result = getattr(request.state, "auth_result", None) or {}
    did = auth_result.get("did", "anonymous")

    session = _session_manager.get_or_create(did)
    return Context(
        session=session,
        did=did,
        request=request,
        auth_result=auth_result,
    )


def _inject_context(
    handler: Callable,
    params: dict[str, Any],
    request: Request,
    has_context: bool,
) -> dict[str, Any]:
    """Inject Context into params if handler needs it.

    Args:
        handler: The RPC method handler function
        params: Coerced params dictionary
        request: FastAPI Request object
        has_context: Whether handler needs Context

    Returns:
        Params with Context injected if needed
    """
    if not has_context:
        return params

    # Create context and inject
    ctx = _create_context(request)

    # Check parameter names to determine key
    sig = inspect.signature(handler)
    for param_name in sig.parameters:
        if param_name in ("ctx", "context"):
            return {**params, param_name: ctx}

    # Fallback: inject as 'ctx'
    return {**params, "ctx": ctx}


# =============================================================================
# JSON-RPC 2.0 Batch Request Processing
# =============================================================================


async def process_single_rpc_request(
    body: dict[str, Any],
    handlers: dict[str, Callable],
    request: Request | None = None,
    method_info_map: dict[str, RPCMethodInfo] | None = None,
) -> dict[str, Any]:
    """Process a single JSON-RPC 2.0 request.

    Args:
        body: Request body dictionary
        handlers: Method handler mapping
        request: FastAPI Request object (for Context injection)
        method_info_map: Method info mapping (for has_context check)

    Returns:
        JSON-RPC 2.0 response dictionary
    """
    try:
        method_name, params, req_id = validate_rpc_request(body)

        if method_name not in handlers:
            return create_rpc_error(
                RPCErrorCodes.METHOD_NOT_FOUND,
                f"Method not found: {method_name}",
                req_id,
            )

        handler = handlers[method_name]

        # Auto-coerce dict params to Pydantic models (hybrid mode)
        coerced_params = coerce_params(handler, params)

        # Inject Context if needed
        if request is not None and method_info_map is not None:
            method_info = method_info_map.get(method_name)
            has_context = method_info.has_context if method_info else False
            coerced_params = _inject_context(
                handler, coerced_params, request, has_context
            )

        # Call handler (bound or unbound method)
        if inspect.iscoroutinefunction(handler):
            result = await handler(**coerced_params)
        else:
            result = handler(**coerced_params)

        return create_rpc_response(result, req_id)

    except ValueError as e:
        return create_rpc_error(
            RPCErrorCodes.INVALID_REQUEST,
            str(e),
            body.get("id"),
        )
    except TypeError as e:
        # Parameter type error
        return create_rpc_error(
            RPCErrorCodes.INVALID_PARAMS,
            str(e),
            body.get("id"),
        )
    except Exception as e:
        return create_rpc_error(
            RPCErrorCodes.INTERNAL_ERROR,
            str(e),
            body.get("id"),
        )


async def process_batch_rpc_request(
    batch: list[dict[str, Any]],
    handlers: dict[str, Callable],
    max_concurrent: int | None = None,
    request: Request | None = None,
    method_info_map: dict[str, RPCMethodInfo] | None = None,
) -> list[dict[str, Any]]:
    """Process batch JSON-RPC 2.0 requests.

    According to JSON-RPC 2.0 spec, each request in batch should be processed independently.
    Notifications (requests without id) should not return responses.

    Args:
        batch: Request list
        handlers: Method handler mapping
        max_concurrent: Max concurrent requests, None for unlimited
        request: FastAPI Request object (for Context injection)
        method_info_map: Method info mapping (for has_context check)

    Returns:
        Response list (excluding notification responses)
    """
    if not batch:
        return []

    # Create tasks
    tasks = [
        process_single_rpc_request(req, handlers, request, method_info_map)
        for req in batch
    ]

    # Concurrent execution (with optional limit)
    if max_concurrent is not None and max_concurrent > 0:
        # Use semaphore to limit concurrency
        semaphore = asyncio.Semaphore(max_concurrent)

        async def limited_task(task: Any) -> dict[str, Any]:
            async with semaphore:
                return await task

        results = await asyncio.gather(*[limited_task(t) for t in tasks])
    else:
        results = await asyncio.gather(*tasks)

    # Filter notification responses (notifications have no id, should not return response)
    responses = []
    for req, resp in zip(batch, results):
        # Include response if original request has id (not a notification)
        if "id" in req:
            responses.append(resp)

    return responses


# =============================================================================
# Information Extraction
# =============================================================================


def _extract_informations(instance: Any) -> list[Information]:
    """Extract Information definitions from agent class/instance.

    Collects:
    1. Static informations from class attribute 'informations'
    2. Dynamic informations from methods decorated with @information

    Args:
        instance: Agent class or instance

    Returns:
        List of Information objects
    """
    informations: list[Information] = []
    cls = instance if isinstance(instance, type) else type(instance)

    # 1. Get static informations from class attribute
    static_infos = getattr(cls, "informations", [])
    if isinstance(static_infos, list):
        for info in static_infos:
            if isinstance(info, Information):
                informations.append(info)

    # 2. Get dynamic informations from @information decorated methods
    info_method_names: tuple[str, ...] = getattr(cls, "_anp_info_method_names", ())
    for method_name in info_method_names:
        method = getattr(instance, method_name, None)
        if method is None:
            continue

        info_type = getattr(method, "_info_type", None)
        info_description = getattr(method, "_info_description", "")
        info_path = getattr(method, "_info_path", None)
        info_mode = getattr(method, "_info_mode", "url")

        if info_type:
            if info_mode == "content":
                # Content mode: call method to get content
                try:
                    if inspect.iscoroutinefunction(method):
                        # Can't call async method here, skip
                        logger.warning(
                            f"Async @information method {method_name} with mode='content' "
                            "is not supported. Use sync method or mode='url'."
                        )
                        continue
                    content = method()
                    informations.append(
                        Information(
                            type=info_type,
                            description=info_description,
                            mode="content",
                            content=content,
                        )
                    )
                except Exception as e:
                    logger.error(f"Error calling @information method {method_name}: {e}")
            else:
                # URL mode: register path
                if info_path:
                    informations.append(
                        Information(
                            type=info_type,
                            description=info_description,
                            mode="url",
                            path=info_path,
                        )
                    )

    return informations


# =============================================================================
# AD Document Generation
# =============================================================================


def generate_ad(
    config: AgentConfig,
    instance: Any,
    base_url: str = "",
    methods: list[RPCMethodInfo] | None = None,
) -> dict[str, Any]:
    """Generate ad.json document for an agent.

    This is a standalone function that can be used to customize ad.json.

    Args:
        config: Agent configuration
        instance: Agent class or instance
        base_url: Base URL for constructing full URLs
        methods: Optional RPC methods list

    Returns:
        ad.json document as dictionary

    Example:
        @router.get("/hotel/ad.json")
        async def custom_ad(request: Request):
            base_url = resolve_base_url(request)
            ad = generate_ad(config, HotelAgent, base_url)
            ad["custom_field"] = "custom_value"
            return ad
    """
    # Build interfaces
    interfaces: list[dict[str, Any]] = []
    if methods:
        # Separate content and link mode methods
        content_methods = [m for m in methods if m.mode == "content"]
        link_methods = [m for m in methods if m.mode == "link"]

        # Content mode: single interface.json with all methods
        if content_methods:
            interface_url = f"{base_url}{config.prefix}/interface.json"
            interfaces.append(
                {
                    "type": "StructuredInterface",
                    "protocol": "openrpc",
                    "url": interface_url,
                    "description": f"{config.name} JSON-RPC interface",
                }
            )

        # Link mode: individual interface files
        for method in link_methods:
            method_url = f"{base_url}{config.prefix}/interface/{method.name}.json"
            interfaces.append(
                {
                    "type": "StructuredInterface",
                    "protocol": "openrpc",
                    "url": method_url,
                    "description": method.description,
                }
            )

    # Build Informations
    informations: list[dict[str, Any]] = []
    info_list = _extract_informations(instance)
    for info in info_list:
        informations.append(info.to_dict(base_url + config.prefix))

    # Generate base document
    doc = generate_ad_document(config, base_url, interfaces if interfaces else None)

    # Add Informations if present
    if informations:
        doc["Infomations"] = informations

    return doc


# =============================================================================
# Route Registration Helpers
# =============================================================================


def _register_ad_route(
    router: APIRouter,
    config: AgentConfig,
    instance: Any,
    methods: list[RPCMethodInfo],
) -> None:
    """Register GET /ad.json route.

    Args:
        router: FastAPI router to register route on
        config: Agent configuration
        instance: Agent instance for customize_ad hook
        methods: RPC method list for interface generation
    """

    @router.get("/ad.json")
    async def get_ad(request: Request) -> JSONResponse:
        """Generate and return ad.json document."""
        base_url = resolve_base_url(request)
        doc = generate_ad(config, instance, base_url, methods)

        # Call customize_ad hook if exists
        if instance is not None and hasattr(instance, "customize_ad"):
            customize_fn = getattr(instance, "customize_ad")
            if inspect.iscoroutinefunction(customize_fn):
                doc = await customize_fn(doc, base_url)
            else:
                doc = customize_fn(doc, base_url)

        return JSONResponse(doc, media_type="application/json; charset=utf-8")


def _register_interface_routes(
    router: APIRouter,
    config: AgentConfig,
    content_methods: list[RPCMethodInfo],
    link_methods: list[RPCMethodInfo],
) -> None:
    """Register interface routes (content mode and link mode).

    Args:
        router: FastAPI router to register routes on
        config: Agent configuration
        content_methods: Methods with mode="content"
        link_methods: Methods with mode="link"
    """
    # GET /interface.json - Content mode methods (all in one document)
    if content_methods:

        @router.get("/interface.json")
        async def get_interface(request: Request) -> JSONResponse:
            """Generate interface.json for content mode methods."""
            base_url = resolve_base_url(request)
            doc = generate_rpc_interface(config, base_url, content_methods)
            return JSONResponse(doc, media_type="application/json; charset=utf-8")

    # GET /interface/{method}.json - Link mode methods (individual documents)
    for method_info in link_methods:

        def make_method_interface_handler(m: RPCMethodInfo) -> Callable:
            async def get_method_interface(request: Request) -> JSONResponse:
                """Generate individual method interface document."""
                base_url = resolve_base_url(request)
                doc = generate_rpc_interface(config, base_url, [m])
                return JSONResponse(doc, media_type="application/json; charset=utf-8")

            return get_method_interface

        router.add_api_route(
            f"/interface/{method_info.name}.json",
            make_method_interface_handler(method_info),
            methods=["GET"],
            name=f"get_interface_{method_info.name}",
        )


def _register_information_routes(
    router: APIRouter,
    instance: Any,
) -> None:
    """Register information endpoints (static and dynamic).

    Args:
        router: FastAPI router to register routes on
        instance: Agent instance for extracting information definitions
    """
    if instance is None:
        return

    info_list = _extract_informations(instance)
    cls = instance if isinstance(instance, type) else type(instance)
    info_method_names: tuple[str, ...] = getattr(cls, "_anp_info_method_names", ())

    # Register URL mode static information endpoints
    for info in info_list:
        if info.mode == "url" and info.path:

            def make_static_info_handler(i: Information) -> Callable:
                async def get_static_info() -> JSONResponse:
                    """Serve static information content."""
                    if i.file:
                        try:
                            import aiofiles

                            async with aiofiles.open(i.file, "r") as f:
                                content = await f.read()
                            return JSONResponse(
                                json.loads(content),
                                media_type="application/json; charset=utf-8",
                            )
                        except ImportError:
                            with open(i.file, "r") as f:
                                content = f.read()
                            return JSONResponse(
                                json.loads(content),
                                media_type="application/json; charset=utf-8",
                            )
                    elif i.content:
                        return JSONResponse(
                            i.content,
                            media_type="application/json; charset=utf-8",
                        )
                    else:
                        return JSONResponse(
                            {"error": "No content available"},
                            status_code=404,
                        )

                return get_static_info

            router.add_api_route(
                info.path,
                make_static_info_handler(info),
                methods=["GET"],
                name=f"get_info_{info.path.replace('/', '_')}",
            )

    # Register dynamic @information method endpoints
    for method_name in info_method_names:
        method = getattr(instance, method_name, None)
        if method is None:
            continue

        info_path = getattr(method, "_info_path", None)
        info_mode = getattr(method, "_info_mode", "url")

        if info_mode == "url" and info_path:

            def make_dynamic_info_handler(m: Callable) -> Callable:
                async def get_dynamic_info() -> JSONResponse:
                    """Serve dynamic information content."""
                    if inspect.iscoroutinefunction(m):
                        result = await m()
                    else:
                        result = m()
                    return JSONResponse(
                        result,
                        media_type="application/json; charset=utf-8",
                    )

                return get_dynamic_info

            router.add_api_route(
                info_path,
                make_dynamic_info_handler(method),
                methods=["GET"],
                name=f"get_info_{method_name}",
            )


def _register_rpc_route(
    router: APIRouter,
    handlers: dict[str, Callable],
    method_info_map: dict[str, RPCMethodInfo],
) -> None:
    """Register POST /rpc JSON-RPC 2.0 endpoint.

    Args:
        router: FastAPI router to register route on
        handlers: Method name to handler function mapping
        method_info_map: Method name to RPCMethodInfo mapping
    """
    if not handlers:
        return

    @router.post("/rpc", response_model=None)
    async def rpc_endpoint(request: Request) -> JSONResponse:
        """Handle JSON-RPC 2.0 requests with standard JSON response.

        Supports both single and batch requests per JSON-RPC 2.0 specification.
        """
        try:
            body = await request.json()
        except Exception:
            return JSONResponse(
                create_rpc_error(
                    RPCErrorCodes.PARSE_ERROR,
                    "Parse error: Invalid JSON",
                    None,
                )
            )

        if isinstance(body, list):
            if not body:
                return JSONResponse(
                    create_rpc_error(
                        RPCErrorCodes.INVALID_REQUEST,
                        "Invalid Request: Empty batch",
                        None,
                    )
                )
            responses = await process_batch_rpc_request(
                body, handlers, request=request, method_info_map=method_info_map
            )
            return JSONResponse(responses)
        else:
            response = await process_single_rpc_request(
                body, handlers, request, method_info_map
            )
            return JSONResponse(response)


# =============================================================================
# Route Generator
# =============================================================================


def create_agent_router(
    config: AgentConfig,
    methods: list[RPCMethodInfo],
    instance: Any = None,
) -> APIRouter:
    """Create a complete ANP agent router.

    Generates a FastAPI router with the following endpoints:
    - GET /prefix/ad.json - Agent description
    - GET /prefix/interface.json - RPC interface (OpenRPC, content mode methods)
    - GET /prefix/interface/{method}.json - Individual method interface (link mode)
    - GET /prefix/{info_path} - Information endpoints (URL mode)
    - POST /prefix/rpc - JSON-RPC 2.0 endpoint (single and batch)

    Context Injection:
    - Methods with ctx: Context parameter get Context automatically injected
    - Context contains session (based on DID), did, request, and auth_result

    Note:
        OpenANP focuses on ANP protocol, not infrastructure.
        For caching, use cachetools/redis.
        For retry, use tenacity.
        For logging, use loguru/structlog.

    Args:
        config: Agent configuration
        methods: RPC method list
        instance: Optional agent instance for lifecycle management

    Returns:
        FastAPI APIRouter
    """
    router = APIRouter(
        prefix=config.prefix or "",
        tags=config.tags or ["ANP"],
    )

    # Build handler and method info maps
    handlers: dict[str, Callable] = {}
    method_info_map: dict[str, RPCMethodInfo] = {}
    for method_info in methods:
        if method_info.handler:
            handlers[method_info.name] = method_info.handler
            method_info_map[method_info.name] = method_info

    # Separate content and link mode methods
    content_methods = [m for m in methods if m.mode == "content"]
    link_methods = [m for m in methods if m.mode == "link"]

    # Register all routes
    _register_ad_route(router, config, instance, methods)
    _register_interface_routes(router, config, content_methods, link_methods)
    _register_information_routes(router, instance)
    _register_rpc_route(router, handlers, method_info_map)

    return router
