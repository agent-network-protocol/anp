"""OpenANP SDK - 自动生成路由

这个模块提供自动生成 FastAPI 路由的功能。
用户可以选择使用这个模块来自动生成路由，或者自己实现。

设计原则：
- 辅助性：不是必需的，用户可以自己实现
- 透明性：生成的路由是标准的 FastAPI 路由
- 可定制：用户可以自定义部分或全部路由
- JSON-RPC 2.0：完整支持单个和批量请求
- Streamable HTTP：所有 /rpc 响应使用 SSE 格式（对齐 MCP）

传输方式（对齐 MCP Streamable HTTP）：
- 所有 /rpc 响应使用 SSE (Server-Sent Events) 格式
- 单个请求：message event + done event
- 批量请求：多个 message events + done event
- 断点续传：支持 Last-Event-ID 头部

使用方式：
1. 使用 @anp_agent 装饰器自动生成（最简单）
2. 手动调用 create_agent_router() 函数
3. 完全自己实现（最灵活）
"""

from __future__ import annotations

import asyncio
import inspect
import json
from collections.abc import AsyncIterator
from typing import (
    TYPE_CHECKING,
    Annotated,
    Any,
    Callable,
    get_args,
    get_origin,
    get_type_hints,
)

# 导入 Request 和 JSONResponse 以供运行时使用
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, StreamingResponse

from .types import AgentConfig, RPCMethodInfo
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
    pass  # 所有类型已在上方导入

__all__ = [
    "create_agent_router",
    "coerce_params",
    "process_single_rpc_request",
    "process_batch_rpc_request",
]


# =============================================================================
# 参数类型强制转换
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

        # Before: {"criteria": {"city": "杭州"}}
        # After:  {"criteria": HotelSearchCriteria(city="杭州")}
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
# JSON-RPC 2.0 批量请求处理
# =============================================================================


async def process_single_rpc_request(
    body: dict[str, Any],
    handlers: dict[str, Callable],
) -> dict[str, Any]:
    """处理单个 JSON-RPC 2.0 请求。

    Args:
        body: 请求体字典
        handlers: 方法处理器映射

    Returns:
        JSON-RPC 2.0 响应字典
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

        # 调用处理器（绑定方法或未绑定方法）
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
        # 参数类型错误
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
) -> list[dict[str, Any]]:
    """处理批量 JSON-RPC 2.0 请求。

    根据 JSON-RPC 2.0 规范，批量请求中的每个请求应该独立处理。
    通知（没有 id 的请求）不应返回响应。

    Args:
        batch: 请求列表
        handlers: 方法处理器映射
        max_concurrent: 最大并发数，None 表示无限制

    Returns:
        响应列表（不包含通知的响应）

    Example:
        # 批量请求
        [
            {"jsonrpc": "2.0", "method": "search", "params": {...}, "id": 1},
            {"jsonrpc": "2.0", "method": "book", "params": {...}, "id": 2},
            {"jsonrpc": "2.0", "method": "notify", "params": {...}}  # 通知，无 id
        ]

        # 响应（不包含通知）
        [
            {"jsonrpc": "2.0", "result": {...}, "id": 1},
            {"jsonrpc": "2.0", "result": {...}, "id": 2}
        ]
    """
    if not batch:
        return []

    # 创建任务
    tasks = [process_single_rpc_request(req, handlers) for req in batch]

    # 并发执行（可选限制）
    if max_concurrent is not None and max_concurrent > 0:
        # 使用信号量限制并发
        semaphore = asyncio.Semaphore(max_concurrent)

        async def limited_task(task: Any) -> dict[str, Any]:
            async with semaphore:
                return await task

        results = await asyncio.gather(*[limited_task(t) for t in tasks])
    else:
        results = await asyncio.gather(*tasks)

    # 过滤通知响应（通知请求没有 id，不应返回响应）
    responses = []
    for req, resp in zip(batch, results):
        # 如果原始请求有 id（不是通知），则包含响应
        if "id" in req:
            responses.append(resp)

    return responses


# =============================================================================
# Streamable HTTP / SSE 响应处理
# =============================================================================

# SSE Event Types (对齐 MCP Streamable HTTP)
SSE_EVENT_MESSAGE = "message"
SSE_EVENT_ERROR = "error"
SSE_EVENT_DONE = "done"


def _sse_headers() -> dict[str, str]:
    """Return standard SSE response headers."""
    return {
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
        "Connection": "keep-alive",
    }


def _format_sse_event(
    event_type: str,
    data: dict[str, Any],
    event_id: str | None = None,
) -> str:
    """Format a single SSE event.

    Args:
        event_type: Event type (message, error, done)
        data: JSON data payload
        event_id: Optional event ID for reconnection

    Returns:
        SSE formatted string
    """
    lines = []
    if event_id:
        lines.append(f"id: {event_id}")
    lines.append(f"event: {event_type}")
    lines.append(f"data: {json.dumps(data, ensure_ascii=False)}")
    lines.append("")  # Empty line marks end of event
    return "\n".join(lines) + "\n"


async def _stream_rpc_response(
    body: dict[str, Any],
    handlers: dict[str, Callable],
    is_streaming_method: bool = False,
) -> AsyncIterator[str]:
    """Generate Streamable HTTP response wrapping results in SSE events.

    For non-streaming methods: single message event + done event
    For streaming methods: multiple message events + done event

    SSE Event Format (对齐 MCP):
        event: message
        id: <event_id>
        data: {"jsonrpc": "2.0", "result": {...}, "id": 1}

        event: done
        data: {}

    Args:
        body: JSON-RPC request body
        handlers: Method handlers mapping
        is_streaming_method: Whether this is a streaming method

    Yields:
        SSE formatted events with JSON-RPC responses
    """
    import logging

    logger = logging.getLogger(__name__)

    req_id = body.get("id")
    event_counter = 0

    try:
        method_name, params, req_id = validate_rpc_request(body)
        logger.debug(f"[SSE] Method: {method_name}, streaming: {is_streaming_method}")

        if method_name not in handlers:
            error = create_rpc_error(
                RPCErrorCodes.METHOD_NOT_FOUND,
                f"Method not found: {method_name}",
                req_id,
            )
            yield _format_sse_event(SSE_EVENT_ERROR, error)
            return

        handler = handlers[method_name]
        coerced_params = coerce_params(handler, params)

        if is_streaming_method:
            # Streaming method: yield multiple message events
            async for chunk in handler(**coerced_params):
                event_counter += 1
                response = create_rpc_response(chunk, req_id)
                yield _format_sse_event(
                    SSE_EVENT_MESSAGE,
                    response,
                    event_id=f"{req_id}-{event_counter}",
                )
        else:
            # Non-streaming method: single message event
            if inspect.iscoroutinefunction(handler):
                result = await handler(**coerced_params)
            else:
                result = handler(**coerced_params)

            event_counter = 1
            response = create_rpc_response(result, req_id)
            yield _format_sse_event(
                SSE_EVENT_MESSAGE,
                response,
                event_id=f"{req_id}-{event_counter}",
            )

        # Always send done event
        yield _format_sse_event(SSE_EVENT_DONE, {})
        logger.debug(f"[SSE] Completed, events: {event_counter}")

    except ValueError as e:
        logger.error(f"[SSE] ValueError: {e}")
        error = create_rpc_error(RPCErrorCodes.INVALID_REQUEST, str(e), req_id)
        yield _format_sse_event(SSE_EVENT_ERROR, error)
    except TypeError as e:
        logger.error(f"[SSE] TypeError: {e}")
        error = create_rpc_error(RPCErrorCodes.INVALID_PARAMS, str(e), req_id)
        yield _format_sse_event(SSE_EVENT_ERROR, error)
    except Exception as e:
        logger.exception(f"[SSE] Unexpected error: {e}")
        error = create_rpc_error(RPCErrorCodes.INTERNAL_ERROR, str(e), req_id)
        yield _format_sse_event(SSE_EVENT_ERROR, error)


async def _error_sse_response(
    code: int,
    message: str,
    request_id: Any,
) -> AsyncIterator[str]:
    """Generate SSE error response.

    Args:
        code: RPC error code
        message: Error message
        request_id: Request ID

    Yields:
        SSE error event
    """
    error = create_rpc_error(code, message, request_id)
    yield _format_sse_event(SSE_EVENT_ERROR, error)


async def _stream_batch_rpc_response(
    batch: list[dict[str, Any]],
    handlers: dict[str, Callable],
) -> AsyncIterator[str]:
    """Generate SSE stream for batch JSON-RPC requests with concurrent execution.

    All requests in the batch are executed concurrently using asyncio.gather.
    Responses are yielded as they complete (乱序返回，客户端通过 id 匹配).
    Notification requests (no id) are skipped in responses.

    Concurrency Model (对齐 MCP):
    - 所有请求并发执行 (asyncio.gather)
    - 响应按完成顺序返回 (asyncio.as_completed)
    - 客户端通过 request id 匹配结果

    Args:
        batch: List of JSON-RPC request bodies
        handlers: Method handlers mapping

    Yields:
        SSE events for each batch response + done event
    """
    import logging

    logger = logging.getLogger(__name__)

    # Filter out notifications (requests without id)
    requests_with_id = [(i, req) for i, req in enumerate(batch) if "id" in req]

    if not requests_with_id:
        # No requests with id, just send done
        yield _format_sse_event(SSE_EVENT_DONE, {})
        return

    # Create concurrent tasks for all requests
    async def process_with_index(index: int, req: dict) -> tuple[int, dict]:
        response = await process_single_rpc_request(req, handlers)
        return index, response

    tasks = [
        asyncio.create_task(process_with_index(i, req)) for i, req in requests_with_id
    ]

    logger.debug(f"[SSE] Batch: starting {len(tasks)} concurrent tasks")

    # Yield responses as they complete (乱序返回)
    event_counter = 0
    for coro in asyncio.as_completed(tasks):
        index, response = await coro
        event_counter += 1

        # Use original request id for event id
        req_id = requests_with_id[index][1].get("id", f"batch-{index}")

        yield _format_sse_event(
            SSE_EVENT_MESSAGE,
            response,
            event_id=f"{req_id}",
        )

    # Always send done event
    yield _format_sse_event(SSE_EVENT_DONE, {})
    logger.debug(f"[SSE] Batch completed, {event_counter} events (concurrent)")


# =============================================================================
# 路由生成器
# =============================================================================


def create_agent_router(
    config: AgentConfig,
    methods: list[RPCMethodInfo],
    instance: Any = None,
) -> APIRouter:
    """Create a complete ANP agent router.

    Generates a FastAPI router with the following endpoints:
    - GET /prefix/ad.json - Agent description
    - GET /prefix/interface.json - RPC interface (OpenRPC)
    - POST /prefix/rpc - JSON-RPC 2.0 endpoint (single and batch)

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

    handlers: dict[str, Callable] = {}
    for method_info in methods:
        if method_info.handler:
            handlers[method_info.name] = method_info.handler

    # Track streaming methods for SSE response routing
    streaming_methods: set[str] = {m.name for m in methods if m.streaming}

    @router.get("/ad.json")
    async def get_ad(request: Request) -> JSONResponse:
        """Generate and return ad.json document."""
        base_url = resolve_base_url(request)

        interfaces = None
        if methods:
            interfaces = [
                {
                    "type": "StructuredInterface",
                    "protocol": "openrpc",
                    "url": f"{base_url}{config.prefix}/interface.json"
                    if config.prefix
                    else f"{base_url}/interface.json",
                    "description": f"{config.name} JSON-RPC interface",
                }
            ]

        doc = generate_ad_document(config, base_url, interfaces)
        return JSONResponse(doc, media_type="application/json; charset=utf-8")

    if methods:

        @router.get("/interface.json")
        async def get_interface(request: Request) -> JSONResponse:
            """Generate and return interface.json document."""
            base_url = resolve_base_url(request)
            doc = generate_rpc_interface(config, base_url, methods)
            return JSONResponse(doc, media_type="application/json; charset=utf-8")

        @router.post("/rpc", response_model=None)
        async def rpc_endpoint(request: Request):
            """Handle JSON-RPC 2.0 requests with Streamable HTTP (SSE only).

            All responses use Server-Sent Events (SSE) format:
            - Single request: SSE stream with message + done events
            - Batch request: SSE stream with multiple message events + done event

            SSE Event Format:
                event: message
                id: <request_id>-<n>
                data: {"jsonrpc": "2.0", "result": {...}, "id": 1}

                event: done
                data: {}
            """
            try:
                body = await request.json()
            except Exception:
                # Parse error: return SSE error event
                return StreamingResponse(
                    _error_sse_response(
                        RPCErrorCodes.PARSE_ERROR,
                        "Parse error: Invalid JSON",
                        None,
                    ),
                    media_type="text/event-stream",
                    headers=_sse_headers(),
                )

            if isinstance(body, list):
                # Batch request: SSE with multiple message events
                if not body:
                    return StreamingResponse(
                        _error_sse_response(
                            RPCErrorCodes.INVALID_REQUEST,
                            "Invalid Request: Empty batch",
                            None,
                        ),
                        media_type="text/event-stream",
                        headers=_sse_headers(),
                    )

                return StreamingResponse(
                    _stream_batch_rpc_response(body, handlers),
                    media_type="text/event-stream",
                    headers=_sse_headers(),
                )
            else:
                # Single request: SSE stream
                method_name = body.get("method")
                is_streaming = method_name in streaming_methods

                return StreamingResponse(
                    _stream_rpc_response(
                        body, handlers, is_streaming_method=is_streaming
                    ),
                    media_type="text/event-stream",
                    headers=_sse_headers(),
                )

    return router
