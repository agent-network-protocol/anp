# pyright: reportMissingImports=false

"""
HTTP operations for ANP protocol.

Fail Fast: Exceptions thrown immediately on errors.
Pure functions composing DIDWbaAuthHeader + aiohttp.

Transport:
- JSON-RPC 2.0 over standard HTTP (application/json).
- call_rpc_stream() degrades to a single-result async iterator.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import AsyncIterator
from typing import Any, Optional

import aiohttp

from ...authentication import DIDWbaAuthHeader


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


async def fetch(
    url: str,
    auth: DIDWbaAuthHeader,
    *,
    method: str = "GET",
    headers: Optional[dict[str, str]] = None,
    json_body: Optional[dict[str, Any]] = None,
    timeout: int = 30,
) -> str:
    """
    Fetch URL with DID-WBA authentication.

    Fail Fast: Raises HttpError on non-2xx status.

    Returns:
        Response body as string
    """
    req_headers = dict(headers) if headers else {}
    req_headers.update(auth.get_auth_header(url))

    if json_body and "Content-Type" not in req_headers:
        req_headers["Content-Type"] = "application/json"

    async with aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=timeout)
    ) as session:
        kwargs: dict[str, Any] = {"headers": req_headers}
        if json_body:
            kwargs["json"] = json_body

        async with session.request(method, url, **kwargs) as resp:
            text = await resp.text()

            # Retry once on 401
            if resp.status == 401:
                auth.clear_token(url)
                req_headers.update(auth.get_auth_header(url, force_new=True))
                kwargs["headers"] = req_headers
                async with session.request(method, url, **kwargs) as retry:
                    text = await retry.text()
                    if retry.status >= 300:
                        raise HttpError(retry.status, retry.reason or "Error", url)
                    return text

            if resp.status >= 300:
                raise HttpError(resp.status, resp.reason or "Error", url)

            return text


async def call_rpc(
    url: str,
    method: str,
    params: dict[str, Any],
    auth: DIDWbaAuthHeader,
    *,
    request_id: Optional[str] = None,
    timeout: int = 30,
) -> Any:
    """
    Execute JSON-RPC 2.0 call over standard HTTP.

    Args:
        url: RPC endpoint URL
        method: JSON-RPC method name
        params: Method parameters
        auth: DID-WBA authentication
        request_id: Optional request ID
        timeout: Request timeout in seconds

    Returns:
        The result field from JSON-RPC response
    """
    rid = request_id or str(uuid.uuid4())

    req_headers: dict[str, str] = {}
    req_headers.update(auth.get_auth_header(url))
    req_headers["Content-Type"] = "application/json"
    req_headers["Accept"] = "application/json"

    async with aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=timeout)
    ) as session:
        async with session.post(
            url,
            json={"jsonrpc": "2.0", "id": rid, "method": method, "params": params},
            headers=req_headers,
        ) as resp:
            if resp.status >= 300:
                raise HttpError(resp.status, resp.reason or "Error", url)

            data = await resp.json()
            if not isinstance(data, dict):
                raise RpcError(-1, "Invalid JSON-RPC response (expected object)", data)
            if "error" in data:
                err = data.get("error", {})
                if not isinstance(err, dict):
                    raise RpcError(-1, "Invalid JSON-RPC error object", err)
                raise RpcError(
                    int(err.get("code", -1)),
                    str(err.get("message", "Unknown")),
                    err.get("data"),
                )
            if "result" not in data:
                raise RpcError(-1, "Missing result field in JSON-RPC response", data)
            return data["result"]


async def call_rpc_stream(
    url: str,
    method: str,
    params: dict[str, Any],
    auth: DIDWbaAuthHeader,
    *,
    request_id: Optional[str] = None,
    timeout: int = 300,
    last_event_id: Optional[str] = None,
) -> AsyncIterator[dict[str, Any]]:
    """
    Execute an RPC call as an async iterator (non-SSE).

    This function intentionally does NOT use SSE. It yields exactly one chunk:
    the JSON-RPC result.

    Args:
        url: RPC endpoint URL
        method: JSON-RPC method name
        params: Method parameters
        auth: DID-WBA authentication header
        request_id: Optional request ID (auto-generated if not provided)
        timeout: Request timeout in seconds (default 300 for long streams)
        last_event_id: Optional Last-Event-ID for reconnection

    Yields:
        Each chunk's result field from message events

    Raises:
        HttpError: On HTTP errors
        RpcError: On error event in stream
    """
    _ = last_event_id  # kept for API compatibility
    result = await call_rpc(
        url,
        method,
        params,
        auth,
        request_id=request_id,
        timeout=timeout,
    )
    if not isinstance(result, dict):
        raise RpcError(-1, "Invalid streaming result (expected object)", result)
    yield result


async def call_rpc_batch(
    url: str,
    calls: list[tuple[str, dict[str, Any]]],
    auth: DIDWbaAuthHeader,
    *,
    timeout: int = 60,
) -> dict[str, Any]:
    """
    Execute multiple JSON-RPC 2.0 calls concurrently using batch request.

    Sends all calls as a batch, server executes them concurrently,
    responses are matched by id.

    Batch model:
    - Single HTTP request sending a JSON array of JSON-RPC calls.
    - Server returns a JSON array of responses.

    Args:
        url: RPC endpoint URL
        calls: List of (method, params) tuples
        auth: DID-WBA authentication
        timeout: Request timeout in seconds

    Returns:
        Dict mapping request_id -> result

    Example:
        results = await call_rpc_batch(url, [
            ("get_weather", {"city": "Beijing"}),
            ("get_weather", {"city": "Shanghai"}),
        ], auth)
        # results = {"1": {...}, "2": {...}}
    """
    # Build batch request with sequential ids
    batch = [
        {"jsonrpc": "2.0", "id": str(i + 1), "method": method, "params": params}
        for i, (method, params) in enumerate(calls)
    ]

    req_headers: dict[str, str] = {}
    req_headers.update(auth.get_auth_header(url))
    req_headers["Content-Type"] = "application/json"
    req_headers["Accept"] = "application/json"

    results: dict[str, Any] = {}

    async with aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=timeout)
    ) as session:
        async with session.post(
            url,
            json=batch,
            headers=req_headers,
        ) as resp:
            if resp.status >= 300:
                raise HttpError(resp.status, resp.reason or "Error", url)

            payload = await resp.json()
            if not isinstance(payload, list):
                raise RpcError(-1, "Invalid batch response (expected array)", payload)

            for item in payload:
                if not isinstance(item, dict):
                    raise RpcError(
                        -1, "Invalid batch response item (expected object)", item
                    )
                req_id = str(item.get("id", ""))
                if "error" in item:
                    err = item.get("error", {})
                    if not isinstance(err, dict):
                        results[req_id] = RpcError(
                            -1, "Invalid JSON-RPC error object", err
                        )
                    else:
                        results[req_id] = RpcError(
                            int(err.get("code", -1)),
                            str(err.get("message", "Unknown")),
                            err.get("data"),
                        )
                else:
                    results[req_id] = item.get("result")

    return results


async def call_rpc_concurrent(
    url: str,
    calls: list[tuple[str, dict[str, Any]]],
    auth: DIDWbaAuthHeader,
    *,
    timeout: int = 60,
) -> list[Any]:
    """
    Execute multiple JSON-RPC 2.0 calls concurrently (parallel HTTP requests).

    Alternative to call_rpc_batch: sends separate HTTP requests in parallel.
    Useful when server doesn't support batch requests.

    Args:
        url: RPC endpoint URL
        calls: List of (method, params) tuples
        auth: DID-WBA authentication
        timeout: Request timeout in seconds

    Returns:
        List of results in same order as calls
    """
    import asyncio

    async def single_call(method: str, params: dict) -> Any:
        return await call_rpc(url, method, params, auth, timeout=timeout)

    tasks = [single_call(method, params) for method, params in calls]
    return await asyncio.gather(*tasks)
