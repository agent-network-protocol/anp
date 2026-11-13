"""Bounded, public HTTPS transport shared by WBA resolvers and discovery.

DNS is validated by the actual aiohttp connector. Literal IPs are checked before
the connector, since aiohttp does not invoke a resolver for numeric addresses.
"""

from __future__ import annotations

import ipaddress
import json
import math
import threading
from contextlib import asynccontextmanager, contextmanager
from typing import Any, Mapping
from urllib.parse import urlsplit

import aiohttp

from .did_web import MAX_DID_DOCUMENT_BYTES, _PublicResolver, _is_public_address
from .http_auth_security import authentication_origin


_OUTBOUND_REQUESTS = threading.BoundedSemaphore(32)


@contextmanager
def outbound_request_budget():
    """Bound in-flight SDK document/discovery work across threads and loops.

    Reject overload rather than growing a waiting queue. This is not an
    application ingress rate limiter or a distributed concurrency guarantee.
    """
    if not _OUTBOUND_REQUESTS.acquire(blocking=False):
        raise ValueError("ANP outbound concurrency budget exhausted")
    try:
        yield
    finally:
        _OUTBOUND_REQUESTS.release()


def validate_public_url(url: str) -> None:
    """Validate the URL before any DNS, connection, or credential generation."""
    authentication_origin(url)
    parsed = urlsplit(url)
    if parsed.scheme != "https":
        raise ValueError("Public ANP requests require HTTPS")
    host = parsed.hostname
    if (
        host is None
        or "%" in host
        or host.endswith(".")
        and host[:-1].lower() == "localhost"
    ):
        raise ValueError("Invalid public host")
    if host.lower() == "localhost" or host.lower().endswith(".localhost"):
        raise ValueError("Non-public ANP destination")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return  # The connector checks the actual DNS result.
    if not _is_public_address(host):
        raise ValueError("Non-public ANP destination")


@asynccontextmanager
async def public_client_session(timeout: aiohttp.ClientTimeout):
    """Bind actual connection DNS to the public resolver, without ambient proxy."""
    with outbound_request_budget():
        resolver = _PublicResolver()
        connector = aiohttp.TCPConnector(resolver=resolver)
        try:
            async with aiohttp.ClientSession(
                connector=connector, timeout=timeout, trust_env=False
            ) as session:
                yield session
        finally:
            await resolver.close()


async def read_bounded_response(
    response: Any, limit: int = MAX_DID_DOCUMENT_BYTES
) -> bytes:
    """Bound the decoded body, not just the peer-provided Content-Length."""
    if response.content_length and response.content_length > limit:
        raise ValueError("ANP response exceeds size limit")
    data = bytearray()
    async for chunk in response.content.iter_chunked(65536):
        data.extend(chunk)
        if len(data) > limit:
            raise ValueError("ANP response exceeds size limit")
    return bytes(data)


async def fetch_public_json(
    url: str,
    *,
    timeout_seconds: float = 10,
    headers: Mapping[str, str] | None = None,
    verify_ssl: bool = True,
    trusted_override: bool = False,
) -> dict[str, Any]:
    """Fetch without redirects, ambient proxies, or unbounded decoded bodies.

    trusted_override is only for explicitly configured host-controlled transport,
    never a switch obtained from an incoming document or request.
    """
    authentication_origin(url)
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise ValueError("Invalid request timeout")
    if not trusted_override:
        validate_public_url(url)
        if not verify_ssl:
            raise ValueError("Public ANP requests require TLS verification")
    with outbound_request_budget():
        resolver = None if trusted_override else _PublicResolver()
        connector = aiohttp.TCPConnector(resolver=resolver)
        try:
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=timeout_seconds),
                trust_env=False,
            ) as session:
                async with session.get(
                    url,
                    headers=dict(headers or {"Accept": "application/json"}),
                    ssl=verify_ssl,
                    allow_redirects=False,
                ) as response:
                    if response.status != 200:
                        raise ValueError("ANP document resolution requires HTTP 200")
                    document = json.loads(await read_bounded_response(response))
                    if not isinstance(document, dict):
                        raise ValueError("ANP document must be an object")
                    return document
        finally:
            if resolver is not None:
                await resolver.close()
