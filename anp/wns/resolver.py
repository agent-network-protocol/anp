"""Handle resolution client — async + sync wrappers.

Resolves a Handle to its HandleResolutionDocument by querying the
Handle Resolution Endpoint defined in WNS spec section 4.2.
"""

import asyncio
import logging
from typing import Optional

import aiohttp

from .exceptions import (
    HandleGoneError,
    HandleMovedError,
    HandleNotFoundError,
    HandleResolutionError,
    HandleValidationError,
)
from .models import HandleResolutionDocument
from .validator import build_resolution_url, normalize_handle, parse_wba_uri, validate_handle


def _strip_wba_scheme(handle_or_uri: str) -> str:
    """Strip ``wba://`` prefix if present, returning a bare handle."""
    if handle_or_uri.startswith("wba://"):
        return handle_or_uri[len("wba://"):]
    return handle_or_uri


async def resolve_handle(
    handle: str,
    *,
    timeout_seconds: float = 10,
    verify_ssl: bool = True,
) -> HandleResolutionDocument:
    """Resolve *handle* to a :class:`HandleResolutionDocument`.

    Accepts both bare handles (``alice.example.com``) and ``wba://`` URIs
    (``wba://alice.example.com``).

    Args:
        handle: A handle string or wba:// URI.
        timeout_seconds: HTTP request timeout.
        verify_ssl: Whether to verify the server TLS certificate.

    Returns:
        The parsed resolution document.

    Raises:
        HandleValidationError: If the handle format is invalid.
        HandleNotFoundError: If the handle does not exist (HTTP 404).
        HandleGoneError: If the handle has been revoked (HTTP 410).
        HandleMovedError: If the handle has migrated (HTTP 301).
        HandleResolutionError: On network / protocol errors.
    """
    local_part, domain = validate_handle(_strip_wba_scheme(handle))
    url = build_resolution_url(local_part, domain)
    normalized = f"{local_part}.{domain}"

    logging.info("Resolving handle '%s' via %s", normalized, url)

    try:
        timeout = aiohttp.ClientTimeout(total=timeout_seconds)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(
                url,
                headers={"Accept": "application/json"},
                ssl=verify_ssl,
                allow_redirects=False,
            ) as response:
                if response.status == 301:
                    redirect_url = response.headers.get("Location", "")
                    raise HandleMovedError(
                        f"Handle '{normalized}' has been migrated",
                        redirect_url=redirect_url,
                    )
                if response.status == 404:
                    raise HandleNotFoundError(
                        f"Handle '{normalized}' does not exist"
                    )
                if response.status == 410:
                    raise HandleGoneError(
                        f"Handle '{normalized}' has been permanently revoked"
                    )
                if response.status != 200:
                    text = await response.text()
                    raise HandleResolutionError(
                        f"Unexpected status {response.status} resolving "
                        f"'{normalized}': {text}"
                    )

                data = await response.json()

    except (HandleMovedError, HandleNotFoundError, HandleGoneError, HandleResolutionError):
        raise
    except aiohttp.ClientError as exc:
        raise HandleResolutionError(
            f"Network error resolving handle '{normalized}': {exc}"
        ) from exc
    except Exception as exc:
        raise HandleResolutionError(
            f"Unexpected error resolving handle '{normalized}': {exc}"
        ) from exc

    doc = HandleResolutionDocument.model_validate(data)

    # Verify that the returned handle matches the requested one.
    if normalize_handle(doc.handle) != normalized:
        raise HandleResolutionError(
            f"Handle mismatch: requested '{normalized}', "
            f"got '{doc.handle}'"
        )

    logging.info("Successfully resolved handle '%s' → %s", normalized, doc.did)
    return doc


def resolve_handle_sync(
    handle: str,
    *,
    timeout_seconds: float = 10,
    verify_ssl: bool = True,
) -> HandleResolutionDocument:
    """Synchronous wrapper around :func:`resolve_handle`."""
    return asyncio.run(
        resolve_handle(
            handle,
            timeout_seconds=timeout_seconds,
            verify_ssl=verify_ssl,
        )
    )


async def resolve_handle_from_uri(
    wba_uri: str,
    *,
    timeout_seconds: float = 10,
    verify_ssl: bool = True,
) -> HandleResolutionDocument:
    """Parse a ``wba://`` URI and resolve the embedded handle."""
    parsed = parse_wba_uri(wba_uri)
    return await resolve_handle(
        parsed.handle,
        timeout_seconds=timeout_seconds,
        verify_ssl=verify_ssl,
    )
