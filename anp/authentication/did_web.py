"""DID Web resource addressing and bounded, public HTTPS resolution."""

from __future__ import annotations

import ipaddress
import json
import math
import re
import socket
from typing import Any, Dict, Optional
from urllib.parse import quote, unquote, urlsplit

import aiohttp

MAX_DID_DOCUMENT_BYTES = 1024 * 1024
_ENCODED_SEGMENT = re.compile(r"(?:[A-Za-z0-9._~-]|%[0-9A-Fa-f]{2})+")
_HOST_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")


def _decode_segment(segment: str) -> str:
    if not _ENCODED_SEGMENT.fullmatch(segment):
        raise ValueError("Invalid DID Web encoded component")
    return unquote(segment, errors="strict")


def build_did_web_resolution_url(did: str) -> str:
    """Return a canonical HTTPS resource URL, rejecting ambiguous DID paths."""
    parts = did.split(":")
    if len(parts) < 3 or parts[:2] != ["did", "web"]:
        raise ValueError("Invalid DID Web")
    authority = _decode_segment(parts[2])
    host_port = authority.split(":")
    host = host_port[0]
    labels = host.split(".")
    if (
        len(host_port) > 2
        or len(host) > 253
        or len(labels) < 2
        or not any(c.isalpha() for c in labels[-1])
        or any(not _HOST_LABEL.fullmatch(label) for label in labels)
    ):
        raise ValueError("DID Web requires a DNS hostname")
    if len(host_port) == 2:
        port = host_port[1]
        if not port.isascii() or not port.isdecimal() or not 1 <= int(port) <= 65535:
            raise ValueError("Invalid DID Web port")
        authority = f"{host.lower()}:{int(port)}"
    else:
        authority = host.lower()
    segments = []
    for raw in parts[3:]:
        segment = _decode_segment(raw)
        if segment in {".", ".."} or any(
            c in "/\\?#%" or ord(c) < 32 or ord(c) == 127 for c in segment
        ):
            raise ValueError("Unsafe DID Web path component")
        segments.append(quote(segment, safe="-._~"))
    path = "/".join(segments) + "/did.json" if segments else ".well-known/did.json"
    return f"https://{authority}/{path}"


class _PublicResolver(aiohttp.abc.AbstractResolver):
    """Validate the actual connector DNS result; do not resolve twice."""

    def __init__(self) -> None:
        self._resolver = aiohttp.resolver.DefaultResolver()

    async def resolve(self, host: str, port: int = 0, family: int = socket.AF_INET):
        addresses = await self._resolver.resolve(host, port, family)
        if not addresses or any(
            not _is_public_address(address["host"]) for address in addresses
        ):
            raise ValueError("DID Web resolved to a non-public address")
        return addresses

    async def close(self) -> None:
        await self._resolver.close()


def _is_public_address(value: str) -> bool:
    address = ipaddress.ip_address(value)
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped:
            address = address.ipv4_mapped
        elif (
            address not in ipaddress.ip_network("2000::/3")
            or address in ipaddress.ip_network("2001::/23")
            or address in ipaddress.ip_network("2002::/16")
            or address in ipaddress.ip_network("3ff0::/12")
        ):
            return False
    return address.is_global and not address.is_multicast


async def fetch_did_web_document(
    did: str,
    *,
    timeout_seconds: float,
    verify_ssl: bool,
    base_url_override: Optional[str],
    headers: Dict[str, str],
) -> Dict[str, Any]:
    """Fetch within a byte/time budget without redirects or ambient proxies.

    ``base_url_override`` is an explicit trusted host/test transport override,
    never a value taken from a peer DID document. Only that mode permits private
    addresses, HTTP or disabled certificate verification.
    """
    url = build_did_web_resolution_url(did)
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise ValueError("Invalid DID Web resolution timeout")
    if not base_url_override and not verify_ssl:
        raise ValueError("DID Web production resolution requires TLS verification")
    resolver = None if base_url_override else _PublicResolver()
    if base_url_override:
        override = urlsplit(base_url_override)
        if (
            override.scheme not in {"http", "https"}
            or not override.hostname
            or override.username is not None
            or override.password is not None
            or override.query
            or override.fragment
        ):
            raise ValueError("Invalid trusted resolution override")
        url = base_url_override.rstrip("/") + urlsplit(url).path
    connector = aiohttp.TCPConnector(resolver=resolver)
    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=timeout_seconds),
            connector=connector,
            auto_decompress=True,
            trust_env=False,
        ) as session:
            async with session.get(
                url,
                headers=headers,
                ssl=verify_ssl,
                allow_redirects=False,
            ) as response:
                if response.status != 200:
                    raise ValueError("DID Web resolution requires HTTP 200")
                if (
                    response.content_length
                    and response.content_length > MAX_DID_DOCUMENT_BYTES
                ):
                    raise ValueError("DID document exceeds resolution size limit")
                data = bytearray()
                async for chunk in response.content.iter_chunked(65536):
                    data.extend(chunk)
                    if len(data) > MAX_DID_DOCUMENT_BYTES:
                        raise ValueError("DID document exceeds resolution size limit")
                document = json.loads(data)
                if not isinstance(document, dict) or document.get("id") != did:
                    raise ValueError("DID document ID mismatch")
                return document
    finally:
        if resolver is not None:
            await resolver.close()
