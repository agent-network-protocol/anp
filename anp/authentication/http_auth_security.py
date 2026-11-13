"""Stateless HTTP auth policy and injectable, atomic replay consumption.

No network or database is accessed by this module. A MemoryReplayStore is only
process-local; clustered servers must inject a shared atomic store.
"""

from __future__ import annotations

import hashlib
import inspect
import ipaddress
import math
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit


@dataclass(frozen=True)
class HttpSignaturePolicy:
    """Real-time validation policy; crypto-only mode must be explicitly chosen."""

    max_age_seconds: int = 300
    future_skew_seconds: int = 60
    check_time: bool = True

    def __post_init__(self) -> None:
        for value in (self.max_age_seconds, self.future_skew_seconds):
            if type(value) is not int or value < 0 or value > 86400:
                raise ValueError("Invalid HTTP signature time policy")
        if self.max_age_seconds == 0 or type(self.check_time) is not bool:
            raise ValueError("Invalid HTTP signature time policy")

    def validate(self, created: int, expires: int | None, now: float) -> int:
        """Return the last acceptable timestamp; reject malformed time values."""
        if type(created) is not int or not 0 <= created <= 999999999999999:
            raise ValueError("Invalid created parameter")
        if expires is not None and (
            type(expires) is not int or not created <= expires <= 999999999999999
        ):
            raise ValueError("Invalid expires parameter")
        if not math.isfinite(now):
            raise ValueError("Invalid verification clock")
        deadline = (
            min(created + self.max_age_seconds, expires)
            if expires is not None
            else created + self.max_age_seconds
        )
        if self.check_time and (
            created > now + self.future_skew_seconds or now > deadline
        ):
            raise ValueError("HTTP signature timestamp is expired or invalid")
        return deadline


def authentication_origin(url: str) -> str:
    """Return an unambiguous HTTP origin, including its effective port."""
    parsed = urlsplit(url)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or "#" in url or "\\" in url
        or any(ord(c) < 33 or ord(c) == 127 for c in url)
    ):
        raise ValueError("Invalid authentication URL")
    host = parsed.hostname.encode("idna").decode("ascii").lower()
    if "%" in host:
        raise ValueError("Invalid authentication host")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if all(char in "0123456789." for char in host):
            raise ValueError("Non-canonical numeric authentication host")
    else:
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            raise ValueError("Mapped IPv6 authentication origins are not supported")
        host = address.compressed
    if ":" in host:
        host = f"[{host}]"
    port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
    if not 1 <= port <= 65535:
        raise ValueError("Invalid authentication port")
    return f"{parsed.scheme}://{host}:{port}"


def normalize_http_headers(raw_headers: list[tuple[bytes, bytes]]) -> dict[str, str]:
    """Preserve signed field semantics and reject ambiguous ASGI auth framing."""
    if len(raw_headers) > 256:
        raise ValueError("Excessive HTTP header count")
    headers: dict[str, str] = {}
    sensitive = {"host", "authorization", "signature-input", "signature", "content-digest", "content-length", "transfer-encoding"}
    for raw_name, raw_value in raw_headers:
        name, value = raw_name.decode("ascii").lower(), raw_value.decode("latin-1")
        if len(name) > 256 or len(value) > 16384 or any(ord(char) < 32 or ord(char) == 127 for char in name + value):
            raise ValueError("Invalid HTTP authentication header")
        if name in headers:
            if name in sensitive:
                raise ValueError("Ambiguous HTTP authentication header")
            headers[name] += ", " + value
        else:
            headers[name] = value
    return headers


def trusted_request_headers(
    request_url: str, raw_headers: list[tuple[bytes, bytes]], allowed_origins: list[str] | None,
) -> tuple[str, dict[str, str]]:
    """Validate an ASGI receiver binding before collapsing repeated HTTP fields.

    Host/Forwarded are inputs, never receiver authorization. Bare configured
    authorities mean HTTPS; an explicit HTTP origin is a trusted test override.
    """
    headers = normalize_http_headers(raw_headers)
    allowed = {authentication_origin(value if "://" in value else "https://" + value) for value in (allowed_origins or [])}
    origin = authentication_origin(request_url)
    if origin not in allowed:
        raise PermissionError("Authentication receiver origin is not configured or approved")
    # Legacy audience stays hostname-only; HTTP signatures bind the exact URL.
    return urlsplit(request_url).hostname, headers


@dataclass(frozen=True)
class ReplayContext:
    """Verified replay facts passed to a shared store, without credentials."""

    signer_did: str
    verifier_scope: str
    replay_key: str
    valid_until: int


def http_replay_context(
    metadata: Mapping[str, Any], url: str, *, scope: str | None = None
) -> ReplayContext:
    """Derive a domain-separated key from verified facts, not signature bytes."""
    keyid = metadata["keyid"]
    signer = keyid.split("#", 1)[0]
    nonce = metadata.get("nonce")
    material = (
        "nonce:" + nonce
        if nonce is not None
        else "base:" + metadata["signature_base_digest"]
    )
    verifier_scope = scope or authentication_origin(url)
    value = "\x00".join(("anp.http-auth.replay.v1", verifier_scope, signer, material))
    # Include the maximum permitted inter-node clock difference in storage TTL.
    return ReplayContext(
        signer,
        verifier_scope,
        hashlib.sha256(value.encode()).hexdigest(),
        metadata["valid_until"] + metadata.get("clock_skew_seconds", 60),
    )


class MemoryReplayStore:
    """Bounded, thread-safe single-process store. Never evict unexpired keys."""

    def __init__(
        self, *, capacity: int = 10000, clock: Callable[[], float] = time.time
    ):
        if capacity <= 0:
            raise ValueError("Replay store capacity must be positive")
        self._capacity = capacity
        self._clock = clock
        self._seen: dict[str, int] = {}
        self._lock = threading.Lock()

    def consume_once(self, context: ReplayContext) -> bool:
        # Retain through the inter-node clock-skew margin. At the exact deadline
        # a signature is still acceptable, so cleanup must use a strict bound.
        with self._lock:
            now = self._clock()
            self._seen = {
                key: expiry for key, expiry in self._seen.items() if expiry >= now
            }
            if context.valid_until < now or context.replay_key in self._seen:
                return False
            if len(self._seen) >= self._capacity:
                raise RuntimeError("Replay store capacity exhausted")
            self._seen[context.replay_key] = context.valid_until
            return True


async def consume_http_replay(store: Any, context: ReplayContext) -> bool:
    """Consume once using a sync/async store or callback; errors propagate closed."""
    callback = store if callable(store) else store.consume_once
    result = callback(context)
    if inspect.isawaitable(result):
        result = await result
    if type(result) is not bool:
        raise ValueError("Replay store must return a boolean")
    return result
