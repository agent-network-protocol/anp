"""Verify a Rust-generated authentication fixture with the Python SDK.

Usage:
    uv run python examples/python/rust_interop_examples/verify_rust_fixture.py
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from anp.authentication import verify_auth_header_signature, verify_http_message_signature


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _rust_root() -> Path:
    return _repo_root() / "rust"


def _run_fixture(*args: str) -> dict:
    cargo = "cargo"
    result = subprocess.run(
        [cargo, "run", "--quiet", "--example", "interop_cli", "--", *args],
        cwd=_rust_root(),
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(result.stdout)


def main() -> None:
    http_fixture = _run_fixture(
        "auth-fixture",
        "--profile",
        "e1",
        "--scheme",
        "http",
        "--url",
        "https://api.example.com/orders",
        "--method",
        "POST",
        "--body",
        '{"item":"book"}',
    )
    is_valid, message, metadata = verify_http_message_signature(
        did_document=http_fixture["did_document"],
        request_method=http_fixture["request_method"],
        request_url=http_fixture["request_url"],
        headers=http_fixture["headers"],
        body=http_fixture["body"].encode("utf-8"),
    )
    print(f"Rust HTTP signature verified in Python: {is_valid} ({message})")
    print(f"Verification metadata: {metadata}")

    legacy_fixture = _run_fixture(
        "auth-fixture",
        "--profile",
        "k1",
        "--scheme",
        "legacy",
        "--service-domain",
        "api.example.com",
    )
    is_valid, message = verify_auth_header_signature(
        legacy_fixture["headers"]["Authorization"],
        legacy_fixture["did_document"],
        legacy_fixture["service_domain"],
    )
    print(f"Rust legacy auth header verified in Python: {is_valid} ({message})")


if __name__ == "__main__":
    main()
