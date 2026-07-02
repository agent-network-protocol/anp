"""Python client for the TypeScript DID-WBA HTTP server example.

Run the TypeScript server first:

    cd typescript/ts_sdk
    npm run build
    node examples/did-wba-http-server.mjs

Then run this client from the repository root:

    uv run python typescript/ts_sdk/examples/python_to_ts_did_wba_client.py
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, Tuple
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from anp.authentication import DIDWbaAuthHeader
from anp.authentication.http_signatures import verify_http_message_signature

HOST = os.environ.get("ANP_TS_DEMO_HOST", "127.0.0.1")
PORT = int(os.environ.get("ANP_TS_DEMO_PORT", "8090"))
SERVER_URL = f"http://{HOST}:{PORT}"


def project_root() -> Path:
    return Path(__file__).resolve().parents[3]


def request_json(url: str, headers: Dict[str, str] | None = None) -> Tuple[int, Dict[str, str], str, Dict]:
    request = Request(url, headers=headers or {}, method="GET")
    try:
        with urlopen(request, timeout=30) as response:
            body_text = response.read().decode("utf-8")
            body = json.loads(body_text)
            return response.status, dict(response.headers.items()), body_text, body
    except HTTPError as exc:
        body_text = exc.read().decode("utf-8")
        body = json.loads(body_text)
        return exc.code, dict(exc.headers.items()), body_text, body


def require_success(status: int, body: Dict) -> None:
    if status < 200 or status >= 300:
        raise RuntimeError(f"Request failed with {status}: {body}")


def verify_server_response(
    server_did_document: Dict,
    url: str,
    headers: Dict[str, str],
    body_text: str,
) -> None:
    server_did = next(
        (value for key, value in headers.items() if key.lower() == "anp-server-did"),
        None,
    )
    if server_did != server_did_document["id"]:
        raise RuntimeError(f"Unexpected server DID: {server_did}")

    is_valid, message, _ = verify_http_message_signature(
        did_document=server_did_document,
        request_method="RESPONSE",
        request_url=url,
        headers=headers,
        body=body_text,
    )
    if not is_valid:
        raise RuntimeError(f"Server response signature verification failed: {message}")
    print(f"Verified server DID response signature for: {server_did}")


def main() -> None:
    root = project_root()
    authenticator = DIDWbaAuthHeader(
        did_document_path=str(root / "docs/did_public/public-did-doc.json"),
        private_key_path=str(root / "docs/did_public/public-private-key.pem"),
    )

    protected_url = f"{SERVER_URL}/api/protected"
    user_info_url = f"{SERVER_URL}/api/user-info"

    print("Step 1: health check")
    status, _, _, body = request_json(f"{SERVER_URL}/health")
    require_success(status, body)
    print({"status": status, "body": body})
    server_did_document = request_json(f"{SERVER_URL}/.well-known/did.json")[3]

    print("\nStep 2: Python client authenticates to TS server with DID-WBA")
    headers = authenticator.get_auth_header(protected_url, force_new=True, method="GET")
    status, response_headers, body_text, body = request_json(protected_url, headers)
    if status == 401 and authenticator.should_retry_after_401(response_headers):
        headers = authenticator.get_challenge_auth_header(
            protected_url,
            response_headers,
            method="GET",
        )
        status, response_headers, body_text, body = request_json(protected_url, headers)
    require_success(status, body)
    verify_server_response(server_did_document, protected_url, response_headers, body_text)
    print({"status": status, "body": body})

    token = authenticator.update_token(protected_url, response_headers)
    if not token:
        raise RuntimeError("TS server did not return a Bearer token")
    print(f"Received Bearer token prefix: {token[:32]}...")

    print("\nStep 3: Python client reuses cached Bearer token")
    headers = authenticator.get_auth_header(user_info_url)
    status, response_headers, body_text, body = request_json(user_info_url, headers)
    require_success(status, body)
    verify_server_response(server_did_document, user_info_url, response_headers, body_text)
    print({"status": status, "body": body})

    print("\nPython client -> TS server mutual DID-WBA authentication completed.")


if __name__ == "__main__":
    main()
