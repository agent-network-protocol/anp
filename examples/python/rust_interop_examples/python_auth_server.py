"""Minimal Python authentication server for Rust interoperability tests.

Usage:
    uv run python examples/python/rust_interop_examples/python_auth_server.py \
        --did-json /path/to/did.json --port 18080 --jwt-secret test-secret
"""

from __future__ import annotations

import argparse
import asyncio
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from anp.authentication import DidWbaVerifier, DidWbaVerifierConfig
from anp.authentication.did_wba_verifier import DidWbaVerifierError
import anp.authentication.did_wba_verifier as verifier_module


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a local Python auth server.")
    parser.add_argument("--did-json", required=True, help="Path to the DID document JSON file.")
    parser.add_argument("--port", type=int, required=True, help="Port to listen on.")
    parser.add_argument(
        "--jwt-secret",
        default="test-secret",
        help="Shared HS256 secret used for issuing Bearer tokens.",
    )
    return parser.parse_args()


def _did_document_path(did_document: dict) -> str:
    did = did_document.get("id", "")
    parts = did.split(":")
    if len(parts) <= 3:
        return "/.well-known/did.json"
    return "/" + "/".join(parts[3:]) + "/did.json"


def main() -> None:
    args = parse_args()
    did_document = json.loads(Path(args.did_json).read_text(encoding="utf-8"))

    async def _resolve_local_did(did: str):
        if did == did_document.get("id"):
            return did_document
        return None

    verifier_module.resolve_did_wba_document = _resolve_local_did
    verifier = DidWbaVerifier(
        DidWbaVerifierConfig(
            jwt_private_key=args.jwt_secret,
            jwt_public_key=args.jwt_secret,
            jwt_algorithm="HS256",
        )
    )
    did_path = _did_document_path(did_document)

    class _Handler(BaseHTTPRequestHandler):
        server_version = "PythonInteropAuthServer/1.0"

        def log_message(self, format: str, *args) -> None:  # noqa: A003
            return

        def do_GET(self) -> None:  # noqa: N802
            self._handle_request()

        def do_POST(self) -> None:  # noqa: N802
            self._handle_request()

        def _handle_request(self) -> None:
            if self.path == "/health":
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"ok")
                return

            if self.path == did_path:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(did_document).encode("utf-8"))
                return

            content_length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(content_length) if content_length else b""
            full_url = f"http://{self.headers['Host']}{self.path}"
            try:
                result = asyncio.run(
                    verifier.verify_request(
                        method=self.command,
                        url=full_url,
                        headers=dict(self.headers.items()),
                        body=body,
                        domain=self.headers["Host"].split(":", 1)[0],
                    )
                )
                self.send_response(200)
                for header_name, header_value in result.get("response_headers", {}).items():
                    self.send_header(header_name, header_value)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(
                    json.dumps(
                        {
                            "did": result["did"],
                            "auth_scheme": result["auth_scheme"],
                        }
                    ).encode("utf-8")
                )
            except DidWbaVerifierError as exc:
                self.send_response(exc.status_code)
                for header_name, header_value in exc.headers.items():
                    self.send_header(header_name, header_value)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"detail": str(exc)}).encode("utf-8"))

    httpd = ThreadingHTTPServer(("127.0.0.1", args.port), _Handler)
    print(f"READY http://127.0.0.1:{args.port}/auth", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
