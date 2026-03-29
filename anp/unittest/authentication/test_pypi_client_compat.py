"""Integration tests for the current PyPI anp client against the local server implementation."""

from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
import tempfile
import textwrap
import threading
import unittest
import urllib.request
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import AsyncMock, patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from anp.authentication import DidWbaVerifier, DidWbaVerifierConfig, create_did_wba_document
from anp.authentication.did_wba_verifier import DidWbaVerifierError


def _current_pypi_anp_version() -> str:
    """Return the latest version currently published on PyPI for anp."""
    with urllib.request.urlopen("https://pypi.org/pypi/anp/json", timeout=20) as response:
        payload = json.load(response)
    return payload["info"]["version"]


def _generate_rsa_pem_pair() -> tuple[str, str]:
    """Generate a JWT RSA key pair for the test server."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_pem, public_pem


@contextmanager
def _run_test_server(verifier: DidWbaVerifier):
    """Run a lightweight HTTP server backed by the local verifier."""

    class _Handler(BaseHTTPRequestHandler):
        server_version = "ANPCompatTestServer/1.0"

        def log_message(self, format: str, *args) -> None:  # noqa: A003
            return

        def do_GET(self) -> None:  # noqa: N802
            content_length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(content_length) if content_length else b""
            full_url = f"http://{self.headers['Host']}{self.path}"
            try:
                result = asyncio.run(
                    self.verifier.verify_request(
                        method="GET",
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

    _Handler.verifier = verifier
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = httpd.server_address
        yield f"http://{host}:{port}/auth"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


class TestCurrentPyPIClientCompatibility(unittest.TestCase):
    """Verify that the current PyPI client can authenticate against the new server."""

    def test_current_pypi_client_can_use_signature_and_access_token(self):
        """The latest PyPI anp client should complete signature auth and Bearer token reuse."""
        if shutil.which("uv") is None:
            self.skipTest("uv is required for PyPI compatibility tests")

        pypi_version = _current_pypi_anp_version()
        did_document, keys = create_did_wba_document(
            "example.com",
            path_segments=["user", "alice"],
            did_profile="k1",
        )
        jwt_private_key, jwt_public_key = _generate_rsa_pem_pair()
        verifier = DidWbaVerifier(
            DidWbaVerifierConfig(
                jwt_private_key=jwt_private_key,
                jwt_public_key=jwt_public_key,
            )
        )

        async def _resolve_local_did(did: str):
            if did == did_document["id"]:
                return did_document
            return None

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            did_document_path = temp_path / "did.json"
            private_key_path = temp_path / "key-1.pem"
            client_script_path = temp_path / "client.py"

            did_document_path.write_text(json.dumps(did_document), encoding="utf-8")
            private_key_path.write_bytes(keys["key-1"][0])
            client_script_path.write_text(
                textwrap.dedent(
                    """
                    import json
                    import sys
                    import urllib.request
                    from anp.authentication import DIDWbaAuthHeader

                    url = sys.argv[1]
                    did_document_path = sys.argv[2]
                    private_key_path = sys.argv[3]

                    auth = DIDWbaAuthHeader(did_document_path, private_key_path)
                    first_headers = auth.get_auth_header(url, force_new=True)
                    first_request = urllib.request.Request(url, headers=first_headers, method="GET")
                    with urllib.request.urlopen(first_request, timeout=20) as response:
                        first_status = response.status
                        first_response_headers = dict(response.headers.items())
                        first_body = json.loads(response.read().decode("utf-8"))

                    token = auth.update_token(url, first_response_headers)
                    second_headers = auth.get_auth_header(url)
                    second_request = urllib.request.Request(url, headers=second_headers, method="GET")
                    with urllib.request.urlopen(second_request, timeout=20) as response:
                        second_status = response.status
                        second_body = json.loads(response.read().decode("utf-8"))

                    print(json.dumps({
                        "first_status": first_status,
                        "second_status": second_status,
                        "first_auth_header": first_headers.get("Authorization", ""),
                        "first_has_signature_input": "Signature-Input" in first_headers,
                        "first_has_signature": "Signature" in first_headers,
                        "second_auth_header": second_headers.get("Authorization", ""),
                        "token": token,
                        "first_body": first_body,
                        "second_body": second_body,
                    }))
                    """
                ),
                encoding="utf-8",
            )

            with patch(
                "anp.authentication.did_wba_verifier.resolve_did_wba_document",
                AsyncMock(side_effect=_resolve_local_did),
            ):
                with _run_test_server(verifier) as server_url:
                    result = subprocess.run(
                        [
                            "uv",
                            "run",
                            "--with",
                            f"anp=={pypi_version}",
                            "python",
                            str(client_script_path),
                            server_url,
                            str(did_document_path),
                            str(private_key_path),
                        ],
                        cwd=temp_dir,
                        capture_output=True,
                        text=True,
                        check=True,
                    )

        payload = json.loads(result.stdout.strip())
        self.assertEqual(payload["first_status"], 200)
        self.assertEqual(payload["second_status"], 200)
        self.assertTrue(
            payload["first_auth_header"].startswith("DIDWba")
            or (
                payload["first_has_signature_input"]
                and payload["first_has_signature"]
            )
        )
        self.assertTrue(payload["second_auth_header"].startswith("Bearer "))
        self.assertTrue(payload["token"])
        self.assertIn(
            payload["first_body"]["auth_scheme"],
            {"legacy_didwba", "http_signatures"},
        )
        self.assertEqual(payload["second_body"]["auth_scheme"], "bearer")


if __name__ == "__main__":
    unittest.main()
