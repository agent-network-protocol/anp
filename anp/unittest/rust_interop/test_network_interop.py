"""Real network interoperability tests between Python clients and the Rust server."""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import tempfile
import textwrap
import time
import unittest
import urllib.error
import urllib.request
from contextlib import contextmanager
from pathlib import Path

from anp.unittest.rust_interop.constants import RELEASED_PYTHON_ANP_VERSION

from anp.authentication import DIDWbaAuthHeader, create_did_wba_document


def _pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class TestRustNetworkInterop(unittest.TestCase):
    """Exercise complete Python client ↔ Rust server authentication flows."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.repo_root = Path(__file__).resolve().parents[3]
        cls.rust_root = cls.repo_root / "rust"
        cargo_path = shutil.which("cargo") or str(Path.home() / ".cargo" / "bin" / "cargo")
        if not Path(cargo_path).exists():
            raise unittest.SkipTest("cargo is required for Rust network interoperability tests")
        cls.cargo = cargo_path
        if shutil.which("uv") is None:
            raise unittest.SkipTest("uv is required for Rust network interoperability tests")

    @contextmanager
    def _run_rust_server(self, did_json_path: Path, jwt_secret: str = "test-secret"):
        port = _pick_free_port()
        process = subprocess.Popen(
            [
                self.cargo,
                "run",
                "--quiet",
                "--example",
                "interop_server",
                "--",
                "--did-json",
                str(did_json_path),
                "--port",
                str(port),
                "--jwt-secret",
                jwt_secret,
            ],
            cwd=self.rust_root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        server_url = f"http://127.0.0.1:{port}/auth"
        health_url = f"http://127.0.0.1:{port}/health"
        try:
            deadline = time.time() + 30
            while time.time() < deadline:
                if process.poll() is not None:
                    stderr = process.stderr.read() if process.stderr else ""
                    raise RuntimeError(f"Rust server exited early: {stderr}")
                try:
                    with urllib.request.urlopen(health_url, timeout=1) as response:
                        if response.status == 200:
                            break
                except Exception:
                    time.sleep(0.2)
            else:
                raise RuntimeError("Rust server did not become ready in time")
            yield server_url
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    def test_current_python_client_to_rust_server(self):
        """Current Python client should complete signature auth then Bearer reuse against Rust."""
        did_document, keys = create_did_wba_document(
            "example.com",
            path_segments=["user", "python-current"],
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            did_path = temp_path / "did.json"
            key_path = temp_path / "key-1.pem"
            did_path.write_text(json.dumps(did_document), encoding="utf-8")
            key_path.write_bytes(keys["key-1"][0])

            with self._run_rust_server(did_path) as server_url:
                auth = DIDWbaAuthHeader(str(did_path), str(key_path))
                first_headers = auth.get_auth_header(server_url, force_new=True)
                first_request = urllib.request.Request(server_url, headers=first_headers, method="GET")
                with urllib.request.urlopen(first_request, timeout=20) as response:
                    first_status = response.status
                    first_body = json.loads(response.read().decode("utf-8"))
                    first_response_headers = dict(response.headers.items())

                token = auth.update_token(server_url, first_response_headers)
                second_headers = auth.get_auth_header(server_url)
                second_request = urllib.request.Request(server_url, headers=second_headers, method="GET")
                with urllib.request.urlopen(second_request, timeout=20) as response:
                    second_status = response.status
                    second_body = json.loads(response.read().decode("utf-8"))

        self.assertEqual(first_status, 200)
        self.assertEqual(second_status, 200)
        self.assertTrue(token)
        self.assertIn(first_body["auth_scheme"], {"http_signatures", "legacy_didwba"})
        self.assertEqual(second_body["auth_scheme"], "bearer")
        self.assertTrue(second_headers["Authorization"].startswith("Bearer "))

    def test_old_python_client_to_rust_server(self):
        """The released Python compatibility baseline should interoperate with the Rust verifier server."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            did_path, key_path = self._generate_old_python_fixture(temp_path)

            with self._run_rust_server(did_path) as server_url:
                payload = self._run_old_python_client(server_url, did_path, key_path, temp_path)

        self.assertEqual(payload["first_status"], 200)
        self.assertEqual(payload["second_status"], 200)
        self.assertTrue(payload["first_auth_header"].startswith("DIDWba"))
        self.assertTrue(payload["second_auth_header"].startswith("Bearer "))
        self.assertEqual(payload["first_body"]["auth_scheme"], "legacy_didwba")
        self.assertEqual(payload["second_body"]["auth_scheme"], "bearer")

    def _generate_old_python_fixture(self, temp_path: Path) -> tuple[Path, Path]:
        did_path = temp_path / "did.json"
        key_path = temp_path / "key-1.pem"
        script = textwrap.dedent(
            """
            import json
            import sys
            from pathlib import Path
            from anp.authentication import create_did_wba_document

            output_dir = Path(sys.argv[1])
            did_document, keys = create_did_wba_document(
                'example.com',
                path_segments=['user', 'python-old-network'],
            )
            (output_dir / 'did.json').write_text(json.dumps(did_document), encoding='utf-8')
            (output_dir / 'key-1.pem').write_bytes(keys['key-1'][0])
            """
        )
        subprocess.run(
            [
                "uv",
                "run",
                "--python",
                "3.13",
                "--with",
                f"anp=={RELEASED_PYTHON_ANP_VERSION}",
                "python",
                "-c",
                script,
                str(temp_path),
            ],
            cwd=temp_path,
            capture_output=True,
            text=True,
            check=True,
        )
        return did_path, key_path

    def _run_old_python_client(
        self,
        server_url: str,
        did_path: Path,
        key_path: Path,
        temp_path: Path,
    ) -> dict:
        script = textwrap.dedent(
            """
            import json
            import sys
            import urllib.request
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import ec, ed25519
            from anp.authentication import create_did_wba_document, generate_auth_header

            url = sys.argv[1]
            did_document_path = sys.argv[2]
            private_key_path = sys.argv[3]

            def _load_private_key(private_key_pem: bytes):
                return serialization.load_pem_private_key(private_key_pem, password=None)

            def _sign_callback(private_key_pem: bytes):
                private_key = _load_private_key(private_key_pem)

                def _callback(content: bytes, verification_method: str) -> bytes:
                    if isinstance(private_key, ec.EllipticCurvePrivateKey):
                        return private_key.sign(content, ec.ECDSA(hashes.SHA256()))
                    if isinstance(private_key, ed25519.Ed25519PrivateKey):
                        return private_key.sign(content)
                    raise TypeError(f'Unsupported key type: {type(private_key).__name__}')

                return _callback

            did_document = json.load(open(did_document_path, 'r', encoding='utf-8'))
            private_key_pem = open(private_key_path, 'rb').read()
            auth_header = generate_auth_header(
                did_document,
                '127.0.0.1',
                _sign_callback(private_key_pem),
                version='1.0',
            )
            first_headers = {'Authorization': auth_header}
            first_request = urllib.request.Request(url, headers=first_headers, method='GET')
            with urllib.request.urlopen(first_request, timeout=20) as response:
                first_status = response.status
                first_response_headers = dict(response.headers.items())
                first_body = json.loads(response.read().decode('utf-8'))

            token = ''
            authentication_info = first_response_headers.get('Authentication-Info', '')
            for item in authentication_info.split(','):
                if item.strip().startswith('access_token='):
                    token = item.split('=', 1)[1].strip().strip('"')
                    break
            if not token and first_response_headers.get('Authorization', '').startswith('Bearer '):
                token = first_response_headers['Authorization'][7:]
            second_headers = {'Authorization': f'Bearer {token}'}
            second_request = urllib.request.Request(url, headers=second_headers, method='GET')
            with urllib.request.urlopen(second_request, timeout=20) as response:
                second_status = response.status
                second_body = json.loads(response.read().decode('utf-8'))

            print(json.dumps({
                'first_status': first_status,
                'second_status': second_status,
                'first_auth_header': first_headers.get('Authorization', ''),
                'second_auth_header': second_headers.get('Authorization', ''),
                'token': token,
                'first_body': first_body,
                'second_body': second_body,
            }))
            """
        )
        result = subprocess.run(
            [
                "uv",
                "run",
                "--python",
                "3.13",
                "--with",
                f"anp=={RELEASED_PYTHON_ANP_VERSION}",
                "python",
                "-c",
                script,
                server_url,
                str(did_path),
                str(key_path),
            ],
            cwd=temp_path,
            capture_output=True,
            text=True,
            check=True,
        )
        return json.loads(result.stdout)


if __name__ == "__main__":
    unittest.main()
