"""Cross-language interoperability tests for the Rust SDK."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

from anp.unittest.rust_interop.constants import RELEASED_PYTHON_ANP_VERSION

from anp.authentication import (
    verify_auth_header_signature,
    verify_http_message_signature,
)


class TestRustInterop(unittest.TestCase):
    """Verify Rust fixtures against current and legacy Python implementations."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.repo_root = Path(__file__).resolve().parents[3]
        cls.rust_root = cls.repo_root / "rust"
        cargo_path = shutil.which("cargo") or str(Path.home() / ".cargo" / "bin" / "cargo")
        if not Path(cargo_path).exists():
            raise unittest.SkipTest("cargo is required for Rust interoperability tests")
        cls.cargo = cargo_path
        if shutil.which("uv") is None:
            raise unittest.SkipTest("uv is required for Python interoperability tests")

    def _run_rust_fixture(self, *args: str) -> dict:
        result = subprocess.run(
            [
                self.cargo,
                "run",
                "--quiet",
                "--example",
                "interop_cli",
                "--",
                *args,
            ],
            cwd=self.rust_root,
            capture_output=True,
            text=True,
            check=True,
        )
        return json.loads(result.stdout)

    def test_rust_generated_http_signature_verifies_in_python(self):
        """Current Python verifier should accept Rust HTTP Message Signatures."""
        fixture = self._run_rust_fixture(
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
            did_document=fixture["did_document"],
            request_method=fixture["request_method"],
            request_url=fixture["request_url"],
            headers=fixture["headers"],
            body=fixture["body"].encode("utf-8"),
        )

        self.assertTrue(is_valid, message)
        self.assertIn("keyid", metadata)

    def test_rust_generated_legacy_auth_header_verifies_in_python(self):
        """Current Python verifier should accept Rust legacy DIDWba headers."""
        fixture = self._run_rust_fixture(
            "auth-fixture",
            "--profile",
            "k1",
            "--scheme",
            "legacy",
            "--service-domain",
            "api.example.com",
        )

        is_valid, message = verify_auth_header_signature(
            fixture["headers"]["Authorization"],
            fixture["did_document"],
            fixture["service_domain"],
        )

        self.assertTrue(is_valid, message)

    def test_rust_generated_legacy_auth_header_verifies_in_old_python(self):
        """The released Python compatibility baseline should verify Rust legacy DIDWba fixtures."""
        fixture = self._run_rust_fixture(
            "auth-fixture",
            "--profile",
            "plain_legacy",
            "--scheme",
            "legacy",
            "--service-domain",
            "api.example.com",
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            fixture_path = Path(temp_dir) / "fixture.json"
            fixture_path.write_text(json.dumps(fixture), encoding="utf-8")
            verifier_script = textwrap.dedent(
                """
                import json
                import sys
                from anp.authentication import verify_auth_header_signature

                fixture = json.load(open(sys.argv[1], 'r', encoding='utf-8'))
                is_valid, message = verify_auth_header_signature(
                    fixture['headers']['Authorization'],
                    fixture['did_document'],
                    fixture['service_domain'],
                )
                print(json.dumps({'is_valid': is_valid, 'message': message}))
                if not is_valid:
                    raise SystemExit(1)
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
                    verifier_script,
                    str(fixture_path),
                ],
                cwd=temp_dir,
                capture_output=True,
                text=True,
                check=True,
            )

        payload = json.loads(result.stdout)
        self.assertTrue(payload["is_valid"], payload["message"])


if __name__ == "__main__":
    unittest.main()
