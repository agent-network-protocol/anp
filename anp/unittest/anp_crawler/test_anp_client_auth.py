"""Tests for ANPClient request signing inputs."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from anp.anp_crawler.anp_client import ANPClient


class _RecordingAuthClient:
    """Capture auth input passed by ANPClient."""

    def __init__(self) -> None:
        self.calls: list[dict] = []
        self.updated_tokens: list[tuple[str, dict]] = []
        self.cleared_tokens: list[str] = []
        self.challenge_calls: list[dict] = []
        self.retry_decisions: list[dict] = []

    def get_auth_header(
        self,
        server_url: str,
        force_new: bool = False,
        method: str = "GET",
        headers: dict | None = None,
        body=None,
    ) -> dict[str, str]:
        self.calls.append(
            {
                "server_url": server_url,
                "force_new": force_new,
                "method": method,
                "headers": dict(headers or {}),
                "body": body,
            }
        )
        return {"Signature-Input": "sig1=(\"@method\")", "Signature": "sig1=:ZmFrZQ==:"}

    def update_token(self, server_url: str, headers: dict) -> None:
        self.updated_tokens.append((server_url, headers))

    def clear_token(self, server_url: str) -> None:
        self.cleared_tokens.append(server_url)

    def should_retry_after_401(self, response_headers: dict) -> bool:
        self.retry_decisions.append(dict(response_headers))
        return True

    def get_challenge_auth_header(
        self,
        server_url: str,
        response_headers: dict,
        method: str = "GET",
        headers: dict | None = None,
        body=None,
    ) -> dict[str, str]:
        self.challenge_calls.append(
            {
                "server_url": server_url,
                "response_headers": dict(response_headers),
                "method": method,
                "headers": dict(headers or {}),
                "body": body,
            }
        )
        return {
            "Signature-Input": "retry-sig1=(\"@method\")",
            "Signature": "retry-sig1=:cmV0cnk=:",
        }


class _FakeResponse:
    """Minimal aiohttp-like response object for tests."""

    def __init__(self, status: int = 200) -> None:
        self.status = status
        self.reason = "OK"
        self.headers = {"Content-Type": "application/json"}
        self.charset = "utf-8"

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        return False

    async def text(self) -> str:
        return "{}"


class _FakeClientSession:
    """Minimal aiohttp.ClientSession replacement for tests."""

    calls: list[tuple[str, dict]] = []
    response_queue: list[_FakeResponse] = []

    def __init__(self, *args, **kwargs) -> None:
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        return False

    def get(self, **kwargs):
        type(self).calls.append(("GET", kwargs))
        if type(self).response_queue:
            return type(self).response_queue.pop(0)
        return _FakeResponse()

    def post(self, **kwargs):
        type(self).calls.append(("POST", kwargs))
        if type(self).response_queue:
            return type(self).response_queue.pop(0)
        return _FakeResponse()


class TestANPClientSigning(unittest.IsolatedAsyncioTestCase):
    """Verify that ANPClient signs the exact outbound request."""

    async def test_fetch_url_signs_final_query_string(self):
        """The signed URL should include the final encoded query string."""
        auth_client = _RecordingAuthClient()
        _FakeClientSession.calls = []
        _FakeClientSession.response_queue = []

        with patch(
            "anp.anp_crawler.anp_client.DIDWbaAuthHeader",
            return_value=auth_client,
        ), patch(
            "anp.anp_crawler.anp_client.aiohttp.ClientSession",
            _FakeClientSession,
        ):
            client = ANPClient(
                did_document_path="did.json",
                private_key_path="key.pem",
            )
            result = await client.fetch_url(
                url="https://example.com/search",
                method="GET",
                params={"q": "hello world", "page": 2},
            )

        self.assertTrue(result["success"])
        self.assertEqual(
            auth_client.calls[0]["server_url"],
            "https://example.com/search?q=hello+world&page=2",
        )
        self.assertEqual(
            _FakeClientSession.calls[0][1]["url"],
            "https://example.com/search?q=hello+world&page=2",
        )

    async def test_fetch_url_signs_same_body_bytes_that_are_sent(self):
        """The signature input body should match the outbound request body bytes."""
        auth_client = _RecordingAuthClient()
        _FakeClientSession.calls = []
        _FakeClientSession.response_queue = []

        with patch(
            "anp.anp_crawler.anp_client.DIDWbaAuthHeader",
            return_value=auth_client,
        ), patch(
            "anp.anp_crawler.anp_client.aiohttp.ClientSession",
            _FakeClientSession,
        ):
            client = ANPClient(
                did_document_path="did.json",
                private_key_path="key.pem",
            )
            result = await client.fetch_url(
                url="https://example.com/orders",
                method="POST",
                headers={"Content-Type": "application/json"},
                body={"item": "book"},
            )

        self.assertTrue(result["success"])
        self.assertEqual(auth_client.calls[0]["method"], "POST")
        self.assertEqual(auth_client.calls[0]["body"], b'{"item":"book"}')
        self.assertEqual(_FakeClientSession.calls[0][1]["data"], b'{"item":"book"}')
        self.assertEqual(
            _FakeClientSession.calls[0][1]["url"],
            "https://example.com/orders",
        )

    async def test_fetch_url_retries_once_with_challenge_headers(self):
        """A 401 challenge should trigger one DID auth retry with server headers."""
        auth_client = _RecordingAuthClient()
        _FakeClientSession.calls = []
        _FakeClientSession.response_queue = [
            _FakeResponse(
                status=401,
            ),
            _FakeResponse(),
        ]
        _FakeClientSession.response_queue[0].headers = {
            "Content-Type": "application/json",
            "WWW-Authenticate": (
                'DIDWba realm="example.com", '
                'error="invalid_nonce", '
                'error_description="Retry with server nonce.", '
                'nonce="server-nonce-xyz"'
            ),
            "Accept-Signature": (
                'sig1=("@method" "@target-uri" "@authority" "content-digest");'
                'created;expires;nonce;keyid'
            ),
        }

        with patch(
            "anp.anp_crawler.anp_client.DIDWbaAuthHeader",
            return_value=auth_client,
        ), patch(
            "anp.anp_crawler.anp_client.aiohttp.ClientSession",
            _FakeClientSession,
        ):
            client = ANPClient(
                did_document_path="did.json",
                private_key_path="key.pem",
            )
            result = await client.fetch_url(
                url="https://example.com/orders",
                method="POST",
                headers={"Content-Type": "application/json"},
                body={"item": "book"},
            )

        self.assertTrue(result["success"])
        self.assertEqual(len(_FakeClientSession.calls), 2)
        self.assertEqual(len(auth_client.challenge_calls), 1)
        self.assertEqual(
            auth_client.challenge_calls[0]["response_headers"]["WWW-Authenticate"],
            (
                'DIDWba realm="example.com", '
                'error="invalid_nonce", '
                'error_description="Retry with server nonce.", '
                'nonce="server-nonce-xyz"'
            ),
        )
        self.assertEqual(
            _FakeClientSession.calls[1][1]["headers"]["Signature-Input"],
            'retry-sig1=("@method")',
        )


if __name__ == "__main__":
    unittest.main()
