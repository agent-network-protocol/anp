"""Unit tests for DID-WBA authentication helpers."""

import json
import os
import tempfile
import unittest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from anp.authentication import (
    DIDWbaAuthHeader,
    create_did_wba_document,
    create_did_wba_document_with_key_binding,
    extract_signature_metadata,
    generate_auth_header,
    generate_http_signature_headers,
    verify_auth_header_signature,
    verify_did_key_binding,
    verify_http_message_signature,
)


def _load_private_key(private_key_pem: bytes):
    """Load a private key from PEM bytes."""
    return serialization.load_pem_private_key(private_key_pem, password=None)


def _sign_callback(private_key_pem: bytes):
    """Build a signature callback using the provided private key."""
    private_key = _load_private_key(private_key_pem)

    def _callback(content: bytes, verification_method: str) -> bytes:
        if isinstance(private_key, ec.EllipticCurvePrivateKey):
            return private_key.sign(content, ec.ECDSA(hashes.SHA256()))
        if isinstance(private_key, ed25519.Ed25519PrivateKey):
            return private_key.sign(content)
        raise TypeError(f"Unsupported key type: {type(private_key).__name__}")

    return _callback


class TestDidDocumentProfiles(unittest.TestCase):
    """Test DID document creation across supported profiles."""

    def test_default_path_profile_is_e1(self):
        """Path-based DID documents should default to the e1 profile."""
        did_document, keys = create_did_wba_document(
            "example.com",
            path_segments=["user", "alice"],
        )

        self.assertRegex(
            did_document["id"],
            r"^did:wba:example\.com:user:alice:e1_[A-Za-z0-9_-]{43}$",
        )
        self.assertEqual(did_document["verificationMethod"][0]["type"], "Multikey")
        self.assertEqual(did_document["proof"]["type"], "DataIntegrityProof")
        self.assertEqual(did_document["proof"]["cryptosuite"], "eddsa-jcs-2022")
        self.assertIn(did_document["verificationMethod"][0]["id"], did_document["authentication"])
        self.assertIn(did_document["verificationMethod"][0]["id"], did_document["assertionMethod"])
        self.assertIn("key-1", keys)
        self.assertTrue(verify_did_key_binding(did_document["id"], did_document["verificationMethod"][0]))

    def test_k1_profile_remains_available(self):
        """The k1 profile should stay available for legacy compatibility."""
        did_document, keys = create_did_wba_document(
            "example.com",
            path_segments=["user", "alice"],
            did_profile="k1",
        )

        self.assertRegex(
            did_document["id"],
            r"^did:wba:example\.com:user:alice:k1_[A-Za-z0-9_-]{43}$",
        )
        self.assertEqual(
            did_document["verificationMethod"][0]["type"],
            "EcdsaSecp256k1VerificationKey2019",
        )
        self.assertEqual(did_document["proof"]["type"], "DataIntegrityProof")
        self.assertEqual(
            did_document["proof"]["cryptosuite"],
            "didwba-jcs-ecdsa-secp256k1-2025",
        )
        self.assertIn("key-1", keys)
        self.assertTrue(verify_did_key_binding(did_document["id"], did_document["verificationMethod"][0]))

    def test_plain_legacy_profile_preserves_old_shape(self):
        """The plain legacy profile should preserve the old identifier shape."""
        did_document, keys = create_did_wba_document(
            "example.com",
            path_segments=["user", "alice"],
            did_profile="plain_legacy",
        )

        self.assertEqual(did_document["id"], "did:wba:example.com:user:alice")
        self.assertEqual(did_document["proof"]["type"], "EcdsaSecp256k1Signature2019")
        self.assertEqual(
            did_document["verificationMethod"][0]["type"],
            "EcdsaSecp256k1VerificationKey2019",
        )
        self.assertIn("key-1", keys)

    def test_k1_wrapper_maps_to_profile_k1(self):
        """The compatibility wrapper should still produce a k1 DID."""
        did_document, _ = create_did_wba_document_with_key_binding(
            "example.com",
            path_prefix=["user", "alice"],
        )
        self.assertIn(":k1_", did_document["id"])


class TestHttpSignatureHelpers(unittest.TestCase):
    """Test HTTP Message Signatures helper functions."""

    def setUp(self):
        self.did_document, self.keys = create_did_wba_document(
            "example.com",
            path_segments=["user", "alice"],
        )
        self.sign_callback = _sign_callback(self.keys["key-1"][0])
        self.url = "https://api.example.com/orders"

    def test_http_signature_verification_succeeds_for_post_body(self):
        """POST requests with a body should verify with Content-Digest."""
        body = b'{"item":"book"}'
        headers = generate_http_signature_headers(
            did_document=self.did_document,
            request_url=self.url,
            request_method="POST",
            sign_callback=self.sign_callback,
            headers={"Content-Type": "application/json"},
            body=body,
        )

        is_valid, message, metadata = verify_http_message_signature(
            did_document=self.did_document,
            request_method="POST",
            request_url=self.url,
            headers=headers,
            body=body,
        )

        self.assertTrue(is_valid, message)
        self.assertEqual(metadata["keyid"], self.did_document["verificationMethod"][0]["id"])
        self.assertIn("Content-Digest", headers)

    def test_http_signature_rejects_tampered_body(self):
        """Changing the request body should invalidate Content-Digest verification."""
        body = b'{"item":"book"}'
        headers = generate_http_signature_headers(
            did_document=self.did_document,
            request_url=self.url,
            request_method="POST",
            sign_callback=self.sign_callback,
            headers={"Content-Type": "application/json"},
            body=body,
        )

        is_valid, message, _ = verify_http_message_signature(
            did_document=self.did_document,
            request_method="POST",
            request_url=self.url,
            headers=headers,
            body=b'{"item":"music"}',
        )

        self.assertFalse(is_valid)
        self.assertIn("Content-Digest", message)

    def test_legacy_authorization_header_still_verifies_for_k1(self):
        """Legacy DIDWba Authorization headers should still work for k1 DID documents."""
        did_document, keys = create_did_wba_document(
            "example.com",
            path_segments=["user", "alice"],
            did_profile="k1",
        )
        auth_header = generate_auth_header(
            did_document,
            "service.example.com",
            _sign_callback(keys["key-1"][0]),
            version="1.1",
        )
        is_valid, message = verify_auth_header_signature(
            auth_header,
            did_document,
            "service.example.com",
        )
        self.assertTrue(is_valid, message)


class TestDIDWbaAuthHeader(unittest.TestCase):
    """Test the high-level client helper."""

    def _write_auth_files(self, did_document: dict, private_key_pem: bytes) -> tuple[str, str]:
        temp_dir = tempfile.mkdtemp()
        did_document_path = os.path.join(temp_dir, "did.json")
        private_key_path = os.path.join(temp_dir, "key-1.pem")
        with open(did_document_path, "w", encoding="utf-8") as file_obj:
            json.dump(did_document, file_obj)
        with open(private_key_path, "wb") as file_obj:
            file_obj.write(private_key_pem)
        return did_document_path, private_key_path

    def test_default_auth_mode_generates_http_signature_headers(self):
        """The default client mode should generate HTTP Message Signatures headers."""
        did_document, keys = create_did_wba_document(
            "example.com",
            path_segments=["user", "alice"],
        )
        did_document_path, private_key_path = self._write_auth_files(
            did_document,
            keys["key-1"][0],
        )

        auth_client = DIDWbaAuthHeader(did_document_path, private_key_path)
        headers = auth_client.get_auth_header("https://api.example.com/orders")

        self.assertIn("Signature-Input", headers)
        self.assertIn("Signature", headers)
        self.assertNotIn("Authorization", headers)

    def test_update_token_prefers_authentication_info(self):
        """The client should cache tokens from Authentication-Info."""
        did_document, keys = create_did_wba_document(
            "example.com",
            path_segments=["user", "alice"],
        )
        did_document_path, private_key_path = self._write_auth_files(
            did_document,
            keys["key-1"][0],
        )

        auth_client = DIDWbaAuthHeader(did_document_path, private_key_path)
        token = auth_client.update_token(
            "https://api.example.com/orders",
            {
                "Authentication-Info": 'access_token="test-token", token_type="Bearer", expires_in=3600',
            },
        )
        self.assertEqual(token, "test-token")

        cached_headers = auth_client.get_auth_header("https://api.example.com/orders")
        self.assertEqual(cached_headers["Authorization"], "Bearer test-token")

    def test_legacy_auth_mode_still_returns_authorization_header(self):
        """Legacy mode should continue to emit a DIDWba Authorization header."""
        did_document, keys = create_did_wba_document(
            "example.com",
            path_segments=["user", "alice"],
            did_profile="k1",
        )
        did_document_path, private_key_path = self._write_auth_files(
            did_document,
            keys["key-1"][0],
        )

        auth_client = DIDWbaAuthHeader(
            did_document_path,
            private_key_path,
            auth_mode="legacy_didwba",
        )
        headers = auth_client.get_auth_header("https://api.example.com/orders")

        self.assertIn("Authorization", headers)
        self.assertTrue(headers["Authorization"].startswith("DIDWba"))

    def test_get_challenge_auth_header_reuses_server_nonce(self):
        """Challenge retries should reuse the nonce and requested components."""
        did_document, keys = create_did_wba_document(
            "example.com",
            path_segments=["user", "alice"],
        )
        did_document_path, private_key_path = self._write_auth_files(
            did_document,
            keys["key-1"][0],
        )
        auth_client = DIDWbaAuthHeader(did_document_path, private_key_path)

        headers = auth_client.get_challenge_auth_header(
            "https://api.example.com/orders",
            {
                "WWW-Authenticate": (
                    'DIDWba realm="api.example.com", '
                    'error="invalid_nonce", '
                    'error_description="Nonce mismatch", '
                    'nonce="server-nonce-123"'
                ),
                "Accept-Signature": (
                    'sig1=("@method" "@target-uri" "@authority" '
                    '"content-digest" "content-type");created;expires;nonce;keyid'
                ),
            },
            method="POST",
            headers={"Content-Type": "application/json"},
            body=b'{"item":"book"}',
        )

        metadata = extract_signature_metadata(headers)
        self.assertEqual(metadata["params"]["nonce"], "server-nonce-123")
        self.assertIn("content-type", metadata["components"])
        self.assertIn("Content-Digest", headers)

    def test_should_retry_after_401_rejects_invalid_did(self):
        """Non-retryable challenge errors should not trigger another auth attempt."""
        did_document, keys = create_did_wba_document(
            "example.com",
            path_segments=["user", "alice"],
        )
        did_document_path, private_key_path = self._write_auth_files(
            did_document,
            keys["key-1"][0],
        )
        auth_client = DIDWbaAuthHeader(did_document_path, private_key_path)

        self.assertFalse(
            auth_client.should_retry_after_401(
                {
                    "WWW-Authenticate": (
                        'DIDWba realm="api.example.com", '
                        'error="invalid_did", '
                        'error_description="DID is unknown."'
                    )
                }
            )
        )

    def test_get_challenge_auth_header_ignores_content_digest_for_get(self):
        """GET challenge retries should not force content-digest without a body."""
        did_document, keys = create_did_wba_document(
            "example.com",
            path_segments=["user", "alice"],
        )
        did_document_path, private_key_path = self._write_auth_files(
            did_document,
            keys["key-1"][0],
        )
        auth_client = DIDWbaAuthHeader(did_document_path, private_key_path)

        headers = auth_client.get_challenge_auth_header(
            "https://api.example.com/profile",
            {
                "WWW-Authenticate": (
                    'DIDWba realm="api.example.com", '
                    'error="invalid_nonce", '
                    'nonce="retry-nonce"'
                ),
                "Accept-Signature": (
                    'sig1=("@method" "@target-uri" "@authority" "content-digest");'
                    'created;expires;nonce;keyid'
                ),
            },
            method="GET",
            body=b"",
        )

        metadata = extract_signature_metadata(headers)
        self.assertEqual(metadata["params"]["nonce"], "retry-nonce")
        self.assertNotIn("content-digest", metadata["components"])


if __name__ == "__main__":
    unittest.main()
