"""Tests for the high-level DID-WBA verifier."""

import asyncio
import copy
import unittest
from unittest.mock import AsyncMock, patch

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from anp.authentication import (
    DidWbaVerifier,
    DidWbaVerifierError,
    DidWbaVerifierConfig,
    create_did_wba_document,
    generate_auth_header,
    generate_http_signature_headers,
)
from anp.proof import PROOF_TYPE_SECP256K1, generate_w3c_proof, verify_w3c_proof


def _sign_callback(private_key_pem: bytes):
    """Build a signature callback for the provided private key."""
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)

    def _callback(content: bytes, verification_method: str) -> bytes:
        if isinstance(private_key, ec.EllipticCurvePrivateKey):
            return private_key.sign(content, ec.ECDSA(hashes.SHA256()))
        if isinstance(private_key, ed25519.Ed25519PrivateKey):
            return private_key.sign(content)
        raise TypeError(f"Unsupported key type: {type(private_key).__name__}")

    return _callback


def _generate_rsa_pem_pair() -> tuple[str, str]:
    """Generate a test RSA key pair for JWT signing."""
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


def _build_legacy_k1_document() -> tuple[dict, dict]:
    """Build a k1 DID document carrying the legacy secp256k1 proof shape."""
    did_document, keys = create_did_wba_document(
        "example.com",
        path_segments=["user", "legacy-alice"],
        did_profile="k1",
    )
    private_key = serialization.load_pem_private_key(keys["key-1"][0], password=None)
    legacy_document = generate_w3c_proof(
        document={key: value for key, value in did_document.items() if key != "proof"},
        private_key=private_key,
        verification_method=f'{did_document["id"]}#key-1',
        proof_type=PROOF_TYPE_SECP256K1,
        proof_purpose="assertionMethod",
    )
    return legacy_document, keys


class TestDidWbaVerifier(unittest.TestCase):
    """Test the unified verifier across new and legacy flows."""

    @classmethod
    def setUpClass(cls):
        jwt_private_key, jwt_public_key = _generate_rsa_pem_pair()
        cls.config = DidWbaVerifierConfig(
            jwt_private_key=jwt_private_key,
            jwt_public_key=jwt_public_key,
        )

    def test_verify_request_accepts_http_signatures_and_returns_dual_headers(self):
        """New HTTP signatures should mint a token and emit dual response headers."""
        did_document, keys = create_did_wba_document(
            "example.com",
            path_segments=["user", "alice"],
        )
        url = "https://api.example.com/orders"
        headers = generate_http_signature_headers(
            did_document=did_document,
            request_url=url,
            request_method="GET",
            sign_callback=_sign_callback(keys["key-1"][0]),
        )
        verifier = DidWbaVerifier(self.config)

        with patch(
            "anp.authentication.did_wba_verifier.resolve_did_wba_document",
            AsyncMock(return_value=did_document),
        ):
            result = asyncio.run(
                verifier.verify_request(
                    method="GET",
                    url=url,
                    headers=headers,
                    body=b"",
                    domain="api.example.com",
                )
            )

        self.assertEqual(result["did"], did_document["id"])
        self.assertEqual(result["auth_scheme"], "http_signatures")
        self.assertIn("Authentication-Info", result["response_headers"])
        self.assertIn("Authorization", result["response_headers"])
        self.assertIn("access_token", result)

    def test_verify_request_accepts_legacy_didwba(self):
        """Legacy DIDWba requests should still be accepted."""
        did_document, keys = create_did_wba_document(
            "example.com",
            path_segments=["user", "alice"],
            did_profile="k1",
        )
        authorization = generate_auth_header(
            did_document,
            "api.example.com",
            _sign_callback(keys["key-1"][0]),
            version="1.1",
        )
        verifier = DidWbaVerifier(self.config)

        with patch(
            "anp.authentication.did_wba_verifier.resolve_did_wba_document",
            AsyncMock(return_value=did_document),
        ):
            result = asyncio.run(
                verifier.verify_request(
                    method="GET",
                    url="https://api.example.com/orders",
                    headers={"Authorization": authorization},
                    body=b"",
                    domain="api.example.com",
                )
            )

        self.assertEqual(result["did"], did_document["id"])
        self.assertEqual(result["auth_scheme"], "legacy_didwba")
        self.assertIn("Authentication-Info", result["response_headers"])
        self.assertIn("Authorization", result["response_headers"])

    def test_verify_request_accepts_bearer_tokens_after_first_exchange(self):
        """Bearer tokens returned from a first exchange should be reusable."""
        did_document, keys = create_did_wba_document(
            "example.com",
            path_segments=["user", "alice"],
        )
        url = "https://api.example.com/orders"
        verifier = DidWbaVerifier(self.config)
        headers = generate_http_signature_headers(
            did_document=did_document,
            request_url=url,
            request_method="GET",
            sign_callback=_sign_callback(keys["key-1"][0]),
        )

        with patch(
            "anp.authentication.did_wba_verifier.resolve_did_wba_document",
            AsyncMock(return_value=did_document),
        ):
            first_result = asyncio.run(
                verifier.verify_request(
                    method="GET",
                    url=url,
                    headers=headers,
                    body=b"",
                    domain="api.example.com",
                )
            )

        bearer_result = asyncio.run(
            verifier.verify_request(
                method="GET",
                url=url,
                headers={"Authorization": f'Bearer {first_result["access_token"]}'},
                body=b"",
                domain="api.example.com",
            )
        )

        self.assertEqual(bearer_result["did"], did_document["id"])
        self.assertEqual(bearer_result["auth_scheme"], "bearer")
        self.assertEqual(bearer_result["response_headers"], {})

    def test_verify_request_rejects_e1_document_without_proof(self):
        """e1 requests should fail when the resolved DID document lacks proof."""
        did_document, keys = create_did_wba_document(
            "example.com",
            path_segments=["user", "alice"],
        )
        tampered_document = copy.deepcopy(did_document)
        tampered_document.pop("proof", None)
        url = "https://api.example.com/orders"
        headers = generate_http_signature_headers(
            did_document=did_document,
            request_url=url,
            request_method="GET",
            sign_callback=_sign_callback(keys["key-1"][0]),
        )
        verifier = DidWbaVerifier(self.config)

        with patch(
            "anp.authentication.did_wba_verifier.resolve_did_wba_document",
            AsyncMock(return_value=tampered_document),
        ):
            with self.assertRaises(DidWbaVerifierError) as cm:
                asyncio.run(
                    verifier.verify_request(
                        method="GET",
                        url=url,
                        headers=headers,
                        body=b"",
                        domain="api.example.com",
                    )
                )

        self.assertEqual(cm.exception.status_code, 401)
        self.assertIn("binding", str(cm.exception).lower())

    def test_legacy_k1_old_proof_request_then_bearer_succeeds(self):
        """Old proof document + legacy k1 request + Bearer reuse should all work."""
        did_document, keys = _build_legacy_k1_document()
        public_key = serialization.load_pem_public_key(keys["key-1"][1])
        self.assertTrue(verify_w3c_proof(did_document, public_key))

        verifier = DidWbaVerifier(self.config)
        url = "https://api.example.com/orders"
        authorization = generate_auth_header(
            did_document,
            "api.example.com",
            _sign_callback(keys["key-1"][0]),
            version="1.1",
        )

        with patch(
            "anp.authentication.did_wba_verifier.resolve_did_wba_document",
            AsyncMock(return_value=did_document),
        ):
            first_result = asyncio.run(
                verifier.verify_request(
                    method="GET",
                    url=url,
                    headers={"Authorization": authorization},
                    body=b"",
                    domain="api.example.com",
                )
            )

        self.assertEqual(first_result["did"], did_document["id"])
        self.assertEqual(first_result["auth_scheme"], "legacy_didwba")
        self.assertIn("Authentication-Info", first_result["response_headers"])
        self.assertIn("Authorization", first_result["response_headers"])

        second_result = asyncio.run(
            verifier.verify_request(
                method="GET",
                url=url,
                headers={
                    "Authorization": first_result["response_headers"]["Authorization"]
                },
                body=b"",
                domain="api.example.com",
            )
        )

        self.assertEqual(second_result["did"], did_document["id"])
        self.assertEqual(second_result["auth_scheme"], "bearer")
        self.assertEqual(second_result["response_headers"], {})


if __name__ == "__main__":
    unittest.main()
