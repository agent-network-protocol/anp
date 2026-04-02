"""Tests for federated service-to-service DID verification."""

import asyncio
import base64
import unittest
from typing import Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from anp.authentication import (
    build_agent_message_service,
    create_did_wba_document,
    generate_http_signature_headers,
    verify_federated_http_request,
    verify_http_message_signature,
)


def _encode_base64url(data: bytes) -> str:
    """Encode bytes into base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _sign_callback(private_key_pem: bytes):
    """Build a signature callback for HTTP signatures."""
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)

    def _callback(content: bytes, verification_method: str) -> bytes:
        if isinstance(private_key, ec.EllipticCurvePrivateKey):
            return private_key.sign(content, ec.ECDSA(hashes.SHA256()))
        if isinstance(private_key, ed25519.Ed25519PrivateKey):
            return private_key.sign(content)
        raise TypeError(f"Unsupported key type: {type(private_key).__name__}")

    return _callback


def _create_did_web_document(did: str) -> Tuple[dict, bytes]:
    """Create a minimal did:web document for signature verification tests."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_key_raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    verification_method_id = f"{did}#key-1"
    did_document = {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [
            {
                "id": verification_method_id,
                "type": "Ed25519VerificationKey2020",
                "controller": did,
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": _encode_base64url(public_key_raw),
                },
            }
        ],
        "authentication": [verification_method_id],
    }
    private_key_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    return did_document, private_key_pem


class TestBareDomainDidSupport(unittest.TestCase):
    """Test bare-domain DID creation and signature verification."""

    def test_bare_domain_did_supports_http_signatures(self):
        """Bare-domain did:wba should sign and verify HTTP requests."""
        did_document, keys = create_did_wba_document("example.com")
        self.assertEqual(did_document["id"], "did:wba:example.com")

        body = b'{"item":"book"}'
        headers = generate_http_signature_headers(
            did_document=did_document,
            request_url="https://api.example.com/orders",
            request_method="POST",
            sign_callback=_sign_callback(keys["key-1"][0]),
            body=body,
        )

        is_valid, message, metadata = verify_http_message_signature(
            did_document=did_document,
            request_method="POST",
            request_url="https://api.example.com/orders",
            headers=headers,
            body=body,
        )
        self.assertTrue(is_valid, message)
        self.assertEqual(metadata["keyid"], f'{did_document["id"]}#key-1')


class TestAnpMessageServiceWithServiceDid(unittest.TestCase):
    """Test ANP message service helpers with serviceDid."""

    def test_build_agent_message_service_sets_service_did(self):
        """Builder should include serviceDid when provided."""
        did_document, _ = create_did_wba_document(
            "example.com",
            path_segments=["agents", "alice"],
        )
        service = build_agent_message_service(
            did=did_document["id"],
            service_endpoint="https://example.com/anp",
            service_did="did:wba:example.com",
        )
        self.assertEqual(service["serviceDid"], "did:wba:example.com")


class TestFederatedHttpVerification(unittest.TestCase):
    """Test federated verification using serviceDid."""

    def test_verify_federated_http_request_with_did_wba_service_did(self):
        """Federated verification should use the declared did:wba serviceDid."""
        sender_document, _ = create_did_wba_document(
            "a.example.com",
            path_segments=["agents", "alice"],
        )
        service_document, service_keys = create_did_wba_document("a.example.com")
        sender_document["service"] = [
            build_agent_message_service(
                did=sender_document["id"],
                service_endpoint="https://a.example.com/anp",
                service_did=service_document["id"],
            )
        ]

        body = b'{"message":"hello"}'
        headers = generate_http_signature_headers(
            did_document=service_document,
            request_url="https://b.example.com/anp",
            request_method="POST",
            sign_callback=_sign_callback(service_keys["key-1"][0]),
            body=body,
        )

        result = asyncio.run(
            verify_federated_http_request(
                sender_did=sender_document["id"],
                request_method="POST",
                request_url="https://b.example.com/anp",
                headers=headers,
                body=body,
                sender_did_document=sender_document,
                service_did_document=service_document,
            )
        )

        self.assertEqual(result.service_did, "did:wba:a.example.com")
        self.assertEqual(result.signature_metadata["keyid"], "did:wba:a.example.com#key-1")

    def test_verify_federated_http_request_with_did_web_service_did(self):
        """Federated verification should also support did:web serviceDid."""
        sender_document, _ = create_did_wba_document(
            "a.example.com",
            path_segments=["agents", "alice"],
        )
        service_document, service_private_key = _create_did_web_document(
            "did:web:a.example.com"
        )
        sender_document["service"] = [
            build_agent_message_service(
                did=sender_document["id"],
                service_endpoint="https://a.example.com/anp",
                service_did=service_document["id"],
            )
        ]

        body = b'{"message":"hello"}'
        headers = generate_http_signature_headers(
            did_document=service_document,
            request_url="https://b.example.com/anp",
            request_method="POST",
            sign_callback=_sign_callback(service_private_key),
            body=body,
        )

        result = asyncio.run(
            verify_federated_http_request(
                sender_did=sender_document["id"],
                request_method="POST",
                request_url="https://b.example.com/anp",
                headers=headers,
                body=body,
                sender_did_document=sender_document,
                service_did_document=service_document,
            )
        )

        self.assertEqual(result.service_did, "did:web:a.example.com")
        self.assertEqual(
            result.signature_metadata["keyid"], "did:web:a.example.com#key-1"
        )
