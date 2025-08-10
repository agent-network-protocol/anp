import os
import re
import sys

# Add the project root directory to Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

import base64
import hashlib
import json
import logging
import unittest
from unittest.mock import MagicMock, patch

import aiohttp
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from agent_connect.authentication.did_wba import (
    create_did_wba_document,
    generate_auth_header,
    generate_auth_json,
    resolve_did_wba_document,
    verify_auth_header_signature,
    verify_auth_json_signature,
)

logging.basicConfig(level=logging.DEBUG)

class TestDIDWBA(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        """Set up test fixtures"""
        self.test_hostname = "example.com"
        self.test_port = 8800
        self.test_path_segments = ["user", "alice"]

    def test_create_did_wba_document(self):
        """Test DID document creation with various parameters"""
        # Test with all parameters
        did_doc, private_keys = create_did_wba_document(
            self.test_hostname,
            self.test_port,
            self.test_path_segments
        )

        # Verify basic structure
        self.assertIn("@context", did_doc)
        self.assertIsInstance(did_doc["@context"], list)
        self.assertIn("https://www.w3.org/ns/did/v1", did_doc["@context"])

        # Verify DID format with encoded port
        expected_did = f"did:wba:{self.test_hostname}%3A{self.test_port}:user:alice"
        self.assertEqual(did_doc["id"], expected_did)

        # Verify verification method
        self.assertIn("verificationMethod", did_doc)
        self.assertIsInstance(did_doc["verificationMethod"], list)
        self.assertTrue(len(did_doc["verificationMethod"]) > 0)

        vm = did_doc["verificationMethod"][0]
        self.assertIn("id", vm)
        self.assertIn("type", vm)
        self.assertIn("controller", vm)
        self.assertIn("publicKeyJwk", vm)

        # Verify authentication
        self.assertIn("authentication", did_doc)
        self.assertIsInstance(did_doc["authentication"], list)

        # Test without optional parameters
        did_doc_simple, private_keys_simple = create_did_wba_document(self.test_hostname)
        self.assertEqual(did_doc_simple["id"], f"did:wba:{self.test_hostname}")

        # Test with IP address (should raise ValueError)
        with self.assertRaises(ValueError):
            create_did_wba_document("127.0.0.1")

        print("test_create_did_wba_document passed")

    def test_auth_header_generation_and_verification(self):
        """Test authentication header generation and verification with real keys"""
        # Generate a real secp256k1 key pair
        private_key = ec.generate_private_key(ec.SECP256K1())
        public_key = private_key.public_key()

        # Create public key JWK using helper function
        def _encode_base64url(data: bytes) -> str:
            return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

        def _public_key_to_jwk(public_key):
            numbers = public_key.public_numbers()
            x = _encode_base64url(numbers.x.to_bytes((numbers.x.bit_length() + 7) // 8, 'big'))
            y = _encode_base64url(numbers.y.to_bytes((numbers.y.bit_length() + 7) // 8, 'big'))
            compressed = public_key.public_bytes(
                encoding=Encoding.X962,
                format=PublicFormat.CompressedPoint
            )
            kid = _encode_base64url(hashlib.sha256(compressed).digest())
            return {
                "kty": "EC",
                "crv": "secp256k1",
                "x": x,
                "y": y,
                "kid": kid
            }

        # Create a DID document with the real key
        did_doc = {
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/jws-2020/v1",
                "https://w3id.org/security/suites/secp256k1-2019/v1"
            ],
            "id": "did:wba:example.com:user:alice",
            "verificationMethod": [{
                "id": "did:wba:example.com:user:alice#key-1",
                "type": "EcdsaSecp256k1VerificationKey2019",
                "controller": "did:wba:example.com:user:alice",
                "publicKeyJwk": _public_key_to_jwk(public_key)
            }],
            "authentication": ["did:wba:example.com:user:alice#key-1"]
        }

        service_domain = "api.example.com"

        # Create a real signing callback using the private key
        def real_sign_callback(content: bytes, vm_fragment: str) -> str:
            return private_key.sign(
                content,
                ec.ECDSA(hashes.SHA256())
            )

        # Generate auth header
        auth_header = generate_auth_header(
            did_doc,
            service_domain,
            real_sign_callback
        )

        # Verify the generated header
        success, message = verify_auth_header_signature(
            auth_header,
            did_doc,
            service_domain
        )
        print(f"verify_auth_header_signature returns: success: {success}, message: {message}")

        self.assertTrue(success, f"Verification failed: {message}")

        # Test with invalid service domain
        success, message = verify_auth_header_signature(
            auth_header,
            did_doc,
            "wrong.domain.com"
        )
        self.assertFalse(success)

        # Test with tampered signature
        tampered_header = re.sub(
            r'signature="[^"]+"',
            'signature="InvalidSignature"',
            auth_header
        )
        success, message = verify_auth_header_signature(
            tampered_header,
            did_doc,
            service_domain
        )
        self.assertFalse(success)

    def test_auth_header_with_generated_did(self):
        """Test authentication header generation and verification using generated DID document"""
        # Generate DID document and private keys using create_did_wba_document
        did_doc, private_keys = create_did_wba_document(
            self.test_hostname,
            self.test_port,
            self.test_path_segments
        )

        service_domain = "api.example.com"

        # Create signing callback function
        def signing_callback(content: bytes, vm_fragment: str) -> bytes:
            # Get corresponding private key PEM from private_keys
            if vm_fragment not in private_keys:
                raise ValueError(f"No private key found for {vm_fragment}")

            private_key_pem, _ = private_keys[vm_fragment]

            # Load private key from PEM
            private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=None
            )

            # Sign using private key
            if isinstance(private_key, ec.EllipticCurvePrivateKey):
                return private_key.sign(
                    content,
                    ec.ECDSA(hashes.SHA256())
                )
            elif isinstance(private_key, ed25519.Ed25519PrivateKey):
                return private_key.sign(content)
            else:
                raise ValueError(f"Unsupported key type: {type(private_key)}")

        # Generate auth header
        auth_header = generate_auth_header(
            did_doc,
            service_domain,
            signing_callback
        )

        # Verify the generated header
        success, message = verify_auth_header_signature(
            auth_header,
            did_doc,
            service_domain
        )
        print(f"Generated DID verification result: success={success}, message={message}")
        self.assertTrue(success, f"Verification failed: {message}")

        # Test with invalid service domain
        wrong_success, wrong_message = verify_auth_header_signature(
            auth_header,
            did_doc,
            "wrong.domain.com"
        )
        self.assertFalse(wrong_success, "Verification should fail with wrong domain")

        # Test with tampered signature
        tampered_header = re.sub(
            r'signature="[^"]+"',
            'signature="InvalidSignature"',
            auth_header
        )
        tampered_success, tampered_message = verify_auth_header_signature(
            tampered_header,
            did_doc,
            service_domain
        )
        self.assertFalse(tampered_success, "Verification should fail with tampered signature")

    @patch('aiohttp.ClientSession.get')
    async def test_resolve_did_wba_document(self, mock_get):
        """Test DID document resolution with various scenarios"""
        # Mock response for well-known endpoint
        mock_did_doc = {
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/jws-2020/v1",
                "https://w3id.org/security/suites/secp256k1-2019/v1"
            ],
            "id": "did:wba:example.com:user:alice",
            "verificationMethod": [{
                "id": "did:wba:example.com:user:alice#key-1",
                "type": "EcdsaSecp256k1VerificationKey2019",
                "controller": "did:wba:example.com:user:alice",
                "publicKeyJwk": {
                    "kty": "EC",
                    "crv": "secp256k1",
                    "x": "abc",
                    "y": "def"
                }
            }],
            "authentication": ["did:wba:example.com:user:alice#key-1"]
        }

        # Configure mock for successful response
        mock_response = MagicMock()
        mock_response.status = 200
        async def async_json():
            return mock_did_doc
        mock_response.json = async_json
        mock_get.return_value.__aenter__.return_value = mock_response

        # Test successful resolution
        did = "did:wba:example.com:user:alice"
        resolved_doc = await resolve_did_wba_document(did)
        self.assertEqual(resolved_doc, mock_did_doc)

        # Test HTTP error case
        mock_response.status = 404
        mock_response.raise_for_status.side_effect = aiohttp.ClientError()
        resolved_doc = await resolve_did_wba_document(did)
        self.assertIsNone(resolved_doc)

        # Test ID mismatch case
        mock_response.status = 200
        mock_response.raise_for_status.side_effect = None
        wrong_did_doc = mock_did_doc.copy()
        wrong_did_doc['id'] = 'wrong:did'
        async def wrong_json():
            return wrong_did_doc
        mock_response.json = wrong_json
        resolved_doc = await resolve_did_wba_document(did)
        self.assertIsNone(resolved_doc)

        # Test connection error case
        mock_get.side_effect = aiohttp.ClientError()
        resolved_doc = await resolve_did_wba_document(did)
        self.assertIsNone(resolved_doc)

        # Test general exception case
        mock_get.side_effect = Exception("Unexpected error")
        resolved_doc = await resolve_did_wba_document(did)
        self.assertIsNone(resolved_doc)

    def test_auth_json_generation_and_verification(self):
        """Test generation and verification of JSON format authentication"""
        # Generate a real secp256k1 key pair
        private_key = ec.generate_private_key(ec.SECP256K1())
        public_key = private_key.public_key()

        # Create public key JWK using helper function
        def _encode_base64url(data: bytes) -> str:
            return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

        def _public_key_to_jwk(public_key):
            numbers = public_key.public_numbers()
            x = _encode_base64url(numbers.x.to_bytes((numbers.x.bit_length() + 7) // 8, 'big'))
            y = _encode_base64url(numbers.y.to_bytes((numbers.y.bit_length() + 7) // 8, 'big'))
            compressed = public_key.public_bytes(
                encoding=Encoding.X962,
                format=PublicFormat.CompressedPoint
            )
            kid = _encode_base64url(hashlib.sha256(compressed).digest())
            return {
                "kty": "EC",
                "crv": "secp256k1",
                "x": x,
                "y": y,
                "kid": kid
            }

        # Create a DID document with the real key
        did_doc = {
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/jws-2020/v1",
                "https://w3id.org/security/suites/secp256k1-2019/v1"
            ],
            "id": "did:wba:example.com:user:alice",
            "verificationMethod": [{
                "id": "did:wba:example.com:user:alice#key-1",
                "type": "EcdsaSecp256k1VerificationKey2019",
                "controller": "did:wba:example.com:user:alice",
                "publicKeyJwk": _public_key_to_jwk(public_key)
            }],
            "authentication": ["did:wba:example.com:user:alice#key-1"]
        }

        service_domain = "api.example.com"

        # Create a real signing callback using the private key
        def real_sign_callback(content: bytes, vm_fragment: str) -> str:
            return private_key.sign(
                content,
                ec.ECDSA(hashes.SHA256())
            )

        # Generate authentication JSON
        auth_json = generate_auth_json(
            did_doc,
            service_domain,
            real_sign_callback
        )

        # Verify the generated JSON
        success, message = verify_auth_json_signature(
            auth_json,
            did_doc,
            service_domain
        )
        print(f"verify_auth_json_signature returns: success: {success}, message: {message}")
        self.assertTrue(success, f"Verification failed: {message}")

        # Test with invalid service domain
        wrong_success, wrong_message = verify_auth_json_signature(
            auth_json,
            did_doc,
            "wrong.domain.com"
        )
        self.assertFalse(wrong_success, "Verification should fail with wrong domain")

        # Test with tampered signature
        auth_data = json.loads(auth_json)
        auth_data['signature'] = "InvalidSignature"
        tampered_json = json.dumps(auth_data)

        tampered_success, tampered_message = verify_auth_json_signature(
            tampered_json,
            did_doc,
            service_domain
        )
        self.assertFalse(tampered_success, "Verification should fail with tampered signature")

        # Test with missing required fields
        incomplete_data = {
            "did": "did:wba:example.com:user:alice",
            "nonce": "abc123",
            # timestamp is missing
            "verification_method": "key-1",
            "signature": "some_signature"
        }
        incomplete_success, incomplete_message = verify_auth_json_signature(
            incomplete_data,
            did_doc,
            service_domain
        )
        self.assertFalse(incomplete_success, "Verification should fail with missing required fields")

        # Test with invalid JSON string
        invalid_json = "{ invalid json string"
        invalid_success, invalid_message = verify_auth_json_signature(
            invalid_json,
            did_doc,
            service_domain
        )
        self.assertFalse(invalid_success, "Verification should fail with invalid JSON string")

if __name__ == '__main__':
    unittest.main()
