# AgentConnect: https://github.com/agent-network-protocol/AgentConnect
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: https://agent-network-protocol.com/
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.


import base64
import json
import unittest
from datetime import datetime, timezone

from ecdsa import NIST256p, SigningKey

from agent_connect.agent_description.proof import generate_proof, verify_proof


class TestProof(unittest.TestCase):
    def setUp(self):
        """
        Setup test environment with ECDSA keys and a sample document
        """
        # Generate ECDSA key pair (secp256r1 curve, also known as NIST P-256)
        self.private_key = SigningKey.generate(curve=NIST256p)
        self.public_key = self.private_key.get_verifying_key()

        # Create a sample document
        self.document = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://agent-network-protocol.com/2023/credentials/v1"
            ],
            "@type": "ad:AgentDescription",
            "id": "did:wba:example.com:user:alice",
            "name": "Alice's Agent",
            "description": "A test agent for unit testing",
            "version": "1.0.0",
            "endpoint": "https://example.com/alice/agent",
            "proof": {
                "type": "EcdsaSecp256r1Signature2019",
                "created": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                "proofPurpose": "assertionMethod",
                "verificationMethod": "did:wba:example.com:user:alice#keys-1",
                "challenge": "1234567890"
            }
        }

    def sign_callback(self, hash_bytes: bytes) -> bytes:
        """
        Sign hash bytes using ECDSA private key
        """
        return self.private_key.sign(hash_bytes)

    def verify_callback(self, hash_bytes: bytes, signature_bytes: bytes) -> bool:
        """
        Verify signature using ECDSA public key
        """
        try:
            self.public_key.verify(signature_bytes, hash_bytes)
            return True
        except:
            return False

    def test_generate_and_verify_proof(self):
        """
        Test the complete flow of generating and verifying a signature
        """
        # Generate signature
        signed_doc = generate_proof(self.document, self.sign_callback)

        print(f"signed_doc: {signed_doc}")

        # Verify document structure
        self.assertIn("proof", signed_doc)
        self.assertIn("proofValue", signed_doc["proof"])

        # Verify proofValue is a URL-safe base64 string
        proof_value = signed_doc["proof"]["proofValue"]
        try:
            # Try to decode proofValue
            decoded = base64.urlsafe_b64decode(proof_value)
        except Exception as e:
            self.fail(f"proofValue is not a valid URL-safe base64 string: {e}")

        # Verify signature
        is_valid = verify_proof(signed_doc, self.verify_callback)
        self.assertTrue(is_valid)

    def test_verify_tampered_document(self):
        """
        Test verification failure when document content is tampered
        """
        # Generate signature
        signed_doc = generate_proof(self.document, self.sign_callback)

        # Tamper with document
        tampered_doc = json.loads(json.dumps(signed_doc))
        tampered_doc["name"] = "Tampered Name"

        # Verification should fail
        is_valid = verify_proof(tampered_doc, self.verify_callback)
        self.assertFalse(is_valid)

    def test_verify_tampered_signature(self):
        """
        Test verification failure when signature is tampered
        """
        # Generate signature
        signed_doc = generate_proof(self.document, self.sign_callback)

        # Tamper with signature
        tampered_doc = json.loads(json.dumps(signed_doc))
        original_signature = tampered_doc["proof"]["proofValue"]
        # Modify the last character of the signature
        tampered_doc["proof"]["proofValue"] = original_signature[:-1] + ('1' if original_signature[-1] != '1' else '2')

        # Verification should fail
        is_valid = verify_proof(tampered_doc, self.verify_callback)
        self.assertFalse(is_valid)

    def test_missing_proof(self):
        """
        Test error handling when proof field is missing
        """
        doc_without_proof = json.loads(json.dumps(self.document))
        del doc_without_proof["proof"]

        with self.assertRaises(ValueError):
            generate_proof(doc_without_proof, self.sign_callback)

    def test_invalid_input_types(self):
        """
        Test error handling for invalid input types
        """
        # Test non-dict input
        with self.assertRaises(ValueError):
            generate_proof("not a dict", self.sign_callback)

        # Test non-callback function
        with self.assertRaises(ValueError):
            generate_proof(self.document, "not a callback")

if __name__ == '__main__':
    unittest.main()
