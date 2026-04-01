"""Tests for ANP IM business proof helpers."""

from __future__ import annotations

import json
import unittest

from cryptography.hazmat.primitives.serialization import load_pem_private_key

from anp.authentication import create_did_wba_document
from anp.proof import (
    build_im_content_digest,
    build_im_signature_input,
    decode_im_signature,
    encode_im_signature,
    generate_im_proof,
    parse_im_signature_input,
    verify_im_proof,
)


def _build_signature_base(
    *,
    method: str,
    target_uri: str,
    content_digest: str,
    signature_input: str,
) -> bytes:
    parsed = parse_im_signature_input(signature_input)
    component_values = {
        "@method": method,
        "@target-uri": target_uri,
        "content-digest": content_digest,
    }
    lines = [f'"{component}": {component_values[component]}' for component in parsed.components]
    lines.append(f'"@signature-params": {parsed.signature_params}')
    return "\n".join(lines).encode("utf-8")


class TestImProof(unittest.TestCase):
    def test_generate_and_verify_e1_im_proof(self):
        bundle, keys = create_did_wba_document(
            "example.com",
            path_segments=["user", "alice"],
            did_profile="e1",
        )
        private_key = load_pem_private_key(keys["key-1"][0], password=None)
        payload = json.dumps({"text": "hello"}, separators=(",", ":")).encode("utf-8")
        signature_input = build_im_signature_input(
            f"{bundle['id']}#key-1",
            nonce="nonce-1",
            created=1712000000,
        )
        signature_base = _build_signature_base(
            method="direct.send",
            target_uri=f"anp://agent/{bundle['id']}",
            content_digest=build_im_content_digest(payload),
            signature_input=signature_input,
        )

        proof = generate_im_proof(
            payload,
            signature_base,
            private_key,
            f"{bundle['id']}#key-1",
            nonce="nonce-1",
            created=1712000000,
        )

        result = verify_im_proof(
            proof,
            payload,
            signature_base,
            did_document=bundle,
            expected_signer_did=bundle["id"],
        )
        self.assertEqual(result.parsed_signature_input.keyid, f"{bundle['id']}#key-1")
        self.assertEqual(result.parsed_signature_input.nonce, "nonce-1")

    def test_generate_and_verify_k1_im_proof(self):
        bundle, keys = create_did_wba_document(
            "example.com",
            path_segments=["user", "bob"],
            did_profile="k1",
        )
        private_key = load_pem_private_key(keys["key-1"][0], password=None)
        payload = b'{"text":"hello-k1"}'
        proof = generate_im_proof(
            payload,
            _build_signature_base(
                method="group.send",
                target_uri=f"anp://group/{bundle['id']}",
                content_digest=build_im_content_digest(payload),
                signature_input=build_im_signature_input(
                    f"{bundle['id']}#key-1",
                    nonce="nonce-k1",
                    created=1712000100,
                ),
            ),
            private_key,
            f"{bundle['id']}#key-1",
            nonce="nonce-k1",
            created=1712000100,
        )
        result = verify_im_proof(
            proof,
            payload,
            _build_signature_base(
                method="group.send",
                target_uri=f"anp://group/{bundle['id']}",
                content_digest=proof["contentDigest"],
                signature_input=proof["signatureInput"],
            ),
            did_document=bundle,
            expected_signer_did=bundle["id"],
        )
        self.assertEqual(result.parsed_signature_input.nonce, "nonce-k1")

    def test_rejects_tampered_payload(self):
        bundle, keys = create_did_wba_document("example.com", path_segments=["user", "eve"])
        private_key = load_pem_private_key(keys["key-1"][0], password=None)
        payload = b'{"text":"hello"}'
        proof = generate_im_proof(
            payload,
            _build_signature_base(
                method="direct.send",
                target_uri=f"anp://agent/{bundle['id']}",
                content_digest=build_im_content_digest(payload),
                signature_input=build_im_signature_input(f"{bundle['id']}#key-1"),
            ),
            private_key,
            f"{bundle['id']}#key-1",
        )
        with self.assertRaisesRegex(ValueError, "contentDigest"):
            verify_im_proof(
                proof,
                b'{"text":"tampered"}',
                _build_signature_base(
                    method="direct.send",
                    target_uri=f"anp://agent/{bundle['id']}",
                    content_digest=build_im_content_digest(payload),
                    signature_input=proof["signatureInput"],
                ),
                did_document=bundle,
                expected_signer_did=bundle["id"],
            )

    def test_rejects_wrong_signer_did(self):
        bundle, keys = create_did_wba_document("example.com", path_segments=["user", "mallory"])
        private_key = load_pem_private_key(keys["key-1"][0], password=None)
        payload = b'{"text":"hello"}'
        proof = generate_im_proof(
            payload,
            _build_signature_base(
                method="direct.send",
                target_uri=f"anp://agent/{bundle['id']}",
                content_digest=build_im_content_digest(payload),
                signature_input=build_im_signature_input(f"{bundle['id']}#key-1"),
            ),
            private_key,
            f"{bundle['id']}#key-1",
        )
        with self.assertRaisesRegex(ValueError, "expected signer DID"):
            verify_im_proof(
                proof,
                payload,
                _build_signature_base(
                    method="direct.send",
                    target_uri=f"anp://agent/{bundle['id']}",
                    content_digest=proof["contentDigest"],
                    signature_input=proof["signatureInput"],
                ),
                did_document=bundle,
                expected_signer_did="did:wba:example.com:user:other:e1_xxx",
            )

    def test_signature_helpers_round_trip(self):
        signature = encode_im_signature(b"hello", label="sig2")
        label, decoded = decode_im_signature(signature)
        self.assertEqual(label, "sig2")
        self.assertEqual(decoded, b"hello")

