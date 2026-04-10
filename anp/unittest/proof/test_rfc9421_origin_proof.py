"""Tests for RFC 9421 origin proof helpers."""

from __future__ import annotations

import unittest
from copy import deepcopy

import jcs
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from anp.authentication import create_did_wba_document
from anp.proof import (
    RFC9421_ORIGIN_PROOF_DEFAULT_LABEL,
    IM_PROOF_DEFAULT_COMPONENTS,
    Rfc9421OriginProofGenerationOptions,
    Rfc9421OriginProofVerificationOptions,
    build_logical_target_uri,
    build_signed_request_object,
    canonicalize_signed_request_object,
    generate_rfc9421_origin_proof,
    verify_rfc9421_origin_proof,
)


class TestRFC9421OriginProof(unittest.TestCase):
    def test_signed_request_object_canonicalization_omits_local_wrapper_fields(self):
        signed_request_object = build_signed_request_object(
            "direct.send",
            {
                "anp_version": "1.0",
                "profile": "anp.direct.base.v1",
                "security_profile": "transport-protected",
                "sender_did": "did:wba:example.com:user:alice:e1_alice",
                "target": {
                    "kind": "agent",
                    "did": "did:wba:example.com:user:bob:e1_bob",
                },
                "operation_id": "op-1",
                "message_id": "msg-1",
                "content_type": "text/plain",
            },
            {"text": "hello"},
        )
        canonical = canonicalize_signed_request_object(signed_request_object)
        self.assertEqual(
            canonical,
            jcs.canonicalize(
                {
                    "method": "direct.send",
                    "meta": signed_request_object["meta"],
                    "body": {"text": "hello"},
                }
            ),
        )
        self.assertNotIn(b'"auth"', canonical)
        self.assertNotIn(b'"client"', canonical)
        self.assertNotIn(b'"jsonrpc"', canonical)
        self.assertNotIn(b'"id"', canonical)

    def test_build_logical_target_uri_uses_percent_encoded_did(self):
        target_uri = build_logical_target_uri(
            "service",
            "did:wba:example.com:services:message:e1_service",
        )
        self.assertEqual(
            target_uri,
            "anp://service/did%3Awba%3Aexample.com%3Aservices%3Amessage%3Ae1_service",
        )

    def test_generate_and_verify_direct_origin_proof(self):
        bundle, keys = create_did_wba_document(
            "example.com",
            path_segments=["user", "alice"],
            did_profile="e1",
        )
        private_key = load_pem_private_key(keys["key-1"][0], password=None)
        meta = {
            "anp_version": "1.0",
            "profile": "anp.direct.base.v1",
            "security_profile": "transport-protected",
            "sender_did": bundle["id"],
            "target": {
                "kind": "agent",
                "did": "did:wba:example.com:user:bob:e1_bob",
            },
            "operation_id": "op-1",
            "message_id": "msg-1",
            "content_type": "text/plain",
        }
        body = {"text": "hello"}

        proof = generate_rfc9421_origin_proof(
            "direct.send",
            meta,
            body,
            private_key,
            f"{bundle['id']}#key-1",
            options=Rfc9421OriginProofGenerationOptions(
                created=1712000000,
                nonce="nonce-1",
            ),
        )
        result = verify_rfc9421_origin_proof(
            proof,
            "direct.send",
            meta,
            body,
            did_document=bundle,
            options=Rfc9421OriginProofVerificationOptions(
                expected_signer_did=bundle["id"],
            ),
        )
        self.assertEqual(result.parsed_signature_input.label, RFC9421_ORIGIN_PROOF_DEFAULT_LABEL)
        self.assertEqual(
            result.parsed_signature_input.components,
            tuple(IM_PROOF_DEFAULT_COMPONENTS),
        )

    def test_generate_and_verify_group_create_origin_proof(self):
        bundle, keys = create_did_wba_document(
            "example.com",
            path_segments=["user", "alice"],
            did_profile="e1",
        )
        private_key = load_pem_private_key(keys["key-1"][0], password=None)
        service_did = "did:wba:example.com:services:message:e1_service"
        meta = {
            "anp_version": "1.0",
            "profile": "anp.group.base.v1",
            "security_profile": "transport-protected",
            "sender_did": bundle["id"],
            "target": {"kind": "service", "did": service_did},
            "operation_id": "op-group-create-1",
            "content_type": "application/json",
        }
        body = {
            "group_profile": {"display_name": "Demo"},
            "group_policy": {
                "admission_mode": "open-join",
                "permissions": {
                    "send": "member",
                    "add": "admin",
                    "remove": "admin",
                    "update_profile": "admin",
                    "update_policy": "owner",
                },
            },
        }

        proof = generate_rfc9421_origin_proof(
            "group.create",
            meta,
            body,
            private_key,
            f"{bundle['id']}#key-1",
            options=Rfc9421OriginProofGenerationOptions(
                created=1712000100,
                nonce="nonce-group-create",
            ),
        )
        result = verify_rfc9421_origin_proof(
            proof,
            "group.create",
            meta,
            body,
            did_document=bundle,
            options=Rfc9421OriginProofVerificationOptions(
                expected_signer_did=bundle["id"],
            ),
        )
        self.assertEqual(result.parsed_signature_input.nonce, "nonce-group-create")

    def test_rejects_non_sig1_signature_label(self):
        bundle, keys = create_did_wba_document(
            "example.com",
            path_segments=["user", "alice"],
            did_profile="e1",
        )
        private_key = load_pem_private_key(keys["key-1"][0], password=None)
        meta = {
            "anp_version": "1.0",
            "profile": "anp.direct.base.v1",
            "security_profile": "transport-protected",
            "sender_did": bundle["id"],
            "target": {
                "kind": "agent",
                "did": "did:wba:example.com:user:bob:e1_bob",
            },
            "operation_id": "op-2",
            "message_id": "msg-2",
            "content_type": "text/plain",
        }
        with self.assertRaisesRegex(ValueError, "signature label sig1"):
            generate_rfc9421_origin_proof(
                "direct.send",
                meta,
                {"text": "hello"},
                private_key,
                f"{bundle['id']}#key-1",
                options=Rfc9421OriginProofGenerationOptions(label="sig2"),
            )

    def test_rejects_signature_input_with_extra_component(self):
        bundle, keys = create_did_wba_document(
            "example.com",
            path_segments=["user", "alice"],
            did_profile="e1",
        )
        private_key = load_pem_private_key(keys["key-1"][0], password=None)
        meta = {
            "anp_version": "1.0",
            "profile": "anp.direct.base.v1",
            "security_profile": "transport-protected",
            "sender_did": bundle["id"],
            "target": {
                "kind": "agent",
                "did": "did:wba:example.com:user:bob:e1_bob",
            },
            "operation_id": "op-3",
            "message_id": "msg-3",
            "content_type": "text/plain",
        }
        body = {"text": "hello"}
        proof = generate_rfc9421_origin_proof(
            "direct.send",
            meta,
            body,
            private_key,
            f"{bundle['id']}#key-1",
            options=Rfc9421OriginProofGenerationOptions(
                created=1712000200,
                nonce="nonce-extra-component",
            ),
        )
        tampered = deepcopy(proof)
        tampered["signatureInput"] = tampered["signatureInput"].replace(
            '("@method" "@target-uri" "content-digest")',
            '("@method" "@target-uri" "content-digest" "@authority")',
        )
        with self.assertRaisesRegex(ValueError, "covered components"):
            verify_rfc9421_origin_proof(
                tampered,
                "direct.send",
                meta,
                body,
                did_document=bundle,
                options=Rfc9421OriginProofVerificationOptions(
                    expected_signer_did=bundle["id"],
                ),
            )


if __name__ == "__main__":
    unittest.main()
