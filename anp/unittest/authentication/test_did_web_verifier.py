"""HTTP authentication uses DID method dispatch and current key purposes."""

import base64
import copy
from unittest.mock import AsyncMock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from anp.proof.object_proof import generate_object_proof, verify_object_proof

from anp.authentication import (
    DidWbaVerifier,
    DidWbaVerifierConfig,
    DidWbaVerifierError,
    generate_http_signature_headers,
)


@pytest.mark.asyncio
async def test_web_http_auth_bearer_and_negative_boundaries():
    # A Web path named e1_* must never trigger WBA thumbprint/root proof rules.
    did = "did:web:example.com:users:e1_web-path"
    keyid = did + "#request"
    private = Ed25519PrivateKey.generate()
    public = (
        base64.urlsafe_b64encode(private.public_key().public_bytes_raw())
        .decode()
        .rstrip("=")
    )
    document = {
        "id": did,
        "verificationMethod": [
            {
                "id": keyid,
                "controller": did,
                "type": "JsonWebKey2020",
                "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": public},
            }
        ],
        "authentication": [keyid],
        "assertionMethod": [keyid],
    }
    url, body = "https://api.example.com/orders", b'{"item":"book"}'
    headers = generate_http_signature_headers(
        document, url, "POST", lambda data, _: private.sign(data), body=body
    )
    verifier = DidWbaVerifier(
        DidWbaVerifierConfig(
            jwt_algorithm="HS256",
            jwt_private_key="unit-test-secret-32-bytes-minimum",
            jwt_public_key="unit-test-secret-32-bytes-minimum",
        )
    )
    with patch(
        "anp.authentication.did_wba_verifier.resolve_did_document",
        AsyncMock(return_value=document),
    ):
        for wrong_url, wrong_body in [
            (url + "/other", body),
            (url, b'{"item":"music"}'),
        ]:
            with pytest.raises(DidWbaVerifierError):
                await verifier.verify_request(
                    method="POST", url=wrong_url, headers=headers, body=wrong_body
                )
        first = await verifier.verify_request(
            method="POST", url=url, headers=headers, body=body
        )
        assert first["did"] == did and first["auth_scheme"] == "http_signatures"
        assert "deviceManifest" not in document
        with pytest.raises(DidWbaVerifierError, match="nonce"):
            await verifier.verify_request(
                method="POST", url=url, headers=headers, body=body
            )
    token_result = await verifier.verify_request(
        method="POST",
        url=url,
        headers={"Authorization": "Bearer " + first["access_token"]},
        body=body,
    )
    assert token_result["did"] == did
    assertion_only = copy.deepcopy(document)
    assertion_only.pop("authentication")
    group_object = generate_object_proof(
        {"group_did": did, "epoch": 3},
        private,
        keyid,
        issuer_did=did,
    )
    assert (
        verify_object_proof(
            group_object,
            issuer_did=did,
            issuer_did_document=assertion_only,
        ).issuer_did
        == did
    )
    group_object["epoch"] = 4
    with pytest.raises(ValueError):
        verify_object_proof(
            group_object, issuer_did=did, issuer_did_document=assertion_only
        )
    with patch(
        "anp.authentication.did_wba_verifier.resolve_did_document",
        AsyncMock(return_value=assertion_only),
    ):
        with pytest.raises(DidWbaVerifierError, match="not authorized"):
            await verifier.verify_request(
                method="POST", url=url, headers=headers, body=body
            )
