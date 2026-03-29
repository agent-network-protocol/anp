"""Compatibility tests for legacy k1 DIDWba requests through OpenANP middleware."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, patch

fastapi = pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from anp.authentication import DidWbaVerifierConfig, create_did_wba_document, generate_auth_header
from anp.openanp.middleware import create_auth_middleware
from anp.proof import PROOF_TYPE_SECP256K1, generate_w3c_proof, verify_w3c_proof


def _generate_rsa_pem_pair() -> tuple[str, str]:
    """Generate a JWT RSA key pair for middleware tests."""
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


def _sign_callback(private_key_pem: bytes):
    """Build a signature callback from a PEM-encoded secp256k1 key."""
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)

    def _callback(content: bytes, verification_method: str) -> bytes:
        if not isinstance(private_key, ec.EllipticCurvePrivateKey):
            raise TypeError("Expected an EC private key for legacy DIDWba auth")
        return private_key.sign(content, ec.ECDSA(hashes.SHA256()))

    return _callback


def _build_legacy_k1_document() -> tuple[dict, dict]:
    """Build a k1 DID document carrying the legacy secp256k1 proof."""
    did_document, keys = create_did_wba_document(
        "example.com",
        path_segments=["user", "middleware-alice"],
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


def test_legacy_k1_request_and_bearer_followup_work_through_openanp_middleware():
    """OpenANP middleware should accept a legacy k1 request and a Bearer follow-up."""
    did_document, keys = _build_legacy_k1_document()
    public_key = serialization.load_pem_public_key(keys["key-1"][1])
    assert verify_w3c_proof(did_document, public_key)

    jwt_private_key, jwt_public_key = _generate_rsa_pem_pair()
    app = FastAPI()
    app.middleware("http")(
        create_auth_middleware(
            DidWbaVerifierConfig(
                jwt_private_key=jwt_private_key,
                jwt_public_key=jwt_public_key,
            ),
            exempt_paths=[],
        )
    )

    @app.get("/secure")
    async def secure_endpoint(request: Request):
        return JSONResponse(
            {
                "did": request.state.did,
                "auth_scheme": request.state.auth_result.get("auth_scheme"),
            }
        )

    authorization = generate_auth_header(
        did_document,
        "testserver",
        _sign_callback(keys["key-1"][0]),
        version="1.1",
    )

    with patch(
        "anp.authentication.did_wba_verifier.resolve_did_wba_document",
        AsyncMock(return_value=did_document),
    ):
        with TestClient(app) as client:
            first_response = client.get(
                "/secure",
                headers={"Authorization": authorization},
            )
            assert first_response.status_code == 200
            assert first_response.json()["did"] == did_document["id"]
            assert first_response.json()["auth_scheme"] == "legacy_didwba"
            assert "Authentication-Info" in first_response.headers
            assert "Authorization" in first_response.headers

            second_response = client.get(
                "/secure",
                headers={"Authorization": first_response.headers["Authorization"]},
            )
            assert second_response.status_code == 200
            assert second_response.json()["did"] == did_document["id"]
            assert second_response.json()["auth_scheme"] == "bearer"
