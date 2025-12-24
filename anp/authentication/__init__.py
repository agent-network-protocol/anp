"""ANP Authentication - DID-WBA authentication SDK.

Modules:
    did_wba: Core DID-WBA functions (create, resolve, sign, verify)
    did_wba_authenticator: Client-side auth header generator
    did_wba_verifier: Server-side verifier with JWT support
    verification_methods: Signature verification strategies

Usage (Client):
    from anp.authentication import DIDWbaAuthHeader

    auth = DIDWbaAuthHeader(did_document_path="did.json", private_key_path="key.pem")
    headers = auth.get_auth_header("https://example.com")

Usage (Server):
    from anp.authentication import DidWbaVerifier, DidWbaVerifierConfig

    verifier = DidWbaVerifier(DidWbaVerifierConfig(jwt_private_key=..., jwt_public_key=...))
    result = await verifier.verify_auth_header(authorization, domain)
"""

# Core DID-WBA functions
from .did_wba import (
    create_did_wba_document,
    extract_auth_header_parts,
    generate_auth_header,
    generate_auth_json,
    resolve_did_wba_document,
    resolve_did_wba_document_sync,
    verify_auth_header_signature,
    verify_auth_json_signature,
)

# Client-side authentication
from .did_wba_authenticator import DIDWbaAuthHeader

# Server-side verification
from .did_wba_verifier import (
    DidWbaVerifier,
    DidWbaVerifierConfig,
    DidWbaVerifierError,
)

# Verification method abstractions (for custom implementations)
from .verification_methods import (
    CURVE_MAPPING,
    EcdsaSecp256k1VerificationKey2019,
    Ed25519VerificationKey2018,
    VerificationMethod,
    create_verification_method,
)

__all__ = [
    # Core functions
    "create_did_wba_document",
    "resolve_did_wba_document",
    "resolve_did_wba_document_sync",
    "generate_auth_header",
    "generate_auth_json",
    "verify_auth_header_signature",
    "verify_auth_json_signature",
    "extract_auth_header_parts",
    # Client
    "DIDWbaAuthHeader",
    # Server
    "DidWbaVerifier",
    "DidWbaVerifierConfig",
    "DidWbaVerifierError",
    # Verification methods (extensible)
    "VerificationMethod",
    "EcdsaSecp256k1VerificationKey2019",
    "Ed25519VerificationKey2018",
    "create_verification_method",
    "CURVE_MAPPING",
]