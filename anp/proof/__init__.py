"""W3C Data Integrity Proof and RFC 9421 origin proof module for ANP.

Provides general-purpose W3C-compatible Proof generation and verification
for JSON documents, supporting multiple signature suites, and high-level
RFC 9421 origin proof helpers for ANP request objects.

Supported proof types:
- EcdsaSecp256k1Signature2019 (secp256k1 ECDSA + SHA-256)
- Ed25519Signature2020 (Ed25519)
- DataIntegrityProof + eddsa-jcs-2022
- DataIntegrityProof + didwba-jcs-ecdsa-secp256k1-2025

Example:
    >>> from anp.proof import generate_w3c_proof, verify_w3c_proof
    >>> proof = generate_w3c_proof(
    ...     document={"id": "example"},
    ...     private_key=my_private_key,
    ...     verification_method="did:wba:example.com#key-1",
    ...     proof_purpose="assertionMethod",
    ... )
    >>> is_valid = verify_w3c_proof(proof, public_key)
"""

from .proof import (
    generate_w3c_proof,
    verify_w3c_proof,
    PROOF_TYPE_SECP256K1,
    PROOF_TYPE_ED25519,
    PROOF_TYPE_DATA_INTEGRITY,
    CRYPTOSUITE_EDDSA_JCS_2022,
    CRYPTOSUITE_DIDWBA_SECP256K1_2025,
)
from .group_receipt import (
    GROUP_RECEIPT_PROOF_PURPOSE,
    GROUP_RECEIPT_REQUIRED_FIELDS,
    generate_group_receipt_proof,
    verify_group_receipt_proof,
)
from .rfc9421_origin import (
    RFC9421_ORIGIN_PROOF_DEFAULT_COMPONENTS,
    RFC9421_ORIGIN_PROOF_DEFAULT_LABEL,
    TARGET_KIND_AGENT,
    TARGET_KIND_GROUP,
    TARGET_KIND_SERVICE,
    Rfc9421OriginProof,
    Rfc9421OriginProofError,
    Rfc9421OriginProofGenerationOptions,
    Rfc9421OriginProofVerificationOptions,
    SignedRequestObject,
    build_logical_target_uri,
    build_rfc9421_origin_signature_base,
    build_signed_request_object,
    canonicalize_signed_request_object,
    generate_rfc9421_origin_proof,
    verify_rfc9421_origin_proof,
)
from .im import (
    IM_PROOF_DEFAULT_COMPONENTS,
    IM_PROOF_RELATION_ASSERTION_METHOD,
    IM_PROOF_RELATION_AUTHENTICATION,
    ImProofError,
    ImProofVerificationResult,
    ParsedImSignatureInput,
    build_im_content_digest,
    verify_im_content_digest,
    build_im_signature_input,
    parse_im_signature_input,
    encode_im_signature,
    decode_im_signature,
    generate_im_proof,
    verify_im_proof,
)

__all__ = [
    "RFC9421_ORIGIN_PROOF_DEFAULT_COMPONENTS",
    "RFC9421_ORIGIN_PROOF_DEFAULT_LABEL",
    "TARGET_KIND_AGENT",
    "TARGET_KIND_GROUP",
    "TARGET_KIND_SERVICE",
    "SignedRequestObject",
    "Rfc9421OriginProof",
    "Rfc9421OriginProofError",
    "Rfc9421OriginProofGenerationOptions",
    "Rfc9421OriginProofVerificationOptions",
    "build_signed_request_object",
    "canonicalize_signed_request_object",
    "build_logical_target_uri",
    "build_rfc9421_origin_signature_base",
    "generate_rfc9421_origin_proof",
    "verify_rfc9421_origin_proof",
    "generate_w3c_proof",
    "verify_w3c_proof",
    "PROOF_TYPE_SECP256K1",
    "PROOF_TYPE_ED25519",
    "PROOF_TYPE_DATA_INTEGRITY",
    "CRYPTOSUITE_EDDSA_JCS_2022",
    "CRYPTOSUITE_DIDWBA_SECP256K1_2025",
    "GROUP_RECEIPT_PROOF_PURPOSE",
    "GROUP_RECEIPT_REQUIRED_FIELDS",
    "generate_group_receipt_proof",
    "verify_group_receipt_proof",
    "IM_PROOF_DEFAULT_COMPONENTS",
    "IM_PROOF_RELATION_AUTHENTICATION",
    "IM_PROOF_RELATION_ASSERTION_METHOD",
    "ImProofError",
    "ImProofVerificationResult",
    "ParsedImSignatureInput",
    "build_im_content_digest",
    "verify_im_content_digest",
    "build_im_signature_input",
    "parse_im_signature_input",
    "encode_im_signature",
    "decode_im_signature",
    "generate_im_proof",
    "verify_im_proof",
]
