"""W3C Data Integrity Proof module for ANP.

Provides general-purpose W3C-compatible Proof generation and verification
for JSON documents, supporting multiple signature suites.

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

__all__ = [
    "generate_w3c_proof",
    "verify_w3c_proof",
    "PROOF_TYPE_SECP256K1",
    "PROOF_TYPE_ED25519",
    "PROOF_TYPE_DATA_INTEGRITY",
    "CRYPTOSUITE_EDDSA_JCS_2022",
    "CRYPTOSUITE_DIDWBA_SECP256K1_2025",
]
