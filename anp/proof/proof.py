# AgentConnect: https://github.com/agent-network-protocol/AgentConnect
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: https://agent-network-protocol.com/
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.

"""W3C Data Integrity Proof generation and verification.

Implements proof generation and verification following the W3C Data Integrity
specification (https://www.w3.org/TR/vc-data-integrity/), adapted for ANP
use cases with JCS canonicalization (RFC 8785).

Flow:
    1. Canonicalize the document (excluding any existing proof) using JCS
    2. Canonicalize the proof options (type, created, verificationMethod, proofPurpose)
    3. Hash both with SHA-256
    4. Concatenate hashes: hash(proof_options) || hash(document)
    5. Sign the concatenated bytes with the private key
    6. Encode signature as base64url → proofValue
    7. Attach proof object to document

Supported Proof Types:
    - EcdsaSecp256k1Signature2019: ECDSA with secp256k1 curve + SHA-256
    - Ed25519Signature2020: Ed25519 (RFC 8032)
"""

import base64
import copy
import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Union

import jcs
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils
from cryptography.hazmat.primitives import hashes, serialization

# Proof type constants
PROOF_TYPE_SECP256K1 = "EcdsaSecp256k1Signature2019"
PROOF_TYPE_ED25519 = "Ed25519Signature2020"

# Mapping from proof type to key type for validation
_PROOF_TYPE_KEY_MAP = {
    PROOF_TYPE_SECP256K1: ec.EllipticCurvePrivateKey,
    PROOF_TYPE_ED25519: ed25519.Ed25519PrivateKey,
}

_PROOF_TYPE_PUBLIC_KEY_MAP = {
    PROOF_TYPE_SECP256K1: ec.EllipticCurvePublicKey,
    PROOF_TYPE_ED25519: ed25519.Ed25519PublicKey,
}


def _b64url_encode(data: bytes) -> str:
    """Encode bytes as base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    """Decode base64url string (with or without padding)."""
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def _canonicalize(obj: Dict[str, Any]) -> bytes:
    """Canonicalize a JSON object using JCS (RFC 8785).

    Args:
        obj: JSON-serializable dictionary.

    Returns:
        Canonical byte representation.
    """
    return jcs.canonicalize(obj)


def _hash_bytes(data: bytes) -> bytes:
    """Compute SHA-256 hash of bytes."""
    return hashlib.sha256(data).digest()


def _sign_secp256k1(private_key: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
    """Sign data with secp256k1 ECDSA, return R||S raw signature."""
    der_sig = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der_sig)
    # Fixed 32-byte encoding for each component
    r_bytes = r.to_bytes(32, byteorder="big")
    s_bytes = s.to_bytes(32, byteorder="big")
    return r_bytes + s_bytes


def _verify_secp256k1(
    public_key: ec.EllipticCurvePublicKey, data: bytes, signature: bytes
) -> bool:
    """Verify secp256k1 ECDSA signature (R||S format)."""
    try:
        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
        der_sig = utils.encode_dss_signature(r, s)
        public_key.verify(der_sig, data, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def _sign_ed25519(private_key: ed25519.Ed25519PrivateKey, data: bytes) -> bytes:
    """Sign data with Ed25519."""
    return private_key.sign(data)


def _verify_ed25519(
    public_key: ed25519.Ed25519PublicKey, data: bytes, signature: bytes
) -> bool:
    """Verify Ed25519 signature."""
    try:
        public_key.verify(signature, data)
        return True
    except Exception:
        return False


def _compute_signing_input(
    document: Dict[str, Any], proof_options: Dict[str, Any]
) -> bytes:
    """Compute the data to be signed.

    Following W3C Data Integrity:
        toBeSigned = hash(canonicalize(proof_options)) || hash(canonicalize(document))

    Args:
        document: The document to sign (without proof field).
        proof_options: Proof options (type, created, verificationMethod, proofPurpose).

    Returns:
        Concatenated hash bytes ready for signing.
    """
    doc_hash = _hash_bytes(_canonicalize(document))
    options_hash = _hash_bytes(_canonicalize(proof_options))
    return options_hash + doc_hash


def generate_w3c_proof(
    document: Dict[str, Any],
    private_key: Union[ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey],
    verification_method: str,
    proof_purpose: str = "assertionMethod",
    proof_type: Optional[str] = None,
    created: Optional[str] = None,
    domain: Optional[str] = None,
    challenge: Optional[str] = None,
) -> Dict[str, Any]:
    """Generate a W3C Data Integrity Proof for a JSON document.

    Generates a proof object and returns a new document with the proof attached.
    The original document is not modified.

    Args:
        document: JSON document to sign. Any existing "proof" field is excluded
            from signing but preserved in the output.
        private_key: Private key for signing. Type determines proof_type if not
            specified explicitly:
            - ec.EllipticCurvePrivateKey (secp256k1) → EcdsaSecp256k1Signature2019
            - ed25519.Ed25519PrivateKey → Ed25519Signature2020
        verification_method: Full DID URL of the verification method,
            e.g. "did:wba:example.com#key-1".
        proof_purpose: The purpose of the proof. Common values:
            - "assertionMethod": General assertions/claims
            - "authentication": Proving control of DID
            - "capabilityInvocation": Invoking a capability
            - "capabilityDelegation": Delegating a capability
        proof_type: Explicit proof type. If None, auto-detected from key type.
        created: ISO 8601 timestamp. If None, uses current UTC time.
        domain: Optional domain restriction for the proof.
        challenge: Optional challenge string for the proof.

    Returns:
        New dict containing the original document fields plus a "proof" field.

    Raises:
        ValueError: If key type doesn't match proof_type, or key type is
            unsupported.

    Example:
        >>> from cryptography.hazmat.primitives.asymmetric import ec
        >>> private_key = ec.generate_private_key(ec.SECP256K1())
        >>> doc = {"id": "did:wba:example.com", "name": "Agent Alice"}
        >>> signed_doc = generate_w3c_proof(
        ...     document=doc,
        ...     private_key=private_key,
        ...     verification_method="did:wba:example.com#key-1",
        ... )
        >>> "proof" in signed_doc
        True
    """
    # Auto-detect proof type from key
    if proof_type is None:
        if isinstance(private_key, ec.EllipticCurvePrivateKey):
            proof_type = PROOF_TYPE_SECP256K1
        elif isinstance(private_key, ed25519.Ed25519PrivateKey):
            proof_type = PROOF_TYPE_ED25519
        else:
            raise ValueError(
                f"Unsupported private key type: {type(private_key).__name__}. "
                f"Supported: EllipticCurvePrivateKey (secp256k1), Ed25519PrivateKey"
            )

    # Validate key type matches proof type
    expected_key_type = _PROOF_TYPE_KEY_MAP.get(proof_type)
    if expected_key_type is None:
        raise ValueError(
            f"Unsupported proof type: {proof_type}. "
            f"Supported: {PROOF_TYPE_SECP256K1}, {PROOF_TYPE_ED25519}"
        )
    if not isinstance(private_key, expected_key_type):
        raise ValueError(
            f"Key type mismatch: proof type '{proof_type}' requires "
            f"{expected_key_type.__name__}, got {type(private_key).__name__}"
        )

    # Prepare timestamp
    if created is None:
        created = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Build proof options (used for hashing, without proofValue)
    proof_options = {
        "type": proof_type,
        "created": created,
        "verificationMethod": verification_method,
        "proofPurpose": proof_purpose,
    }
    if domain is not None:
        proof_options["domain"] = domain
    if challenge is not None:
        proof_options["challenge"] = challenge

    # Remove existing proof from document for signing
    doc_without_proof = {k: v for k, v in document.items() if k != "proof"}

    # Compute signing input
    to_be_signed = _compute_signing_input(doc_without_proof, proof_options)

    # Sign
    if proof_type == PROOF_TYPE_SECP256K1:
        signature = _sign_secp256k1(private_key, to_be_signed)
    elif proof_type == PROOF_TYPE_ED25519:
        signature = _sign_ed25519(private_key, to_be_signed)

    # Encode signature
    proof_value = _b64url_encode(signature)

    # Build complete proof object
    proof = dict(proof_options)
    proof["proofValue"] = proof_value

    # Return new document with proof
    result = copy.deepcopy(document)
    result["proof"] = proof
    return result


def verify_w3c_proof(
    document: Dict[str, Any],
    public_key: Union[ec.EllipticCurvePublicKey, ed25519.Ed25519PublicKey],
    expected_purpose: Optional[str] = None,
    expected_domain: Optional[str] = None,
    expected_challenge: Optional[str] = None,
) -> bool:
    """Verify a W3C Data Integrity Proof on a JSON document.

    Args:
        document: Document containing a "proof" field with the standard
            W3C proof structure (type, created, verificationMethod,
            proofPurpose, proofValue).
        public_key: Public key for signature verification:
            - ec.EllipticCurvePublicKey (secp256k1) for EcdsaSecp256k1Signature2019
            - ed25519.Ed25519PublicKey for Ed25519Signature2020
        expected_purpose: If provided, verify that proofPurpose matches.
        expected_domain: If provided, verify that domain matches.
        expected_challenge: If provided, verify that challenge matches.

    Returns:
        True if the proof is valid, False otherwise.

    Example:
        >>> is_valid = verify_w3c_proof(signed_doc, public_key)
        >>> assert is_valid
    """
    try:
        proof = document.get("proof")
        if not proof:
            logging.error("Document has no proof field")
            return False

        # Extract proof fields
        proof_type = proof.get("type")
        proof_value = proof.get("proofValue")
        proof_purpose = proof.get("proofPurpose")
        verification_method = proof.get("verificationMethod")
        created = proof.get("created")

        if not all([proof_type, proof_value, proof_purpose, verification_method, created]):
            logging.error("Proof is missing required fields")
            return False

        # Validate proof type
        expected_key_type = _PROOF_TYPE_PUBLIC_KEY_MAP.get(proof_type)
        if expected_key_type is None:
            logging.error(f"Unsupported proof type: {proof_type}")
            return False

        if not isinstance(public_key, expected_key_type):
            logging.error(
                f"Key type mismatch: proof type '{proof_type}' requires "
                f"{expected_key_type.__name__}, got {type(public_key).__name__}"
            )
            return False

        # Check optional constraints
        if expected_purpose is not None and proof_purpose != expected_purpose:
            logging.error(
                f"Proof purpose mismatch: expected '{expected_purpose}', "
                f"got '{proof_purpose}'"
            )
            return False

        if expected_domain is not None:
            if proof.get("domain") != expected_domain:
                logging.error(f"Domain mismatch: expected '{expected_domain}'")
                return False

        if expected_challenge is not None:
            if proof.get("challenge") != expected_challenge:
                logging.error(f"Challenge mismatch: expected '{expected_challenge}'")
                return False

        # Reconstruct proof options (everything except proofValue)
        proof_options = {k: v for k, v in proof.items() if k != "proofValue"}

        # Reconstruct document without proof
        doc_without_proof = {k: v for k, v in document.items() if k != "proof"}

        # Compute signing input
        to_be_signed = _compute_signing_input(doc_without_proof, proof_options)

        # Decode signature
        signature = _b64url_decode(proof_value)

        # Verify
        if proof_type == PROOF_TYPE_SECP256K1:
            return _verify_secp256k1(public_key, to_be_signed, signature)
        elif proof_type == PROOF_TYPE_ED25519:
            return _verify_ed25519(public_key, to_be_signed, signature)

        return False

    except Exception as e:
        logging.error(f"Proof verification failed: {e}")
        return False
