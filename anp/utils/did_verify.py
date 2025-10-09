# AgentConnect: https://github.com/agent-network-protocol/AgentConnect
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: https://agent-network-protocol.com/
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.

from copy import deepcopy
from typing import Any, Dict, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec

from anp.utils.crypto_tool import (
    verify_did_with_public_key,
    verify_signature_for_json,
)


def extract_public_key(did_document: Dict[str, Any], key_id: str) -> ec.EllipticCurvePublicKey:
    """Extract public key from DID document"""
    for vm in did_document['verificationMethod']:
        if vm['id'] == key_id and vm['type'] == "EcdsaSecp256r1VerificationKey2019":
            public_key_hex = vm['publicKeyHex']
            public_key_bytes = bytes.fromhex(public_key_hex[2:])
            return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_key_bytes)
    raise ValueError(f"Public key {key_id} not found in DID document")

def verify_did_document(did_document: dict) -> Tuple[bool, str]:
    """Verify DID document"""
    try:
        # Extract signature-related data
        proof = did_document['proof']
        verification_method = proof['verificationMethod']
        signature = proof['proofValue']

        # Extract public key
        public_key = extract_public_key(did_document, verification_method)

        # Extract DID
        did = did_document['id']

        # Verify public key and DID
        is_did_valid = verify_did_with_public_key(did, public_key)
        if not is_did_valid:
            return False, "public key is not valid"

        # Verify signature
        # Remove proof field to get original message
        original_message = deepcopy(did_document)
        del original_message['proof']['proofValue']
        is_signature_valid = verify_signature_for_json(public_key, original_message, signature)

        return is_signature_valid, "verify signature error" if not is_signature_valid else ""
    except ValueError as ve:
        return False, str(ve)
    except InvalidSignature:
        return False, "Bad Signature Error"

