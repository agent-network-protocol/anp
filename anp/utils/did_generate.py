# AgentConnect: https://github.com/agent-network-protocol/AgentConnect
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: https://agent-network-protocol.com/
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.

import datetime
import json
from typing import Any, Dict, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from anp.utils.crypto_tool import (
    generate_bitcoin_address,
    generate_secp256r1_private_key,
    generate_secp256r1_public_key,
    generate_signature_for_json,
)


def generate_did(bitcoin_address: str) -> str:
    """Generate DID based on Bitcoin address"""
    return f"did:all:{bitcoin_address}"

def create_did_document(did: str, public_key: ec.EllipticCurvePublicKey,
                        service_endpoint: str, router: str) -> Dict[str, Any]:
    """Generate DID document"""
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    public_key_hex = '04' + public_key_bytes.hex()
    return {
        "@context": "https://www.w3.org/ns/did/v1",
        "id": did,
        "controller": did,
        "verificationMethod": [
            {
                "id": f"{did}#keys-1",
                "type": "EcdsaSecp256r1VerificationKey2019",
                "controller": did,
                "publicKeyHex": public_key_hex
            }
        ],
        "authentication": [
            {
                "id": f"{did}#keys-1",
                "type": "EcdsaSecp256r1VerificationKey2019",
                "controller": did,
                "publicKeyHex": public_key_hex
            }
        ],
        "service": [
            {
                "id": f"{did}#communication",
                "type": "messageService",
                "router": router,
                "serviceEndpoint": service_endpoint
            }
        ]
    }

def sign_did_document_secp256r1(private_key: ec.EllipticCurvePrivateKey, did_document: Dict[str, Any]) -> Dict[str, Any]:
    """Sign the DID document"""

    # Add timestamp
    created = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    proof = {
        "type": "EcdsaSecp256r1Signature2019",
        "created": created,
        "proofPurpose": "assertionMethod",
        "verificationMethod": f"{did_document['id']}#keys-1",
    }

    # Add proof to DID document for signing
    did_document['proof'] = proof

    proof_value = generate_signature_for_json(private_key, did_document)

    # Add signature to proof
    proof['proofValue'] = proof_value
    did_document['proof'] = proof

    return did_document

def did_generate(communication_service_endpoint: str, router: str="",
                 did_server_domain: str="", did_server_port: str="") -> \
                Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey, str, str]:
    private_key = generate_secp256r1_private_key()
    public_key = generate_secp256r1_public_key(private_key)
    bitcoin_address = generate_bitcoin_address(public_key)

    did = generate_did(bitcoin_address)

    if did_server_domain:
        did = did + "@" + did_server_domain
        if did_server_port:
            did = did + ":" + str(did_server_port)

    if not router:
        router = did

    did_document = create_did_document(did, public_key, communication_service_endpoint, router)
    signed_did_document = sign_did_document_secp256r1(private_key, did_document)
    did_document_json = json.dumps(signed_did_document, indent=2)
    return private_key, public_key, did, did_document_json
