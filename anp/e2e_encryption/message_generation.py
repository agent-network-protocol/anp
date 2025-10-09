# AgentConnect: https://github.com/agent-network-protocol/AgentConnect
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: https://agent-network-protocol.com/
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.


import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives.asymmetric import ec

from anp.utils.crypto_tool import (
    encrypt_aes_gcm_sha256,
    generate_16_char_from_random_num,
    generate_random_hex,
    generate_signature_for_json,
)


def generate_register_message(version: str,
                              routers: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generate a message for registering routers.
    :param routers: A list containing router information, each router should include router DID, nonce and proof.
    :return: A dictionary of the constructed registration message.
    """
    registration_message = {
        "version": version,
        "type": "register",
        "timestamp": datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
        "messageId": generate_random_hex(16),
        "routers": routers
    }
    return registration_message


# Generate SourceHello message
def generate_source_hello(version: str,
                          session_id: str,
                          source_private_key: ec.EllipticCurvePrivateKey,
                          source_did: str,
                          destination_did: str,
                          random: str,
                          source_public_key_hex: str,
                          key_share_list: List[Dict[str, Any]],
                          cipher_suite_list: List[str],
                          protocol_hash: Optional[str] = None) -> Dict[str, Any]:

    source_hello = {
        "version": version,
        "type": "sourceHello",
        "timestamp": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
        "messageId": generate_random_hex(16),
        "sessionId": session_id,
        "sourceDid": source_did,
        "destinationDid": destination_did,
        "verificationMethod": {
            "id": f"{source_did}#keys-1",
            "type": "EcdsaSecp256r1VerificationKey2019",
            "publicKeyHex": source_public_key_hex
        },
        "random": random,
        "supportedVersions": ["1.0"],
        "cipherSuites": cipher_suite_list,
        "supportedGroups": [
            "secp256r1"
            # "secp384r1",
            # "secp521r1"
        ],
        "keyShares": key_share_list,
        "metaProtocol": {
            "version": "1.0",
            "protocolHash": protocol_hash
        }
    }

    proof = {
        "type": "EcdsaSecp256k1Signature2019",
        "verificationMethod": f"{source_did}#keys-1",
        "created": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
    }

    source_hello["proof"] = proof

    # Sign the message using the source private key
    proof["proofValue"] = generate_signature_for_json(source_private_key, source_hello)

    source_hello["proof"] = proof

    return source_hello

# Generate DestinationHello message
def generate_destination_hello(version: str, session_id: str, source_private_key: ec.EllipticCurvePrivateKey,
                               source_did: str, destination_did: str, random: str,
                               source_public_key_hex: str, key_share: Dict[str, Any],
                               cipher_suite: str) -> Dict[str, Any]:

    destination_hello = {
        "version": version,
        "type": "destinationHello",
        "timestamp": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
        "messageId": generate_random_hex(16),
        "sessionId": session_id,
        "sourceDid": source_did,
        "destinationDid": destination_did,
        "verificationMethod": {
            "id": f"{source_did}#keys-1",
            "type": "EcdsaSecp256r1VerificationKey2019",
            "publicKeyHex": source_public_key_hex
        },
        "random": random,
        "selectedVersion": version,
        "cipherSuite": cipher_suite,
        "keyShare": key_share
    }

    # Prepare signature
    proof = {
        "type": "EcdsaSecp256k1Signature2019",
        "verificationMethod": f"{source_did}#keys-1",
        "created": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
    }

    destination_hello["proof"] = proof

    # Sign the message using the source private key
    proof["proofValue"] = generate_signature_for_json(source_private_key, destination_hello)

    destination_hello["proof"] = proof

    return destination_hello


def generate_finished_message(version: str, session_id: str, source_did: str, destination_did: str,
                              source_hello_random: str, destination_hello_random: str,
                              data_secret: bytes) -> Dict[str, Any]:
    """
    Generate Finished message
    :param version: Current protocol version
    :param session_id: Session ID
    :param source_did: Source DID identifier
    :param destination_did: Destination DID identifier
    :param source_hello_random: Random number from source Hello message
    :param destination_hello_random: Random number from destination Hello message
    :param data_secret: Negotiated handshake key
    :return: Dictionary of the Finished message
    """
    # Generate secret_key_id
    secret_key_id = generate_16_char_from_random_num(source_hello_random, destination_hello_random)

    secret_key_id_dict = {
        "secretKeyId": secret_key_id,
    }
    # Generate verifyData
    verify_data_dict = encrypt_aes_gcm_sha256(json.dumps(secret_key_id_dict).encode(), data_secret)

    # Construct Finished message
    finished_message = {
        "version": version,
        "type": "finished",
        "timestamp": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
        "messageId": generate_random_hex(16),
        "sessionId": session_id,
        "sourceDid": source_did,
        "destinationDid": destination_did,
        "verifyData": verify_data_dict
    }

    return finished_message

def generate_response_message(version: str, original_type: str, message_id: str,
                              code: int, detail: str) -> Dict[str, Any]:
    """
    Generate response message
    :param version: Current protocol version
    :param original_type: Original message type
    :param code: Response code
    :param detail: Response details
    :return: Dictionary of the response message
    """
    response_message = {
        "version": version,
        "type": "response",
        "timestamp": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
        "messageId": message_id,
        "originalType": original_type,
        "code": code,
        "detail": detail
    }
    return response_message

def generate_encrypted_message(version: str,  message_id: str, source_did: str,
                               destination_did: str, secret_key_id: str,
                               data: bytes, data_secret: bytes) -> Dict[str, Any]:
    """
    Generate encrypted message
    """
    encrypted_data = encrypt_aes_gcm_sha256(data, data_secret)
    encrypted_message = {
        "version": version,
        "type": "message",
        "timestamp": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
        "messageId": message_id,
        "sourceDid": source_did,
        "destinationDid": destination_did,
        "secretKeyId": secret_key_id,
        "encryptedData": encrypted_data
    }
    return encrypted_message



