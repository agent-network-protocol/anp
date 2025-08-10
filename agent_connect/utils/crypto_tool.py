# AgentConnect: https://github.com/agent-network-protocol/AgentConnect
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: https://agent-network-protocol.com/
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.


from datetime import datetime
import hashlib
import base64
import json
import os
import secrets
import logging
from typing import Any, Dict, Tuple
import base58
import struct
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Generate 32 bytes of random data
def generate_random_hex(length=32):
    return secrets.token_hex(length)

def generate_16_char_from_random_num(random_num1: str, random_num2: str):
    content = random_num1 + random_num2
    random_bytes = content.encode('utf-8')
    
    # Use HKDF to derive 8 bytes of random data
    hkdf = HKDF(
        algorithm=hashes.SHA256(),  # Ensure using hash algorithm instance from cryptography library
        length=8,  # Generate 8-byte key
        salt=None,
        info=b'',  # Optional context information to differentiate keys for different purposes
        backend=default_backend()  # Use default crypto backend
    )
    
    derived_key = hkdf.derive(random_bytes)
    
    # Encode the derived key as a hexadecimal string
    derived_key_hex = derived_key.hex()
    
    return derived_key_hex

def get_hex_from_public_key(public_key: ec.EllipticCurvePublicKey) -> str:
    """Convert EC public key to hexadecimal string"""
    # Get byte representation of public key
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    # Convert bytes to hexadecimal string
    return public_key_bytes.hex()

def get_public_key_from_hex(public_key_hex: str, curve: ec.EllipticCurve = ec.SECP256R1()) -> ec.EllipticCurvePublicKey:
    """Extract EC public key from hexadecimal string, specifying elliptic curve"""
    # Convert hexadecimal string to bytes
    public_key_bytes = bytes.fromhex(public_key_hex)
    # Create public key from bytes
    return ec.EllipticCurvePublicKey.from_encoded_point(curve, public_key_bytes)


# Generate ECDSA private and public key pair
def generate_ec_key_pair(curve: ec.EllipticCurve=ec.SECP256R1()) -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey, str]:
    private_key = ec.generate_private_key(curve, default_backend())
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()
    public_key_hex = '04' + format(public_numbers.x, '064x') + format(public_numbers.y, '064x')
    return private_key, public_key, public_key_hex

def generate_secp256r1_private_key() -> ec.EllipticCurvePrivateKey:
    """Generate Secp256r1 private key"""
    return ec.generate_private_key(ec.SECP256R1())

def generate_secp256r1_public_key(private_key: ec.EllipticCurvePrivateKey) -> ec.EllipticCurvePublicKey:
    """Generate public key from Secp256r1 private key"""
    return private_key.public_key()


def generate_bitcoin_address(public_key: ec.EllipticCurvePublicKey) -> str:
    """Generate Bitcoin address from public key"""
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    sha256_pk = hashlib.sha256(public_key_bytes).digest()
    ripemd160_pk = hashlib.new('ripemd160', sha256_pk).digest()
    pubkey_hash = b'\x00' + ripemd160_pk
    checksum = hashlib.sha256(hashlib.sha256(pubkey_hash).digest()).digest()[:4]
    address = base58.b58encode(pubkey_hash + checksum).decode('utf-8')
    return address

def generate_signature_for_json(private_key: ec.EllipticCurvePrivateKey, did_document: Dict[str, Any]) -> str:
    # Convert data to be signed to JSON string
    did_document_str = json.dumps(did_document, separators=(',', ':'), sort_keys=True)
    did_document_bytes = did_document_str.encode('utf-8')
    
    # Sign data using private key
    signature = private_key.sign(did_document_bytes, ec.ECDSA(hashes.SHA256()))
    
    # Separate r and s values
    r, s = decode_dss_signature(signature)
    
    # Convert r and s to bytes
    r_bytes = r.to_bytes((r.bit_length() + 7) // 8, byteorder='big')
    s_bytes = s.to_bytes((s.bit_length() + 7) // 8, byteorder='big')
    
    # Base64 URL-safe encode
    proof_value = base64.urlsafe_b64encode(r_bytes + s_bytes).rstrip(b'=').decode('utf-8')
    
    return proof_value

def verify_signature_for_json(public_key: ec.EllipticCurvePublicKey, did_document: Dict[str, Any], signature: str) -> bool:
    """Verify signature of JSON message"""
    try:
        # Decode signature from Base64Url encoding to byte string
        signature_bytes = base64.urlsafe_b64decode(signature + '==')
        
        # Split r and s values
        r_length = len(signature_bytes) // 2
        r_bytes = signature_bytes[:r_length]
        s_bytes = signature_bytes[r_length:]
        
        r = int.from_bytes(r_bytes, byteorder='big')
        s = int.from_bytes(s_bytes, byteorder='big')
        
        # Reassemble into ASN.1 DER encoded format
        der_encoded_signature = encode_dss_signature(r, s)
        
        # Convert message to byte string
        message_str = json.dumps(did_document, separators=(',', ':'), sort_keys=True)
        message_bytes = message_str.encode('utf-8')
        
        # Verify signature
        public_key.verify(der_encoded_signature, message_bytes, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception as e:
        logging.error(f"Signature verification failed: {e}")
        return False
    
def generate_router_json(private_key: ec.EllipticCurvePrivateKey, did_document: Dict[str, Any]) -> Dict[str, Any]:
    """Generate router JSON dictionary based on private key and DID document"""
    router_did = did_document.get("id")
    nonce = generate_random_hex(32)  # Generate random hex string for nonce
    current_time = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')

    # Get verificationMethod from DID document
    verification_methods = did_document.get("verificationMethod", [])
    verification_method_id = next((vm["id"] for vm in verification_methods if vm["type"] == "EcdsaSecp256r1VerificationKey2019"), None)

    # Create router dictionary
    router = {
        "router": router_did,
        "nonce": nonce,
        "proof": {
            "type": "EcdsaSecp256r1Signature2019",
            "created": current_time,
            "proofPurpose": "assertionMethod",
            "verificationMethod": verification_method_id
        }
    }

    # Sign router information using private key
    proof_value = generate_signature_for_json(private_key, router)
    router["proof"]["proofValue"] = proof_value

    return router

def verify_did_with_public_key(did: str, public_key: ec.EllipticCurvePublicKey) -> bool:
    """Verify if the public key matches the DID"""
    try:
        # Extract Bitcoin address from DID
        did_parts = did.split(':')
        bitcoin_address = did_parts[2].split('@')[0]

        # Generate Bitcoin address from public key
        generated_address = generate_bitcoin_address(public_key)

        # Verify if the generated Bitcoin address matches the address in the DID
        return bitcoin_address == generated_address
    except Exception as e:
        logging.error(f"Failed to verify DID with public key: {e}")
        return False

def get_pem_from_private_key(private_key: ec.EllipticCurvePrivateKey) -> str:
    """Get PEM format string from EllipticCurvePrivateKey"""
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem.decode('utf-8')


# Load private key from PEM format string
def load_private_key_from_pem(pem_str: str) -> ec.EllipticCurvePrivateKey:
    return serialization.load_pem_private_key(
        pem_str.encode('utf-8'),
        password=None,
        backend=default_backend()
    )


def generate_shared_secret(private_key: ec.EllipticCurvePrivateKey, 
                           peer_public_key: ec.EllipticCurvePublicKey) -> bytes:
    # Generate shared secret using peer's public key and own private key
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_secret

def hkdf_label(length: int, label: bytes, context: bytes) -> bytes:
    full_label = b"als10 " + label
    hkdf_label = struct.pack("!H", length) + struct.pack("!B", len(full_label)) + full_label + struct.pack("!B", len(context)) + context
    return hkdf_label

def get_key_length_from_cipher_suite(cipher_suite: str) -> int:
    if cipher_suite == "TLS_AES_128_GCM_SHA256":
        return 16
    elif cipher_suite == "TLS_AES_256_GCM_SHA384":
        return 32
    elif cipher_suite == "TLS_CHACHA20_POLY1305_SHA256":
        return 32
    else:
        raise ValueError(f"Unsupported cipher suite: {cipher_suite}")


def derive_tls13_data_keys(shared_secret: bytes, source_hello_random: bytes, 
                           destination_hello_random: bytes, 
                           key_length=16, hash_algorithm=hashes.SHA256()):
    backend = default_backend()

    # HKDF Extract stage
    hkdf_extract = HKDF(
        algorithm=hash_algorithm,
        length=hash_algorithm.digest_size,
        salt=b'\x00' * hash_algorithm.digest_size,  # Initial salt is zeros
        info=None,
        backend=backend
    )
    extracted_key = hkdf_extract.derive(shared_secret)

    # Derive-Secret function in TLS 1.3
    def derive_secret(secret: bytes, label: bytes, messages: bytes) -> bytes:
        hkdf_expand = HKDFExpand(
            algorithm=hash_algorithm,
            length=hash_algorithm.digest_size,
            info=hkdf_label(hash_algorithm.digest_size, label, messages),
            backend=backend
        )
        return hkdf_expand.derive(secret)

    # Generate handshake traffic secrets
    source_data_traffic_secret = derive_secret(extracted_key, b"s ap traffic", source_hello_random + destination_hello_random)
    destination_data_traffic_secret = derive_secret(extracted_key, b"d ap traffic", source_hello_random + destination_hello_random)

    # Expand to generate actual handshake keys
    source_data_key = HKDF(
        algorithm=hash_algorithm,
        length=key_length,  # 256-bit key for AES-256
        salt=None,
        info=hkdf_label(32, b"key", source_data_traffic_secret),
        backend=backend
    ).derive(source_data_traffic_secret)

    destination_data_key = HKDF(
        algorithm=hash_algorithm,
        length=key_length,  # 256-bit key for AES-256
        salt=None,
        info=hkdf_label(32, b"key", destination_data_traffic_secret),
        backend=backend
    ).derive(destination_data_traffic_secret)

    # Return derived handshake keys and secrets
    return (source_data_key, destination_data_key, source_data_traffic_secret, destination_data_traffic_secret)

# Generate TLS1.3 application layer keys, not used for now
def derive_tls13_application_keys(client_handshake_traffic_secret, server_handshake_traffic_secret, hash_algorithm=hashes.SHA256()):
    backend = default_backend()

    # Derive application traffic secrets
    client_application_traffic_secret = HKDFExpand(
        algorithm=hash_algorithm,
        length=hash_algorithm.digest_size,
        info=hkdf_label(hash_algorithm.digest_size, b"c ap traffic", b""),
        backend=backend
    ).derive(client_handshake_traffic_secret)

    server_application_traffic_secret = HKDFExpand(
        algorithm=hash_algorithm,
        length=hash_algorithm.digest_size,
        info=hkdf_label(hash_algorithm.digest_size, b"s ap traffic", b""),
        backend=backend
    ).derive(server_handshake_traffic_secret)

    # Expand to generate actual application keys
    client_application_key = HKDF(
        algorithm=hash_algorithm,
        length=32,  # 256-bit key for AES-256
        salt=None,
        info=hkdf_label(32, b"key", client_application_traffic_secret),
        backend=backend
    ).derive(client_application_traffic_secret)

    server_application_key = HKDF(
        algorithm=hash_algorithm,
        length=32,  # 256-bit key for AES-256
        salt=None,
        info=hkdf_label(32, b"key", server_application_traffic_secret),
        backend=backend
    ).derive(server_application_traffic_secret)

    # Return derived application keys and secrets
    return {
        'client_application_key': client_application_key,
        'server_application_key': server_application_key,
        'client_application_traffic_secret': client_application_traffic_secret,
        'server_application_traffic_secret': server_application_traffic_secret
    }

# TLS_AES_128_GCM_SHA256 encryption function
def encrypt_aes_gcm_sha256(data: bytes, key: bytes) -> Dict[str, str]:
    # Ensure key length is 16 bytes (128 bits)
    if len(key) != 16:
        raise ValueError("Key must be 128 bits (16 bytes).")
    
    # Generate random IV
    iv = os.urandom(12)  # 12 bytes is recommended for GCM mode
    
    # Create encryptor object
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    
    # Encrypt data
    ciphertext = encryptor.update(data) + encryptor.finalize()
    
    # Get authentication tag
    tag = encryptor.tag
    
    # Encode as Base64
    iv_encoded = base64.b64encode(iv).decode('utf-8')
    tag_encoded = base64.b64encode(tag).decode('utf-8')
    ciphertext_encoded = base64.b64encode(ciphertext).decode('utf-8')
    
    # Create JSON object
    encrypted_data = {
        "iv": iv_encoded,
        "tag": tag_encoded,
        "ciphertext": ciphertext_encoded
    }
        
    return encrypted_data

def decrypt_aes_gcm_sha256(encrypted_json: Dict[str, str], key: bytes) -> str:
    # Base64 decode components
    iv = base64.b64decode(encrypted_json["iv"])
    ciphertext = base64.b64decode(encrypted_json["ciphertext"])
    tag = base64.b64decode(encrypted_json["tag"])
    
    # Create decryptor object
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()
    
    # Decrypt data
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    return plaintext.decode()


