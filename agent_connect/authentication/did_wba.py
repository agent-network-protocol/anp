# AgentConnect: https://github.com/agent-network-protocol/AgentConnect
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: https://agent-network-protocol.com/
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.

import asyncio
import base64
import hashlib
import json
import logging
import re
import secrets
import traceback
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

import aiohttp
import base58  # Need to add this dependency
import jcs
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from .verification_methods import CURVE_MAPPING, create_verification_method


def _is_ip_address(hostname: str) -> bool:
    """Check if a hostname is an IP address."""
    # IPv4 pattern
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    # IPv6 pattern (simplified)
    ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
    
    return bool(re.match(ipv4_pattern, hostname) or re.match(ipv6_pattern, hostname))

def _encode_base64url(data: bytes) -> str:
    """Encode bytes data to base64url format"""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

def _public_key_to_jwk(public_key: ec.EllipticCurvePublicKey) -> Dict:
    """Convert secp256k1 public key to JWK format"""
    numbers = public_key.public_numbers()
    x = _encode_base64url(numbers.x.to_bytes((numbers.x.bit_length() + 7) // 8, 'big'))
    y = _encode_base64url(numbers.y.to_bytes((numbers.y.bit_length() + 7) // 8, 'big')) 
    compressed = public_key.public_bytes(encoding=Encoding.X962, format=PublicFormat.CompressedPoint)
    kid = _encode_base64url(hashlib.sha256(compressed).digest())
    return {
        "kty": "EC",
        "crv": "secp256k1",
        "x": x,
        "y": y,
        "kid": kid
    }

def create_did_wba_document(
    hostname: str,
    port: Optional[int] = None,
    path_segments: Optional[List[str]] = None,
    agent_description_url: Optional[str] = None
) -> Tuple[Dict[str, Any], Dict[str, Tuple[bytes, bytes]]]:
    """
    Generate DID document and corresponding private key dictionary
    
    Args:
        hostname: Hostname
        port: Optional port number
        path_segments: Optional DID path segments list, e.g. ['user', 'alice']
        agent_description_url: Optional URL for agent description
    
    Returns:
        Tuple[Dict, Dict]: Returns a tuple containing two dictionaries:
            - First dict is the DID document 
            - Second dict is the keys dictionary where key is DID fragment (e.g. "key-1") 
              and value is a tuple of (private_key_pem_bytes, public_key_pem_bytes)
              
    Raises:
        ValueError: If hostname is empty or is an IP address

    Note: Currently only secp256k1 is supported
    """
    if not hostname:
        raise ValueError("Hostname cannot be empty")
        
    if _is_ip_address(hostname):
        raise ValueError("Hostname cannot be an IP address")
    
    logging.info(f"Creating DID WBA document for hostname: {hostname}")
    
    # Build base DID
    did_base = f"did:wba:{hostname}"
    if port is not None:
        encoded_port = urllib.parse.quote(f":{port}")
        did_base = f"{did_base}{encoded_port}"
        logging.debug(f"Added port to DID base: {did_base}")
    
    did = did_base
    if path_segments:
        did_path = ":".join(path_segments)
        did = f"{did_base}:{did_path}"
        logging.debug(f"Added path segments to DID: {did}")
    
    # Generate secp256k1 key pair
    logging.debug("Generating secp256k1 key pair")
    secp256k1_private_key = ec.generate_private_key(ec.SECP256K1())
    secp256k1_public_key = secp256k1_private_key.public_key()
    
    # Build verification method
    verification_method = {
        "id": f"{did}#key-1",
        "type": "EcdsaSecp256k1VerificationKey2019",
        "controller": did,
        "publicKeyJwk": _public_key_to_jwk(secp256k1_public_key)
    }
    
    # Build DID document
    did_document = {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
            "https://w3id.org/security/suites/secp256k1-2019/v1"
        ],
        "id": did,
        "verificationMethod": [verification_method],
        "authentication": [verification_method["id"]]
    }

    # Add agent description if URL is provided
    if agent_description_url is not None:
        did_document["service"] = [{
            "id": f"{did}#ad",
            "type": "AgentDescription",
            "serviceEndpoint": agent_description_url
        }]
    
    # Build keys dictionary with both private and public keys in PEM format
    keys = {
        "key-1": (
            secp256k1_private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption()
            ),
            secp256k1_public_key.public_bytes(
                encoding=Encoding.PEM,
                format=PublicFormat.SubjectPublicKeyInfo
            )
        )
    }
    
    logging.info(f"Successfully created DID document with ID: {did}")
    return did_document, keys

async def resolve_did_wba_document(did: str) -> Dict:
    """
    Resolve DID document from Web DID asynchronously

    Args:
        did: DID to resolve, e.g. did:wba:example.com:user:alice

    Returns:
        Dict: Resolved DID document

    Raises:
        ValueError: If DID format is invalid
        aiohttp.ClientError: If HTTP request fails
    """
    logging.info(f"Resolving DID document for: {did}")

    # Validate DID format
    if not did.startswith("did:wba:"):
        raise ValueError("Invalid DID format: must start with 'did:wba:'")

    # Extract domain and path from DID
    did_parts = did.split(":", 3)
    if len(did_parts) < 4:
        raise ValueError("Invalid DID format: missing domain")

    domain = urllib.parse.unquote(did_parts[2])
    path_segments = did_parts[3].split(":") if len(did_parts) > 3 else []

    try:
        # Create HTTP client
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            url = f"https://{domain}"
            if path_segments:
                url += '/' + '/'.join(path_segments) + '/did.json'
            else:
                url += '/.well-known/did.json'
            
            logging.debug(f"Requesting DID document from URL: {url}")
            
            # TODO: Add DNS-over-HTTPS support
            # resolver = aiohttp.AsyncResolver(nameservers=['8.8.8.8'])
            # connector = aiohttp.TCPConnector(resolver=resolver)
            
            async with session.get(
                url,
                headers={
                    'Accept': 'application/json'
                },
                ssl=True
                # connector=connector
            ) as response:
                response.raise_for_status()
                did_document = await response.json()

                # Verify document ID
                if did_document.get('id') != did:
                    raise ValueError(
                        f"DID document ID mismatch. Expected: {did}, "
                        f"Got: {did_document.get('id')}"
                    )

                logging.info(f"Successfully resolved DID document for: {did}")
                return did_document

    except aiohttp.ClientError as e:
        logging.error(f"Failed to resolve DID document: {str(e)}\nStack trace:\n{traceback.format_exc()}")
        return None
    except Exception as e:
        logging.error(f"Failed to resolve DID document: {str(e)}\nStack trace:\n{traceback.format_exc()}")
        return None

# Add a sync wrapper for backward compatibility
def resolve_did_wba_document_sync(did: str) -> Dict:
    """
    Synchronous wrapper for resolve_did_wba_document

    Args:
        did: DID to resolve, e.g. did:wba:example.com:user:alice

    Returns:
        Dict: Resolved DID document
    """
    return asyncio.run(resolve_did_wba_document(did))

def generate_auth_header(
    did_document: Dict,
    service_domain: str,
    sign_callback: Callable[[bytes, str], bytes]
) -> str:
    """
    Generate the Authorization header for DID authentication.
    
    Args:
        did_document: DID document dictionary.
        service_domain: Server domain.
        sign_callback: Signature callback function that takes the content to sign and the verification method fragment as parameters.
            callback(content_to_sign: bytes, verification_method_fragment: str) -> bytes.
            If ECDSA, return signature in DER format.
            
    Returns:
        str: Value of the Authorization header. Do not include "Authorization:" prefix.
        
    Raises:
        ValueError: If the DID document format is invalid.
    """
    logging.info("Starting to generate DID authentication header.")
    
    # Validate DID document
    did = did_document.get('id')
    if not did:
        raise ValueError("DID document is missing the id field.")
    
    # Select authentication method
    method_dict, verification_method_fragment = _select_authentication_method(did_document)
    
    # Generate a 16-byte random nonce
    nonce = secrets.token_hex(16)
    
    # Generate ISO 8601 formatted UTC timestamp
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    
    # Construct the data to sign
    data_to_sign = {
        "nonce": nonce,
        "timestamp": timestamp,
        "service": service_domain,
        "did": did
    }
    
    # Normalize JSON using JCS
    canonical_json = jcs.canonicalize(data_to_sign)
    logging.debug(f"generate_auth_header Canonical JSON: {canonical_json}")
    
    # Calculate SHA-256 hash
    content_hash = hashlib.sha256(canonical_json).digest()
    
    # Create verifier and encode signature
    verifier = create_verification_method(method_dict)
    signature_bytes = sign_callback(content_hash, verification_method_fragment)
    signature = verifier.encode_signature(signature_bytes)
    
    # Construct the Authorization header
    auth_header = (
        f'DIDWba did="{did}", '
        f'nonce="{nonce}", '
        f'timestamp="{timestamp}", '
        f'verification_method="{verification_method_fragment}", '
        f'signature="{signature}"'
    )
    
    logging.info("Successfully generated DID authentication header.")
    logging.debug(f"Generated Authorization header: {auth_header}")
    
    return auth_header

def _find_verification_method(did_document: Dict, verification_method_id: str) -> Optional[Dict]:
    """
    Find verification method in DID document by ID.
    Searches in both verificationMethod and authentication arrays.
    
    Args:
        did_document: DID document
        verification_method_id: Full verification method ID
        
    Returns:
        Optional[Dict]: Verification method if found, None otherwise
    """
    # Search in verificationMethod array
    for method in did_document.get('verificationMethod', []):
        if method['id'] == verification_method_id:
            return method
            
    # Search in authentication array
    for auth in did_document.get('authentication', []):
        # Handle both reference string and embedded verification method
        if isinstance(auth, str):
            if auth == verification_method_id:
                # If it's a reference, look up in verificationMethod
                for method in did_document.get('verificationMethod', []):
                    if method['id'] == verification_method_id:
                        return method
        elif isinstance(auth, dict) and auth.get('id') == verification_method_id:
            return auth
            
    return None


def _select_authentication_method(did_document: Dict) -> Tuple[Dict, str]:
    """
    Select an authentication method from DID document.
    
    Args:
        did_document: DID document dictionary
        
    Returns:
        Tuple[Dict, str]: A tuple containing:
            - The verification method dictionary
            - The verification method fragment
            
    Raises:
        ValueError: If no valid authentication method is found
    """
    # Get authentication methods
    authentication = did_document.get('authentication', [])
    if not authentication:
        raise ValueError("DID document is missing authentication methods.")
    
    # Get the first authentication method
    auth_method = authentication[0]
    
    # Extract verification method
    if isinstance(auth_method, str):
        # If auth_method is a string (reference), find the verification method
        method_dict = _find_verification_method(did_document, auth_method)
        if not method_dict:
            raise ValueError(f"Referenced verification method not found: {auth_method}")
        verification_method_fragment = auth_method.split('#')[-1]
    else:
        # If auth_method is an object (embedded verification method)
        method_dict = auth_method
        if 'id' not in method_dict:
            raise ValueError("Embedded verification method missing 'id' field")
        verification_method_fragment = method_dict['id'].split('#')[-1]
    
    if not method_dict:
        raise ValueError("Could not find valid verification method")
        
    return method_dict, verification_method_fragment


def _extract_ec_public_key_from_jwk(jwk: Dict) -> ec.EllipticCurvePublicKey:
    """
    Extract EC public key from JWK format.
    
    Args:
        jwk: JWK dictionary
        
    Returns:
        ec.EllipticCurvePublicKey: Public key
        
    Raises:
        ValueError: If JWK format is invalid or curve is unsupported
    """
    if jwk.get('kty') != 'EC':
        raise ValueError("Invalid JWK: kty must be EC")
        
    crv = jwk.get('crv')
    if not crv:
        raise ValueError("Missing curve parameter in JWK")
        
    curve = CURVE_MAPPING.get(crv)
    if curve is None:
        raise ValueError(f"Unsupported curve: {crv}. Supported curves: {', '.join(CURVE_MAPPING.keys())}")
        
    try:
        # Decode using base64url
        x = int.from_bytes(base64.urlsafe_b64decode(
            jwk['x'] + '=' * (-len(jwk['x']) % 4)), 'big')
        y = int.from_bytes(base64.urlsafe_b64decode(
            jwk['y'] + '=' * (-len(jwk['y']) % 4)), 'big')
        public_numbers = ec.EllipticCurvePublicNumbers(x, y, curve)
        return public_numbers.public_key()
    except Exception as e:
        logging.error(f"Invalid JWK parameters: {str(e)}\nStack trace:\n{traceback.format_exc()}")
        raise ValueError(f"Invalid JWK parameters: {str(e)}")

def _extract_ed25519_public_key_from_multibase(multibase: str) -> ed25519.Ed25519PublicKey:
    """
    Extract Ed25519 public key from multibase format.
    
    Args:
        multibase: Multibase encoded string
        
    Returns:
        ed25519.Ed25519PublicKey: Public key
        
    Raises:
        ValueError: If multibase format is invalid
    """
    if not multibase.startswith('z'):
        raise ValueError("Unsupported multibase encoding")
    try:
        key_bytes = base58.b58decode(multibase[1:])
        return ed25519.Ed25519PublicKey.from_public_bytes(key_bytes)
    except Exception as e:
        logging.error(f"Invalid multibase key: {str(e)}\nStack trace:\n{traceback.format_exc()}")
        raise ValueError(f"Invalid multibase key: {str(e)}")

def _extract_ed25519_public_key_from_base58(base58_key: str) -> ed25519.Ed25519PublicKey:
    """
    Extract Ed25519 public key from base58 format.
    
    Args:
        base58_key: Base58 encoded string
        
    Returns:
        ed25519.Ed25519PublicKey: Public key
        
    Raises:
        ValueError: If base58 format is invalid
    """
    try:
        key_bytes = base58.b58decode(base58_key)
        return ed25519.Ed25519PublicKey.from_public_bytes(key_bytes)
    except Exception as e:
        logging.error(f"Invalid base58 key: {str(e)}\nStack trace:\n{traceback.format_exc()}")
        raise ValueError(f"Invalid base58 key: {str(e)}")
def _extract_secp256k1_public_key_from_multibase(multibase: str) -> ec.EllipticCurvePublicKey:
    """
    Extract secp256k1 public key from multibase format.
    
    Args:
        multibase: Multibase encoded string (base58btc format starting with 'z')
        
    Returns:
        ec.EllipticCurvePublicKey: secp256k1 public key object
        
    Raises:
        ValueError: If multibase format is invalid
    """
    if not multibase.startswith('z'):
        raise ValueError("Unsupported multibase encoding format, must start with 'z' (base58btc)")
    
    try:
        # Decode base58btc (remove the 'z' prefix)
        key_bytes = base58.b58decode(multibase[1:])
        
        # The compressed format public key for secp256k1 is 33 bytes:
        # 1 byte prefix (0x02 or 0x03) + 32 bytes X coordinate
        if len(key_bytes) != 33:
            raise ValueError("Invalid secp256k1 public key length")
            
        # Recover public key from compressed format
        return ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256K1(),
            key_bytes
        )
    except Exception as e:
        logging.error(f"Invalid multibase key: {str(e)}\nStack trace:\n{traceback.format_exc()}")
        raise ValueError(f"Invalid multibase key: {str(e)}")

def _extract_public_key(verification_method: Dict) -> Union[ec.EllipticCurvePublicKey, ed25519.Ed25519PublicKey]:
    """
    Extract public key from verification method.
    
    Supported verification method types:
    - EcdsaSecp256k1VerificationKey2019 (JWK, Multibase)
    - Ed25519VerificationKey2020 (JWK, Base58, Multibase)
    - Ed25519VerificationKey2018 (JWK, Base58, Multibase)
    - JsonWebKey2020 (JWK)
    
    Args:
        verification_method: Verification method dictionary
        
    Returns:
        Union[ec.EllipticCurvePublicKey, ed25519.Ed25519PublicKey]: Public key
        
    Raises:
        ValueError: If key format or type is unsupported or invalid
    """
    method_type = verification_method.get('type')
    if not method_type:
        raise ValueError("Verification method missing 'type' field")
        
    # Handle EcdsaSecp256k1VerificationKey2019
    if method_type == 'EcdsaSecp256k1VerificationKey2019':
        if 'publicKeyJwk' in verification_method:
            jwk = verification_method['publicKeyJwk']
            if jwk.get('crv') != 'secp256k1':
                raise ValueError("Invalid curve for EcdsaSecp256k1VerificationKey2019")
            return _extract_ec_public_key_from_jwk(jwk)
        elif 'publicKeyMultibase' in verification_method:
            return _extract_secp256k1_public_key_from_multibase(
                verification_method['publicKeyMultibase']
            )
            
    # Handle Ed25519 verification methods
    elif method_type in ['Ed25519VerificationKey2020', 'Ed25519VerificationKey2018']:
        if 'publicKeyJwk' in verification_method:
            jwk = verification_method['publicKeyJwk']
            if jwk.get('kty') != 'OKP' or jwk.get('crv') != 'Ed25519':
                raise ValueError(f"Invalid JWK parameters for {method_type}")
            try:
                key_bytes = base64.b64decode(jwk['x'] + '==')
                return ed25519.Ed25519PublicKey.from_public_bytes(key_bytes)
            except Exception as e:
                raise ValueError(f"Invalid Ed25519 JWK: {str(e)}")
        elif 'publicKeyBase58' in verification_method:
            return _extract_ed25519_public_key_from_base58(
                verification_method['publicKeyBase58']
            )
        elif 'publicKeyMultibase' in verification_method:
            return _extract_ed25519_public_key_from_multibase(
                verification_method['publicKeyMultibase']
            )
            
    # Handle JsonWebKey2020
    elif method_type == 'JsonWebKey2020':
        if 'publicKeyJwk' in verification_method:
            return _extract_ec_public_key_from_jwk(verification_method['publicKeyJwk'])
            
    raise ValueError(
        f"Unsupported verification method type or missing required key format: {method_type}"
    )

def extract_auth_header_parts(auth_header: str) -> Tuple[str, str, str, str, str]:
    """
    Extract authentication information from the authorization header.
    
    Args:
        auth_header: Authorization header value without "Authorization:" prefix.
        
    Returns:
        Tuple[str, str, str, str, str]: A tuple containing:
            - did: DID string
            - nonce: Nonce value
            - timestamp: Timestamp string
            - verification_method: Verification method fragment
            - signature: Signature value
            
    Raises:
        ValueError: If any required field is missing in the auth header
    """
    logging.debug(f"Extracting auth header parts from: {auth_header}")
    
    required_fields = {
        'did': r'(?i)did="([^"]+)"',
        'nonce': r'(?i)nonce="([^"]+)"',
        'timestamp': r'(?i)timestamp="([^"]+)"',
        'verification_method': r'(?i)verification_method="([^"]+)"',
        'signature': r'(?i)signature="([^"]+)"'
    }
    
    # Verify the header starts with DIDWba
    if not auth_header.strip().startswith('DIDWba'):
        raise ValueError("Authorization header must start with 'DIDWba'")
    
    parts = {}
    for field, pattern in required_fields.items():
        match = re.search(pattern, auth_header)
        if not match:
            raise ValueError(f"Missing required field in auth header: {field}")
        parts[field] = match.group(1)
    
    logging.debug(f"Extracted auth header parts: {parts}")
    return (parts['did'], parts['nonce'], parts['timestamp'], 
            parts['verification_method'], parts['signature'])

def verify_auth_header_signature(
    auth_header: str,
    did_document: Dict,
    service_domain: str
) -> Tuple[bool, str]:
    """
    Verify the DID authentication header signature.
    
    Args:
        auth_header: Authorization header value without "Authorization:" prefix.
        did_document: DID document dictionary.
        service_domain: Server domain that should match the one used to generate the signature.
        
    Returns:
        Tuple[bool, str]: A tuple containing:
            - Boolean indicating if verification was successful
            - Message describing the verification result or error
    """
    logging.info("Starting DID authentication header verification")
    
    try:
        # Extract auth header parts
        client_did, nonce, timestamp_str, verification_method, signature = extract_auth_header_parts(auth_header)
         
        # Verify DID (case-sensitive)
        if did_document.get('id').lower() != client_did.lower():
            return False, "DID mismatch"
            
        # Construct data to verify
        data_to_verify = {
            "nonce": nonce,
            "timestamp": timestamp_str,
            "service": service_domain,
            "did": client_did
        }
        
        canonical_json = jcs.canonicalize(data_to_verify)
        content_hash = hashlib.sha256(canonical_json).digest()
        
        verification_method_id = f"{client_did}#{verification_method}"
        method_dict = _find_verification_method(did_document, verification_method_id)
        if not method_dict:
            return False, "Verification method not found"
            
        try:
            verifier = create_verification_method(method_dict)
            if verifier.verify_signature(content_hash, signature):
                return True, "Verification successful"
            return False, "Signature verification failed"
        except ValueError as e:
            return False, f"Invalid or unsupported verification method: {str(e)}"
        except Exception as e:
            return False, f"Verification error: {str(e)}"
            
    except ValueError as e:
        logging.error(f"Error extracting auth header parts: {str(e)}")
        return False, str(e)
    except Exception as e:
        logging.error(f"Error during verification process: {str(e)}")
        return False, f"Verification process error: {str(e)}"

def generate_auth_json(
    did_document: Dict,
    service_domain: str,
    sign_callback: Callable[[bytes, str], bytes]
) -> str:
    """
    Generate JSON format string for DID authentication.
    
    Args:
        did_document: DID document dictionary
        service_domain: Server domain
        sign_callback: Signature callback function that takes content to sign and verification method fragment
            callback(content_to_sign: bytes, verification_method_fragment: str) -> bytes
            For ECDSA, return signature in DER format
            
    Returns:
        str: Authentication information in JSON format
        
    Raises:
        ValueError: If DID document format is invalid
    """
    logging.info("Starting to generate DID authentication JSON")
    
    # Validate DID document
    did = did_document.get('id')
    if not did:
        raise ValueError("DID document missing id field")
    
    # Select authentication method
    method_dict, verification_method_fragment = _select_authentication_method(did_document)
    
    # Generate 16-byte random nonce
    nonce = secrets.token_hex(16)
    
    # Generate ISO 8601 formatted UTC timestamp
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    
    # Construct data to sign
    data_to_sign = {
        "nonce": nonce,
        "timestamp": timestamp,
        "service": service_domain,
        "did": did
    }
    
    # Normalize JSON using JCS
    canonical_json = jcs.canonicalize(data_to_sign)
    
    # Calculate SHA-256 hash
    content_hash = hashlib.sha256(canonical_json).digest()
    
    # Create verifier and encode signature
    verifier = create_verification_method(method_dict)
    signature_bytes = sign_callback(content_hash, verification_method_fragment)
    signature = verifier.encode_signature(signature_bytes)
    
    # Construct authentication JSON
    auth_json = {
        "did": did,
        "nonce": nonce,
        "timestamp": timestamp,
        "verification_method": verification_method_fragment,
        "signature": signature
    }
    
    logging.info("Successfully generated DID authentication JSON")
    return json.dumps(auth_json)

def verify_auth_json_signature(
    auth_json: Union[str, Dict],
    did_document: Dict,
    service_domain: str
) -> Tuple[bool, str]:
    """
    Verify the signature of DID authentication JSON.
    
    Args:
        auth_json: Authentication information in JSON string or dictionary format
        did_document: DID document dictionary
        service_domain: Server domain, must match the domain used to generate the signature
        
    Returns:
        Tuple[bool, str]: A tuple containing:
            - Boolean indicating if verification was successful
            - Message describing the verification result or error
    """
    logging.info("Starting DID authentication JSON verification")
    
    try:
        # Parse JSON string (if input is string)
        if isinstance(auth_json, str):
            try:
                auth_data = json.loads(auth_json)
            except json.JSONDecodeError as e:
                return False, f"Invalid JSON format: {str(e)}"
        else:
            auth_data = auth_json
            
        # Extract authentication data
        client_did = auth_data.get('did')
        nonce = auth_data.get('nonce')
        timestamp_str = auth_data.get('timestamp')
        verification_method = auth_data.get('verification_method')
        signature = auth_data.get('signature')
        
        # Verify all required fields exist
        if not all([client_did, nonce, timestamp_str, verification_method, signature]):
            return False, "Authentication JSON missing required fields"
         
        # Verify DID (case-sensitive)
        if did_document.get('id').lower() != client_did.lower():
            return False, "DID mismatch"
            
        # Construct data to verify
        data_to_verify = {
            "nonce": nonce,
            "timestamp": timestamp_str,
            "service": service_domain,
            "did": client_did
        }
        
        canonical_json = jcs.canonicalize(data_to_verify)
        content_hash = hashlib.sha256(canonical_json).digest()
        
        verification_method_id = f"{client_did}#{verification_method}"
        method_dict = _find_verification_method(did_document, verification_method_id)
        if not method_dict:
            return False, "Verification method not found"
            
        try:
            verifier = create_verification_method(method_dict)
            if verifier.verify_signature(content_hash, signature):
                return True, "Verification successful"
            return False, "Signature verification failed"
        except ValueError as e:
            return False, f"Invalid or unsupported verification method: {str(e)}"
        except Exception as e:
            return False, f"Verification error: {str(e)}"
            
    except ValueError as e:
        logging.error(f"Error extracting authentication data: {str(e)}")
        return False, str(e)
    except Exception as e:
        logging.error(f"Error during verification process: {str(e)}")
        return False, f"Verification process error: {str(e)}"
