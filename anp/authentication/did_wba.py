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

from anp.proof import generate_w3c_proof, verify_w3c_proof

from .verification_methods import CURVE_MAPPING, create_verification_method

# DID 文档中验证方法的 fragment 标识符（仅写入侧使用）
VM_KEY_AUTH = "key-1"           # secp256k1, 用于 DID 认证（authentication）
VM_KEY_E2EE_SIGNING = "key-2"   # secp256r1, 用于 E2EE 消息签名
VM_KEY_E2EE_AGREEMENT = "key-3" # X25519, 用于 E2EE 密钥协商（keyAgreement）


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

def compute_jwk_fingerprint(public_key: ec.EllipticCurvePublicKey) -> str:
    """
    Compute JWK Thumbprint (RFC 7638) for a secp256k1 public key.

    Canonical input is the minimal JWK with fixed field order (crv, kty, x, y),
    using SHA-256 + base64url without padding, producing a 43-character output.

    IMPORTANT: x/y coordinates are encoded as fixed 32 bytes per RFC 7518 Section 6.2.1.2,
    not variable-length based on bit_length(). This ensures the same key always produces
    the same fingerprint.

    Args:
        public_key: secp256k1 public key object

    Returns:
        str: 43-character base64url fingerprint
    """
    numbers = public_key.public_numbers()
    # Fixed 32-byte encoding per RFC 7518 Section 6.2.1.2 (SEC1 Section 2.3.5)
    x = _encode_base64url(numbers.x.to_bytes(32, 'big'))
    y = _encode_base64url(numbers.y.to_bytes(32, 'big'))
    # Canonical JSON with fixed field order (alphabetical, matching RFC 7638)
    canonical = f'{{"crv":"secp256k1","kty":"EC","x":"{x}","y":"{y}"}}'
    digest = hashlib.sha256(canonical.encode('ascii')).digest()
    return _encode_base64url(digest)


def _public_key_to_jwk(public_key: ec.EllipticCurvePublicKey) -> Dict:
    """Convert secp256k1 public key to JWK format"""
    numbers = public_key.public_numbers()
    x = _encode_base64url(numbers.x.to_bytes(32, 'big'))
    y = _encode_base64url(numbers.y.to_bytes(32, 'big'))
    compressed = public_key.public_bytes(encoding=Encoding.X962, format=PublicFormat.CompressedPoint)
    kid = _encode_base64url(hashlib.sha256(compressed).digest())
    return {
        "kty": "EC",
        "crv": "secp256k1",
        "x": x,
        "y": y,
        "kid": kid
    }


def _secp256r1_public_key_to_jwk(public_key: ec.EllipticCurvePublicKey) -> Dict:
    """Convert secp256r1 (P-256) public key to JWK format."""
    numbers = public_key.public_numbers()
    x = _encode_base64url(numbers.x.to_bytes(32, 'big'))
    y = _encode_base64url(numbers.y.to_bytes(32, 'big'))
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": x,
        "y": y,
    }


def _build_e2ee_entries(
    did: str,
) -> Tuple[List[Dict[str, Any]], List[str], Dict[str, Tuple[bytes, bytes]]]:
    """Build E2EE verification method entries (secp256r1 + X25519).

    Uses lazy imports to avoid hard dependency on e2e_encryption_hpke.

    Args:
        did: The DID identifier string.

    Returns:
        Tuple containing:
            - vm_entries: list of two verificationMethod dicts (#key-2, #key-3)
            - ka_refs: list of keyAgreement references (["#key-3"])
            - keys_dict: {"key-2": (priv_pem, pub_pem), "key-3": (priv_pem, pub_pem)}
    """
    from anp.e2e_encryption_hpke.key_pair import (
        generate_x25519_key_pair,
        public_key_to_multibase,
    )

    # Generate secp256r1 key pair
    secp256r1_private_key = ec.generate_private_key(ec.SECP256R1())
    secp256r1_public_key = secp256r1_private_key.public_key()

    # Generate X25519 key pair
    x25519_private_key, x25519_public_key = generate_x25519_key_pair()

    # Build verification method entries
    vm_key2 = {
        "id": f"{did}#{VM_KEY_E2EE_SIGNING}",
        "type": "EcdsaSecp256r1VerificationKey2019",
        "controller": did,
        "publicKeyJwk": _secp256r1_public_key_to_jwk(secp256r1_public_key),
    }

    vm_key3 = {
        "id": f"{did}#{VM_KEY_E2EE_AGREEMENT}",
        "type": "X25519KeyAgreementKey2019",
        "controller": did,
        "publicKeyMultibase": public_key_to_multibase(x25519_public_key),
    }

    vm_entries = [vm_key2, vm_key3]
    ka_refs = [f"{did}#{VM_KEY_E2EE_AGREEMENT}"]

    # Serialize keys to PEM
    from cryptography.hazmat.primitives.serialization import (
        Encoding as _Enc,
        NoEncryption as _NoEnc,
        PrivateFormat as _PF,
        PublicFormat as _PubF,
    )

    keys_dict = {
        VM_KEY_E2EE_SIGNING: (
            secp256r1_private_key.private_bytes(
                encoding=_Enc.PEM,
                format=_PF.PKCS8,
                encryption_algorithm=_NoEnc(),
            ),
            secp256r1_public_key.public_bytes(
                encoding=_Enc.PEM,
                format=_PubF.SubjectPublicKeyInfo,
            ),
        ),
        VM_KEY_E2EE_AGREEMENT: (
            x25519_private_key.private_bytes(
                encoding=_Enc.PEM,
                format=_PF.PKCS8,
                encryption_algorithm=_NoEnc(),
            ),
            x25519_public_key.public_bytes(
                encoding=_Enc.PEM,
                format=_PubF.SubjectPublicKeyInfo,
            ),
        ),
    }

    return vm_entries, ka_refs, keys_dict

def create_did_wba_document(
    hostname: str,
    port: Optional[int] = None,
    path_segments: Optional[List[str]] = None,
    agent_description_url: Optional[str] = None,
    services: Optional[List[Dict[str, Any]]] = None,
    # --- proof 参数 ---
    proof_purpose: str = "assertionMethod",
    verification_method: Optional[str] = None,
    domain: Optional[str] = None,
    challenge: Optional[str] = None,
    created: Optional[str] = None,
    # --- E2EE 参数 ---
    enable_e2ee: bool = True,
) -> Tuple[Dict[str, Any], Dict[str, Tuple[bytes, bytes]]]:
    """
    Generate DID document and corresponding private key dictionary

    Args:
        hostname: Hostname
        port: Optional port number
        path_segments: Optional DID path segments list, e.g. ['user', 'alice']
        agent_description_url: Optional URL for agent description
        services: Optional list of custom service entries. Each entry is a dict
            with at least "id", "type", "serviceEndpoint" keys. If "id" starts
            with "#", it will be automatically prefixed with the DID.
        proof_purpose: Proof purpose string, default "assertionMethod"
        verification_method: Verification method ID for proof. If None,
            uses the first method from the document.
        domain: Optional domain for proof
        challenge: Optional challenge for proof
        created: Optional ISO 8601 timestamp for proof
        enable_e2ee: If True (default), add secp256r1 (#key-2) and X25519
            (#key-3) verification methods for E2EE support.

    Returns:
        Tuple[Dict, Dict]: Returns a tuple containing two dictionaries:
            - First dict is the DID document
            - Second dict is the keys dictionary where key is DID fragment (e.g. "key-1")
              and value is a tuple of (private_key_pem_bytes, public_key_pem_bytes)

    Raises:
        ValueError: If hostname is empty or is an IP address
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
    vm_entry = {
        "id": f"{did}#{VM_KEY_AUTH}",
        "type": "EcdsaSecp256k1VerificationKey2019",
        "controller": did,
        "publicKeyJwk": _public_key_to_jwk(secp256k1_public_key)
    }

    verification_methods = [vm_entry]
    contexts = [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/suites/jws-2020/v1",
        "https://w3id.org/security/suites/secp256k1-2019/v1",
    ]

    # Build keys dictionary with both private and public keys in PEM format
    keys = {
        VM_KEY_AUTH: (
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

    # Build DID document
    did_document = {
        "@context": contexts,
        "id": did,
        "verificationMethod": verification_methods,
        "authentication": [vm_entry["id"]],
    }

    # Add E2EE keys if enabled
    if enable_e2ee:
        e2ee_vms, ka_refs, e2ee_keys = _build_e2ee_entries(did)
        verification_methods.extend(e2ee_vms)
        did_document["keyAgreement"] = ka_refs
        contexts.append("https://w3id.org/security/suites/x25519-2019/v1")
        keys.update(e2ee_keys)

    # 合并所有 service 条目
    all_services = []
    if agent_description_url is not None:
        all_services.append({
            "id": f"{did}#ad",
            "type": "AgentDescription",
            "serviceEndpoint": agent_description_url,
        })
    if services:
        for svc in services:
            svc_id = svc.get("id", "")
            if svc_id.startswith("#"):
                svc = {**svc, "id": f"{did}{svc_id}"}
            all_services.append(svc)
    if all_services:
        did_document["service"] = all_services

    # Self-sign the DID document with W3C Data Integrity Proof
    proof_vm = verification_method
    if proof_vm is None:
        proof_vm = did_document["verificationMethod"][0]["id"]

    did_document = generate_w3c_proof(
        document=did_document,
        private_key=secp256k1_private_key,
        verification_method=proof_vm,
        proof_purpose=proof_purpose,
        domain=domain,
        challenge=challenge,
        created=created,
    )

    logging.info(f"Successfully created DID document with ID: {did}")
    return did_document, keys


def create_did_wba_document_with_key_binding(
    hostname: str,
    port: Optional[int] = None,
    path_prefix: Optional[List[str]] = None,
    agent_description_url: Optional[str] = None,
    services: Optional[List[Dict[str, Any]]] = None,
    proof_purpose: str = "assertionMethod",
    verification_method: Optional[str] = None,
    domain: Optional[str] = None,
    challenge: Optional[str] = None,
    created: Optional[str] = None,
    # --- E2EE 参数 ---
    enable_e2ee: bool = True,
) -> Tuple[Dict[str, Any], Dict[str, Tuple[bytes, bytes]]]:
    """
    Generate a key-bound DID document where the DID identifier contains a
    cryptographic fingerprint of the public key (JWK Thumbprint per RFC 7638).

    The DID format is: did:wba:{domain}:{path_prefix}:k1_{fingerprint}
    where k1_ is a version prefix for secp256k1 + SHA-256, and fingerprint
    is a 43-character base64url-encoded JWK Thumbprint.

    This binding prevents the hosting provider from replacing the public key
    in the DID document, since any such change would invalidate the fingerprint
    embedded in the DID itself.

    Args:
        hostname: Hostname
        port: Optional port number
        path_prefix: Path segments before the key-bound ID, e.g. ['user'] or ['agent'].
            Defaults to ['user'] if None.
        agent_description_url: Optional URL for agent description
        services: Optional list of custom service entries. Each entry is a dict
            with at least "id", "type", "serviceEndpoint" keys. If "id" starts
            with "#", it will be automatically prefixed with the DID.
        proof_purpose: Proof purpose string, default "assertionMethod"
        verification_method: Verification method ID for proof. If None,
            uses the first method from the document.
        domain: Optional domain for proof
        challenge: Optional challenge for proof
        created: Optional ISO 8601 timestamp for proof
        enable_e2ee: If True (default), add secp256r1 (#key-2) and X25519
            (#key-3) verification methods for E2EE support.

    Returns:
        Tuple[Dict, Dict]: Returns a tuple containing two dictionaries:
            - First dict is the DID document
            - Second dict is the keys dictionary where key is DID fragment (e.g. "key-1")
              and value is a tuple of (private_key_pem_bytes, public_key_pem_bytes)

    Raises:
        ValueError: If hostname is empty or is an IP address
    """
    if not hostname:
        raise ValueError("Hostname cannot be empty")

    if _is_ip_address(hostname):
        raise ValueError("Hostname cannot be an IP address")

    if path_prefix is None:
        path_prefix = ["user"]

    logging.info(f"Creating key-bound DID WBA document for hostname: {hostname}")

    # Generate secp256k1 key pair
    secp256k1_private_key = ec.generate_private_key(ec.SECP256K1())
    secp256k1_public_key = secp256k1_private_key.public_key()

    # Compute JWK Thumbprint fingerprint
    fp = compute_jwk_fingerprint(secp256k1_public_key)
    unique_id = f"k1_{fp}"

    # Build path segments: path_prefix + key-bound ID
    path_segments = path_prefix + [unique_id]

    # Build base DID
    did_base = f"did:wba:{hostname}"
    if port is not None:
        encoded_port = urllib.parse.quote(f":{port}")
        did_base = f"{did_base}{encoded_port}"

    did_path = ":".join(path_segments)
    did = f"{did_base}:{did_path}"

    # Build verification method
    vm_entry = {
        "id": f"{did}#{VM_KEY_AUTH}",
        "type": "EcdsaSecp256k1VerificationKey2019",
        "controller": did,
        "publicKeyJwk": _public_key_to_jwk(secp256k1_public_key)
    }

    verification_methods = [vm_entry]
    contexts = [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/suites/jws-2020/v1",
        "https://w3id.org/security/suites/secp256k1-2019/v1",
    ]

    # Build keys dictionary with both private and public keys in PEM format
    keys = {
        VM_KEY_AUTH: (
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

    # Build DID document
    did_document = {
        "@context": contexts,
        "id": did,
        "verificationMethod": verification_methods,
        "authentication": [vm_entry["id"]],
    }

    # Add E2EE keys if enabled
    if enable_e2ee:
        e2ee_vms, ka_refs, e2ee_keys = _build_e2ee_entries(did)
        verification_methods.extend(e2ee_vms)
        did_document["keyAgreement"] = ka_refs
        contexts.append("https://w3id.org/security/suites/x25519-2019/v1")
        keys.update(e2ee_keys)

    # Merge all service entries
    all_services = []
    if agent_description_url is not None:
        all_services.append({
            "id": f"{did}#ad",
            "type": "AgentDescription",
            "serviceEndpoint": agent_description_url,
        })
    if services:
        for svc in services:
            svc_id = svc.get("id", "")
            if svc_id.startswith("#"):
                svc = {**svc, "id": f"{did}{svc_id}"}
            all_services.append(svc)
    if all_services:
        did_document["service"] = all_services

    # Self-sign the DID document with W3C Data Integrity Proof
    proof_vm = verification_method
    if proof_vm is None:
        proof_vm = did_document["verificationMethod"][0]["id"]

    did_document = generate_w3c_proof(
        document=did_document,
        private_key=secp256k1_private_key,
        verification_method=proof_vm,
        proof_purpose=proof_purpose,
        domain=domain,
        challenge=challenge,
        created=created,
    )

    logging.info(f"Successfully created key-bound DID document with ID: {did}")
    return did_document, keys


def verify_did_key_binding(did: str, public_key_jwk: Dict) -> bool:
    """
    Verify that the fingerprint in a key-bound DID matches the public key.

    For DIDs with a k1_ prefix in the last segment, this function recomputes
    the JWK Thumbprint from the provided public key JWK and compares it with
    the fingerprint embedded in the DID.

    For DIDs without a recognized key-binding prefix (e.g. u1_ or plain IDs),
    this function returns True (no binding to verify).

    Args:
        did: DID string, e.g. did:wba:example.com:user:k1_{fingerprint}
        public_key_jwk: The publicKeyJwk from the DID document's verification method

    Returns:
        bool: True if fingerprint matches or if DID has no key-binding prefix
    """
    # Extract the last segment from the DID
    parts = did.split(":")
    if len(parts) < 4:
        return True  # No path segments, nothing to verify

    last_segment = parts[-1]

    # Only verify k1_ prefixed segments
    if not last_segment.startswith("k1_"):
        return True

    fp_from_did = last_segment[3:]  # Remove "k1_" prefix

    # Reconstruct public key from JWK and compute fingerprint
    try:
        public_key = _extract_ec_public_key_from_jwk(public_key_jwk)
        fp_computed = compute_jwk_fingerprint(public_key)
        return fp_computed == fp_from_did
    except (ValueError, KeyError):
        return False


async def resolve_did_wba_document(did: str, verify_proof: bool = False) -> Dict:
    """
    Resolve DID document from Web DID asynchronously

    Args:
        did: DID to resolve, e.g. did:wba:example.com:user:alice
        verify_proof: If True and the resolved document contains a proof field,
            verify the proof signature using the document's verification method.

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

                # Optionally verify W3C proof if present
                if verify_proof and "proof" in did_document:
                    proof = did_document["proof"]
                    vm_id = proof.get("verificationMethod")
                    if not vm_id:
                        logging.warning("Proof missing verificationMethod field")
                        return None

                    method_dict = _find_verification_method(did_document, vm_id)
                    if not method_dict:
                        logging.warning(f"Verification method not found: {vm_id}")
                        return None

                    try:
                        public_key = _extract_public_key(method_dict)
                    except ValueError as e:
                        logging.warning(f"Failed to extract public key: {e}")
                        return None

                    if not verify_w3c_proof(did_document, public_key):
                        logging.warning("DID document proof verification failed")
                        return None

                    logging.info("DID document proof verified successfully")

                return did_document

    except aiohttp.ClientError as e:
        logging.error(f"Failed to resolve DID document: {str(e)}\nStack trace:\n{traceback.format_exc()}")
        return None
    except Exception as e:
        logging.error(f"Failed to resolve DID document: {str(e)}\nStack trace:\n{traceback.format_exc()}")
        return None

# Add a sync wrapper for backward compatibility
def resolve_did_wba_document_sync(did: str, verify_proof: bool = False) -> Dict:
    """
    Synchronous wrapper for resolve_did_wba_document

    Args:
        did: DID to resolve, e.g. did:wba:example.com:user:alice
        verify_proof: If True and the resolved document contains a proof field,
            verify the proof signature using the document's verification method.

    Returns:
        Dict: Resolved DID document
    """
    return asyncio.run(resolve_did_wba_document(did, verify_proof=verify_proof))

def generate_auth_header(
    did_document: Dict,
    service_domain: str,
    sign_callback: Callable[[bytes, str], bytes],
    version: str = "1.1"
) -> str:
    """
    Generate the Authorization header for DID authentication.

    Args:
        did_document: DID document dictionary.
        service_domain: Server domain.
        sign_callback: Signature callback function that takes the content to sign and the verification method fragment as parameters.
            callback(content_to_sign: bytes, verification_method_fragment: str) -> bytes.
            If ECDSA, return signature in DER format.
        version: Protocol version (default "1.1"). Versions >= 1.1 use "aud" field instead of "service" in signature.

    Returns:
        str: Value of the Authorization header. Do not include "Authorization:" prefix.

    Raises:
        ValueError: If the DID document format is invalid.
    """
    logging.info(f"Starting to generate DID authentication header with version {version}.")

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

    # Determine which field to use based on version
    # For version >= 1.1, use "aud" instead of "service"
    try:
        version_float = float(version)
        domain_field = "aud" if version_float >= 1.1 else "service"
    except ValueError:
        # If version is not a valid float, default to "service" for backward compatibility
        domain_field = "service"
        logging.warning(f"Invalid version format '{version}', using 'service' field for backward compatibility")

    # Construct the data to sign
    data_to_sign = {
        "nonce": nonce,
        "timestamp": timestamp,
        domain_field: service_domain,
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
        f'DIDWba v="{version}", '
        f'did="{did}", '
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

    # Handle EcdsaSecp256r1VerificationKey2019
    elif method_type == 'EcdsaSecp256r1VerificationKey2019':
        if 'publicKeyJwk' in verification_method:
            jwk = verification_method['publicKeyJwk']
            if jwk.get('crv') != 'P-256':
                raise ValueError("Invalid curve for EcdsaSecp256r1VerificationKey2019")
            return _extract_ec_public_key_from_jwk(jwk)

    # Handle Ed25519 verification methods
    elif method_type in ['Ed25519VerificationKey2020', 'Ed25519VerificationKey2018']:
        if 'publicKeyJwk' in verification_method:
            jwk = verification_method['publicKeyJwk']
            if jwk.get('kty') != 'OKP' or jwk.get('crv') != 'Ed25519':
                raise ValueError(f"Invalid JWK parameters for {method_type}")
            try:
                key_bytes = base64.urlsafe_b64decode(jwk['x'] + '=' * (-len(jwk['x']) % 4))
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

def extract_auth_header_parts(auth_header: str) -> Tuple[str, str, str, str, str, Optional[str]]:
    """
    Extract authentication information from the authorization header.

    Args:
        auth_header: Authorization header value without "Authorization:" prefix.

    Returns:
        Tuple[str, str, str, str, str, Optional[str]]: A tuple containing:
            - did: DID string
            - nonce: Nonce value
            - timestamp: Timestamp string
            - verification_method: Verification method fragment
            - signature: Signature value
            - version: Version string (optional, defaults to "1.1" if not present)

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

    # Optional version field (defaults to "1.1")
    version_pattern = r'(?i)v="([^"]+)"'

    # Verify the header starts with DIDWba
    if not auth_header.strip().startswith('DIDWba'):
        raise ValueError("Authorization header must start with 'DIDWba'")

    parts = {}
    for field, pattern in required_fields.items():
        match = re.search(pattern, auth_header)
        if not match:
            raise ValueError(f"Missing required field in auth header: {field}")
        parts[field] = match.group(1)

    # Extract version if present, default to "1.1"
    version_match = re.search(version_pattern, auth_header)
    version = version_match.group(1) if version_match else "1.1"

    logging.debug(f"Extracted auth header parts: {parts}, version: {version}")
    return (parts['did'], parts['nonce'], parts['timestamp'],
            parts['verification_method'], parts['signature'], version)

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
        # Extract auth header parts (now includes version)
        client_did, nonce, timestamp_str, verification_method, signature, version = extract_auth_header_parts(auth_header)

        # Verify DID (case-insensitive comparison)
        if did_document.get('id').lower() != client_did.lower():
            return False, "DID mismatch"

        # Determine which field to use based on version
        # For version >= 1.1, use "aud" instead of "service"
        try:
            version_float = float(version)
            domain_field = "aud" if version_float >= 1.1 else "service"
        except ValueError:
            # If version is not a valid float, default to "service" for backward compatibility
            domain_field = "service"
            logging.warning(f"Invalid version format '{version}', using 'service' field for verification")

        # Construct data to verify
        data_to_verify = {
            "nonce": nonce,
            "timestamp": timestamp_str,
            domain_field: service_domain,
            "did": client_did
        }

        canonical_json = jcs.canonicalize(data_to_verify)
        logging.debug(f"verify_auth_header_signature Canonical JSON: {canonical_json}")
        content_hash = hashlib.sha256(canonical_json).digest()

        verification_method_id = f"{client_did}#{verification_method}"
        method_dict = _find_verification_method(did_document, verification_method_id)
        if not method_dict:
            return False, "Verification method not found"

        try:
            verifier = create_verification_method(method_dict)
            if verifier.verify_signature(content_hash, signature):
                logging.info(f"Signature verification successful for version {version}")
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
    sign_callback: Callable[[bytes, str], bytes],
    version: str = "1.1"
) -> str:
    """
    Generate JSON format string for DID authentication.

    Args:
        did_document: DID document dictionary
        service_domain: Server domain
        sign_callback: Signature callback function that takes content to sign and verification method fragment
            callback(content_to_sign: bytes, verification_method_fragment: str) -> bytes
            For ECDSA, return signature in DER format
        version: Protocol version (default "1.1"). Versions >= 1.1 use "aud" field instead of "service" in signature.

    Returns:
        str: Authentication information in JSON format

    Raises:
        ValueError: If DID document format is invalid
    """
    logging.info(f"Starting to generate DID authentication JSON with version {version}")

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

    # Determine which field to use based on version
    # For version >= 1.1, use "aud" instead of "service"
    try:
        version_float = float(version)
        domain_field = "aud" if version_float >= 1.1 else "service"
    except ValueError:
        # If version is not a valid float, default to "service" for backward compatibility
        domain_field = "service"
        logging.warning(f"Invalid version format '{version}', using 'service' field for backward compatibility")

    # Construct data to sign
    data_to_sign = {
        "nonce": nonce,
        "timestamp": timestamp,
        domain_field: service_domain,
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
        "v": version,
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
        version = auth_data.get('v', '1.1')  # Default to "1.1"

        # Verify all required fields exist
        if not all([client_did, nonce, timestamp_str, verification_method, signature]):
            return False, "Authentication JSON missing required fields"

        # Verify DID (case-insensitive comparison)
        if did_document.get('id').lower() != client_did.lower():
            return False, "DID mismatch"

        # Determine which field to use based on version
        # For version >= 1.1, use "aud" instead of "service"
        try:
            version_float = float(version)
            domain_field = "aud" if version_float >= 1.1 else "service"
        except ValueError:
            # If version is not a valid float, default to "service" for backward compatibility
            domain_field = "service"
            logging.warning(f"Invalid version format '{version}', using 'service' field for verification")

        # Construct data to verify
        data_to_verify = {
            "nonce": nonce,
            "timestamp": timestamp_str,
            domain_field: service_domain,
            "did": client_did
        }

        canonical_json = jcs.canonicalize(data_to_verify)
        logging.debug(f"verify_auth_json_signature Canonical JSON: {canonical_json}")
        content_hash = hashlib.sha256(canonical_json).digest()

        verification_method_id = f"{client_did}#{verification_method}"
        method_dict = _find_verification_method(did_document, verification_method_id)
        if not method_dict:
            return False, "Verification method not found"

        try:
            verifier = create_verification_method(method_dict)
            if verifier.verify_signature(content_hash, signature):
                logging.info(f"JSON signature verification successful for version {version}")
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
