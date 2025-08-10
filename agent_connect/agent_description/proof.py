# AgentConnect: https://github.com/agent-network-protocol/AgentConnect
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: https://agent-network-protocol.com/
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.

import json
import base64
import hashlib
import datetime
from typing import Any, Callable, Dict, Optional
import jcs
import copy

def remove_proof_value(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create a copy of the document with proofValue field removed.
    
    Args:
        data: Original document
        
    Returns:
        Dict[str, Any]: Document copy with proofValue removed
    """
    # Create a deep copy
    doc = copy.deepcopy(data)
    
    # Remove proofValue if exists
    if "proof" in doc and "proofValue" in doc["proof"]:
        del doc["proof"]["proofValue"]
    
    return doc

def canonicalize_json(data: Dict[str, Any]) -> bytes:
    """
    Canonicalize JSON data according to JCS (RFC 8785).
    
    Args:
        data: JSON data to canonicalize
        
    Returns:
        bytes: Canonicalized JSON bytes
    
    Raises:
        ValueError: If the JSON cannot be canonicalized
    """
    try:
        # Use jcs library for canonicalization
        return jcs.canonicalize(data)
    except Exception as e:
        raise ValueError(f"Failed to canonicalize JSON: {str(e)}")

def generate_proof(
    document: Dict[str, Any],
    sign_callback: Callable[[bytes], bytes],
) -> Dict[str, Any]:
    """
    Generate a proof for a JSON document.
    The input document should already contain all proof fields except proofValue.
    
    The process follows these steps:
    1. Remove proofValue field from the document
    2. Canonicalize the document using JCS (RFC 8785)
    3. Calculate SHA-256 hash of the canonicalized string
    4. Sign the hash using the callback function
    5. Encode the signature using URL-safe base64
    6. Add the encoded signature as proofValue

    Args:
        document: JSON document to sign, containing all proof fields except proofValue
        sign_callback: Callback function that signs the hash and returns raw signature bytes

    Returns:
        Dict[str, Any]: Document with proof
        
    Raises:
        ValueError: If input parameters are invalid or JSON canonicalization fails
    """
    if not isinstance(document, dict):
        raise ValueError("Document must be a dictionary")
    if not callable(sign_callback):
        raise ValueError("sign_callback must be callable")
    if "proof" not in document:
        raise ValueError("Document must contain a proof object")
    
    try:
        # Step 1: Remove proofValue field if exists
        doc_without_proof = remove_proof_value(document)
        
        # Step 2: Canonicalize the document using JCS
        canonical_bytes = canonicalize_json(doc_without_proof)
        
        # Step 3: Calculate SHA-256 hash
        hash_value = hashlib.sha256(canonical_bytes).digest()
        
        # Step 4: Generate signature using callback
        signature_bytes = sign_callback(hash_value)
        
        # Step 5: Encode signature using URL-safe base64
        signature = base64.urlsafe_b64encode(signature_bytes).decode('utf-8')
        
        # Step 6: Add signature to proof
        result = copy.deepcopy(document)
        result["proof"]["proofValue"] = signature
        
        return result
        
    except Exception as e:
        raise ValueError(f"Failed to generate proof: {str(e)}")

def verify_proof(
    document: Dict[str, Any],
    verify_callback: Callable[[bytes, bytes], bool]
) -> bool:
    """
    Verify the proof of a JSON document.
    
    The verification process follows these steps:
    1. Extract and decode the proofValue from URL-safe base64
    2. Remove proofValue field from the document
    3. Canonicalize the document using JCS (RFC 8785)
    4. Calculate SHA-256 hash of the canonicalized string
    5. Verify the signature using the callback function

    Args:
        document: JSON document to verify
        verify_callback: Callback function that verifies the raw signature bytes

    Returns:
        bool: True if verification succeeds, False otherwise
        
    Raises:
        ValueError: If input parameters are invalid
    """
    if not isinstance(document, dict):
        raise ValueError("Document must be a dictionary")
    if not callable(verify_callback):
        raise ValueError("verify_callback must be callable")
    if "proof" not in document or "proofValue" not in document["proof"]:
        return False
    
    try:
        # Step 1: Get and decode signature from URL-safe base64
        signature_b64 = document["proof"]["proofValue"]
        signature_bytes = base64.urlsafe_b64decode(signature_b64)
        
        # Step 2: Remove proofValue for verification
        doc_without_proof = remove_proof_value(document)
        
        # Step 3: Generate canonical bytes
        canonical_bytes = canonicalize_json(doc_without_proof)
        
        # Step 4: Calculate hash
        hash_value = hashlib.sha256(canonical_bytes).digest()
        
        # Step 5: Verify signature using callback
        return verify_callback(hash_value, signature_bytes)
    except Exception as e:
        return False
