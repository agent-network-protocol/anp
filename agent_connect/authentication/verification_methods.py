from abc import ABC, abstractmethod
import base64
import base58
from typing import Dict, Union, Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption
)
import logging

# Define supported curve mapping
CURVE_MAPPING = {
    'secp256k1': ec.SECP256K1(),
    'P-256': ec.SECP256R1(),
    'P-384': ec.SECP384R1(),
    'P-521': ec.SECP521R1(),
}

class VerificationMethod(ABC):
    """Abstract base class for verification methods"""
    
    @abstractmethod
    def verify_signature(self, content: bytes, signature: str) -> bool:
        """Verify signature"""
        pass
        
    @classmethod
    @abstractmethod
    def from_dict(cls, method_dict: Dict) -> 'VerificationMethod':
        """Create instance from verification method dictionary in DID document"""
        pass

    @staticmethod
    @abstractmethod
    def encode_signature(signature_bytes: bytes) -> str:
        """
        Encode signature bytes to base64url format
        
        Args:
            signature_bytes: Raw signature bytes
            
        Returns:
            str: base64url encoded signature
        """
        pass

class EcdsaSecp256k1VerificationKey2019(VerificationMethod):
    """EcdsaSecp256k1VerificationKey2019 implementation"""
    
    def __init__(self, public_key: ec.EllipticCurvePublicKey):
        self.public_key = public_key
    
    def verify_signature(self, content: bytes, signature: str) -> bool:
        try:
            # Decode base64url signature
            signature_bytes = base64.urlsafe_b64decode(signature + '=' * (-len(signature) % 4))
            
            # Convert R|S format to DER format
            r_length = len(signature_bytes) // 2
            r = int.from_bytes(signature_bytes[:r_length], 'big')
            s = int.from_bytes(signature_bytes[r_length:], 'big')
            signature_der = utils.encode_dss_signature(r, s)
            
            self.public_key.verify(
                signature_der,
                content,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except Exception as e:
            logging.error(f"Secp256k1 signature verification failed: {str(e)}")
            return False

    @classmethod
    def from_dict(cls, method_dict: Dict) -> 'EcdsaSecp256k1VerificationKey2019':
        if 'publicKeyJwk' in method_dict:
            return cls(cls._extract_public_key_from_jwk(method_dict['publicKeyJwk']))
        elif 'publicKeyMultibase' in method_dict:
            return cls(cls._extract_public_key_from_multibase(method_dict['publicKeyMultibase']))
        raise ValueError("Unsupported key format for EcdsaSecp256k1VerificationKey2019")

    @staticmethod
    def _extract_public_key_from_jwk(jwk: Dict) -> ec.EllipticCurvePublicKey:
        if jwk.get('kty') != 'EC' or jwk.get('crv') != 'secp256k1':
            raise ValueError("Invalid JWK parameters for Secp256k1")
        
        x = int.from_bytes(base64.urlsafe_b64decode(
            jwk['x'] + '=' * (-len(jwk['x']) % 4)), 'big')
        y = int.from_bytes(base64.urlsafe_b64decode(
            jwk['y'] + '=' * (-len(jwk['y']) % 4)), 'big')
        
        return ec.EllipticCurvePublicNumbers(
            x, y, ec.SECP256K1()
        ).public_key()

    @staticmethod
    def _extract_public_key_from_multibase(multibase: str) -> ec.EllipticCurvePublicKey:
        if not multibase.startswith('z'):
            raise ValueError("Unsupported multibase encoding")
        key_bytes = base58.b58decode(multibase[1:])
        return ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256K1(),
            key_bytes
        )

    @staticmethod
    def encode_signature(signature_bytes: bytes) -> str:
        """
        Encode signature bytes to base64url format. If the signature is in DER format, first convert it to R|S format.
        
        Args:
            signature_bytes: Raw signature bytes, which may be in DER format or R|S format
            
        Returns:
            str: base64url encoded signature
            
        Raises:
            ValueError: If signature format is invalid
        """
        try:
            # Try to parse DER format
            try:
                r, s = utils.decode_dss_signature(signature_bytes)
                # If successful parsing as DER format, convert to R|S format
                r_bytes = r.to_bytes((r.bit_length() + 7) // 8, byteorder='big')
                s_bytes = s.to_bytes((s.bit_length() + 7) // 8, byteorder='big')
                signature = r_bytes + s_bytes
            except Exception:
                # If not DER format, assume it's already in R|S format
                if len(signature_bytes) % 2 != 0:
                    raise ValueError("Invalid R|S signature format: length must be even")
                signature = signature_bytes
            
            # Encode to base64url
            return base64.urlsafe_b64encode(signature).rstrip(b'=').decode('ascii')
            
        except Exception as e:
            logging.error(f"Failed to encode signature: {str(e)}")
            raise ValueError(f"Invalid signature format: {str(e)}")

class Ed25519VerificationKey2018(VerificationMethod):
    """Ed25519VerificationKey2018 implementation"""
    
    def __init__(self, public_key: ed25519.Ed25519PublicKey):
        self.public_key = public_key
    
    def verify_signature(self, content: bytes, signature: str) -> bool:
        try:
            signature_bytes = base64.urlsafe_b64decode(signature + '=' * (-len(signature) % 4))
            self.public_key.verify(signature_bytes, content)
            return True
        except Exception as e:
            logging.error(f"Ed25519 signature verification failed: {str(e)}")
            return False

    @classmethod
    def from_dict(cls, method_dict: Dict) -> 'Ed25519VerificationKey2018':
        if 'publicKeyJwk' in method_dict:
            return cls(cls._extract_public_key_from_jwk(method_dict['publicKeyJwk']))
        elif 'publicKeyMultibase' in method_dict:
            return cls(cls._extract_public_key_from_multibase(method_dict['publicKeyMultibase']))
        elif 'publicKeyBase58' in method_dict:
            return cls(cls._extract_public_key_from_base58(method_dict['publicKeyBase58']))
        raise ValueError("Unsupported key format for Ed25519VerificationKey2018")

    @staticmethod
    def _extract_public_key_from_jwk(jwk: Dict) -> ed25519.Ed25519PublicKey:
        if jwk.get('kty') != 'OKP' or jwk.get('crv') != 'Ed25519':
            raise ValueError("Invalid JWK parameters for Ed25519")
        key_bytes = base64.urlsafe_b64decode(jwk['x'] + '=' * (-len(jwk['x']) % 4))
        return ed25519.Ed25519PublicKey.from_public_bytes(key_bytes)

    @staticmethod
    def _extract_public_key_from_multibase(multibase: str) -> ed25519.Ed25519PublicKey:
        if not multibase.startswith('z'):
            raise ValueError("Unsupported multibase encoding")
        key_bytes = base58.b58decode(multibase[1:])
        return ed25519.Ed25519PublicKey.from_public_bytes(key_bytes)

    @staticmethod
    def _extract_public_key_from_base58(base58_key: str) -> ed25519.Ed25519PublicKey:
        key_bytes = base58.b58decode(base58_key)
        return ed25519.Ed25519PublicKey.from_public_bytes(key_bytes)

    @staticmethod
    def encode_signature(signature_bytes: bytes) -> str:
        """
        Encode Ed25519 signature bytes to base64url format
        """
        # Ed25519 uses raw signature
        return base64.urlsafe_b64encode(signature_bytes).rstrip(b'=').decode('ascii')

def create_verification_method(method_dict: Dict) -> VerificationMethod:
    """Factory method to create corresponding instance based on verification method type"""
    
    method_type = method_dict.get('type')
    if not method_type:
        raise ValueError("Missing verification method type")
        
    method_mapping = {
        'EcdsaSecp256k1VerificationKey2019': EcdsaSecp256k1VerificationKey2019,
        'Ed25519VerificationKey2018': Ed25519VerificationKey2018,
    }
    
    method_class = method_mapping.get(method_type)
    if not method_class:
        raise ValueError(f"Unsupported verification method type: {method_type}")
        
    return method_class.from_dict(method_dict) 