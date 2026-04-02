use std::fmt;

use base64::{
    engine::general_purpose::STANDARD, engine::general_purpose::URL_SAFE_NO_PAD, Engine as _,
};
use ed25519_dalek::{
    Signature as Ed25519Signature, Signer as Ed25519Signer, SigningKey as Ed25519SigningKey,
    VerifyingKey as Ed25519VerifyingKey,
};
use k256::ecdsa::{
    Signature as K256Signature, SigningKey as Secp256k1SigningKey,
    VerifyingKey as Secp256k1VerifyingKey,
};
use num_bigint::BigUint;
use p256::ecdsa::{
    Signature as P256Signature, SigningKey as Secp256r1SigningKey,
    VerifyingKey as Secp256r1VerifyingKey,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

pub enum PrivateKeyMaterial {
    Secp256k1(Secp256k1SigningKey),
    Secp256r1(Secp256r1SigningKey),
    Ed25519(Ed25519SigningKey),
    X25519(X25519StaticSecret),
}

impl fmt::Debug for PrivateKeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Secp256k1(_) => write!(f, "PrivateKeyMaterial::Secp256k1(..)"),
            Self::Secp256r1(_) => write!(f, "PrivateKeyMaterial::Secp256r1(..)"),
            Self::Ed25519(_) => write!(f, "PrivateKeyMaterial::Ed25519(..)"),
            Self::X25519(_) => write!(f, "PrivateKeyMaterial::X25519(..)"),
        }
    }
}

#[derive(Debug, Clone)]
pub enum PublicKeyMaterial {
    Secp256k1(Secp256k1VerifyingKey),
    Secp256r1(Secp256r1VerifyingKey),
    Ed25519(Ed25519VerifyingKey),
    X25519([u8; 32]),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GeneratedKeyPairPem {
    pub private_key_pem: String,
    pub public_key_pem: String,
}

#[derive(Debug, Error)]
pub enum KeyMaterialError {
    #[error("Unsupported key type")]
    UnsupportedKeyType,
    #[error("Invalid PEM label: {0}")]
    InvalidPemLabel(String),
    #[error("Invalid PEM structure")]
    InvalidPemStructure,
    #[error("Invalid key bytes")]
    InvalidKeyBytes,
    #[error("Invalid signature encoding")]
    InvalidSignatureEncoding,
    #[error("Verification is not supported for X25519")]
    X25519VerificationUnsupported,
}

impl PrivateKeyMaterial {
    pub fn public_key(&self) -> PublicKeyMaterial {
        match self {
            Self::Secp256k1(key) => PublicKeyMaterial::Secp256k1(*key.verifying_key()),
            Self::Secp256r1(key) => PublicKeyMaterial::Secp256r1(*key.verifying_key()),
            Self::Ed25519(key) => PublicKeyMaterial::Ed25519(key.verifying_key()),
            Self::X25519(key) => PublicKeyMaterial::X25519(X25519PublicKey::from(key).to_bytes()),
        }
    }

    pub fn sign_message(&self, message: &[u8]) -> Result<Vec<u8>, KeyMaterialError> {
        match self {
            Self::Secp256k1(key) => {
                use k256::ecdsa::signature::Signer;
                let signature: K256Signature = key.sign(message);
                Ok(signature.to_bytes().to_vec())
            }
            Self::Secp256r1(key) => {
                use p256::ecdsa::signature::Signer;
                let signature: P256Signature = key.sign(message);
                Ok(signature.to_bytes().to_vec())
            }
            Self::Ed25519(key) => Ok(key.sign(message).to_bytes().to_vec()),
            Self::X25519(_) => Err(KeyMaterialError::UnsupportedKeyType),
        }
    }

    pub fn to_pem(&self) -> String {
        match self {
            Self::Secp256k1(key) => encode_pem("ANP SECP256K1 PRIVATE KEY", &key.to_bytes()),
            Self::Secp256r1(key) => encode_pem("ANP SECP256R1 PRIVATE KEY", &key.to_bytes()),
            Self::Ed25519(key) => encode_pem("ANP ED25519 PRIVATE KEY", &key.to_bytes()),
            Self::X25519(key) => encode_pem("ANP X25519 PRIVATE KEY", &key.to_bytes()),
        }
    }

    pub fn from_pem(input: &str) -> Result<Self, KeyMaterialError> {
        let (label, bytes) = decode_pem(input)?;
        match label.as_str() {
            "ANP SECP256K1 PRIVATE KEY" => {
                let key = Secp256k1SigningKey::from_slice(&bytes)
                    .map_err(|_| KeyMaterialError::InvalidKeyBytes)?;
                Ok(Self::Secp256k1(key))
            }
            "ANP SECP256R1 PRIVATE KEY" => {
                let key = Secp256r1SigningKey::from_slice(&bytes)
                    .map_err(|_| KeyMaterialError::InvalidKeyBytes)?;
                Ok(Self::Secp256r1(key))
            }
            "ANP ED25519 PRIVATE KEY" => {
                let bytes: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| KeyMaterialError::InvalidKeyBytes)?;
                Ok(Self::Ed25519(Ed25519SigningKey::from_bytes(&bytes)))
            }
            "ANP X25519 PRIVATE KEY" => {
                let bytes: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| KeyMaterialError::InvalidKeyBytes)?;
                Ok(Self::X25519(X25519StaticSecret::from(bytes)))
            }
            _ => Err(KeyMaterialError::InvalidPemLabel(label)),
        }
    }
}

impl PublicKeyMaterial {
    pub fn verify_message(
        &self,
        message: &[u8],
        signature_bytes: &[u8],
    ) -> Result<(), KeyMaterialError> {
        match self {
            Self::Secp256k1(key) => {
                use k256::ecdsa::signature::Verifier;
                if signature_bytes.len() == 64 {
                    let normalized = normalize_ecdsa_signature(
                        signature_bytes,
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
                    )?;
                    let signature = K256Signature::from_slice(&normalized)
                        .map_err(|_| KeyMaterialError::InvalidSignatureEncoding)?;
                    key.verify(message, &signature)
                        .map_err(|_| KeyMaterialError::InvalidSignatureEncoding)
                } else {
                    let signature = K256Signature::from_der(signature_bytes)
                        .map_err(|_| KeyMaterialError::InvalidSignatureEncoding)?;
                    key.verify(message, &signature)
                        .map_err(|_| KeyMaterialError::InvalidSignatureEncoding)
                }
            }
            Self::Secp256r1(key) => {
                use p256::ecdsa::signature::Verifier;
                if signature_bytes.len() == 64 {
                    let normalized = normalize_ecdsa_signature(
                        signature_bytes,
                        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
                    )?;
                    let signature = P256Signature::from_slice(&normalized)
                        .map_err(|_| KeyMaterialError::InvalidSignatureEncoding)?;
                    key.verify(message, &signature)
                        .map_err(|_| KeyMaterialError::InvalidSignatureEncoding)
                } else {
                    let signature = P256Signature::from_der(signature_bytes)
                        .map_err(|_| KeyMaterialError::InvalidSignatureEncoding)?;
                    key.verify(message, &signature)
                        .map_err(|_| KeyMaterialError::InvalidSignatureEncoding)
                }
            }
            Self::Ed25519(key) => {
                use ed25519_dalek::Verifier;
                let signature = Ed25519Signature::from_slice(signature_bytes)
                    .map_err(|_| KeyMaterialError::InvalidSignatureEncoding)?;
                key.verify(message, &signature)
                    .map_err(|_| KeyMaterialError::InvalidSignatureEncoding)
            }
            Self::X25519(_) => Err(KeyMaterialError::X25519VerificationUnsupported),
        }
    }

    pub fn to_pem(&self) -> String {
        match self {
            Self::Secp256k1(key) => encode_pem(
                "ANP SECP256K1 PUBLIC KEY",
                key.to_encoded_point(true).as_bytes(),
            ),
            Self::Secp256r1(key) => encode_pem(
                "ANP SECP256R1 PUBLIC KEY",
                key.to_encoded_point(true).as_bytes(),
            ),
            Self::Ed25519(key) => encode_pem("ANP ED25519 PUBLIC KEY", &key.to_bytes()),
            Self::X25519(key) => encode_pem("ANP X25519 PUBLIC KEY", key),
        }
    }

    pub fn from_pem(input: &str) -> Result<Self, KeyMaterialError> {
        let (label, bytes) = decode_pem(input)?;
        match label.as_str() {
            "ANP SECP256K1 PUBLIC KEY" => {
                let key = Secp256k1VerifyingKey::from_sec1_bytes(&bytes)
                    .map_err(|_| KeyMaterialError::InvalidKeyBytes)?;
                Ok(Self::Secp256k1(key))
            }
            "ANP SECP256R1 PUBLIC KEY" => {
                let key = Secp256r1VerifyingKey::from_sec1_bytes(&bytes)
                    .map_err(|_| KeyMaterialError::InvalidKeyBytes)?;
                Ok(Self::Secp256r1(key))
            }
            "ANP ED25519 PUBLIC KEY" => {
                let bytes: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| KeyMaterialError::InvalidKeyBytes)?;
                let key = Ed25519VerifyingKey::from_bytes(&bytes)
                    .map_err(|_| KeyMaterialError::InvalidKeyBytes)?;
                Ok(Self::Ed25519(key))
            }
            "ANP X25519 PUBLIC KEY" => {
                let bytes: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| KeyMaterialError::InvalidKeyBytes)?;
                Ok(Self::X25519(bytes))
            }
            _ => Err(KeyMaterialError::InvalidPemLabel(label)),
        }
    }
}

impl fmt::Display for PublicKeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Secp256k1(_) => write!(f, "secp256k1"),
            Self::Secp256r1(_) => write!(f, "secp256r1"),
            Self::Ed25519(_) => write!(f, "ed25519"),
            Self::X25519(_) => write!(f, "x25519"),
        }
    }
}

pub(crate) fn base64url_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub(crate) fn base64url_decode(value: &str) -> Result<Vec<u8>, KeyMaterialError> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| KeyMaterialError::InvalidSignatureEncoding)
}

pub(crate) fn encode_signature_bytes(signature_bytes: &[u8]) -> String {
    base64url_encode(signature_bytes)
}

pub(crate) fn decode_signature_bytes(signature: &str) -> Result<Vec<u8>, KeyMaterialError> {
    base64url_decode(signature)
}

pub(crate) fn encode_pem(label: &str, contents: &[u8]) -> String {
    let encoded = STANDARD.encode(contents);
    let mut wrapped = String::new();
    for chunk in encoded.as_bytes().chunks(64) {
        wrapped.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        wrapped.push('\n');
    }
    format!("-----BEGIN {label}-----\n{wrapped}-----END {label}-----\n")
}

pub(crate) fn decode_pem(input: &str) -> Result<(String, Vec<u8>), KeyMaterialError> {
    let mut lines = input.lines();
    let begin = lines.next().ok_or(KeyMaterialError::InvalidPemStructure)?;
    if !begin.starts_with("-----BEGIN ") || !begin.ends_with("-----") {
        return Err(KeyMaterialError::InvalidPemStructure);
    }
    let label = begin
        .trim_start_matches("-----BEGIN ")
        .trim_end_matches("-----")
        .to_string();
    let end_marker = format!("-----END {label}-----");
    let mut body = String::new();
    let mut found_end = false;
    for line in lines {
        if line == end_marker {
            found_end = true;
            break;
        }
        body.push_str(line.trim());
    }
    if !found_end {
        return Err(KeyMaterialError::InvalidPemStructure);
    }
    let bytes = STANDARD
        .decode(body.as_bytes())
        .map_err(|_| KeyMaterialError::InvalidPemStructure)?;
    Ok((label, bytes))
}

fn normalize_ecdsa_signature(
    signature_bytes: &[u8],
    order_hex: &str,
) -> Result<Vec<u8>, KeyMaterialError> {
    if signature_bytes.len() % 2 != 0 {
        return Err(KeyMaterialError::InvalidSignatureEncoding);
    }
    let half = signature_bytes.len() / 2;
    let r = &signature_bytes[..half];
    let s = &signature_bytes[half..];
    let order = BigUint::parse_bytes(order_hex.as_bytes(), 16)
        .ok_or(KeyMaterialError::InvalidSignatureEncoding)?;
    let half_order = &order >> 1;
    let s_value = BigUint::from_bytes_be(s);
    let normalized_s = if s_value > half_order {
        order - s_value
    } else {
        s_value
    };
    let mut normalized = Vec::with_capacity(signature_bytes.len());
    normalized.extend_from_slice(r);
    let mut s_bytes = normalized_s.to_bytes_be();
    if s_bytes.len() > half {
        return Err(KeyMaterialError::InvalidSignatureEncoding);
    }
    if s_bytes.len() < half {
        let mut padding = vec![0u8; half - s_bytes.len()];
        padding.append(&mut s_bytes);
        normalized.extend_from_slice(&padding);
    } else {
        normalized.extend_from_slice(&s_bytes);
    }
    Ok(normalized)
}
