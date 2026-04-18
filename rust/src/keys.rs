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
use pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding};
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
            Self::Secp256k1(key) => key
                .to_pkcs8_pem(LineEnding::LF)
                .expect("secp256k1 private key should encode as PKCS#8")
                .to_string(),
            Self::Secp256r1(key) => key
                .to_pkcs8_pem(LineEnding::LF)
                .expect("secp256r1 private key should encode as PKCS#8")
                .to_string(),
            Self::Ed25519(key) => encode_pem("PRIVATE KEY", &ed25519_pkcs8_der(&key.to_bytes())),
            Self::X25519(key) => encode_pem("PRIVATE KEY", &x25519_pkcs8_der(&key.to_bytes())),
        }
    }

    pub fn from_pem(input: &str) -> Result<Self, KeyMaterialError> {
        let (label, bytes) = decode_pem(input)?;
        if label != "PRIVATE KEY" {
            return Err(KeyMaterialError::InvalidPemLabel(label));
        }
        if let Ok(bytes) = ed25519_private_from_pkcs8_der(&bytes) {
            return Ok(Self::Ed25519(Ed25519SigningKey::from_bytes(&bytes)));
        }
        if let Ok(key) = Ed25519SigningKey::from_pkcs8_der(&bytes) {
            return Ok(Self::Ed25519(key));
        }
        if let Ok(key) = Secp256r1SigningKey::from_pkcs8_der(&bytes) {
            return Ok(Self::Secp256r1(key));
        }
        if let Ok(key) = Secp256k1SigningKey::from_pkcs8_der(&bytes) {
            return Ok(Self::Secp256k1(key));
        }
        if let Ok(bytes) = x25519_private_from_pkcs8_der(&bytes) {
            return Ok(Self::X25519(X25519StaticSecret::from(bytes)));
        }
        Err(KeyMaterialError::InvalidKeyBytes)
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
            Self::Secp256k1(key) => key
                .to_public_key_pem(LineEnding::LF)
                .expect("secp256k1 public key should encode as SPKI"),
            Self::Secp256r1(key) => key
                .to_public_key_pem(LineEnding::LF)
                .expect("secp256r1 public key should encode as SPKI"),
            Self::Ed25519(key) => encode_pem("PUBLIC KEY", &ed25519_spki_der(&key.to_bytes())),
            Self::X25519(key) => encode_pem("PUBLIC KEY", &x25519_spki_der(key)),
        }
    }

    pub fn from_pem(input: &str) -> Result<Self, KeyMaterialError> {
        let (label, bytes) = decode_pem(input)?;
        if label != "PUBLIC KEY" {
            return Err(KeyMaterialError::InvalidPemLabel(label));
        }
        if let Ok(bytes) = ed25519_public_from_spki_der(&bytes) {
            let key = Ed25519VerifyingKey::from_bytes(&bytes)
                .map_err(|_| KeyMaterialError::InvalidKeyBytes)?;
            return Ok(Self::Ed25519(key));
        }
        if let Ok(key) = Ed25519VerifyingKey::from_public_key_der(&bytes) {
            return Ok(Self::Ed25519(key));
        }
        if let Ok(key) = Secp256r1VerifyingKey::from_public_key_der(&bytes) {
            return Ok(Self::Secp256r1(key));
        }
        if let Ok(key) = Secp256k1VerifyingKey::from_public_key_der(&bytes) {
            return Ok(Self::Secp256k1(key));
        }
        if let Ok(bytes) = x25519_public_from_spki_der(&bytes) {
            return Ok(Self::X25519(bytes));
        }
        Err(KeyMaterialError::InvalidKeyBytes)
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

const ED25519_PKCS8_PREFIX: &[u8] = &[
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];
const ED25519_SPKI_PREFIX: &[u8] = &[
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
const X25519_PKCS8_PREFIX: &[u8] = &[
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
];
const X25519_SPKI_PREFIX: &[u8] = &[
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00,
];

fn ed25519_pkcs8_der(private_key: &[u8; 32]) -> Vec<u8> {
    okp_pkcs8_der(ED25519_PKCS8_PREFIX, private_key)
}

fn ed25519_private_from_pkcs8_der(der: &[u8]) -> Result<[u8; 32], KeyMaterialError> {
    okp_private_from_pkcs8_der(ED25519_PKCS8_PREFIX, der)
}

fn ed25519_spki_der(public_key: &[u8; 32]) -> Vec<u8> {
    okp_spki_der(ED25519_SPKI_PREFIX, public_key)
}

fn ed25519_public_from_spki_der(der: &[u8]) -> Result<[u8; 32], KeyMaterialError> {
    okp_public_from_spki_der(ED25519_SPKI_PREFIX, der)
}

fn x25519_pkcs8_der(private_key: &[u8; 32]) -> Vec<u8> {
    okp_pkcs8_der(X25519_PKCS8_PREFIX, private_key)
}

fn x25519_private_from_pkcs8_der(der: &[u8]) -> Result<[u8; 32], KeyMaterialError> {
    okp_private_from_pkcs8_der(X25519_PKCS8_PREFIX, der)
}

fn x25519_spki_der(public_key: &[u8; 32]) -> Vec<u8> {
    okp_spki_der(X25519_SPKI_PREFIX, public_key)
}

fn x25519_public_from_spki_der(der: &[u8]) -> Result<[u8; 32], KeyMaterialError> {
    okp_public_from_spki_der(X25519_SPKI_PREFIX, der)
}

fn okp_pkcs8_der(prefix: &[u8], private_key: &[u8; 32]) -> Vec<u8> {
    let mut der = Vec::with_capacity(prefix.len() + private_key.len());
    der.extend_from_slice(prefix);
    der.extend_from_slice(private_key);
    der
}

fn okp_private_from_pkcs8_der(prefix: &[u8], der: &[u8]) -> Result<[u8; 32], KeyMaterialError> {
    if der.len() != prefix.len() + 32 || !der.starts_with(prefix) {
        return Err(KeyMaterialError::InvalidKeyBytes);
    }
    der[prefix.len()..]
        .try_into()
        .map_err(|_| KeyMaterialError::InvalidKeyBytes)
}

fn okp_spki_der(prefix: &[u8], public_key: &[u8; 32]) -> Vec<u8> {
    let mut der = Vec::with_capacity(prefix.len() + public_key.len());
    der.extend_from_slice(prefix);
    der.extend_from_slice(public_key);
    der
}

fn okp_public_from_spki_der(prefix: &[u8], der: &[u8]) -> Result<[u8; 32], KeyMaterialError> {
    if der.len() != prefix.len() + 32 || !der.starts_with(prefix) {
        return Err(KeyMaterialError::InvalidKeyBytes);
    }
    der[prefix.len()..]
        .try_into()
        .map_err(|_| KeyMaterialError::InvalidKeyBytes)
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
