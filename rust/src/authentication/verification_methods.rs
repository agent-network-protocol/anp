use serde_json::Value;
use thiserror::Error;

use crate::keys::{base64url_decode, decode_signature_bytes, encode_signature_bytes};
use crate::PublicKeyMaterial;

#[derive(Debug, Error)]
pub enum VerificationMethodError {
    #[error("Missing verification method type")]
    MissingType,
    #[error("Unsupported verification method type: {0}")]
    UnsupportedType(String),
    #[error("Missing key material")]
    MissingKeyMaterial,
    #[error("Invalid key material")]
    InvalidKeyMaterial,
    #[error("Signature encoding error")]
    SignatureEncoding,
}

#[derive(Debug, Clone)]
pub struct VerificationMethod {
    pub id: String,
    pub method_type: String,
    pub public_key: PublicKeyMaterial,
}

impl VerificationMethod {
    pub fn verify_signature(
        &self,
        content: &[u8],
        signature: &str,
    ) -> Result<(), VerificationMethodError> {
        let signature_bytes = decode_signature_bytes(signature)
            .map_err(|_| VerificationMethodError::SignatureEncoding)?;
        self.public_key
            .verify_message(content, &signature_bytes)
            .map_err(|_| VerificationMethodError::SignatureEncoding)
    }

    pub fn encode_signature(
        &self,
        signature_bytes: &[u8],
    ) -> Result<String, VerificationMethodError> {
        match self.public_key {
            PublicKeyMaterial::X25519(_) => Err(VerificationMethodError::UnsupportedType(
                self.method_type.clone(),
            )),
            _ => Ok(encode_signature_bytes(signature_bytes)),
        }
    }
}

pub fn create_verification_method(
    method_dict: &Value,
) -> Result<VerificationMethod, VerificationMethodError> {
    let object = method_dict
        .as_object()
        .ok_or(VerificationMethodError::InvalidKeyMaterial)?;
    let method_type = object
        .get("type")
        .and_then(Value::as_str)
        .ok_or(VerificationMethodError::MissingType)?;
    let id = object
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let public_key = extract_public_key(method_dict)?;
    Ok(VerificationMethod {
        id,
        method_type: method_type.to_string(),
        public_key,
    })
}

pub fn extract_public_key(
    method_dict: &Value,
) -> Result<PublicKeyMaterial, VerificationMethodError> {
    let object = method_dict
        .as_object()
        .ok_or(VerificationMethodError::InvalidKeyMaterial)?;
    let method_type = object
        .get("type")
        .and_then(Value::as_str)
        .ok_or(VerificationMethodError::MissingType)?;

    match method_type {
        "EcdsaSecp256k1VerificationKey2019" => extract_secp256k1_key(object),
        "EcdsaSecp256r1VerificationKey2019" => extract_secp256r1_key(object),
        "Ed25519VerificationKey2018" | "Ed25519VerificationKey2020" | "Multikey" => {
            extract_ed25519_key(object)
        }
        "X25519KeyAgreementKey2019" => extract_x25519_key(object),
        "JsonWebKey2020" => extract_ec_jwk_key(object),
        other => Err(VerificationMethodError::UnsupportedType(other.to_string())),
    }
}

fn extract_secp256k1_key(
    object: &serde_json::Map<String, Value>,
) -> Result<PublicKeyMaterial, VerificationMethodError> {
    if let Some(jwk) = object.get("publicKeyJwk") {
        return extract_ec_key_from_jwk(jwk, "secp256k1").map(PublicKeyMaterial::Secp256k1);
    }
    if let Some(multibase) = object.get("publicKeyMultibase").and_then(Value::as_str) {
        let bytes = bs58::decode(multibase.trim_start_matches('z'))
            .into_vec()
            .map_err(|_| VerificationMethodError::InvalidKeyMaterial)?;
        let key = k256::ecdsa::VerifyingKey::from_sec1_bytes(&bytes)
            .map_err(|_| VerificationMethodError::InvalidKeyMaterial)?;
        return Ok(PublicKeyMaterial::Secp256k1(key));
    }
    Err(VerificationMethodError::MissingKeyMaterial)
}

fn extract_secp256r1_key(
    object: &serde_json::Map<String, Value>,
) -> Result<PublicKeyMaterial, VerificationMethodError> {
    if let Some(jwk) = object.get("publicKeyJwk") {
        return extract_p256_key_from_jwk(jwk, "P-256").map(PublicKeyMaterial::Secp256r1);
    }
    if let Some(multibase) = object.get("publicKeyMultibase").and_then(Value::as_str) {
        let bytes = bs58::decode(multibase.trim_start_matches('z'))
            .into_vec()
            .map_err(|_| VerificationMethodError::InvalidKeyMaterial)?;
        let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&bytes)
            .map_err(|_| VerificationMethodError::InvalidKeyMaterial)?;
        return Ok(PublicKeyMaterial::Secp256r1(key));
    }
    Err(VerificationMethodError::MissingKeyMaterial)
}

fn extract_ec_jwk_key(
    object: &serde_json::Map<String, Value>,
) -> Result<PublicKeyMaterial, VerificationMethodError> {
    let jwk = object
        .get("publicKeyJwk")
        .ok_or(VerificationMethodError::MissingKeyMaterial)?;
    let crv = jwk
        .get("crv")
        .and_then(Value::as_str)
        .ok_or(VerificationMethodError::InvalidKeyMaterial)?;
    match crv {
        "secp256k1" => extract_ec_key_from_jwk(jwk, crv).map(PublicKeyMaterial::Secp256k1),
        "P-256" => extract_p256_key_from_jwk(jwk, crv).map(PublicKeyMaterial::Secp256r1),
        _ => Err(VerificationMethodError::UnsupportedType(crv.to_string())),
    }
}

fn extract_ed25519_key(
    object: &serde_json::Map<String, Value>,
) -> Result<PublicKeyMaterial, VerificationMethodError> {
    if let Some(jwk) = object.get("publicKeyJwk") {
        let x = jwk
            .get("x")
            .and_then(Value::as_str)
            .ok_or(VerificationMethodError::InvalidKeyMaterial)?;
        let bytes = base64url_decode(x).map_err(|_| VerificationMethodError::InvalidKeyMaterial)?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(
            &bytes
                .try_into()
                .map_err(|_| VerificationMethodError::InvalidKeyMaterial)?,
        )
        .map_err(|_| VerificationMethodError::InvalidKeyMaterial)?;
        return Ok(PublicKeyMaterial::Ed25519(key));
    }
    if let Some(multibase) = object.get("publicKeyMultibase").and_then(Value::as_str) {
        let mut bytes = bs58::decode(multibase.trim_start_matches('z'))
            .into_vec()
            .map_err(|_| VerificationMethodError::InvalidKeyMaterial)?;
        if bytes.len() == 34 && bytes.starts_with(&[0xed, 0x01]) {
            bytes = bytes[2..].to_vec();
        }
        let key = ed25519_dalek::VerifyingKey::from_bytes(
            &bytes
                .try_into()
                .map_err(|_| VerificationMethodError::InvalidKeyMaterial)?,
        )
        .map_err(|_| VerificationMethodError::InvalidKeyMaterial)?;
        return Ok(PublicKeyMaterial::Ed25519(key));
    }
    if let Some(base58_key) = object.get("publicKeyBase58").and_then(Value::as_str) {
        let bytes = bs58::decode(base58_key)
            .into_vec()
            .map_err(|_| VerificationMethodError::InvalidKeyMaterial)?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(
            &bytes
                .try_into()
                .map_err(|_| VerificationMethodError::InvalidKeyMaterial)?,
        )
        .map_err(|_| VerificationMethodError::InvalidKeyMaterial)?;
        return Ok(PublicKeyMaterial::Ed25519(key));
    }
    Err(VerificationMethodError::MissingKeyMaterial)
}

fn extract_x25519_key(
    object: &serde_json::Map<String, Value>,
) -> Result<PublicKeyMaterial, VerificationMethodError> {
    let multibase = object
        .get("publicKeyMultibase")
        .and_then(Value::as_str)
        .ok_or(VerificationMethodError::MissingKeyMaterial)?;
    let mut bytes = bs58::decode(multibase.trim_start_matches('z'))
        .into_vec()
        .map_err(|_| VerificationMethodError::InvalidKeyMaterial)?;
    if bytes.len() == 34 && bytes.starts_with(&[0xec, 0x01]) {
        bytes = bytes[2..].to_vec();
    }
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| VerificationMethodError::InvalidKeyMaterial)?;
    Ok(PublicKeyMaterial::X25519(bytes))
}

fn extract_ec_key_from_jwk(
    jwk: &Value,
    expected_curve: &str,
) -> Result<k256::ecdsa::VerifyingKey, VerificationMethodError> {
    let object = jwk
        .as_object()
        .ok_or(VerificationMethodError::InvalidKeyMaterial)?;
    if object.get("kty").and_then(Value::as_str) != Some("EC") {
        return Err(VerificationMethodError::InvalidKeyMaterial);
    }
    if object.get("crv").and_then(Value::as_str) != Some(expected_curve) {
        return Err(VerificationMethodError::InvalidKeyMaterial);
    }
    let x = decode_coordinate(object.get("x").and_then(Value::as_str))?;
    let y = decode_coordinate(object.get("y").and_then(Value::as_str))?;
    let encoded = k256::EncodedPoint::from_affine_coordinates((&x).into(), (&y).into(), false);
    k256::ecdsa::VerifyingKey::from_encoded_point(&encoded)
        .map_err(|_| VerificationMethodError::InvalidKeyMaterial)
}

fn extract_p256_key_from_jwk(
    jwk: &Value,
    expected_curve: &str,
) -> Result<p256::ecdsa::VerifyingKey, VerificationMethodError> {
    let object = jwk
        .as_object()
        .ok_or(VerificationMethodError::InvalidKeyMaterial)?;
    if object.get("kty").and_then(Value::as_str) != Some("EC") {
        return Err(VerificationMethodError::InvalidKeyMaterial);
    }
    if object.get("crv").and_then(Value::as_str) != Some(expected_curve) {
        return Err(VerificationMethodError::InvalidKeyMaterial);
    }
    let x = decode_coordinate(object.get("x").and_then(Value::as_str))?;
    let y = decode_coordinate(object.get("y").and_then(Value::as_str))?;
    let encoded = p256::EncodedPoint::from_affine_coordinates((&x).into(), (&y).into(), false);
    p256::ecdsa::VerifyingKey::from_encoded_point(&encoded)
        .map_err(|_| VerificationMethodError::InvalidKeyMaterial)
}

fn decode_coordinate(value: Option<&str>) -> Result<[u8; 32], VerificationMethodError> {
    let bytes = base64url_decode(value.ok_or(VerificationMethodError::InvalidKeyMaterial)?)
        .map_err(|_| VerificationMethodError::InvalidKeyMaterial)?;
    bytes
        .try_into()
        .map_err(|_| VerificationMethodError::InvalidKeyMaterial)
}
