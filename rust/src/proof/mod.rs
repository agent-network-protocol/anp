//! W3C Data Integrity Proof support for ANP.

pub mod group_receipt;
pub mod im;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::canonical_json::{canonicalize_json, CanonicalJsonError};
use crate::{PrivateKeyMaterial, PublicKeyMaterial};

pub use group_receipt::*;
pub use im::*;

pub const PROOF_TYPE_SECP256K1: &str = "EcdsaSecp256k1Signature2019";
pub const PROOF_TYPE_ED25519: &str = "Ed25519Signature2020";
pub const PROOF_TYPE_DATA_INTEGRITY: &str = "DataIntegrityProof";

pub const CRYPTOSUITE_EDDSA_JCS_2022: &str = "eddsa-jcs-2022";
pub const CRYPTOSUITE_DIDWBA_SECP256K1_2025: &str = "didwba-jcs-ecdsa-secp256k1-2025";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProofGenerationOptions {
    pub proof_purpose: Option<String>,
    pub proof_type: Option<String>,
    pub cryptosuite: Option<String>,
    pub created: Option<String>,
    pub domain: Option<String>,
    pub challenge: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProofVerificationOptions {
    pub expected_purpose: Option<String>,
    pub expected_domain: Option<String>,
    pub expected_challenge: Option<String>,
}

#[derive(Debug, Error)]
pub enum ProofError {
    #[error("Canonicalization error: {0}")]
    Canonicalization(#[from] CanonicalJsonError),
    #[error("Unsupported proof type: {0}")]
    UnsupportedProofType(String),
    #[error("Unsupported cryptosuite: {0}")]
    UnsupportedCryptosuite(String),
    #[error("Key type mismatch for proof generation")]
    KeyTypeMismatch,
    #[error("Missing proof object")]
    MissingProof,
    #[error("Missing proof field: {0}")]
    MissingProofField(String),
    #[error("Verification failed")]
    VerificationFailed,
    #[error("Invalid proof value encoding")]
    InvalidProofValue,
    #[error("Invalid public key for proof verification")]
    InvalidPublicKey,
    #[error("Signing error")]
    SigningError,
}

pub fn generate_w3c_proof(
    document: &Value,
    private_key: &PrivateKeyMaterial,
    verification_method: &str,
    options: ProofGenerationOptions,
) -> Result<Value, ProofError> {
    let proof_type = match options.proof_type.clone() {
        Some(value) => value,
        None => infer_proof_type(private_key),
    };

    validate_key_compatibility(private_key, &proof_type, options.cryptosuite.as_deref())?;

    let created = options
        .created
        .clone()
        .unwrap_or_else(|| Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string());
    let proof_purpose = options
        .proof_purpose
        .clone()
        .unwrap_or_else(|| "assertionMethod".to_string());

    let mut proof_object = Map::new();
    proof_object.insert("type".to_string(), Value::String(proof_type.clone()));
    proof_object.insert("created".to_string(), Value::String(created));
    proof_object.insert(
        "verificationMethod".to_string(),
        Value::String(verification_method.to_string()),
    );
    proof_object.insert("proofPurpose".to_string(), Value::String(proof_purpose));
    if proof_type == PROOF_TYPE_DATA_INTEGRITY {
        let cryptosuite = options
            .cryptosuite
            .clone()
            .unwrap_or_else(|| infer_cryptosuite(private_key));
        validate_cryptosuite(private_key, &cryptosuite)?;
        proof_object.insert("cryptosuite".to_string(), Value::String(cryptosuite));
    }
    if let Some(domain) = options.domain.clone() {
        proof_object.insert("domain".to_string(), Value::String(domain));
    }
    if let Some(challenge) = options.challenge.clone() {
        proof_object.insert("challenge".to_string(), Value::String(challenge));
    }

    let mut signing_document = document.clone();
    if let Some(object) = signing_document.as_object_mut() {
        object.remove("proof");
    }

    let signing_input =
        compute_signing_input(&signing_document, &Value::Object(proof_object.clone()))?;
    let signature = private_key
        .sign_message(&signing_input)
        .map_err(|_| ProofError::SigningError)?;
    proof_object.insert(
        "proofValue".to_string(),
        Value::String(crate::keys::base64url_encode(&signature)),
    );

    let mut signed_document = document.clone();
    let object = signed_document
        .as_object_mut()
        .ok_or(ProofError::VerificationFailed)?;
    object.insert("proof".to_string(), Value::Object(proof_object));
    Ok(signed_document)
}

pub fn verify_w3c_proof(
    document: &Value,
    public_key: &PublicKeyMaterial,
    options: ProofVerificationOptions,
) -> bool {
    verify_w3c_proof_detailed(document, public_key, options).is_ok()
}

pub fn verify_w3c_proof_detailed(
    document: &Value,
    public_key: &PublicKeyMaterial,
    options: ProofVerificationOptions,
) -> Result<(), ProofError> {
    let proof = document
        .get("proof")
        .and_then(Value::as_object)
        .ok_or(ProofError::MissingProof)?;

    let proof_type = proof
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| ProofError::MissingProofField("type".to_string()))?;
    let proof_value = proof
        .get("proofValue")
        .and_then(Value::as_str)
        .ok_or_else(|| ProofError::MissingProofField("proofValue".to_string()))?;
    let verification_method = proof
        .get("verificationMethod")
        .and_then(Value::as_str)
        .ok_or_else(|| ProofError::MissingProofField("verificationMethod".to_string()))?;
    let proof_purpose = proof
        .get("proofPurpose")
        .and_then(Value::as_str)
        .ok_or_else(|| ProofError::MissingProofField("proofPurpose".to_string()))?;
    let _created = proof
        .get("created")
        .and_then(Value::as_str)
        .ok_or_else(|| ProofError::MissingProofField("created".to_string()))?;

    if let Some(expected) = options.expected_purpose.as_deref() {
        if expected != proof_purpose {
            return Err(ProofError::VerificationFailed);
        }
    }
    if let Some(expected) = options.expected_domain.as_deref() {
        if proof.get("domain").and_then(Value::as_str) != Some(expected) {
            return Err(ProofError::VerificationFailed);
        }
    }
    if let Some(expected) = options.expected_challenge.as_deref() {
        if proof.get("challenge").and_then(Value::as_str) != Some(expected) {
            return Err(ProofError::VerificationFailed);
        }
    }

    let cryptosuite = proof.get("cryptosuite").and_then(Value::as_str);
    validate_public_key_compatibility(public_key, proof_type, cryptosuite)?;

    let mut proof_options = proof.clone();
    proof_options.remove("proofValue");
    proof_options.insert(
        "verificationMethod".to_string(),
        Value::String(verification_method.to_string()),
    );

    let mut signing_document = document.clone();
    if let Some(object) = signing_document.as_object_mut() {
        object.remove("proof");
    }
    let signing_input = compute_signing_input(&signing_document, &Value::Object(proof_options))?;
    let signature =
        crate::keys::base64url_decode(proof_value).map_err(|_| ProofError::InvalidProofValue)?;
    public_key
        .verify_message(&signing_input, &signature)
        .map_err(|_| ProofError::VerificationFailed)
}

pub(crate) fn compute_signing_input(
    document: &Value,
    proof_options: &Value,
) -> Result<Vec<u8>, ProofError> {
    let document_hash = hash_bytes(&canonicalize_json(document)?);
    let proof_hash = hash_bytes(&canonicalize_json(proof_options)?);
    let mut output = Vec::with_capacity(document_hash.len() + proof_hash.len());
    output.extend_from_slice(&proof_hash);
    output.extend_from_slice(&document_hash);
    Ok(output)
}

pub(crate) fn hash_bytes(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}

fn infer_proof_type(private_key: &PrivateKeyMaterial) -> String {
    match private_key {
        PrivateKeyMaterial::Secp256k1(_) => PROOF_TYPE_SECP256K1.to_string(),
        PrivateKeyMaterial::Ed25519(_) => PROOF_TYPE_ED25519.to_string(),
        _ => PROOF_TYPE_DATA_INTEGRITY.to_string(),
    }
}

fn infer_cryptosuite(private_key: &PrivateKeyMaterial) -> String {
    match private_key {
        PrivateKeyMaterial::Ed25519(_) => CRYPTOSUITE_EDDSA_JCS_2022.to_string(),
        _ => CRYPTOSUITE_DIDWBA_SECP256K1_2025.to_string(),
    }
}

fn validate_key_compatibility(
    private_key: &PrivateKeyMaterial,
    proof_type: &str,
    cryptosuite: Option<&str>,
) -> Result<(), ProofError> {
    match proof_type {
        PROOF_TYPE_SECP256K1 => match private_key {
            PrivateKeyMaterial::Secp256k1(_) => Ok(()),
            _ => Err(ProofError::KeyTypeMismatch),
        },
        PROOF_TYPE_ED25519 => match private_key {
            PrivateKeyMaterial::Ed25519(_) => Ok(()),
            _ => Err(ProofError::KeyTypeMismatch),
        },
        PROOF_TYPE_DATA_INTEGRITY => validate_cryptosuite(private_key, cryptosuite.unwrap_or("")),
        other => Err(ProofError::UnsupportedProofType(other.to_string())),
    }
}

fn validate_cryptosuite(
    private_key: &PrivateKeyMaterial,
    cryptosuite: &str,
) -> Result<(), ProofError> {
    match cryptosuite {
        CRYPTOSUITE_EDDSA_JCS_2022 => match private_key {
            PrivateKeyMaterial::Ed25519(_) => Ok(()),
            _ => Err(ProofError::KeyTypeMismatch),
        },
        CRYPTOSUITE_DIDWBA_SECP256K1_2025 => match private_key {
            PrivateKeyMaterial::Secp256k1(_) => Ok(()),
            _ => Err(ProofError::KeyTypeMismatch),
        },
        other => Err(ProofError::UnsupportedCryptosuite(other.to_string())),
    }
}

fn validate_public_key_compatibility(
    public_key: &PublicKeyMaterial,
    proof_type: &str,
    cryptosuite: Option<&str>,
) -> Result<(), ProofError> {
    match proof_type {
        PROOF_TYPE_SECP256K1 => match public_key {
            PublicKeyMaterial::Secp256k1(_) => Ok(()),
            _ => Err(ProofError::InvalidPublicKey),
        },
        PROOF_TYPE_ED25519 => match public_key {
            PublicKeyMaterial::Ed25519(_) => Ok(()),
            _ => Err(ProofError::InvalidPublicKey),
        },
        PROOF_TYPE_DATA_INTEGRITY => match cryptosuite {
            Some(CRYPTOSUITE_EDDSA_JCS_2022) => match public_key {
                PublicKeyMaterial::Ed25519(_) => Ok(()),
                _ => Err(ProofError::InvalidPublicKey),
            },
            Some(CRYPTOSUITE_DIDWBA_SECP256K1_2025) => match public_key {
                PublicKeyMaterial::Secp256k1(_) => Ok(()),
                _ => Err(ProofError::InvalidPublicKey),
            },
            Some(other) => Err(ProofError::UnsupportedCryptosuite(other.to_string())),
            None => Err(ProofError::MissingProofField("cryptosuite".to_string())),
        },
        other => Err(ProofError::UnsupportedProofType(other.to_string())),
    }
}

#[allow(dead_code)]
fn _proof_without_value(document: &Value) -> Value {
    let mut copy = document.clone();
    if let Some(object) = copy.as_object_mut() {
        if let Some(Value::Object(proof)) = object.get_mut("proof") {
            proof.remove("proofValue");
        }
    }
    copy
}
