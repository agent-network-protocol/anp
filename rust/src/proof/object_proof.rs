use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::authentication::{
    create_verification_method, find_verification_method, is_assertion_method_authorized,
    validate_did_document_binding,
};
use crate::proof::{
    compute_signing_input, ProofError, CRYPTOSUITE_EDDSA_JCS_2022, PROOF_TYPE_DATA_INTEGRITY,
};
use crate::{PrivateKeyMaterial, PublicKeyMaterial};

pub const OBJECT_PROOF_PURPOSE: &str = "assertionMethod";
pub const OBJECT_PROOF_SIGNATURE_MULTIBASE_PREFIX: &str = "z";
pub const OBJECT_PROOF_REQUIRED_FIELDS: [&str; 6] = [
    "type",
    "cryptosuite",
    "verificationMethod",
    "proofPurpose",
    "created",
    "proofValue",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObjectProofVerificationResult {
    pub issuer_did: String,
    pub verification_method_id: String,
    pub verification_method: Value,
}

pub fn generate_object_proof(
    document: &Value,
    private_key: &PrivateKeyMaterial,
    verification_method: &str,
    issuer_did: &str,
    created: Option<String>,
) -> Result<Value, ProofError> {
    ensure_object(document)?;
    ensure_ed25519_private_key(private_key)?;
    ensure_verification_method_matches_issuer(verification_method, issuer_did)?;
    let created_value = normalize_rfc3339(created)?;

    let mut proof_object = Map::new();
    proof_object.insert(
        "type".to_string(),
        Value::String(PROOF_TYPE_DATA_INTEGRITY.to_string()),
    );
    proof_object.insert(
        "cryptosuite".to_string(),
        Value::String(CRYPTOSUITE_EDDSA_JCS_2022.to_string()),
    );
    proof_object.insert(
        "verificationMethod".to_string(),
        Value::String(verification_method.to_string()),
    );
    proof_object.insert(
        "proofPurpose".to_string(),
        Value::String(OBJECT_PROOF_PURPOSE.to_string()),
    );
    proof_object.insert("created".to_string(), Value::String(created_value));

    let signing_document = document_without_top_level_proof(document)?;
    let signing_input =
        compute_signing_input(&signing_document, &Value::Object(proof_object.clone()))?;
    let signature = private_key
        .sign_message(&signing_input)
        .map_err(|_| ProofError::SigningError)?;
    proof_object.insert(
        "proofValue".to_string(),
        Value::String(encode_signature_multibase(&signature)),
    );

    let mut signed_document = document.clone();
    signed_document
        .as_object_mut()
        .ok_or_else(|| ProofError::InvalidProofField("document must be an object".to_string()))?
        .insert("proof".to_string(), Value::Object(proof_object));
    Ok(signed_document)
}

pub fn verify_object_proof(
    document: &Value,
    issuer_did: &str,
    issuer_document: &Value,
) -> Result<(), ProofError> {
    verify_object_proof_detailed(document, issuer_did, issuer_document).map(|_| ())
}

pub fn verify_object_proof_detailed(
    document: &Value,
    issuer_did: &str,
    issuer_document: &Value,
) -> Result<ObjectProofVerificationResult, ProofError> {
    ensure_object(document)?;
    ensure_object(issuer_document)?;
    if issuer_document.get("id").and_then(Value::as_str) != Some(issuer_did) {
        return Err(ProofError::IssuerDidMismatch);
    }
    if issuer_did.starts_with("did:wba:") && !validate_did_document_binding(issuer_document, false)
    {
        return Err(ProofError::InvalidIssuerDidDocument);
    }

    let proof = document
        .get("proof")
        .and_then(Value::as_object)
        .ok_or(ProofError::MissingProof)?;
    for field in OBJECT_PROOF_REQUIRED_FIELDS {
        let value = proof.get(field).and_then(Value::as_str).unwrap_or_default();
        if value.is_empty() {
            return Err(ProofError::MissingProofField(field.to_string()));
        }
    }
    if proof.get("type").and_then(Value::as_str) != Some(PROOF_TYPE_DATA_INTEGRITY) {
        return Err(ProofError::InvalidProofField("type".to_string()));
    }
    if proof.get("cryptosuite").and_then(Value::as_str) != Some(CRYPTOSUITE_EDDSA_JCS_2022) {
        return Err(ProofError::InvalidProofField("cryptosuite".to_string()));
    }
    if proof.get("proofPurpose").and_then(Value::as_str) != Some(OBJECT_PROOF_PURPOSE) {
        return Err(ProofError::InvalidProofField("proofPurpose".to_string()));
    }

    let verification_method_id = proof
        .get("verificationMethod")
        .and_then(Value::as_str)
        .ok_or_else(|| ProofError::MissingProofField("verificationMethod".to_string()))?;
    ensure_verification_method_matches_issuer(verification_method_id, issuer_did)?;
    parse_rfc3339(
        proof
            .get("created")
            .and_then(Value::as_str)
            .ok_or_else(|| ProofError::MissingProofField("created".to_string()))?,
    )?;

    if !is_assertion_method_authorized(issuer_document, verification_method_id) {
        return Err(ProofError::UnauthorizedVerificationMethod);
    }
    let method = find_verification_method(issuer_document, verification_method_id)
        .ok_or_else(|| ProofError::InvalidProofField("verificationMethod".to_string()))?;
    let verification_method =
        create_verification_method(&method).map_err(|_| ProofError::InvalidPublicKey)?;
    let public_key = match &verification_method.public_key {
        PublicKeyMaterial::Ed25519(key) => PublicKeyMaterial::Ed25519(*key),
        _ => return Err(ProofError::InvalidPublicKey),
    };

    let proof_value = proof
        .get("proofValue")
        .and_then(Value::as_str)
        .ok_or_else(|| ProofError::MissingProofField("proofValue".to_string()))?;
    let signature = decode_signature_multibase(proof_value)?;
    let mut proof_options = proof.clone();
    proof_options.remove("proofValue");
    let signing_document = document_without_top_level_proof(document)?;
    let signing_input = compute_signing_input(&signing_document, &Value::Object(proof_options))?;
    public_key
        .verify_message(&signing_input, &signature)
        .map_err(|_| ProofError::VerificationFailed)?;

    Ok(ObjectProofVerificationResult {
        issuer_did: issuer_did.to_string(),
        verification_method_id: verification_method_id.to_string(),
        verification_method: method,
    })
}

fn ensure_object(value: &Value) -> Result<(), ProofError> {
    if value.is_object() {
        Ok(())
    } else {
        Err(ProofError::InvalidProofField(
            "document must be an object".to_string(),
        ))
    }
}

fn ensure_ed25519_private_key(private_key: &PrivateKeyMaterial) -> Result<(), ProofError> {
    match private_key {
        PrivateKeyMaterial::Ed25519(_) => Ok(()),
        _ => Err(ProofError::InvalidPublicKey),
    }
}

fn ensure_verification_method_matches_issuer(
    verification_method: &str,
    issuer_did: &str,
) -> Result<(), ProofError> {
    if did_from_verification_method(verification_method)? == issuer_did {
        Ok(())
    } else {
        Err(ProofError::IssuerDidMismatch)
    }
}

fn did_from_verification_method(verification_method: &str) -> Result<&str, ProofError> {
    let (did, fragment) = verification_method
        .split_once('#')
        .ok_or_else(|| ProofError::InvalidProofField("verificationMethod".to_string()))?;
    if did.starts_with("did:") && !fragment.is_empty() {
        Ok(did)
    } else {
        Err(ProofError::InvalidProofField(
            "verificationMethod".to_string(),
        ))
    }
}

fn normalize_rfc3339(value: Option<String>) -> Result<String, ProofError> {
    match value {
        Some(value) => {
            parse_rfc3339(&value)?;
            Ok(value)
        }
        None => Ok(Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()),
    }
}

pub(crate) fn parse_rfc3339(value: &str) -> Result<DateTime<Utc>, ProofError> {
    DateTime::parse_from_rfc3339(value)
        .map(|parsed| parsed.with_timezone(&Utc))
        .map_err(|_| ProofError::InvalidTimestamp(value.to_string()))
}

fn encode_signature_multibase(signature: &[u8]) -> String {
    format!(
        "{}{}",
        OBJECT_PROOF_SIGNATURE_MULTIBASE_PREFIX,
        bs58::encode(signature).into_string()
    )
}

fn decode_signature_multibase(value: &str) -> Result<Vec<u8>, ProofError> {
    if !value.starts_with(OBJECT_PROOF_SIGNATURE_MULTIBASE_PREFIX) {
        return Err(ProofError::InvalidProofValue);
    }
    let signature = bs58::decode(value.trim_start_matches(OBJECT_PROOF_SIGNATURE_MULTIBASE_PREFIX))
        .into_vec()
        .map_err(|_| ProofError::InvalidProofValue)?;
    if signature.len() != 64 {
        return Err(ProofError::InvalidProofValue);
    }
    Ok(signature)
}

pub(crate) fn document_without_top_level_proof(document: &Value) -> Result<Value, ProofError> {
    let mut output = document.clone();
    output
        .as_object_mut()
        .ok_or_else(|| ProofError::InvalidProofField("document must be an object".to_string()))?
        .remove("proof");
    Ok(output)
}
