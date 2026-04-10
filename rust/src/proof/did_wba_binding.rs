use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::authentication::{find_verification_method, is_assertion_method_authorized};
use crate::keys::base64url_decode;
use crate::proof::{parse_rfc3339, verify_object_proof, ProofError};
use crate::PrivateKeyMaterial;

use super::generate_object_proof;

pub const DID_WBA_BINDING_REQUIRED_FIELDS: [&str; 5] = [
    "agent_did",
    "verification_method",
    "leaf_signature_key_b64u",
    "issued_at",
    "expires_at",
];

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct DidWbaBindingVerificationOptions {
    pub now: Option<String>,
    pub expected_leaf_signature_key_b64u: Option<String>,
    pub expected_credential_identity: Option<String>,
}

pub fn generate_did_wba_binding(
    agent_did: &str,
    verification_method: &str,
    leaf_signature_key_b64u: &str,
    private_key: &PrivateKeyMaterial,
    issued_at: &str,
    expires_at: &str,
    proof_created: Option<String>,
) -> Result<Value, ProofError> {
    let binding = json!({
        "agent_did": agent_did,
        "verification_method": verification_method,
        "leaf_signature_key_b64u": leaf_signature_key_b64u,
        "issued_at": issued_at,
        "expires_at": expires_at,
    });
    validate_binding_fields(&binding)?;
    generate_object_proof(
        &binding,
        private_key,
        verification_method,
        agent_did,
        proof_created.or_else(|| Some(issued_at.to_string())),
    )
}

pub fn verify_did_wba_binding(
    binding: &Value,
    issuer_document: &Value,
    options: DidWbaBindingVerificationOptions,
) -> Result<(), ProofError> {
    validate_binding_fields(binding)?;
    let binding_object = binding.as_object().ok_or_else(|| {
        ProofError::InvalidProofField("did_wba_binding must be an object".to_string())
    })?;
    let agent_did = binding_object
        .get("agent_did")
        .and_then(Value::as_str)
        .ok_or_else(|| ProofError::MissingProofField("agent_did".to_string()))?;
    let verification_method = binding_object
        .get("verification_method")
        .and_then(Value::as_str)
        .ok_or_else(|| ProofError::MissingProofField("verification_method".to_string()))?;
    if verification_method.split('#').next() != Some(agent_did) {
        return Err(ProofError::IssuerDidMismatch);
    }
    if !is_assertion_method_authorized(issuer_document, verification_method) {
        return Err(ProofError::UnauthorizedVerificationMethod);
    }
    if find_verification_method(issuer_document, verification_method).is_none() {
        return Err(ProofError::InvalidProofField(
            "verification_method".to_string(),
        ));
    }
    if let Some(expected_leaf_key) = options.expected_leaf_signature_key_b64u.as_deref() {
        if binding_object
            .get("leaf_signature_key_b64u")
            .and_then(Value::as_str)
            != Some(expected_leaf_key)
        {
            return Err(ProofError::InvalidProofField(
                "leaf_signature_key_b64u".to_string(),
            ));
        }
    }
    if let Some(expected_identity) = options.expected_credential_identity.as_deref() {
        if expected_identity != agent_did {
            return Err(ProofError::InvalidProofField(
                "credential.identity".to_string(),
            ));
        }
    }

    let issued_at = parse_rfc3339(
        binding_object
            .get("issued_at")
            .and_then(Value::as_str)
            .ok_or_else(|| ProofError::MissingProofField("issued_at".to_string()))?,
    )?;
    let expires_at = parse_rfc3339(
        binding_object
            .get("expires_at")
            .and_then(Value::as_str)
            .ok_or_else(|| ProofError::MissingProofField("expires_at".to_string()))?,
    )?;
    if issued_at > expires_at {
        return Err(ProofError::InvalidProofField("expires_at".to_string()));
    }
    let now = match options.now.as_deref() {
        Some(value) => parse_rfc3339(value)?,
        None => Utc::now(),
    };
    ensure_time_window(now, issued_at, expires_at)?;

    verify_object_proof(binding, agent_did, issuer_document)
}

fn validate_binding_fields(binding: &Value) -> Result<(), ProofError> {
    let object = binding.as_object().ok_or_else(|| {
        ProofError::InvalidProofField("did_wba_binding must be an object".to_string())
    })?;
    for field in DID_WBA_BINDING_REQUIRED_FIELDS {
        let value = object
            .get(field)
            .and_then(Value::as_str)
            .unwrap_or_default();
        if value.is_empty() {
            return Err(ProofError::MissingProofField(field.to_string()));
        }
    }
    let leaf_key = object
        .get("leaf_signature_key_b64u")
        .and_then(Value::as_str)
        .ok_or_else(|| ProofError::MissingProofField("leaf_signature_key_b64u".to_string()))?;
    base64url_decode(leaf_key)
        .map_err(|_| ProofError::InvalidProofField("leaf_signature_key_b64u".to_string()))?;
    parse_rfc3339(
        object
            .get("issued_at")
            .and_then(Value::as_str)
            .ok_or_else(|| ProofError::MissingProofField("issued_at".to_string()))?,
    )?;
    parse_rfc3339(
        object
            .get("expires_at")
            .and_then(Value::as_str)
            .ok_or_else(|| ProofError::MissingProofField("expires_at".to_string()))?,
    )?;
    Ok(())
}

fn ensure_time_window(
    now: DateTime<Utc>,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> Result<(), ProofError> {
    if now < issued_at || now > expires_at {
        return Err(ProofError::VerificationFailed);
    }
    Ok(())
}
